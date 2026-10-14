package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a pause or destroy never waits on a machine that can't snapshot: one that never got past boot isn't asked at
// all; one that answers "nothing to snapshot" (X-Snapshot-None, a machine still booting) ends the wait at once;
// while it does wait, the session says what it waits on
func TestLastSnapshotNeverWaitsOnABootingMachine(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.cfg.SnapshotWait = 30 * time.Second
	running := func(booted string) {
		r.st.Do(func(d *persisted) {
			s := d.Sessions["s1"]
			s.State, s.MachineID, s.Booted = "started", "m1", booted
			s.Live = &Liveness{LastReport: time.Now()}
		})
	}
	timed := func() time.Duration {
		t0 := time.Now()
		done := make(chan struct{})
		go func() { r.lastSnapshot("s1", "m1"); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("lastSnapshot held on")
		}
		return time.Since(t0)
	}
	// never booted (e.g. looping on a locked store): no wait at all
	running("")
	if d := timed(); d > 2*time.Second {
		t.Fatalf("a never-booted machine held it %s", d)
	}
	// booted: asked (the snapshot word), and the session shows what it waits on until the machine answers
	running("m1")
	done := make(chan struct{})
	go func() { r.lastSnapshot("s1", "m1"); close(done) }()
	var waiting string
	for i := 0; i < 50 && waiting == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		r.st.Do(func(d *persisted) { waiting = d.Sessions["s1"].Waiting })
	}
	if waiting != "waiting for the machine's last snapshot (up to 30 s)" {
		t.Fatalf("waiting = %q", waiting)
	}
	if a := r.out("m1").take(); len(a.Commands) != 1 || a.Commands[0] != "snapshot" {
		t.Fatalf("the machine wasn't asked: %+v", a)
	}
	r.snapshotArrived("m1") // what POST /m/snapshot (with X-Snapshot-None too) does
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the answer didn't end the wait")
	}
	r.st.Do(func(d *persisted) { waiting = d.Sessions["s1"].Waiting })
	if waiting != "" {
		t.Fatalf("still waiting: %q", waiting)
	}
	// booted but silent (its machine stopped or gone): not asked
	running("m1")
	r.st.Do(func(d *persisted) { d.Sessions["s1"].Live.LastReport = time.Now().Add(-10 * time.Minute) })
	if d := timed(); d > 2*time.Second {
		t.Fatalf("a silent machine held it %s", d)
	}
	if waitText(10*time.Minute) != "10 min" {
		t.Fatal(waitText(10 * time.Minute))
	}
}

// a crash cut actions off (no goroutine runs them any more): at start each such session becomes a plain one with
// the reason, nothing is run again by itself, and Deyao's retry works from there (Deyao, 2026-10-13)
func TestCutOffActionsEndWithAReason(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID = "starting", "" // a resume cut off before its spawn: the source is unspent
		src := func() *Chain { return &Chain{Source: s.Chain.Source} }
		d.Sessions["sNew"] = &Session{ID: "sNew", State: "starting"} // a new session's first start, no source yet
		d.Sessions["sP"] = &Session{ID: "sP", State: "pausing", MachineID: "m2", Chain: src(), Waiting: "x"}
		d.Sessions["sD"] = &Session{ID: "sD", State: "destroying", MachineID: "m3", Chain: src()}
		d.Sessions["sR"] = &Session{ID: "sR", State: "resuming", Chain: src()}
		d.Sessions["sS"] = &Session{ID: "sS", State: "resuming", Chain: &Chain{Source: s.Chain.Source, Spawn: "spawned"}} // spawned already
		d.Sessions["sOK"] = &Session{ID: "sOK", State: "started", MachineID: "m4", Chain: src()}
	})
	r.endCutOff()
	want := map[string]string{"s1": "paused", "sR": "paused", "sS": "failed", "sNew": "failed", "sP": "failed", "sD": "failed", "sOK": "started"}
	r.st.Do(func(d *persisted) {
		for id, st := range want {
			s := d.Sessions[id]
			if s.State != st {
				t.Errorf("%s: %s, want %s", id, s.State, st)
			}
			if st != "started" && !strings.Contains(s.Error, "cut off by a router crash") {
				t.Errorf("%s: error %q", id, s.Error)
			}
			if s.Waiting != "" {
				t.Errorf("%s: still waiting %q", id, s.Waiting)
			}
		}
	})
	// the retry: the cut-off resume can be asked again (it is paused on its source)
	if err := r.Resume("s1", ResumeIn{}); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(10 * time.Second); time.Now().Before(until); time.Sleep(20 * time.Millisecond) {
		if unlock, err := r.lock("s1", "test"); err == nil {
			unlock()
			break
		}
	}
}

// state.json from before the drain kept "pendingStart" on a resuming session: it loads (the field is dropped)
func TestOldPendingStartIsDropped(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"sessions":{"s1":{"id":"s1","state":"resuming","pendingStart":{"upgrade":true,"machine":"m9"}}}}`), 0o600)
	st, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Do(func(d *persisted) {})
	b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(b), "pendingStart") {
		t.Fatalf("pendingStart kept: %s", b)
	}
}
