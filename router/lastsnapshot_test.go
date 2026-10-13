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
			s.State, s.MachineID, s.Booted, s.Cert = "started", "m1", booted, rg.cert
			s.Live = &Liveness{LastReport: time.Now()}
		})
	}

	// never booted (e.g. looping on a locked store): no wait at all
	running("")
	t0 := time.Now()
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatalf("a never-booted machine held the pause: %v", err)
	}
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("pause took %s", d)
	}

	// booted: asked, and the session shows what it waits on until the machine answers "nothing to snapshot"
	running("m1")
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	var waiting string
	for i := 0; i < 50 && waiting == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		r.st.Do(func(d *persisted) { waiting = d.Sessions["s1"].Waiting })
	}
	if waiting != "waiting for the machine's last snapshot (up to 30 s)" {
		t.Fatalf("waiting = %q", waiting)
	}
	r.snapshotArrived("m1") // what POST /m/snapshot with X-Snapshot-None does
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatalf("the answer didn't end the wait: %v", err)
	}
	r.st.Do(func(d *persisted) { waiting = d.Sessions["s1"].Waiting })
	if waiting != "" {
		t.Fatalf("still waiting: %q", waiting)
	}
	// booted but silent (its machine stopped or gone): not asked, the pause goes straight to the kill
	running("m1")
	r.st.Do(func(d *persisted) { d.Sessions["s1"].Live.LastReport = time.Now().Add(-10 * time.Minute) })
	t0 = time.Now()
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil || time.Since(t0) > 5*time.Second {
		t.Fatalf("a silent machine held the pause: %v", err)
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
		s.State, s.MachineID, s.Cert = "starting", "", rg.cert       // a resume: its line is still there
		d.Sessions["sNew"] = &Session{ID: "sNew", State: "starting"} // a new line's first start
		d.Sessions["sP"] = &Session{ID: "sP", State: "pausing", MachineID: "m2", Cert: rg.cert, Waiting: "x"}
		d.Sessions["sD"] = &Session{ID: "sD", State: "destroying", MachineID: "m3", Cert: rg.cert}
		d.Sessions["sR"] = &Session{ID: "sR", State: "resuming", Cert: rg.cert}
		d.Sessions["sOK"] = &Session{ID: "sOK", State: "started", MachineID: "m4", Cert: rg.cert}
	})
	r.endCutOff()
	want := map[string]string{"s1": "paused", "sR": "paused", "sNew": "failed", "sP": "failed", "sD": "failed", "sOK": "started"}
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
	rg.core.mu.Lock()
	calls := len(rg.core.calls)
	rg.core.mu.Unlock()
	if calls != 0 {
		t.Fatalf("the core was called (something ran again): %v", rg.core.calls)
	}
	// the retry: the cut-off resume resumes again
	if err := r.Resume("s1", false); err != nil {
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
