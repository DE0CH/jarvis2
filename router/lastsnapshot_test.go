package main

import (
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
	if waitText(10*time.Minute) != "10 min" {
		t.Fatal(waitText(10 * time.Minute))
	}
}

// a router restart cut off a destroy (the session sat at "destroying" for ever): the new router destroys it again
// on start, and the core's kill force-destroys the machine (running, stopped or gone)
func TestRestartResumesACutOffDestroy(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Cert = "destroying", "m1", rg.cert
	})
	r.resumeInterrupted()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		st := ""
		r.st.Do(func(d *persisted) {
			if s := d.Sessions["s1"]; s != nil {
				st = s.State
			}
		})
		if st != "destroying" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	killed := false
	rg.core.mu.Lock()
	for _, c := range rg.core.calls {
		killed = killed || c == "/kill"
	}
	rg.core.mu.Unlock()
	var left *Session
	r.st.Do(func(d *persisted) { left = d.Sessions["s1"] })
	if !killed || (left != nil && left.State == "destroying") {
		t.Fatalf("killed=%v, session %+v", killed, left)
	}
}
