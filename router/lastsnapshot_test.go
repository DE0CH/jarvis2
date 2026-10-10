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
