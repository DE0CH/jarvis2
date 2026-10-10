package main

import (
	"errors"
	"testing"
)

// a machine waiting on a locked store: the session says which until a pull goes through
func TestLockedStoreShownUntilThePullGoesThrough(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID = "initialising", "m1"
		d.Machines["m1"] = "s1"
	})
	get := func() (v string) { r.st.Do(func(d *persisted) { v = d.Sessions["s1"].LockedStore }); return }

	r.noteSecretsPull("m1", &CoreError{Status: 423, Msg: "core: store claude is locked"})
	if get() != "claude" {
		t.Fatalf("lockedStore = %q", get())
	}
	r.noteSecretsPull("m1", errors.New("core /pull-secrets: connection refused")) // another failure: kept
	if get() != "claude" {
		t.Fatalf("lockedStore after another error = %q", get())
	}
	r.noteSecretsPull("m1", nil)
	if get() != "" {
		t.Fatalf("lockedStore after the pull = %q", get())
	}
	r.noteSecretsPull("m2", &CoreError{Status: 423, Msg: "core: store x is locked"}) // not this session's machine
	if get() != "" {
		t.Fatalf("another machine's pull touched s1: %q", get())
	}
}
