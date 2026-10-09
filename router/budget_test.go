package main

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestCosts(t *testing.T) {
	small := &flyGuest{CPUKind: "shared", CPUs: 2, MemoryMB: 2048}
	if !near(hourlyMachineCost(small), 2*0.0015+2*5.0/730) {
		t.Fatal(hourlyMachineCost(small))
	}
	perf := &flyGuest{CPUKind: "performance", CPUs: 2, MemoryMB: 4096}
	if !near(hourlyMachineCost(perf), 2*0.0315+4*5.0/730) {
		t.Fatal(hourlyMachineCost(perf))
	}
	if hourlyMachineCost(nil) != 0 || !near(hourlyVolumeCost(10), 1.5/730) {
		t.Fatal("nil guest / volume")
	}
	b := burnRate([]flyMachine{
		{State: "started", Config: struct {
			Guest *flyGuest `json:"guest"`
		}{small}},
		{State: "stopped", Config: struct {
			Guest *flyGuest `json:"guest"`
		}{perf}},
	}, []flyVolume{{State: "created", SizeGB: 10}, {State: "destroyed", SizeGB: 99}})
	if b.Running != 1 || b.Volumes != 1 || !near(b.RatePerHour, hourlyMachineCost(small)+hourlyVolumeCost(10)) {
		t.Fatalf("%+v", b)
	}
}

func TestApplySample(t *testing.T) {
	t0 := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s, a, _ := applySample(nil, t0, 1, 30, 25)
	if s.SpentUSD != 0 || a != (budgetActions{}) || s.Month != "2026-10" {
		t.Fatalf("first sample %+v %+v", s, a)
	}
	// a gap longer than maxDeltaH bills only maxDeltaH
	s, _, dh := applySample(&s, t0.Add(10*time.Hour), 1, 30, 25)
	if dh != maxDeltaH || s.SpentUSD != 6 {
		t.Fatalf("gap %v %+v", dh, s)
	}
	// clock going backwards bills nothing
	s2, _, dh := applySample(&s, t0.Add(9*time.Hour), 1, 30, 25)
	if dh != 0 || s2.SpentUSD != 6 {
		t.Fatalf("backwards %v %+v", dh, s2)
	}
	// warn once
	s.SpentUSD = 24.5
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 1, 30, 25)
	if !a.WarnDM || a.Enforce || !s.Warned {
		t.Fatalf("warn %+v %+v", s, a)
	}
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 1, 30, 25)
	if a.WarnDM {
		t.Fatal("warned twice")
	}
	// cap: DM once, enforce every tick
	s.SpentUSD = 29.5
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 1, 30, 25)
	if !a.Enforce || !a.CapDM || !s.Capped || s.CappedAt == nil {
		t.Fatalf("cap %+v %+v", s, a)
	}
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 0, 30, 25)
	if !a.Enforce || a.CapDM {
		t.Fatalf("still capped %+v", a)
	}
	// a new month starts from zero
	s, a, _ = applySample(&s, time.Date(2026, 11, 1, 0, 1, 0, 0, time.UTC), 1, 30, 25)
	if s.Month != "2026-11" || s.SpentUSD != 0 || s.Capped || s.Warned || a.Enforce {
		t.Fatalf("new month %+v %+v", s, a)
	}
	// straight past both lines: the cap, without a warn DM
	_, a, _ = applySample(&BudgetState{Month: "2026-11", SpentUSD: 20, LastSampleAt: s.LastSampleAt}, s.LastSampleAt.Add(5*time.Hour), 3, 30, 25)
	if !a.CapDM || a.WarnDM {
		t.Fatalf("jump %+v", a)
	}
}

func TestThresholds(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if c, w := budgetThresholds(env(nil)); c != 30 || w != 25 {
		t.Fatal(c, w)
	}
	if c, w := budgetThresholds(env(map[string]string{"FLY_BUDGET_USD": "50"})); c != 50 || w != 40 {
		t.Fatal(c, w)
	}
	if c, w := budgetThresholds(env(map[string]string{"FLY_BUDGET_USD": "0", "FLY_BUDGET_WARN_USD": "0"})); c != 0 || w != 0 {
		t.Fatal(c, w)
	}
}

type fakeFly struct {
	ms  []flyMachine
	vs  []flyVolume
	err error
}

func (f *fakeFly) Machines() ([]flyMachine, error) { return f.ms, f.err }
func (f *fakeFly) Volumes() ([]flyVolume, error)   { return f.vs, nil }

func machine(id, state string) flyMachine {
	m := flyMachine{ID: id, State: state}
	m.Config.Guest = &flyGuest{CPUKind: "shared", CPUs: 4, MemoryMB: 4096}
	return m
}

func TestBudgetTick(t *testing.T) {
	st, _ := LoadState(t.TempDir())
	r := NewRouter(Config{}, st, nil, Policy{})
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", MachineID: "m1", Label: "one", State: "started"}
		d.Sessions["s2"] = &Session{ID: "s2", MachineID: "m2", Label: "two", State: "started"}
		d.Sessions["s3"] = &Session{ID: "s3", MachineID: "", State: "paused"}
		d.Machines["m1"], d.Machines["m2"], d.Machines["m3old"] = "s1", "s2", "s3"
	})
	var paused, dms []string
	budgetPause = func(r *Router, sid string) error {
		if sid == "s2" {
			return errBusy
		}
		paused = append(paused, sid)
		return nil
	}
	budgetDM = func(r *Router, text string) { dms = append(dms, text) }
	defer func() {
		budgetPause = func(r *Router, sid string) error { return r.Pause(sid) }
		budgetDM = func(r *Router, text string) { r.DM(text) }
	}()
	fly := &fakeFly{ms: []flyMachine{machine("m1", "started"), machine("m2", "started"), machine("m3old", "started"), machine("x9", "started"), machine("m4", "stopped")},
		vs: []flyVolume{{ID: "v1", State: "created", SizeGB: 1}}}
	t0 := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

	// under the warn line: nothing happens; Also on Fly lists the strangers
	a, _, err := r.budgetTick(fly, t0, 30, 25)
	if err != nil || a != (budgetActions{}) || len(dms) != 0 {
		t.Fatalf("%v %+v %v", err, a, dms)
	}
	other := budgetView.fly["other"].([]flyOther)
	var ids []string
	for _, o := range other {
		ids = append(ids, o.Kind+":"+o.ID)
	}
	if strings.Join(ids, ",") != "machine:m3old,machine:m4,machine:x9,volume:v1" {
		t.Fatalf("also on fly %v", ids)
	}

	// over the cap: pause what can be paused, DM once with the strangers named
	st.Do(func(d *persisted) { d.Budget.SpentUSD = 31 })
	a, p, _ := r.budgetTick(fly, t0.Add(time.Minute), 30, 25)
	if !a.Enforce || !a.CapDM || strings.Join(p, ",") != "one" || strings.Join(paused, ",") != "s1" {
		t.Fatalf("%+v %v %v", a, p, paused)
	}
	if len(dms) != 1 || !strings.Contains(dms[0], "Paused 1 running session(s): one") || !strings.Contains(dms[0], "m3old, x9") {
		t.Fatalf("dm %q", dms)
	}
	if budgetView.budget["capped"] != true {
		t.Fatalf("view %v", budgetView.budget)
	}
	// next tick: s2 is free now and gets paused, with a DM naming it; nothing to pause → no DM
	paused = nil
	budgetPause = func(r *Router, sid string) error { paused = append(paused, sid); return nil }
	r.budgetTick(fly, t0.Add(2*time.Minute), 30, 25)
	if strings.Join(paused, ",") != "s1,s2" || len(dms) != 2 {
		t.Fatalf("%v %v", paused, dms)
	}
	r.budgetTick(&fakeFly{}, t0.Add(3*time.Minute), 30, 25)
	if len(dms) != 2 {
		t.Fatalf("DM with nothing paused: %v", dms)
	}

	// Fly unreachable: the error shows, nothing else changes
	if _, _, err := r.budgetTick(&fakeFly{err: errors.New("down")}, t0.Add(4*time.Minute), 30, 25); err == nil || budgetView.fly["error"] != "down" {
		t.Fatal("no error shown")
	}
}

func TestStateHook(t *testing.T) {
	out := map[string]any{}
	for _, h := range stateHooks {
		h(nil, out)
	}
	if _, ok := out["budget"]; !ok || out["flyApp"] != sessionsApp {
		t.Fatalf("%v", out)
	}
}
