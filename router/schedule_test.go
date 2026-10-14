package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func body(s string) map[string]any {
	m := map[string]any{}
	json.Unmarshal([]byte(s), &m)
	return m
}

func TestNormalizeWakeup(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	id := strings.Repeat("a", 32)
	w, err := normalizeWakeup(body(`{"delaySeconds": 3600, "id": "`+id+`"}`), now)
	if err != nil || w.Name != "default" || w.At != now.Add(time.Hour).UnixMilli() || w.ID != id || w.ArmedAt != now.UnixMilli() {
		t.Fatalf("%+v %v", w, err)
	}
	w, err = normalizeWakeup(body(`{"at": "2026-10-10T08:00:00Z", "id": "`+id+`", "name": "hotel-1"}`), now)
	if err != nil || w.Name != "hotel-1" || w.At != time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC).UnixMilli() {
		t.Fatalf("%+v %v", w, err)
	}
	if w, err = normalizeWakeup(body(`{"at": 1791633600000, "id": "`+id+`"}`), now); err != nil || w.At != 1791633600000 {
		t.Fatalf("ms epoch: %+v %v", w, err)
	}
	for _, b := range []string{
		`{"delaySeconds": 60}`, `{"delaySeconds": 60, "id": "` + id + `", "prompt": "the text stays on the machine"}`,
		`{"delaySeconds": 60, "id": "xyz"}`, `{"id": "` + id + `"}`, `{"delaySeconds": -1, "id": "` + id + `"}`,
		`{"at": "2026-10-01T00:00:00Z", "id": "` + id + `"}`, `{"delaySeconds": 8000000, "id": "` + id + `"}`,
		`{"delaySeconds": 60, "id": "` + id + `", "name": "bad name"}`, `{"at": "tomorrow", "id": "` + id + `"}`,
	} {
		if _, err := normalizeWakeup(body(b), now); err == nil {
			t.Fatalf("%s should be refused", b)
		}
	}
}

func TestNormalizeCronAndAdvance(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	id := strings.Repeat("b", 32)
	c, err := normalizeCron(body(`{"name": "tix", "id": "`+id+`", "time": "12:00", "tz": "Asia/Shanghai"}`), now)
	// 12:00 in Shanghai = 04:00 UTC; today's is past → tomorrow's
	if err != nil || c.NextAt != time.Date(2026, 10, 10, 4, 0, 0, 0, time.UTC).UnixMilli() || c.Every != 86400 || c.TZ != "Asia/Shanghai" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = normalizeCron(body(`{"name": "d", "id": "`+id+`", "everySeconds": 21600, "until": "2026-12-10T00:00:00Z"}`), now)
	if err != nil || c.NextAt != now.Add(6*time.Hour).UnixMilli() || c.Until == nil {
		t.Fatalf("%+v %v", c, err)
	}
	for _, b := range []string{`{"id": "` + id + `"}`, `{"name": "a", "id": "` + id + `", "everySeconds": 60}`, `{"name": "a", "id": "` + id + `", "tz": "Mars/Base"}`,
		`{"name": "a", "id": "` + id + `", "time": "25:00"}`, `{"name": "a", "id": "` + id + `", "until": "2026-10-09T13:00:00Z"}`,
		`{"name": "a", "prompt": "p"}`, `{"name": "a", "id": "` + id + `", "prompt": "p"}`} {
		if _, err := normalizeCron(body(b), now); err == nil {
			t.Fatalf("%s should be refused", b)
		}
	}
	// a session unreachable for 3.5 periods fires once and moves to the next occurrence after now
	c = &Cron{Every: 3600, NextAt: now.UnixMilli()}
	next, ok := advanceCron(c, now.Add(210*time.Minute))
	if !ok || next != now.Add(4*time.Hour).UnixMilli() {
		t.Fatalf("next %v", time.UnixMilli(next).UTC())
	}
	u := now.Add(30 * time.Minute).UnixMilli()
	c.Until = &u
	if _, ok := advanceCron(c, now.Add(time.Minute)); ok {
		t.Fatal("past until: the cron ends")
	}
}

type fakeDelivery struct {
	mu    sync.Mutex
	texts []string
	err   error
}

// install: due signals recorded as "<session>: <kind> <id> [run n] [outcome]"
func (f *fakeDelivery) install(t *testing.T) {
	old := deliverDueHook
	deliverDueHook = func(r *Router, sid string, d Due) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.err != nil {
			return f.err
		}
		x := sid + ": " + d.Kind + " " + d.ID
		if d.Run > 0 {
			x += fmt.Sprintf(" run %d", d.Run)
		}
		if d.Outcome != "" {
			x += " " + d.Outcome
		}
		f.texts = append(f.texts, x)
		return nil
	}
	t.Cleanup(func() { deliverDueHook = old })
}

func (f *fakeDelivery) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.texts...)
}

func captureDM(t *testing.T) *[]string {
	var mu sync.Mutex
	var dms []string
	old := dmHook
	dmHook = func(s string) { mu.Lock(); dms = append(dms, s); mu.Unlock() }
	t.Cleanup(func() { dmHook = old })
	return &dms
}

// waitIdle: the tick's goroutines are done
func waitIdle(t *testing.T) {
	for i := 0; i < 200; i++ {
		schedRun.init()
		schedRun.mu.Lock()
		n := len(schedRun.busy)
		schedRun.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("tick still busy")
}

func TestWakeupFiresOnceAndClears(t *testing.T) {
	r := newTestRouter(t)
	f := &fakeDelivery{}
	f.install(t)
	addSession(r, "s1", "started", "m1", false)
	now := time.Now()
	r.ArmWakeup("s1", &Wakeup{Name: "default", At: now.Add(-time.Second).UnixMilli(), ID: "go", ArmedAt: 1})
	r.ArmWakeup("s1", &Wakeup{Name: "later", At: now.Add(time.Hour).UnixMilli(), ID: "later", ArmedAt: 2})
	r.ArmWakeup("s1", &Wakeup{Name: "named", At: now.Add(-time.Second).UnixMilli(), ID: "x", ArmedAt: 3})
	r.scheduleTick(now)
	waitIdle(t)
	r.scheduleTick(now)
	waitIdle(t)
	got := f.got()
	if len(got) != 2 || !contains(got, "s1: wakeup go") || !contains(got, "s1: wakeup x") {
		t.Fatalf("delivered %q", got)
	}
	ws, _ := r.ListWakeups("s1")
	if len(ws) != 1 || ws[0].Name != "later" {
		t.Fatalf("left %+v", ws)
	}
	if p := r.PendingSchedule("s1"); len(p) != 1 || p[0] != "wakeup later" {
		t.Fatalf("pending %v", p)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func TestWakeupRearmedDuringFireIsKept(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "started", "m1", false)
	old := deliverDueHook
	deliverDueHook = func(r *Router, sid string, d Due) error {
		r.ArmWakeup("s1", &Wakeup{Name: "default", At: time.Now().Add(time.Hour).UnixMilli(), ID: "new", ArmedAt: 99})
		return nil
	}
	t.Cleanup(func() { deliverDueHook = old })
	r.ArmWakeup("s1", &Wakeup{Name: "default", At: time.Now().Add(-time.Second).UnixMilli(), ID: "old", ArmedAt: 1})
	r.scheduleTick(time.Now())
	waitIdle(t)
	ws, _ := r.ListWakeups("s1")
	if len(ws) != 1 || ws[0].ID != "new" {
		t.Fatalf("%+v", ws)
	}
}

func TestWakeupFailuresBackOffThenDrop(t *testing.T) {
	r := newTestRouter(t)
	dms := captureDM(t)
	f := &fakeDelivery{err: errors.New("the machine refused or failed: no wakeup this session armed has that id")}
	f.install(t)
	addSession(r, "s2", "started", "m2", false)
	r.ArmWakeup("s2", &Wakeup{Name: "default", At: time.Now().Add(-time.Second).UnixMilli(), ID: "go", ArmedAt: 1})
	at := time.Now()
	for i := 0; i < scheduleMaxAttempt; i++ {
		r.scheduleTick(at)
		waitIdle(t)
		at = at.Add(9 * time.Minute) // past every backoff
	}
	if ws, _ := r.ListWakeups("s2"); len(ws) != 0 {
		t.Fatalf("dropped after %d attempts: %+v", scheduleMaxAttempt, ws)
	}
	if len(*dms) != 1 || !strings.Contains((*dms)[0], "could not be delivered") {
		t.Fatalf("dms %q", *dms)
	}
}

func TestCronFiresAndAdvances(t *testing.T) {
	r := newTestRouter(t)
	f := &fakeDelivery{}
	f.install(t)
	addSession(r, "s5", "started", "m5", false)
	now := time.Now()
	r.ArmCron("s5", &Cron{Name: "daily", ID: "daily", Every: 86400, TZ: "UTC", NextAt: now.Add(-time.Minute).UnixMilli(), ArmedAt: 1})
	r.scheduleTick(now)
	waitIdle(t)
	got := f.got()
	if len(got) != 1 || got[0] != "s5: cron daily run 1" {
		t.Fatalf("%q", got)
	}
	// the next run counts up
	r.st.Do(func(d *persisted) { d.Schedules["s5"].Crons["daily"].NextAt = now.Add(-time.Second).UnixMilli() })
	r.scheduleTick(now)
	waitIdle(t)
	if got := f.got(); len(got) != 2 || got[1] != "s5: cron daily run 2" {
		t.Fatalf("%q", got)
	}
	cs, _ := r.ListCrons("s5")
	if len(cs) != 1 || cs[0].Runs != 2 || cs[0].NextAt <= now.UnixMilli() || cs[0].LastFiredAt == nil {
		t.Fatalf("%+v", cs[0])
	}
}

func TestScheduleGoesWithItsSession(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s8", "started", "m8", false)
	r.ArmWakeup("s8", &Wakeup{Name: "default", At: time.Now().Add(time.Hour).UnixMilli(), ID: "x", ArmedAt: 1})
	if !r.ScheduleDueWithin("s8", 2*time.Hour) || r.ScheduleDueWithin("s8", time.Minute) {
		t.Fatal("due within")
	}
	r.finish("s8")
	r.scheduleTick(time.Now())
	r.st.Do(func(d *persisted) {
		if d.Schedules["s8"] != nil {
			t.Fatal("the schedule outlived its session")
		}
	})
	if err := r.ArmWakeup("gone", &Wakeup{Name: "default"}); !errors.Is(err, errNoSession) {
		t.Fatal(err)
	}
}

// the autopilot asks the scheduler's veto while it holds the state lock: the veto must not take it again
// (it did, and the first tick with a started session froze the whole router)
func TestAutopilotVetoDoesNotDeadlock(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s9", "started", "m9", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["s9"].Live = &Liveness{Reg: &Registry{Status: "idle"}, LastReport: time.Now()}
	})
	r.ArmWakeup("s9", &Wakeup{Name: "default", At: time.Now().Add(5 * time.Minute).UnixMilli(), ID: "x", ArmedAt: 1})
	done := make(chan struct{})
	go func() { r.autopilotTick(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("autopilotTick deadlocked on the scheduler's veto")
	}
}
