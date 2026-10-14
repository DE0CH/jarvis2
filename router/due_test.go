package main

// Due signals and notices through the command channel to a machine on the kernel: a wakeup the session armed fires as
// {kind, id} and the guard's answer ends it; a cron's runs count from 1; a paused session is resumed first; a notice
// names only its strict values.

import (
	"strings"
	"testing"
	"time"
)

// answerDue: plays the guard for due signals and notices, recording them
func answerDue(m *vmach, stop chan struct{}) *[]string {
	var got []string
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			a := m.commands()
			for _, d := range a.Due {
				got = append(got, d.Kind+" "+d.ID)
				m.json("POST", "/m/due-result", DueResult{Kind: d.Kind, ID: d.ID, OK: true}, nil)
			}
			for _, n := range a.Notices {
				got = append(got, "notice "+n.Kind)
				m.json("POST", "/m/notice-result", NoticeResult{Kind: n.Kind, OK: true}, nil)
			}
		}
	}()
	return &got
}

func TestADueWakeupReachesTheMachine(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	sid, m := g.newSession()
	m.boot()
	stop := make(chan struct{})
	defer close(stop)
	got := answerDue(m, stop)
	id := strings.Repeat("d", 32)
	if code := m.json("POST", "/m/api/sessions/"+sid+"/wakeups", map[string]any{"delaySeconds": 60, "id": id, "name": "w"}, nil); code != 200 {
		t.Fatal(code)
	}
	g.r.st.Do(func(d *persisted) { d.Schedules[sid].Wakeups["w"].At = time.Now().Add(-time.Second).UnixMilli() })
	g.r.scheduleTick(time.Now())
	waitIdle(t)
	if len(*got) != 1 || (*got)[0] != "wakeup "+id {
		t.Fatalf("%v", *got)
	}
	if ws, _ := g.r.ListWakeups(sid); len(ws) != 0 {
		t.Fatal("a delivered wakeup stayed")
	}
	// a notice: the nudge, numbers only
	if err := g.r.deliverNotice(sid, Notice{Kind: "nudge", Minutes: 20, Jobs: 2}, false); err != nil {
		t.Fatal(err)
	}
	if (*got)[len(*got)-1] != "notice nudge" {
		t.Fatalf("%v", *got)
	}
}

// a due wakeup of a paused session resumes it first, then goes in
func TestADueWakeupResumesAPausedSession(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	sid := g.pausedSession()
	id := strings.Repeat("e", 32)
	g.r.ArmWakeup(sid, &Wakeup{Name: "w", ID: id, At: time.Now().Add(-time.Second).UnixMilli(), ArmedAt: 1})
	done := make(chan error, 1)
	go func() { done <- g.r.fireWakeup(sid, "w", 1) }()
	s := g.waitState(sid, "initialising")
	m := g.vm(s.MachineID)
	m.boot()
	stop := make(chan struct{})
	defer close(stop)
	got := answerDue(m, stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("not delivered")
	}
	if len(*got) != 1 || (*got)[0] != "wakeup "+id {
		t.Fatalf("%v", *got)
	}
}
