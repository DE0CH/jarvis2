package main

import (
	"strings"
	"testing"
	"time"
)

// the read-only terminal: the machine pushes its pane, and the terminal shows it with no grant and no exec
func TestPushedScreenNeedsNoGrant(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	if code, out := m.do(t, r.MachineHandler(), "POST", "/m/screen", jsonString(map[string]string{"screen": "\x1b[1mhello\x1b[0m", "cursor": "0,1,80,24,1"})); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, v := appDo(t, r, "GET", "/api/sessions/sA/terminal", "")
	if code != 200 || !strings.Contains(v["screen"].(string), "hello") || v["cursor"] != "0,1,80,24,1" || v["at"] == "" {
		t.Fatalf("%d %v", code, v)
	}
	// typing still needs a terminal (a phone-signed add-on)
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/terminal", `{"text":"x"}`); code == 200 {
		t.Fatal("typing went through without a terminal")
	}
	// a stale push (no heartbeat) isn't shown; another machine's push doesn't land on this session
	r.st.Do(func(d *persisted) { d.Sessions["sA"].Live.screen.at = time.Now().Add(-screenFresh) })
	if _, ok := r.pushedScreen("sA"); ok {
		t.Fatal("a stale screen was used")
	}
	addSession(r, "sB", "started", "mB", false)
	other := newTestMachine(r, "mB")
	other.do(t, r.MachineHandler(), "POST", "/m/screen", jsonString(map[string]string{"screen": "other", "cursor": "0,0,80,24,1"}))
	if s, ok := r.pushedScreen("sA"); ok && strings.Contains(s.Screen, "other") {
		t.Fatal("another machine's screen")
	}
	// a paused session drops it
	r.st.Do(func(d *persisted) { d.Sessions["sB"].State, d.Sessions["sB"].MachineID = "paused", "" })
	if _, ok := r.pushedScreen("sB"); ok {
		t.Fatal("a paused session's screen")
	}
}
