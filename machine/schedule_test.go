package main

import (
	"strings"
	"testing"
	"time"
)

func arm(t *testing.T, x *world, path string, body string) string {
	t.Helper()
	st, _, _, err := x.g.arm(path, "", []byte(body))
	if err != nil || st != 200 {
		t.Fatalf("%d %v", st, err)
	}
	for id, w := range x.g.rec.read().Wakeups {
		if strings.Contains(body, w.Prompt) && w.Delivered == "" {
			return id
		}
	}
	for id, c := range x.g.rec.read().Crons {
		if strings.Contains(body, c.Prompt) {
			return id
		}
	}
	for id, w := range x.g.rec.read().Watches {
		if strings.Contains(body, w.Prompt) {
			return id
		}
	}
	t.Fatal("not recorded")
	return ""
}

// the router says only "X is due": the text is the session's own, and each is delivered by the guard's own rules
func TestDueDeliversOnlyTheSessionsOwnTextOnce(t *testing.T) {
	x := newWorld(t)
	sent := captureHarness(t)
	markBooted(t)
	w := arm(t, x, "/api/sessions/s1/wakeup", `{"name":"release","prompt":"ship it"}`)
	if err := x.g.deliverDue(Due{Kind: "wakeup", ID: w}); err != nil {
		t.Fatal(err)
	}
	if err := x.g.deliverDue(Due{Kind: "wakeup", ID: w}); err == nil {
		t.Fatal("a wakeup was delivered twice")
	}
	for _, d := range []Due{{Kind: "wakeup", ID: strings.Repeat("a", 32)}, {Kind: "wakeup", ID: "../x"}, {Kind: "peer", ID: w}, {Kind: "cron", ID: w}} {
		if err := x.g.deliverDue(d); err == nil {
			t.Fatalf("delivered %+v", d)
		}
	}
	c := arm(t, x, "/api/sessions/s1/crons", `{"name":"tick","prompt":"check","everySeconds":3600}`)
	if err := x.g.deliverDue(Due{Kind: "cron", ID: c, Run: 1}); err != nil {
		t.Fatal(err)
	}
	x.clock = x.clock.Add(2 * time.Hour)
	if err := x.g.deliverDue(Due{Kind: "cron", ID: c, Run: 1}); err == nil {
		t.Fatal("a cron run was delivered twice")
	}
	x.clock = x.clock.Add(-110 * time.Minute) // 10 min after run 1
	if err := x.g.deliverDue(Due{Kind: "cron", ID: c, Run: 2}); err == nil || !strings.Contains(err.Error(), "half") {
		t.Fatalf("a cron ran far faster than its period: %v", err)
	}
	x.clock = x.clock.Add(time.Hour)
	if err := x.g.deliverDue(Due{Kind: "cron", ID: c, Run: 2}); err != nil {
		t.Fatal(err)
	}
	wa := arm(t, x, "/api/sessions/s1/watches", `{"name":"ci","script":"echo green","prompt":"CI done"}`)
	if err := x.g.deliverDue(Due{Kind: "watch", ID: wa, Outcome: "exploded"}); err == nil {
		t.Fatal("a watch outcome that isn't one")
	}
	if err := x.g.deliverDue(Due{Kind: "watch", ID: wa, Outcome: "met"}); err != nil {
		t.Fatal(err)
	}
	if err := x.g.deliverDue(Due{Kind: "watch", ID: wa, Outcome: "gave-up"}); err == nil {
		t.Fatal("a watch was delivered twice")
	}
	want := []string{`[scheduled wakeup "release"] ship it`, `[recurring wakeup "tick" — run 1] check`, `[recurring wakeup "tick" — run 2] check`, `[watch "ci" met] CI done`}
	if len(*sent) != 4 {
		t.Fatalf("sent %q", *sent)
	}
	for i, s := range want {
		if !strings.HasPrefix((*sent)[i], s) {
			t.Fatalf("sent %q, want %q", (*sent)[i], s)
		}
	}
	if !strings.Contains((*sent)[3], "green") {
		t.Fatal("the watch's check wasn't run again here")
	}
	// not before boot, not while stopped for the final snapshot
	frozen.Store(true)
	w2 := arm(t, x, "/api/sessions/s1/wakeup", `{"name":"two","prompt":"again"}`)
	if err := x.g.deliverDue(Due{Kind: "wakeup", ID: w2}); err == nil {
		t.Fatal("delivered into a stopped session")
	}
}

func TestNoticesAreBuiltHere(t *testing.T) {
	x := newWorld(t)
	x.g.rec.update(func(r *recordsData) error { r.Leases["iphone"] = "tap   the\nbutton"; return nil })
	if s, err := x.g.noticeText(Notice{Kind: "lease-granted", Device: "iphone", Minutes: 10}); err != nil || !strings.HasSuffix(s, "Your note: tap the button") {
		t.Fatalf("%q %v", s, err)
	}
	for _, n := range []Notice{{Kind: "peer"}, {Kind: "prompt"}, {Kind: "lease-granted", Device: "../x", Minutes: 1}, {Kind: "lease-granted", Device: "iphone"},
		{Kind: "upgraded", From: "tiny", To: "large"}, {Kind: "nudge"}, {Kind: "request-outcome", Filing: "x"}} {
		if _, err := x.g.noticeText(n); err == nil {
			t.Fatalf("built %+v", n)
		}
	}
	// an Inbox outcome: from the session's own filing, each item once
	x.g.rec.update(func(r *recordsData) error {
		r.Filings[strings.Repeat("b", 32)] = filing{Path: "/api/requests/add-store", Body: []byte(`{"store":"gmail","explanation":"mail"}`)}
		return nil
	})
	n := Notice{Kind: "request-outcome", Filing: strings.Repeat("b", 32), Items: []OutcomeItem{{Item: 0, Outcome: "approved", Ref: "r1"}}}
	s, err := x.g.noticeText(n)
	if err != nil || !strings.Contains(s, `adding the store "gmail"`) || !strings.Contains(s, "APPROVED") {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := x.g.noticeText(n); err == nil {
		t.Fatal("an outcome was told twice")
	}
	if _, err := x.g.noticeText(Notice{Kind: "request-outcome", Filing: strings.Repeat("c", 32), Items: n.Items}); err == nil {
		t.Fatal("an outcome for a filing this session never made")
	}
}

func TestUnknownCommandsAreRefused(t *testing.T) {
	x := newWorld(t)
	for _, c := range []string{"refresh-secrets", "exec", "allow scheduler 720h", "claude-prepare:abc", "add-store gmail", "downgrade"} {
		if c == "claude-prepare:abc" {
			continue // a known word with a malformed generation: refused inside (claudelogin.go)
		}
		if x.g.command(c) {
			t.Fatalf("took %q", c)
		}
	}
	// before the chain is checked, only a snapshot is answered
	x.g.ready.Store(false)
	g := x.grantFor([]string{"shell"})
	x.g.handle(Commands{Grant: &g, Shell: []ShellRequest{{ID: "c1", Cmd: "true"}}})
	if x.g.grant() != nil {
		t.Fatal("took a grant while booting")
	}
}
