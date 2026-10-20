package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

const acct2 = `{"oauthAccount":{"accountUuid":"acct-2","emailAddress":"acct-2@example.com"}}`

// twoAccounts: claude-a (acct-1, the default) and claude-b (acct-2), both signed in; the expiries of their pairs
func twoAccounts(t *testing.T) (*Router, *loginHub, *loginHub, int64, int64) {
	f := newFakeAnthropic(t)
	f.accounts["b"] = "acct-2"
	r, a := ownRouter(t)
	b, err := r.accounts().add("b")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	expA, expB := now+3_600_000, now+7_200_000
	if ok, err := a.offer(pairOf("a", expA), acct1, "seed", true, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := b.offer(pairOf("b", expB), acct2, "seed", true, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	return r, a, b, expA, expB
}

func setReg(r *Router, id string, fn func(g *Registry)) {
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s.Live == nil {
			s.Live = &Liveness{}
		}
		if s.Live.Reg == nil {
			s.Live.Reg = &Registry{}
		}
		fn(s.Live.Reg)
		s.Live.LastReport = time.Now()
	})
}

func shortSwapWaits(t *testing.T) {
	saved := []time.Duration{swapLoginWait, swapRestartWait, swapUpWait, swapPoll}
	swapLoginWait, swapRestartWait, swapUpWait, swapPoll = 3*time.Second, 300*time.Millisecond, 3*time.Second, 10*time.Millisecond
	t.Cleanup(func() { swapLoginWait, swapRestartWait, swapUpWait, swapPoll = saved[0], saved[1], saved[2], saved[3] })
}

// a running session: the account changes, the machine takes the new pair, and a host the machine doesn't restart by
// itself (an older image, a host that isn't idle) is restarted through the terminal holder; the conversation goes on
func TestAccountSwitchRunning(t *testing.T) {
	r, _, _, expA, expB := twoAccounts(t)
	shortSwapWaits(t)
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].ClaudeAccount = "claude-a" })
	setReg(r, "sA", func(g *Registry) {
		g.HostPid, g.CredsExpiresAt, g.BridgeSessionID, g.Status = 100, expA, "cse_1", "busy"
	})
	addGrant(r, "sA", "terminal", "rule")
	stop := make(chan struct{})
	defer close(stop)
	cmds := answerExecs(r, "mA", 0, stop)

	// errors first: an unknown account, the same account
	if code, out := appDo(t, r, "POST", "/api/sessions/sA/account", `{"account":"nope"}`); code != 400 {
		t.Fatal(code, out)
	}
	if code, out := appDo(t, r, "POST", "/api/sessions/sA/account", `{"account":"a"}`); code != 200 || out["unchanged"] != true {
		t.Fatal(code, out)
	}

	code, out := appDo(t, r, "POST", "/api/sessions/sA/account", `{"account":"claude-b"}`)
	if code != 202 || out["from"] != "claude-a" || out["to"] != "claude-b" {
		t.Fatal(code, out)
	}
	r.st.Do(func(d *persisted) {
		if d.Sessions["sA"].ClaudeAccount != "claude-b" {
			t.Fatal("the account didn't change")
		}
	})
	if q := r.queue("mA"); len(q) == 0 || <-q != "claude-account" {
		t.Fatal("the machine wasn't told")
	}
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/account", `{"account":"claude-a"}`); code != 409 {
		t.Fatal("a second switch while the first runs", code)
	}
	// the machine takes the new pair; nobody restarts the host: the router does, through the terminal holder
	setReg(r, "sA", func(g *Registry) { g.CredsExpiresAt = expB })
	waitFor(t, "the host killed through the terminal holder", func() bool {
		r.cmdMu.Lock()
		defer r.cmdMu.Unlock()
		return len(*cmds) == 1 && (*cmds)[0] == swapKillCmd
	})
	if j := r.ops.jobView("sA"); j == nil || j["phase"] != "restarting Claude" {
		t.Fatal("phase", j)
	}
	setReg(r, "sA", func(g *Registry) { g.HostPid, g.Status = 200, "idle" })
	waitFor(t, "the switch done", func() bool { j := r.ops.jobView("sA"); return j != nil && j["phase"] == "done" })
	if r.ops.busyOf("sA") != nil {
		t.Fatal("the session stayed locked")
	}
}

// a running session whose machine restarts the host by itself (images with the "claude-account" command): no exec
func TestAccountSwitchMachineRestarts(t *testing.T) {
	r, _, _, expA, expB := twoAccounts(t)
	shortSwapWaits(t)
	swapRestartWait = 3 * time.Second
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].ClaudeAccount = "claude-a" })
	setReg(r, "sA", func(g *Registry) { g.HostPid, g.CredsExpiresAt, g.BridgeSessionID, g.Status = 100, expA, "cse_1", "idle" })
	stop := make(chan struct{})
	defer close(stop)
	cmds := answerExecs(r, "mA", 0, stop)
	if code, out := appDo(t, r, "POST", "/api/sessions/sA/account", `{"account":"b"}`); code != 202 {
		t.Fatal(code, out)
	}
	setReg(r, "sA", func(g *Registry) { g.CredsExpiresAt, g.HostPid = expB, 300 })
	waitFor(t, "the switch done", func() bool { j := r.ops.jobView("sA"); return j != nil && j["phase"] == "done" })
	if len(*cmds) != 0 {
		t.Fatal("an exec although the machine restarted the host", *cmds)
	}
}

// the machine never takes the pair: the job fails and says so
func TestAccountSwitchNoPairFails(t *testing.T) {
	r, _, _, expA, _ := twoAccounts(t)
	shortSwapWaits(t)
	swapLoginWait = 200 * time.Millisecond
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].ClaudeAccount = "claude-a" })
	setReg(r, "sA", func(g *Registry) { g.HostPid, g.CredsExpiresAt, g.Status = 100, expA, "idle" })
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/account", `{"account":"b"}`); code != 202 {
		t.Fatal(code)
	}
	waitFor(t, "failed", func() bool { j := r.ops.jobView("sA"); return j != nil && j["phase"] == "failed" })
	if j := r.ops.jobView("sA"); !strings.Contains(j["error"].(string), "didn't take claude-b's login") {
		t.Fatal(j)
	}
}

// a paused session: the next start takes the new account; with continue, "continue" goes in once its host is up and idle
func TestAccountSwitchPausedContinueAfterStart(t *testing.T) {
	r, _, _, _, _ := twoAccounts(t)
	addSession(r, "sP", "paused", "", false)
	r.st.Do(func(d *persisted) { d.Sessions["sP"].ClaudeAccount = "claude-a" })
	code, out := appDo(t, r, "POST", "/api/sessions/sP/account", `{"account":"b","continue":true}`)
	if code != 200 || out["nextStart"] != true || out["to"] != "claude-b" {
		t.Fatal(code, out)
	}
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions["sP"] })
	if s.ClaudeAccount != "claude-b" || s.Ops == nil || !s.Ops.ContinueAfterStart {
		t.Fatalf("%+v %+v", s.ClaudeAccount, s.Ops)
	}
	// started again: nothing until its host is up and idle, then one "continue"
	live := &Liveness{Reg: &Registry{Status: "busy", BridgeSessionID: "cse_2"}, LastReport: time.Now(), HostUp: "m1"}
	d := running("sP", live)
	d.Sessions["sP"].Ops = &SessionOps{ContinueAfterStart: true}
	plan := func() (n int) {
		for _, a := range planTick(d, time.Now(), nil, defaultPilot, fakeLocks{}.busy, func(string) bool { return false }) {
			if a.Kind == "continue" && a.Session == "sP" {
				n++
			}
		}
		return
	}
	if plan() != 0 {
		t.Fatal("continue into a busy host")
	}
	live.Reg.Status = "idle"
	if plan() != 1 || plan() != 0 {
		t.Fatal("not exactly one continue")
	}
}

// a machine's long poll held on its old account's hub returns at the switch with the new account's login
func TestAccountSwitchWakesTheLongPoll(t *testing.T) {
	r, a, _, expA, expB := twoAccounts(t)
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].ClaudeAccount = "claude-a" })
	got := make(chan loginAnswer, 1)
	go func() {
		ans, _ := r.pollWithSwitch(context.Background(), "mA", a, expA, 0, 30*time.Second)
		got <- ans
	}()
	time.Sleep(100 * time.Millisecond)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].ClaudeAccount = "claude-b" })
	signalAccountSwitch()
	select {
	case ans := <-got:
		if accountUUID(ans.Account) != "acct-2" || ans.ExpiresAt != expB || ans.Credentials == "" {
			t.Fatalf("%+v", ans)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the poll held on the old account")
	}
}

// the Inbox says what a requested switch does: which session, from which account to which
func TestAccountSwitchCallDoes(t *testing.T) {
	r, _, _, _, _ := twoAccounts(t)
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["sA"].ClaudeAccount = "claude-a"
		got := callDoes(d, RequestParams{Method: "POST", Path: "/api/sessions/sA/account", Body: `{"account":"b","continue":true}`})
		if !strings.Contains(got, "“label sA” (sA) from Claude account claude-a to claude-b") || !strings.Contains(got, "continue") {
			t.Fatal(got)
		}
		if callDoes(d, RequestParams{Method: "POST", Path: "/api/sessions/sA/permission-mode"}) != "" {
			t.Fatal("does for another route")
		}
	})
	if _, rule, err := r.callRoute("POST", "/api/sessions/sA/account"); err != nil || rule != callBody {
		t.Fatal("not requestable as an API call", rule, err)
	}
}
