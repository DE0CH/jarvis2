package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const sampleRaw = `{"pid":846,"sessionId":"aaaaaaaa-1111","name":"fix the build","nameSource":"derived","status":"shell","statusUpdatedAt":1791533106447,"startedAt":2,"bridgeSessionId":"session_x"}
{"pid":900,"sessionId":"bbbbbbbb-2222","name":"relay","status":"busy","startedAt":1}
__TITLES__
{"type":"ai-title","aiTitle":"Fix the build","sessionId":"aaaaaaaa-1111"}
__BG__
846 0
0
__ONESHOT__
__AUTH__
aaaaaaaa-1111 uuid-login-1
__CREDS__
1791539182634
__REFUSAL__
{"type":"system","subtype":"model_refusal_fallback","originalModel":"claude-opus-5-5","fallbackModel":"claude-fable-5-1","apiRefusalCategory":"cyber","uuid":"u2","timestamp":"2026-10-09T10:00:02.000Z"}
{"type":"assistant","uuid":"u1","timestamp":"2026-10-09T10:00:01.000Z","message":{"model":"<synthetic>","stop_reason":"refusal","stop_details":{"category":"cyber"},"content":[{"type":"text","text":"API Error: Opus 5.5's safeguards flagged this message"}]}}
`

func TestParseRegistry(t *testing.T) {
	g := parseRegistry(sampleRaw)
	if g == nil {
		t.Fatal("nil")
	}
	if g.SessionID != "aaaaaaaa-1111" || g.LiveName != "fix the build" || g.AiTitle != "Fix the build" {
		t.Fatalf("host: %+v", g)
	}
	if g.Status != "idle" || g.BgTasks != 1 { // "shell" folds into idle + ≥ 1 background job
		t.Fatalf("status %q bg %d", g.Status, g.BgTasks)
	}
	if g.AuthFailed != "uuid-login-1" || g.CredsExpiresAt != 1791539182634 || g.SessionsInside != 2 || g.OneShotDone {
		t.Fatalf("login/inside: %+v", g)
	}
	if len(g.Refusals) != 2 || g.Refusals[0].Kind != "refusal" || g.Refusals[0].Model != "Opus 5.5" || g.Refusals[1].To != "claude-fable-5-1" {
		t.Fatalf("refusals: %+v", g.Refusals)
	}
	if !strings.Contains(downgradeText("x", g.Refusals), "switched it to claude-fable-5-1") {
		t.Fatal(downgradeText("x", g.Refusals))
	}
	if !strings.Contains(downgradeText("x", g.Refusals[:1]), "Opus 5.5's safeguards flagged a message (cyber) and the turn stopped") {
		t.Fatal(downgradeText("x", g.Refusals[:1]))
	}
}

func TestParseRegistryEmptyAndOneShot(t *testing.T) {
	if parseRegistry("__TITLES__\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n__REFUSAL__\n") != nil {
		t.Fatal("no claude inside should be nil")
	}
	g := parseRegistry("__TITLES__\n{\"type\":\"ai-title\",\"aiTitle\":\"Job\",\"sessionId\":\"z\"}\n__BG__\n__ONESHOT__\ndone 2026-10-09\n__AUTH__\n__CREDS__\n__REFUSAL__\n")
	if g == nil || !g.OneShotDone || g.AiTitle != "Job" {
		t.Fatalf("one-shot: %+v", g)
	}
	if s, n := normalize("busy", 2); s != "busy" || n != 2 {
		t.Fatal(s, n)
	}
}

type fakeLocks map[string]bool

func (f fakeLocks) busy(id string) bool { return f[id] }

func running(id string, live *Liveness) *persisted {
	return &persisted{Sessions: map[string]*Session{id: {ID: id, MachineID: "m1", State: "started", Harness: "claude", Live: live}}}
}

func report(l *Liveness, now time.Time, g *Registry) { l.Reg, l.LastReport = g, now }

func kinds(a []pilotAction) string {
	var k []string
	for _, x := range a {
		k = append(k, x.Kind)
	}
	return strings.Join(k, ",")
}

func TestAutoPause(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{}
	d := running("s1", l)
	idle := &Registry{Status: "idle", StatusUpdatedAt: 5}
	none := fakeLocks{}
	veto := func(string) bool { return false }
	report(l, now, idle)
	if a := planTick(d, now, 0, c, none.busy, veto); kinds(a) != "" {
		t.Fatalf("first idle tick: %s", kinds(a))
	}
	now2 := now.Add(c.IdlePause)
	report(l, now2, idle)
	if a := planTick(d, now2, 0, c, none.busy, veto); !strings.Contains(kinds(a), "pause") {
		t.Fatalf("after an hour: %s", kinds(a))
	}
	// a lifecycle action holds it: no pause
	if a := planTick(d, now2, 0, c, fakeLocks{"s1": true}.busy, veto); strings.Contains(kinds(a), "pause") {
		t.Fatal("paused a busy session")
	}
	// busy resets the clock
	report(l, now2, &Registry{Status: "busy"})
	planTick(d, now2, 0, c, none.busy, veto)
	if !l.idleSince.IsZero() {
		t.Fatal("busy should reset the idle clock")
	}
	// background jobs are work
	report(l, now2, &Registry{Status: "idle", BgTasks: 1})
	planTick(d, now2, 0, c, none.busy, veto)
	if !l.idleSince.IsZero() {
		t.Fatal("background jobs should reset the idle clock")
	}
	// switched off
	l.AutoPauseOff = true
	report(l, now, idle)
	planTick(d, now, 0, c, none.busy, veto)
	report(l, now2, idle)
	if a := planTick(d, now2, 0, c, none.busy, veto); strings.Contains(kinds(a), "pause") {
		t.Fatal("auto-pause off but paused")
	}
	// vetoed (a wakeup due soon)
	l.AutoPauseOff = false
	l.idleSince = now
	if a := planTick(d, now2, 0, c, none.busy, func(string) bool { return true }); strings.Contains(kinds(a), "pause") {
		t.Fatal("vetoed but paused")
	}
	// paused sessions forget their clocks and their report
	l.idleSince = now
	d.Sessions["s1"].State, d.Sessions["s1"].MachineID = "paused", ""
	planTick(d, now2, 0, c, none.busy, veto)
	if !l.idleSince.IsZero() || l.Reg != nil {
		t.Fatal("paused session kept its clock or report")
	}
}

func TestOneShotDestroysOnce(t *testing.T) {
	now := time.Now()
	l := &Liveness{OneShot: true, AutoPauseOff: true}
	d := running("s1", l)
	report(l, now, &Registry{OneShotDone: true})
	no := func(string) bool { return false }
	if a := planTick(d, now, 0, defaultPilot, no, no); kinds(a) != "destroy" {
		t.Fatalf("got %s", kinds(a))
	}
	if a := planTick(d, now, 0, defaultPilot, no, no); kinds(a) != "" {
		t.Fatalf("second tick: %s", kinds(a))
	}
}

func TestStaleWaitingEscapeOnce(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour // keep the DMs out of this test
	l := &Liveness{}
	d := running("s1", l)
	no := func(string) bool { return false }
	w := &Registry{Status: "waiting", StatusUpdatedAt: 7}
	report(l, now, w)
	planTick(d, now, 0, c, no, no)
	later := now.Add(c.WaitingCancel)
	report(l, later, w)
	a := planTick(d, later, 0, c, no, no)
	if !strings.Contains(kinds(a), "escape") {
		t.Fatalf("got %s", kinds(a))
	}
	if a := planTick(d, later, 0, c, no, no); strings.Contains(kinds(a), "escape") {
		t.Fatal("escaped twice in one episode")
	}
	// refused before: backing off
	l.waiting.cancelled = false
	l.grantRetry = map[string]time.Time{"status": later.Add(time.Minute)}
	if a := planTick(d, later, 0, c, no, no); strings.Contains(kinds(a), "escape") {
		t.Fatal("escaped while backing off from a refusal")
	}
}

func TestAttentionDM(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{}
	d := running("s1", l)
	d.Sessions["s1"].Label = "Build"
	no := func(string) bool { return false }
	idle := &Registry{Status: "idle", StatusUpdatedAt: 1}
	report(l, now, idle)
	planTick(d, now, 0, c, no, no)
	t5 := now.Add(c.Attention)
	report(l, t5, idle)
	a := planTick(d, t5, 0, c, no, no)
	if len(a) != 1 || a[0].Kind != "dm" || !strings.Contains(a[0].Text, "is idle") {
		t.Fatalf("got %+v", a)
	}
	if a := planTick(d, t5, 0, c, no, no); strings.Contains(kinds(a), "dm") {
		t.Fatal("pinged twice")
	}
	// muted idle ping
	l.settled, l.NotifyIdleOff = nil, true
	planTick(d, now, 0, c, no, no)
	if a := planTick(d, t5, 0, c, no, no); strings.Contains(kinds(a), "dm") {
		t.Fatal("idle ping is muted")
	}
	// no report for a while = dead, which still pings
	l.LastReport = now.Add(-time.Hour)
	l.settled = nil
	planTick(d, now, 0, c, no, no)
	a = planTick(d, t5, 0, c, no, no)
	if len(a) != 1 || !strings.Contains(a[0].Text, "isn't running a live Claude session") {
		t.Fatalf("dead: %+v", a)
	}
}

func TestStallNudgeRepeats(t *testing.T) {
	c, now := defaultPilot, time.Now()
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	no := func(string) bool { return false }
	g := &Registry{Status: "idle", BgTasks: 2, StatusUpdatedAt: 3}
	report(l, now, g)
	planTick(d, now, 0, c, no, no)
	for i := 1; i <= 2; i++ {
		at := now.Add(time.Duration(i) * c.StallNudge)
		report(l, at, g)
		a := planTick(d, at, 0, c, no, no)
		found := false
		for _, x := range a {
			if x.Kind == "nudge" && strings.HasPrefix(x.Text, "Jarvis watchdog: this session has been idle for 15 min while 2 background jobs have") {
				found = true
			}
		}
		if !found {
			t.Fatalf("nudge %d: %+v", i, a)
		}
	}
	// a turn (statusUpdatedAt changed) restarts the clock
	g2 := &Registry{Status: "idle", BgTasks: 2, StatusUpdatedAt: 4}
	at := now.Add(3 * c.StallNudge)
	report(l, at, g2)
	if a := planTick(d, at, 0, c, no, no); strings.Contains(kinds(a), "nudge") {
		t.Fatal("nudged right after a turn")
	}
}

func TestLoginDecisions(t *testing.T) {
	c, now := defaultPilot, time.Now()
	stored := now.Add(time.Hour).UnixMilli()
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	no := func(string) bool { return false }
	// behind the shared pair → write, no repair
	report(l, now, &Registry{Status: "busy", CredsExpiresAt: stored - 1})
	a := planTick(d, now, stored, c, no, no)
	if len(a) != 1 || a[0].Kind != "login" || a[0].Repair != "" {
		t.Fatalf("write: %+v", a)
	}
	if a := planTick(d, now, stored, c, no, no); len(a) != 0 {
		t.Fatal("a second login while one runs")
	}
	l.loginBusy = false
	// up to date → nothing
	report(l, now, &Registry{Status: "busy", CredsExpiresAt: stored})
	if a := planTick(d, now, stored, c, no, no); len(a) != 0 {
		t.Fatalf("up to date: %+v", a)
	}
	// stuck on "Please run /login" → repair once per error
	report(l, now, &Registry{Status: "idle", CredsExpiresAt: stored, AuthFailed: "u1"})
	a = planTick(d, now, stored, c, no, no)
	var login *pilotAction
	for i := range a {
		if a[i].Kind == "login" {
			login = &a[i]
		}
	}
	if login == nil || login.Repair != "u1" {
		t.Fatalf("repair: %+v", a)
	}
	l.loginBusy = false
	if a := planTick(d, now.Add(time.Hour), stored, c, no, no); strings.Contains(kinds(a), "login") {
		t.Fatal("repaired the same error twice")
	}
	// the shared pair itself expired → nothing to push
	report(l, now, &Registry{Status: "idle", CredsExpiresAt: 0, AuthFailed: "u2"})
	if a := planTick(d, now, now.Add(-time.Minute).UnixMilli(), c, no, no); strings.Contains(kinds(a), "login") {
		t.Fatal("pushed an expired pair")
	}
}

func TestDowngradeOnceAndDialog(t *testing.T) {
	c, now := defaultPilot, time.Now()
	c.Attention = 1000 * time.Hour
	l := &Liveness{AutoPauseOff: true}
	d := running("s1", l)
	no := func(string) bool { return false }
	ev := []Refusal{{Kind: "refusal", At: now.UnixMilli(), UUID: "u1", Model: "Opus 5.5"}}
	report(l, now, &Registry{Status: "busy", Refusals: ev})
	a := planTick(d, now, 0, c, no, no)
	if len(a) != 1 || !strings.Contains(a[0].Text, "safeguards flagged") {
		t.Fatalf("got %+v", a)
	}
	if a := planTick(d, now, 0, c, no, no); len(a) != 0 {
		t.Fatal("reported twice")
	}
	// an old event (before the lookback) isn't reported
	l2 := &Liveness{AutoPauseOff: true}
	d2 := running("s2", l2)
	report(l2, now, &Registry{Status: "busy", Refusals: []Refusal{{Kind: "refusal", At: routerStarted.Add(-time.Hour).UnixMilli()}}})
	if a := planTick(d2, now, 0, c, no, no); len(a) != 0 {
		t.Fatal("reported an old refusal")
	}
	// waiting: the pane is checked once per waiting episode
	report(l2, now, &Registry{Status: "waiting", StatusUpdatedAt: 9})
	if a := planTick(d2, now, 0, c, no, no); kinds(a) != "dialog" {
		t.Fatalf("dialog check: %s", kinds(a))
	}
	if a := planTick(d2, now, 0, c, no, no); kinds(a) != "" {
		t.Fatal("checked the pane twice")
	}
	if !promptOnScreen("\x1b[1mOpus 5.5's Safeguards flagged\x1b[0m this message") {
		t.Fatal("promptOnScreen")
	}
}

func TestWriteCredsCmd(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	home := t.TempDir()
	run := func(exp int64) string {
		creds := `{"claudeAiOauth":{"accessToken":"it's \"quoted\"","expiresAt":` + itoa(exp) + `}}`
		cmd := exec.Command("bash", "-c", writeCredsCmd(creds))
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := run(200); got != "written" {
		t.Fatal(got)
	}
	if got := run(100); got != "kept" {
		t.Fatal(got)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".claude", ".credentials.json"))
	if credsExpiry(string(b)) != 200 || !strings.Contains(string(b), `it's \"quoted\"`) {
		t.Fatalf("file: %s", b)
	}
	fi, _ := os.Stat(filepath.Join(home, ".claude", ".credentials.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if strings.Contains(writeCredsCmd("SECRETVALUE"), "SECRETVALUE") {
		t.Fatal("the pair is in the command in the clear")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestSharedLogin(t *testing.T) {
	var gotID, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotID, gotUA = req.Header.Get("CF-Access-Client-Id"), req.Header.Get("User-Agent")
		w.Write([]byte(`{"credentials":"{\"claudeAiOauth\":{\"expiresAt\":42}}","account":"x"}`))
	}))
	defer srv.Close()
	old := loginURL
	loginURL = srv.URL
	defer func() { loginURL = old; loginCache.pair = sharedPair{} }()
	loginCache.pair = sharedPair{}
	t.Setenv("JARVIS1_CREDENTIALS_ID", "")
	r := &Router{}
	if _, err := r.sharedLogin(); !errorsIsNoLogin(err) {
		t.Fatal("expected no-login error", err)
	}
	t.Setenv("JARVIS1_CREDENTIALS_ID", "id1")
	t.Setenv("JARVIS1_CREDENTIALS_SECRET", "sec")
	p, err := r.sharedLogin()
	if err != nil || p.ExpiresAt != 42 || gotID != "id1" || gotUA == "" {
		t.Fatalf("%+v %v %q %q", p, err, gotID, gotUA)
	}
}

func TestToggleRoutesAndView(t *testing.T) {
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := NewRouter(Config{}, st, nil, Policy{})
	mux := http.NewServeMux()
	r.registerAutopilot(func(p string, fn http.HandlerFunc) { mux.HandleFunc(p, fn) },
		func(p string, fn func(http.ResponseWriter, *http.Request, string, []byte)) {})
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Live: &Liveness{idleSince: time.Now()}}
	})
	call := func(path, body string) int {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return w.Code
	}
	if c := call("/api/sessions/s1/auto-pause", `{"on":false}`); c != 200 {
		t.Fatal(c)
	}
	if c := call("/api/sessions/s1/notify-idle", `{"enabled":false}`); c != 200 {
		t.Fatal(c)
	}
	if c := call("/api/sessions/nope/auto-pause", `{"on":true}`); c != 404 {
		t.Fatal(c)
	}
	st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		if !s.Live.AutoPauseOff || !s.Live.NotifyIdleOff || !s.Live.idleSince.IsZero() {
			t.Fatalf("%+v", s.Live)
		}
		s.Live.AutoPauseOff = false
		s.Live.idleSince = time.Now().Add(-10 * time.Minute)
		s.Live.Reg, s.Live.LastReport = &Registry{Status: "idle", AiTitle: "T"}, time.Now()
		v := sessionView(s, d)
		ms, ok := v["pauseInMs"].(int64)
		if v["autoPause"] != "on" || v["notifyIdle"] != "off" || v["aiTitle"] != "T" || !ok || ms < 49*60*1000 || ms > 50*60*1000 {
			t.Fatalf("view: %v", v)
		}
	})
}

func TestOneShotEnv(t *testing.T) {
	on := false
	s := &Session{Live: newLiveness(NewSession{OneShot: true})}
	e := map[string]string{}
	liveEnv(s, e)
	if e["SESSION_ONE_SHOT"] != "1" || !s.Live.AutoPauseOff {
		t.Fatal(e, s.Live)
	}
	if l := newLiveness(NewSession{AutoPause: &on}); !l.AutoPauseOff || l.OneShot {
		t.Fatal(l)
	}
	if l := newLiveness(NewSession{}); l.AutoPauseOff {
		t.Fatal("auto-pause is on by default")
	}
}
