package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func supPush(t *testing.T, r *Router, m testMachine, lines ...string) int {
	t.Helper()
	ls := []map[string]string{}
	for _, l := range lines {
		ls = append(ls, map[string]string{"at": time.Now().UTC().Format(time.RFC3339Nano), "text": l})
	}
	code, _ := m.do(t, r.MachineHandler(), "POST", "/m/supervisor-log", jsonString(map[string]any{"lines": ls}))
	return code
}

// the machine pushes its lines; the app reads them after a seq; a machine of no session is refused
func TestSupervisorLogPushAndRead(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	if c := supPush(t, r, m, "supervisor started (oom_score_adj -1000)", "guard: exec allowed"); c != 200 {
		t.Fatal(c)
	}
	if c := supPush(t, r, m, strings.Repeat("x", 3000)); c != 200 {
		t.Fatal(c)
	}
	code, v := appDo(t, r, "GET", "/api/sessions/sA/supervisor-log", "")
	lines, _ := v["lines"].([]any)
	if code != 200 || len(lines) != 3 || v["machine"] != "mA" || v["next"].(float64) != 3 {
		t.Fatalf("%d %v", code, v)
	}
	if l := lines[2].(map[string]any); len(l["text"].(string)) > supLogMaxLine+4 || l["machine"] != "mA" {
		t.Fatal("a long line wasn't clipped")
	}
	_, v = appDo(t, r, "GET", "/api/sessions/sA/supervisor-log?after=2", "")
	if ls := v["lines"].([]any); len(ls) != 1 || ls[0].(map[string]any)["seq"].(float64) != 3 {
		t.Fatalf("after: %v", v)
	}
	stray := newTestMachine(r, "mX") // started by the core, but no session's
	if c := supPush(t, r, stray, "hello"); c != 404 {
		t.Fatalf("a machine of no session: %d", c)
	}
	too := make([]string, supLogMaxLines+1)
	if c := supPush(t, r, m, too...); c != 400 {
		t.Fatalf("too many lines: %d", c)
	}
	// a paused session keeps its log
	r.st.Do(func(d *persisted) { d.Sessions["sA"].State, d.Sessions["sA"].MachineID = "paused", "" })
	if _, v := appDo(t, r, "GET", "/api/sessions/sA/supervisor-log", ""); len(v["lines"].([]any)) != 3 {
		t.Fatalf("paused: %v", v)
	}
	// the seq goes on after a router restart (read back from the file)
	r2 := NewRouter(r.cfg, r.st, nil, Policy{})
	r2.st.Do(func(d *persisted) { d.Sessions["sA"].MachineID = "mA" })
	if err := r2.appendSupLog("sA", "mA", []SupLine{{At: nowText(), Text: "after restart"}}); err != nil {
		t.Fatal(err)
	}
	if ls, next := r2.supLogLines("sA", 0, 100); len(ls) != 4 || next != 4 {
		t.Fatalf("%v %d", ls, next)
	}
}

// past the cap the file keeps its newer half and says so
func TestSupervisorLogCap(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	old := supLogMaxFile
	supLogMaxFile = 4000
	t.Cleanup(func() { supLogMaxFile = old })
	for i := 0; i < 100; i++ {
		r.appendSupLog("sA", "mA", []SupLine{{At: nowText(), Text: fmt.Sprintf("line %03d", i)}})
	}
	fi, _ := os.Stat(r.supLogPath("sA"))
	if fi.Size() > 4000+200 {
		t.Fatalf("file %d bytes", fi.Size())
	}
	ls, _ := r.supLogLines("sA", 0, 1000)
	if !strings.Contains(ls[0].Text, "oldest lines were dropped") || ls[len(ls)-1].Text != "line 099" {
		t.Fatalf("first %q last %q", ls[0].Text, ls[len(ls)-1].Text)
	}
	for i := 1; i < len(ls); i++ {
		if ls[i].Seq <= ls[i-1].Seq {
			t.Fatal("seq not increasing after a cut")
		}
	}
}

// lcFakeFly: events and logs per machine, as Fly answers them (events repeat on every poll)
type lcFakeFly struct {
	mu     sync.Mutex
	events map[string][]flyEvent
	logs   map[string][]flyLogLine
	calls  int
	refuse bool
}

func useFakeFly(t *testing.T, r *Router) *lcFakeFly {
	f := &lcFakeFly{events: map[string][]flyEvent{}, logs: map[string][]flyLogLine{}}
	r.lc.flyEvents = func(m string) ([]flyEvent, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		return append([]flyEvent{}, f.events[m]...), nil
	}
	r.lc.flyLogs = func(m, next string) ([]flyLogLine, string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.refuse {
			return nil, next, &flyLogsRefused{403}
		}
		ls := f.logs[m]
		i := 0
		fmt.Sscan(next, &i)
		return append([]flyLogLine{}, ls[i:]...), fmt.Sprint(len(ls)), nil
	}
	r.lc.flyOn = func() bool { return true }
	r.lc.pollEvery, r.lc.tail = 20*time.Millisecond, 100*time.Millisecond
	return f
}

func (f *lcFakeFly) event(m, typ, status string, at time.Time) {
	f.mu.Lock()
	f.events[m] = append(f.events[m], flyEvent{Type: typ, Status: status, Source: "flyd", Timestamp: at.UnixMilli()})
	f.mu.Unlock()
}

func (f *lcFakeFly) log(m, provider, msg string, at time.Time) {
	f.mu.Lock()
	f.logs[m] = append(f.logs[m], flyLogLine{ID: fmt.Sprint(len(f.logs[m])), Timestamp: at.UTC().Format(time.RFC3339Nano), Message: msg, Provider: provider})
	f.mu.Unlock()
}

func opEntries(t *testing.T, r *Router, session string) (map[string]any, []map[string]any) {
	t.Helper()
	code, v := appDo(t, r, "GET", "/api/sessions/"+session+"/lifecycle", "")
	ops, _ := v["ops"].([]any)
	if code != 200 || len(ops) == 0 {
		t.Fatalf("ops: %d %v", code, v)
	}
	id := ops[0].(map[string]any)["id"].(string)
	code, op := appDo(t, r, "GET", "/api/sessions/"+session+"/lifecycle/"+id, "")
	if code != 200 {
		t.Fatalf("op: %d %v", code, op)
	}
	es := []map[string]any{}
	for _, e := range op["entries"].([]any) {
		es = append(es, e.(map[string]any))
	}
	return op, es
}

func texts(es []map[string]any) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%s|%s\n", e["source"], e["text"])
	}
	return b.String()
}

// a pause is one operation: the router's steps, Fly's events (each once, though Fly repeats them) and its platform
// log lines (not the app's stdout), and the supervisor's lines, in time order
func TestPauseRecordsItsLifecycleLog(t *testing.T) {
	rg := newRig(t)
	rg.r.cfg.NoAccess = true
	fly := useFakeFly(t, rg.r)
	rg.r.lc.tail = 10 * time.Second // the tail polls on after the pause (a loaded test box is slow)
	runningM2(rg, false)
	rg.writeSnapshot(t, "m2", rg.files)
	m := testMachine{"m2", rg.mkey.k}
	now := time.Now()
	fly.event("m2", "exit", "stopped", now)
	fly.event("m2", "destroy", "destroyed", now.Add(10*time.Millisecond))
	fly.log("m2", "runner", "Machine destroyed", now.Add(20*time.Millisecond))
	fly.log("m2", "app", "[jarvis2] stdout of the machine", now.Add(20*time.Millisecond))
	supPush(t, rg.r, m, "supervisor: snapshot committed")
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "Fly read three times", func() bool { fly.mu.Lock(); defer fly.mu.Unlock(); return fly.calls >= 3 })
	op, es := opEntries(t, rg.r, "s1")
	all := texts(es)
	if op["kind"] != "pause" || op["state"] != "done" || op["running"] != false || fmt.Sprint(op["machines"]) != "[m2]" {
		t.Fatalf("op %v", op)
	}
	for _, want := range []string{"router|the machine's final snapshot is already here", "router|asked the core to destroy the machine on Fly",
		"router|the core confirmed the machine destroyed on Fly", "fly|Fly: machine exit → stopped (flyd)", "fly|Fly: machine destroy → destroyed (flyd)",
		"fly|Fly runner: Machine destroyed", "supervisor|supervisor: snapshot committed"} {
		if strings.Count(all, want) != 1 {
			t.Fatalf("%q %d times in\n%s", want, strings.Count(all, want), all)
		}
	}
	if strings.Contains(all, "stdout of the machine") {
		t.Fatal("the app's own stdout came in from Fly")
	}
	for i := 1; i < len(es); i++ {
		if parseAt(es[i]["at"].(string)).Before(parseAt(es[i-1]["at"].(string))) {
			t.Fatalf("not in time order:\n%s", all)
		}
	}
}

// Fly's logs API refusing the read-only token: one note, then events only
func TestFlyLogsRefusedFallsBackToEvents(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	fly := useFakeFly(t, r)
	fly.mu.Lock()
	fly.refuse = true
	fly.mu.Unlock()
	addSession(r, "sA", "started", "mA", false)
	h := r.lcBegin("sA", "pause")
	h.machine("mA")
	fly.event("mA", "start", "started", time.Now())
	time.Sleep(100 * time.Millisecond)
	h.end("done", "")
	time.Sleep(150 * time.Millisecond)
	_, es := opEntries(t, r, "sA")
	all := texts(es)
	if strings.Count(all, "HTTP 403 for the router's read-only token") != 1 || strings.Count(all, "start → started") != 1 {
		t.Fatalf("%s", all)
	}
}

// the dedupe: the same Fly event seen on every poll is kept once; an event from before the operation isn't
func TestFlyEventDedupe(t *testing.T) {
	r := newTestRouter(t)
	fly := useFakeFly(t, r)
	r.lc.pollEvery = time.Hour // polled by hand
	addSession(r, "sA", "started", "mA", false)
	fly.event("mA", "launch", "created", time.Now().Add(-time.Hour))
	h := r.lcBegin("sA", "boot")
	h.machine("mA")
	fly.event("mA", "start", "started", time.Now())
	for i := 0; i < 3; i++ {
		r.lcPollOnce(h.run)
	}
	_, entries := r.lcRead(r.lcPath("sA"))
	got := entries[h.run.op.ID]
	if len(got) != 1 || !strings.Contains(got[0].Text, "start → started") {
		t.Fatalf("%+v", got)
	}
}

// the merge: router and Fly entries and the supervisor lines of the op's machines in its window, by time
func TestLifecycleMergeOrder(t *testing.T) {
	r := newTestRouter(t)
	t0 := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	at := func(s int) string { return t0.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
	op := LcOp{ID: "o", Started: at(0), Ended: at(10), State: "done", Machines: []string{"m1"}}
	own := []LcEntry{{At: at(1), Source: "router", Text: "r1"}, {At: at(5), Source: "fly", Text: "f5"}, {At: at(3), Source: "fly", Text: "f3"}}
	sup := []SupLine{{At: at(-60), Machine: "m1", Text: "too early"}, {At: at(-2), Machine: "m1", Text: "s-2"}, {At: at(4), Machine: "m1", Text: "s4"},
		{At: at(4), Machine: "m9", Text: "other machine"}, {At: at(35), Machine: "m1", Text: "s35"}, {At: at(60), Machine: "m1", Text: "too late"}}
	var got []string
	for _, e := range r.lcOpLog(op, own, sup) {
		got = append(got, e.Text)
	}
	if strings.Join(got, ",") != "s-2,r1,f3,s4,f5,s35" {
		t.Fatalf("%v", got)
	}
}

// Destroy: the supervisor log and every operation (the destroy's too) go into the archive, then off the volume
func TestDestroyArchivesTheLogs(t *testing.T) {
	rg := newRig(t)
	rg.r.cfg.NoAccess = true
	runningM2(rg, false)
	rg.writeSnapshot(t, "m2", rg.files)
	m := testMachine{"m2", rg.mkey.k}
	supPush(t, rg.r, m, "supervisor started")
	if err := rg.r.Destroy("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil && rg.r.record("s1").Archive != nil })
	dir := rg.r.record("s1").Archive.Dir + "/jarvis2/"
	sup := string(rg.dav.get(dir + "supervisor-log.jsonl"))
	if !strings.Contains(sup, "supervisor started") {
		t.Fatalf("supervisor log %q", sup)
	}
	var ops []map[string]any
	if err := json.Unmarshal(rg.dav.get(dir+"lifecycle.json"), &ops); err != nil || len(ops) != 1 || ops[0]["kind"] != "destroy" {
		t.Fatalf("lifecycle.json %v %v", err, ops)
	}
	b, _ := json.Marshal(ops[0]["entries"])
	if !strings.Contains(string(b), "archived to ") || !strings.Contains(string(b), "supervisor started") {
		t.Fatalf("entries %s", b)
	}
	if fileExists(rg.r.supLogPath("s1")) || fileExists(rg.r.lcPath("s1")) {
		t.Fatal("the logs stayed on the volume")
	}
}

// the supervisor's pause/resume of the Claude process: queued for the machine, and an operation of its own
func TestHarnessPauseQueuesTheCommand(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	if code, v := appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"pause"}`); code != 200 || v["command"] != "pause-harness" {
		t.Fatalf("%d %v", code, v)
	}
	select {
	case c := <-r.queue("mA"):
		if c != "pause-harness" {
			t.Fatal(c)
		}
	default:
		t.Fatal("nothing queued")
	}
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"stop"}`); code != 400 {
		t.Fatal(code)
	}
	appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"resume"}`)
	if c := <-r.queue("mA"); c != "resume-harness" {
		t.Fatal(c)
	}
	op, es := opEntries(t, r, "sA")
	if op["kind"] != "harness-resume" || !strings.Contains(texts(es), "sent the supervisor resume-harness") {
		t.Fatalf("%v %v", op, es)
	}
	r.st.Do(func(d *persisted) { d.Sessions["sA"].MachineID = "" })
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/harness", `{"action":"pause"}`); code != 409 {
		t.Fatal(code)
	}
}

// an operation left open by a crash is closed as cut off at the next leader's start
func TestLifecycleCutOff(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	addSession(r, "sA", "started", "mA", false)
	r.lcBegin("sA", "pause")
	r2 := NewRouter(r.cfg, r.st, nil, Policy{})
	r2.lcCutOff()
	op, _ := opEntries(t, r2, "sA")
	if op["state"] != "cut off" || op["ended"] == "" {
		t.Fatalf("%v", op)
	}
}
