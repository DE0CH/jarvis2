package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeWatch(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	w, err := normalizeWatch(body(`{"name":"ci","script":"exit 1\r\n","id":"cccccccccccccccccccccccccccccccc","interval":5,"maxSeconds":3600}`), now)
	if err != nil || w.Script != "exit 1\n" || w.ID != strings.Repeat("c", 32) || w.Interval != watchMinInterval || w.MaxSeconds != 3600 || w.NextAt != now.UnixMilli() {
		t.Fatalf("%+v %v", w, err)
	}
	if w, _ := normalizeWatch(body(`{"name":"a","script":"x","id":"cccccccccccccccccccccccccccccccc"}`), now); w.Interval != 60 || w.MaxSeconds != 7*86400 {
		t.Fatalf("defaults %+v", w)
	}
	if w, _ := normalizeWatch(body(`{"name":"a","script":"x","id":"cccccccccccccccccccccccccccccccc","maxSeconds":99999999999,"interval":99999}`), now); w.MaxSeconds != watchMaxSeconds || w.Interval != watchMaxInterval {
		t.Fatalf("ceilings %+v", w)
	}
	for _, b := range []string{`{"script":"x","id":"cccccccccccccccccccccccccccccccc"}`, `{"name":"a","id":"cccccccccccccccccccccccccccccccc"}`, `{"name":"a","script":"x"}`,
		`{"name":"a","script":"x","id":"cccccccccccccccccccccccccccccccc","prompt":"the text stays on the machine"}`, `{"name":"a","script":"x","id":"cccccccccccccccccccccccccccccccc","failPrompt":"f"}`,
		`{"name":"bad name","script":"x","id":"cccccccccccccccccccccccccccccccc"}`, `{"name":"a","script":"x","id":"cccccccccccccccccccccccccccccccc","maxSeconds":-1}`,
		`{"name":"a","script":"` + strings.Repeat("x", watchMaxScript+1) + `","id":"cccccccccccccccccccccccccccccccc"}`} {
		if _, err := normalizeWatch(body(b), now); err == nil {
			t.Fatalf("%s should be refused", b)
		}
	}
}

type fakeRunner struct {
	mu   sync.Mutex
	exit int
	runs []string
}

func (f *fakeRunner) install(t *testing.T) {
	old := runCheckHook
	runCheckHook = func(w *Watch) (*checkResult, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.runs = append(f.runs, w.Name)
		return &checkResult{Exit: f.exit, Stdout: "found " + w.Name, Stderr: "note\nlast line"}, nil
	}
	t.Cleanup(func() { watchWG.Wait(); runCheckHook = old })
}

func TestWatchLifecycle(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "paused", "", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()
	var fd fakeDelivery
	fd.install(t)
	var fr fakeRunner
	fr.exit = 1
	fr.install(t)

	code, out := m.do(t, h, "POST", "/m/api/sessions/sA/watches", `{"name":"ci","script":"exit 1","id":"cccccccccccccccccccccccccccccccc","interval":30}`)
	if code != 200 || out["ok"] != true || out["watch"].(map[string]any)["name"] != "ci" {
		t.Fatalf("%d %v", code, out)
	}
	if _, ok := out["watch"].(map[string]any)["script"]; ok {
		t.Fatal("the view carries no script")
	}
	if code, _ := m.do(t, h, "POST", "/m/api/sessions/sB/watches", `{"name":"x","script":"x","id":"cccccccccccccccccccccccccccccccc"}`); code != 403 {
		t.Fatal("another session's path")
	}
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/watches", `{"name":"x","script":"x","prompt":"p"}`); code != 400 {
		t.Fatal("the app can't arm one (no text on the machine)")
	}
	if p := r.PendingSchedule("sA"); len(p) != 1 || p[0] != "watch ci" {
		t.Fatalf("a watch keeps the session: %v", p)
	}
	// not yet: checked, kept, next check an interval later
	r.watchTick(time.Now())
	watchWG.Wait()
	ws, _ := r.ListWatches("sA")
	if len(ws) != 1 || ws[0]["runs"] != 1 || ws[0]["lastExit"] != 1 || ws[0]["lastError"] != "last line" || ws[0]["lastOutput"] != "found ci" || len(fd.texts) != 0 {
		t.Fatalf("%v %v", ws, fd.texts)
	}
	r.watchTick(time.Now()) // not due again yet
	watchWG.Wait()
	if len(fr.runs) != 1 {
		t.Fatalf("checked again before its interval: %v", fr.runs)
	}
	// met: a due signal (kind watch, its id, met), and the watch is gone
	fr.exit = 0
	r.watchTick(time.Now().Add(31 * time.Second))
	watchWG.Wait()
	if len(fd.texts) != 1 || fd.texts[0] != "sA: watch "+strings.Repeat("c", 32)+" met" {
		t.Fatalf("%v", fd.texts)
	}
	if ws, _ := r.ListWatches("sA"); len(ws) != 0 || len(r.PendingSchedule("sA")) != 0 {
		t.Fatalf("delivered watch kept: %v", ws)
	}

	// give up: exit 3, and the maximum age
	m.do(t, h, "POST", "/m/api/sessions/sA/watches", `{"name":"g","script":"exit 3","id":"cccccccccccccccccccccccccccccccc"}`)
	fr.exit = 3
	r.watchTick(time.Now())
	watchWG.Wait()
	if len(fd.texts) != 2 || !strings.HasSuffix(fd.texts[1], " gave-up") {
		t.Fatalf("%v", fd.texts)
	}
	m.do(t, h, "POST", "/m/api/sessions/sA/watches", `{"name":"old","script":"exit 1","id":"cccccccccccccccccccccccccccccccc","maxSeconds":60}`)
	fr.exit = 1
	r.st.Do(func(d *persisted) { d.Schedules["sA"].Watches["old"].ArmedAt -= 120_000 })
	// the arming's identity moved: re-read it as the tick does
	r.watchTick(time.Now())
	watchWG.Wait()
	if len(fd.texts) != 3 || !strings.HasSuffix(fd.texts[2], " gave-up") {
		t.Fatalf("expired watch: %v", fd.texts)
	}

	// a failed delivery is retried; the outcome is kept meanwhile
	m.do(t, h, "POST", "/m/api/sessions/sA/watches", `{"name":"r","script":"exit 0","id":"cccccccccccccccccccccccccccccccc"}`)
	fr.exit = 0
	fd.mu.Lock()
	fd.err = errNoAnswer
	fd.mu.Unlock()
	r.watchTick(time.Now())
	watchWG.Wait()
	ws, _ = r.ListWatches("sA")
	if len(ws) != 1 || ws[0]["outcome"] != "met" || !strings.HasPrefix(ws[0]["lastError"].(string), "delivery: ") {
		t.Fatalf("%v", ws)
	}
	// cancel
	if code, out := m.do(t, h, "DELETE", "/m/api/sessions/sA/watches/r", ``); code != 200 || out["ok"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := appDo(t, r, "GET", "/api/sessions/sA/watches", ``); code != 200 || len(out["watches"].([]any)) != 0 {
		t.Fatalf("%d %v", code, out)
	}
	// the session's view lists them
	m.do(t, h, "POST", "/m/api/sessions/sA/watches", `{"name":"v","script":"exit 1","id":"cccccccccccccccccccccccccccccccc"}`)
	var v map[string]any
	r.st.Do(func(d *persisted) { v = sessionView(d.Sessions["sA"], d) })
	if ws := v["watches"].([]map[string]any); len(ws) != 1 || ws[0]["name"] != "v" {
		t.Fatalf("%v", v["watches"])
	}
}
