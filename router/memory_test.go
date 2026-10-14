package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func i64(n int64) *int64     { return &n }
func f64(x float64) *float64 { return &x }

func TestMemWatchEpisodes(t *testing.T) {
	now := time.Now()
	m := &memState{machine: "m1"}
	healthy := &MemSample{TotalKb: 4 << 20, AvailKb: 2 << 20, OOMKills: i64(0), PSIFull60: f64(0)}
	if m.observe(healthy, now) || m.alert != nil {
		t.Fatal("a healthy machine starts no episode")
	}
	// the kernel killed something
	oom := &MemSample{TotalKb: 4 << 20, AvailKb: 400 << 10, OOMKills: i64(2), PSIFull60: f64(1),
		Top: []MemProc{{900 << 10, "claude"}, {300 << 10, "chrome"}, {50 << 10, "node"}}}
	if !m.observe(oom, now.Add(10*time.Second)) {
		t.Fatal("an OOM kill starts an episode")
	}
	if !strings.Contains(m.alert.Reason, "killed 2 processes") || m.alert.Detail != "400 MB free of 4.0 GB (biggest: claude 0.9 GB, chrome 0.3 GB)" {
		t.Fatalf("%+v", m.alert)
	}
	// more starvation in the same episode: no second DM
	thrash := &MemSample{TotalKb: 4 << 20, AvailKb: 300 << 10, OOMKills: i64(2), PSIFull60: f64(25)}
	if m.observe(thrash, now.Add(20*time.Second)) || !strings.Contains(m.alert.Reason, "thrashing") {
		t.Fatalf("%+v", m.alert)
	}
	// healthy for less than memClear: still on; then off
	healthy = &MemSample{TotalKb: 4 << 20, AvailKb: 2 << 20, OOMKills: i64(2), PSIFull60: f64(0)}
	m.observe(healthy, now.Add(time.Minute))
	if m.alert == nil {
		t.Fatal("cleared too early")
	}
	m.observe(healthy, now.Add(time.Minute+memClear))
	if m.alert != nil {
		t.Fatal("not cleared after memClear of healthy samples")
	}
	// almost out
	low := &MemSample{TotalKb: 4 << 20, AvailKb: 100 << 10, OOMKills: i64(2)}
	if !m.observe(low, now.Add(time.Hour)) || m.alert.Reason != "it is almost out of memory" {
		t.Fatalf("%+v", m.alert)
	}
}

func TestMemSilentTick(t *testing.T) {
	now := time.Now()
	short := &MemSample{TotalKb: 4 << 20, AvailKb: 300 << 10}
	d := &persisted{Sessions: map[string]*Session{
		"s1": {ID: "s1", Label: "Busy one", State: "started", MachineID: "m1", Size: "small",
			Live: &Liveness{mem: &memState{machine: "m1", last: short, lastAt: now.Add(-2 * time.Minute)}}},
		"s2": {ID: "s2", State: "started", MachineID: "m2",
			Live: &Liveness{mem: &memState{machine: "m2", last: &MemSample{TotalKb: 4 << 20, AvailKb: 3 << 20}, lastAt: now.Add(-2 * time.Minute)}}},
		"s3": {ID: "s3", State: "paused", Live: &Liveness{mem: &memState{machine: "m3", last: short, lastAt: now.Add(-time.Hour)}}},
	}}
	dms := memSilentTick(d, now)
	if len(dms) != 1 || !strings.Contains(dms[0], "“Busy one”") || !strings.Contains(dms[0], "stopped answering") || !strings.Contains(dms[0], "medium (4 GB)") {
		t.Fatalf("%q", dms)
	}
	if len(memSilentTick(d, now.Add(time.Minute))) != 0 {
		t.Fatal("one DM per episode")
	}
	if d.Sessions["s3"].Live.mem != nil {
		t.Fatal("a paused session's watch is dropped")
	}
	if d.Sessions["s2"].Live.mem.alert != nil {
		t.Fatal("a silent machine with plenty of memory isn't starving")
	}
}

func TestMemoryReportViewAndUpgradeRefusals(t *testing.T) {
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := NewRouter(Config{}, st, nil, Policy{})
	var dms []string
	old := dmHook
	dmHook = func(s string) { dms = append(dms, s) }
	defer func() { dmHook = old }()
	mux := http.NewServeMux()
	r.registerMemory(func(p string, fn http.HandlerFunc) { mux.HandleFunc(p, fn) },
		func(p string, fn func(http.ResponseWriter, *http.Request, string, []byte)) {
			mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) {
				b := make([]byte, 1<<16)
				n, _ := req.Body.Read(b)
				fn(w, req, req.Header.Get("X-Machine"), b[:n])
			})
		})
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", Label: "Megathread", State: "started", MachineID: "m1", Size: "medium"}
		d.Sessions["s2"] = &Session{ID: "s2", State: "started", MachineID: "m2", Size: "large"}
		d.Sessions["s3"] = &Session{ID: "s3", State: "paused", Size: "small"}
		d.Machines["m1"], d.Machines["m2"] = "s1", "s2"
	})
	post := func(path, machine, body string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("X-Machine", machine)
		mux.ServeHTTP(w, req)
		return w.Code
	}
	if c := post("/m/memory", "m1", `{"totalKb":4000000,"availKb":2000000,"oomKills":0}`); c != 200 {
		t.Fatal(c)
	}
	if c := post("/m/memory", "m1", `{"totalKb":4000000,"availKb":100000,"oomKills":1,"top":[{"rssKb":2000000,"comm":"claude"}]}`); c != 200 {
		t.Fatal(c)
	}
	if c := post("/m/memory", "m1", `{"totalKb":0}`); c != 400 {
		t.Fatal(c)
	}
	if len(dms) != 1 || !strings.Contains(dms[0], "“Megathread” is running out of memory: the kernel killed 1 process for lack of memory") ||
		!strings.Contains(dms[0], "large (8 GB)") {
		t.Fatalf("%q", dms)
	}
	st.Do(func(d *persisted) {
		v := sessionView(d.Sessions["s1"], d)
		a, ok := v["memAlert"].(map[string]any)
		if !ok || a["nextSize"] != "large" || !strings.Contains(a["detail"].(string), "biggest: claude 1.9 GB") {
			t.Fatalf("%v", v["memAlert"])
		}
		if mem, ok := v["memory"].(map[string]any); !ok || mem["availMb"] != int64(97) {
			t.Fatalf("%v", v["memory"])
		}
		if _, ok := sessionView(d.Sessions["s2"], d)["memAlert"]; ok {
			t.Fatal("no alert on a session that reported nothing")
		}
	})
	if c := post("/api/sessions/s2/upgrade", "", `{}`); c != 409 {
		t.Fatalf("already large: %d", c)
	}
	if c := post("/api/sessions/s3/upgrade", "", `{}`); c != 409 {
		t.Fatalf("paused: %d", c)
	}
	if c := post("/api/sessions/nope/upgrade", "", `{}`); c != 404 {
		t.Fatalf("no session: %d", c)
	}
}
