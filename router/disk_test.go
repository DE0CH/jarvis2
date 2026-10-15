package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// the disk report: one DM per low-disk episode, the alert and usage in the session's view, the next size
func TestALowDiskIsReportedOnce(t *testing.T) {
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
		d.Sessions["s1"] = &Session{ID: "s1", Label: "k-matrix clone", State: "started", MachineID: "m1", Size: "large"}
		d.Machines["m1"] = "s1"
	})
	post := func(body string) {
		req := httptest.NewRequest("POST", "/m/memory", strings.NewReader(body))
		req.Header.Set("X-Machine", "m1")
		mux.ServeHTTP(httptest.NewRecorder(), req)
	}
	const mem = `"totalKb":8000000,"availKb":6000000`
	post(`{` + mem + `,"diskTotalKb":8126464,"diskAvailKb":4000000}`) // 4 GB free: fine
	post(`{` + mem + `,"diskTotalKb":8126464,"diskAvailKb":600000}`)  // 0.6 GB: low
	post(`{` + mem + `,"diskTotalKb":8126464,"diskAvailKb":500000}`)  // same episode
	if len(dms) != 1 || !strings.Contains(dms[0], "“k-matrix clone” is running out of disk: 0.6 GB free of 7.8 GB") || !strings.Contains(dms[0], "16 GB disk") {
		t.Fatalf("%q", dms)
	}
	st.Do(func(d *persisted) {
		v := sessionView(d.Sessions["s1"], d)
		a, ok := v["diskAlert"].(map[string]any)
		if !ok || a["nextDiskGb"] != 16 {
			t.Fatalf("%v", v["diskAlert"])
		}
		if u, ok := v["diskUsage"].(map[string]any); !ok || u["availMb"] != int64(500000/1024) {
			t.Fatalf("%v", v["diskUsage"])
		}
	})
	post(`{` + mem + `,"diskTotalKb":8126464,"diskAvailKb":5000000}`) // freed: the episode ends
	post(`{` + mem + `,"diskTotalKb":8126464,"diskAvailKb":100000}`)  // a new one
	if len(dms) != 2 {
		t.Fatalf("%q", dms)
	}
	if nextDisk(0) != 16 || nextDisk(16) != 32 || nextDisk(512) != 0 || diskSize(24) {
		t.Fatal("disk sizes")
	}
}

// the start asks the core for the session's disk; a core that ignores it is noticed
func TestTheStartAsksForTheDisk(t *testing.T) {
	rg, vc := v2Rig(t)
	_ = rg.r.applyResumeOptions("s1", ResumeOptions{Disk: 32})
	var s Session
	rg.r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	if s.Disk != 32 {
		t.Fatalf("disk %d", s.Disk)
	}
	rg.r.startMachine("img", "small", 32)
	if b := vc.last("/start"); b["disk"] != float64(32) {
		t.Fatalf("start %v", b)
	}
	diskRefused.Store(false)
	rg.r.noteDiskAnswer(32, 0)
	if !diskRefused.Load() {
		t.Fatal("a core that ignored the disk went unnoticed")
	}
	rg.r.noteDiskAnswer(32, 32)
	if diskRefused.Load() {
		t.Fatal("a core that set the disk counts as refusing")
	}
}
