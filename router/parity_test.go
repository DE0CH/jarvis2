package main

// Tests for the parity pieces of 2026-10-10: the core-not-running answer, the app's search forwarding, the
// Claude app's title, live transcript sync, indexing an archive by hand, and one-shot destroys.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRelayCoreNotRunning(t *testing.T) {
	r := newTestRouter(t)
	r.core = &CoreClient{base: "http://127.0.0.1:1", http: &http.Client{Timeout: time.Second}}
	code, out := appDo(t, r, "GET", "/api/core/identity", "")
	if code != 503 || out["error"] != "the core isn't running" || out["coreDown"] != true {
		t.Fatalf("%d %v", code, out)
	}
}

func TestAppSearchForwardsToJarvis1(t *testing.T) {
	r := newTestRouter(t)
	var got []*http.Request
	var bodies []string
	j1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got, bodies = append(got, req), append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":[]}`))
	}))
	defer j1.Close()
	t.Setenv("JARVIS1_URL", j1.URL)
	t.Setenv("JARVIS1_SERVICES_ID", "id")
	t.Setenv("JARVIS1_SERVICES_SECRET", "sec")
	for _, c := range []struct{ method, target, body string }{
		{"GET", "/api/search?q=hello+world&group=1", ""},
		{"GET", "/api/search/context?id=7&before=3", ""},
		{"GET", "/api/search/status", ""},
		{"GET", "/api/icloud/search?q=passport", ""},
		{"GET", "/api/icloud/file?path=Documents%2Fa.pdf", ""},
		{"GET", "/api/icloud/status", ""},
		{"POST", "/api/icloud/relist", "{}"},
	} {
		code, _ := appDo(t, r, c.method, c.target, c.body)
		if code != 200 {
			t.Fatalf("%s %s: %d", c.method, c.target, code)
		}
		g := got[len(got)-1]
		if g.Method != c.method || g.URL.RequestURI() != c.target || g.Header.Get("CF-Access-Client-Id") != "id" ||
			g.Header.Get("CF-Access-Client-Secret") != "sec" || g.Header.Values("X-Jarvis2-Session") != nil {
			t.Fatalf("%s %s forwarded as %s %s %v", c.method, c.target, g.Method, g.URL.RequestURI(), g.Header)
		}
		if bodies[len(bodies)-1] != c.body {
			t.Fatalf("body %q", bodies[len(bodies)-1])
		}
	}
	// not on the list: the router's own 404 (the web page's fallback), never Jarvis 1
	n := len(got)
	appDo(t, r, "POST", "/api/icloud/retry", "")
	if len(got) != n {
		t.Fatal("an unlisted path reached Jarvis 1")
	}
}

func TestAppTitleFromStatusReport(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	raw := `{"pid":1,"sessionId":"c1","name":"x","nameSource":"derived","status":"idle","bridgeSessionId":"session_abc","startedAt":1}` +
		"\n__TITLES__\n" + `{"type":"ai-title","aiTitle":"AI title","sessionId":"c1"}` + "\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n__REFUSAL__\n"
	if code, out := m.do(t, r.MachineHandler(), "POST", "/m/status", jsonString(map[string]string{"raw": raw, "appTitle": "  Renamed\nin   the app "})); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions["sA"] })
	if s.AppTitle != "Renamed in the app" || sessionTitle(s) != "Renamed in the app" {
		t.Fatalf("app title %q, title %q", s.AppTitle, sessionTitle(s))
	}
	// the label gave way; the view carries Jarvis 1's serverTitle
	r.core = &CoreClient{base: "http://127.0.0.1:1", http: &http.Client{Timeout: time.Second}}
	_, st := appDo(t, r, "GET", "/api/state", "")
	v := st["sessions"].([]any)[0].(map[string]any)
	if v["serverTitle"] != "Renamed in the app" || v["title"] != "Renamed in the app" || v["aiTitle"] != "AI title" {
		t.Fatalf("view %v", v)
	}
	// a report without a title keeps the last one (the machine sends "" when the API can't be read)
	m.do(t, r.MachineHandler(), "POST", "/m/status", jsonString(map[string]string{"raw": raw}))
	r.st.Do(func(d *persisted) { s = *d.Sessions["sA"] })
	if s.AppTitle != "Renamed in the app" {
		t.Fatal("an empty report dropped the title")
	}
	// a resume names the new Remote Control entry with it — unless a label is pinned
	s.Label = ""
	if r.machineEnv(&s)["SESSION_RESUME_TITLE"] != "Renamed in the app" {
		t.Fatal("no SESSION_RESUME_TITLE")
	}
	s.Label = "pinned"
	if _, ok := r.machineEnv(&s)["SESSION_RESUME_TITLE"]; ok {
		t.Fatal("SESSION_RESUME_TITLE with a pinned label")
	}
}

func TestLiveTranscriptSync(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	addSession(r, "s2", "started", "m2", false)
	m := newTestMachine(r, "m2")
	other := newTestMachine(r, "m9") // a machine with no running session
	h := r.MachineHandler()
	put := func(mm testMachine, name, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest("POST", "/m/live-transcript", strings.NewReader(body))
		req.Header.Set("X-Name", name)
		return mm.doReq(t, h, req, body)
	}
	name := "0b6a2f3e-1111-4222-8333-444455556666.jsonl"
	if code, out := put(m, name, `{"type":"user"}`+"\n"); code != 200 || out["stored"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if got := string(rg.dav.get(".live/s2/" + name)); got != "" {
		t.Fatalf("written outside claude-records: %q", got)
	}
	if got := string(rg.dav.get("claude-records/.live/s2/" + name)); got != `{"type":"user"}`+"\n" {
		t.Fatalf("on the box: %q", got)
	}
	// a newer copy replaces it
	put(m, name, "a\nb\n")
	if got := string(rg.dav.get("claude-records/.live/s2/" + name)); got != "a\nb\n" {
		t.Fatalf("replaced: %q", got)
	}
	var ls *LiveSync
	r.st.Do(func(d *persisted) { ls = d.Sessions["s2"].LiveSync })
	if ls == nil || !ls.Stored || ls.Files[name] != 4 {
		t.Fatalf("liveSync %+v", ls)
	}
	for _, bad := range []string{"../x.jsonl", "a/b.jsonl", "x.txt", ".hidden.jsonl"} {
		if code, _ := put(m, bad, "x"); code != 400 {
			t.Fatalf("name %q: %d", bad, code)
		}
	}
	if code, _ := put(other, name, "x"); code != 403 {
		t.Fatalf("a machine with no session: %d", code)
	}
	// records off (the e2e test): received, not written
	t.Setenv("RECORDS_OFF", "1")
	if code, out := put(m, "c.jsonl", "x"); code != 200 || out["stored"] != false {
		t.Fatalf("%d %v", code, out)
	}
	t.Setenv("RECORDS_OFF", "")
	// destroy: the archive supersedes the live copy
	r.clearLive("s2")
	if len(rg.dav.under("claude-records/.live/s2")) != 0 {
		t.Fatalf("live copy kept: %v", rg.dav.under("claude-records/.live/s2"))
	}
	// env: the interval reaches the machine
	t.Setenv("LIVE_SYNC_SECONDS", "20")
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions["s2"] })
	if r.machineEnv(&s)["JARVIS2_LIVE_SYNC_SECONDS"] != "20" {
		t.Fatal("no JARVIS2_LIVE_SYNC_SECONDS")
	}
}

func TestIndexArchiveByHand(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.cfg.NoAccess = true
	dir := "claude-records/2026-09-01 Train tickets"
	tr := "transcript-0b6a2f3e-1111-4222-8333-444455556666.jsonl"
	rg.dav.files[dir+"/"+tr] = []byte(line(map[string]any{"type": "user", "message": map[string]any{"content": "book it"}}))
	if code, out := appDo(t, r, "POST", "/api/records", jsonString(map[string]any{"archiveDir": dir, "transcripts": []string{"missing.jsonl"}})); code != 400 ||
		!strings.Contains(out["error"].(string), "not on the Storage Box") {
		t.Fatalf("%d %v", code, out)
	}
	for _, b := range []map[string]any{
		{"archiveDir": "claude-records/.paused/x", "transcripts": []string{tr}},
		{"archiveDir": "elsewhere/x", "transcripts": []string{tr}},
		{"archiveDir": dir, "transcripts": []string{"../../etc/passwd"}},
		{"archiveDir": dir},
	} {
		if code, _ := appDo(t, r, "POST", "/api/records", jsonString(b)); code != 400 {
			t.Fatalf("%v: %d", b, code)
		}
	}
	code, out := appDo(t, r, "POST", "/api/records", jsonString(map[string]any{"archiveDir": dir + "/", "transcripts": []string{tr},
		"title": "Train tickets", "environment": "default", "repos": []string{"https://github.com/DE0CH/x"}, "permissionMode": "bypass"}))
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	rec := r.record("archive-0b6a2f3e")
	if rec == nil || rec.Archive.Dir != dir || rec.Label != "Train tickets" || rec.PermissionMode != "bypass" || rec.Repos != "https://github.com/DE0CH/x" {
		t.Fatalf("record %+v", rec)
	}
	if tail, st, err := r.RecordTail(rec.ID); err != nil || st != 200 || len(tail.Messages) != 1 {
		t.Fatalf("tail %v %d %+v", err, st, tail)
	}
	if code, _ := appDo(t, r, "POST", "/api/records", jsonString(map[string]any{"archiveDir": dir, "transcripts": []string{tr}})); code != 400 {
		t.Fatal("indexed twice")
	}
	if _, err := r.RestoreRecord(rec.ID, "rq"); err != errHandIndex {
		t.Fatalf("restore: %v", err)
	}
	if !strings.Contains(string(rg.dav.get(recordsIndex)), `"archive-0b6a2f3e"`) {
		t.Fatal("not in the Storage Box index")
	}
}

func TestOneShotDestroyDMsLostWork(t *testing.T) {
	rg := newRig(t) // s1 paused; its snapshot recorded "proj 2 1" and "other 0 -1"
	dms := make(chan string, 4)
	old := dmHook
	dmHook = func(t string) { dms <- t }
	defer func() { dmHook = old }()
	if err := rg.r.finishOneShot("s1"); err != nil {
		t.Fatal(err)
	}
	dm := recvDM(t, dms)
	for _, want := range []string{"one-shot session “Fix the: router”", "proj: 2 uncommitted file(s), 1 unpushed commit(s)",
		"other: branch has no upstream", "claude-records/2026-10-01 Fix the router"} {
		if !strings.Contains(dm, want) {
			t.Fatalf("DM lacks %q:\n%s", want, dm)
		}
	}
	if rec := rg.r.record("s1"); rec == nil || rec.Archive == nil {
		t.Fatal("not archived")
	}
}

func TestOneShotForcedWhenArchiveFails(t *testing.T) {
	rg := newRig(t)
	rg.dav.fail = "claude-records/2026"
	dms := make(chan string, 4)
	old := dmHook
	dmHook = func(t string) { dms <- t }
	defer func() { dmHook = old }()
	rg.r.finishOneShot("s1")
	if dm := recvDM(t, dms); !strings.Contains(dm, "the archive to the Storage Box failed") {
		t.Fatalf("DM %s", dm)
	}
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil })
	if rec := rg.r.record("s1"); rec == nil || rec.ArchiveError == "" {
		t.Fatalf("a one-shot must be destroyed even when its archive fails: %+v", rec)
	}
}

func recvDM(t *testing.T, dms chan string) string {
	t.Helper()
	select {
	case dm := <-dms:
		return dm
	case <-time.After(5 * time.Second):
		t.Fatal("no DM")
	}
	return ""
}

// doReq: like do, for a request built by the caller (extra headers)
func (m testMachine) doReq(t *testing.T, h http.Handler, req *http.Request, body string) (int, map[string]any) {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256([]byte(body))
	sig, _ := signP256(m.key, []byte(req.Method+" "+req.URL.Path+" "+ts+" "+hex.EncodeToString(sum[:])))
	req.Header.Set("X-Machine", m.id)
	req.Header.Set("X-Time", ts)
	req.Header.Set("X-Sig", sig)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestOneShotLostDMNothingLost(t *testing.T) {
	if s := oneShotLostDM("x", map[string]any{"checked": true, "repos": []RepoChange{{"a", 0, 0}}}, &ArchiveInfo{Dir: "d"}, nil); s != "" {
		t.Fatalf("DM when nothing was lost: %s", s)
	}
	if s := oneShotLostDM("x", map[string]any{"checked": false, "reason": "no snapshot"}, nil, nil); !strings.Contains(s, "could not check the repos for unsaved work (no snapshot)") {
		t.Fatal(s)
	}
}
