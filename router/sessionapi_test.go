package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

type testMachine struct {
	id  string
	key *ecdh.PrivateKey
}

func newTestMachine(r *Router, id string) testMachine {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	r.st.Do(func(d *persisted) {
		d.Started[id] = &Started{ID: id, SigningKey: base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())}
	})
	return testMachine{id, k}
}

// do: a request to the machines' listener, signed as the machine signs it (decoded path, no query)
func (m testMachine) do(t *testing.T, h http.Handler, method, target, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256([]byte(body))
	sig, _ := signP256(m.key, []byte(method+" "+req.URL.Path+" "+ts+" "+hex.EncodeToString(sum[:])))
	req.Header.Set("X-Machine", m.id)
	req.Header.Set("X-Time", ts)
	req.Header.Set("X-Sig", sig)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestMachineAPIWakeupsAndCrons(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()

	code, out := m.do(t, h, "POST", "/m/api/sessions/sA/wakeup", `{"delaySeconds": 3600, "prompt": "retry", "name": "r1"}`)
	if code != 200 || out["ok"] != true || out["wakeup"].(map[string]any)["name"] != "r1" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = m.do(t, h, "GET", "/m/api/sessions/sA/wakeup", "")
	if code != 200 || len(out["wakeups"].([]any)) != 1 || out["wakeup"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	// another session's id: refused
	if code, _ := m.do(t, h, "POST", "/m/api/sessions/sB/wakeup", `{"delaySeconds": 60, "prompt": "x"}`); code != 403 {
		t.Fatalf("another session's path: %d", code)
	}
	if code, out := m.do(t, h, "POST", "/m/api/sessions/sA/wakeups", `{"prompt": "x"}`); code != 400 || !strings.Contains(out["error"].(string), "delaySeconds") {
		t.Fatalf("%d %v", code, out)
	}
	code, out = m.do(t, h, "POST", "/m/api/sessions/sA/crons", `{"name": "c1", "prompt": "daily", "time": "08:00", "tz": "Europe/London"}`)
	if code != 200 || out["cron"].(map[string]any)["tz"] != "Europe/London" {
		t.Fatalf("%d %v", code, out)
	}
	// retiring with pending ones is refused
	if code, out := m.do(t, h, "DELETE", "/m/api/sessions/sA", ""); code != 409 || len(out["pending"].([]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := m.do(t, h, "DELETE", "/m/api/sessions/sA/wakeups/r1", ""); code != 200 || out["cancelled"].([]any)[0] != "r1" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := m.do(t, h, "DELETE", "/m/api/sessions/sA/crons/c1", ""); code != 200 {
		t.Fatal(code)
	}
	if code, out := m.do(t, h, "GET", "/m/api/sessions/sA/crons", ""); code != 200 || len(out["crons"].([]any)) != 0 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := m.do(t, h, "POST", "/m/api/sessions/sA/notify-idle", `{"enabled": false}`); code != 200 || out["notifyIdle"] != "off" || !r.st.data.Sessions["sA"].Live.NotifyIdleOff {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := m.do(t, h, "POST", "/m/api/sessions/sA/watches", `{}`); code != 501 {
		t.Fatalf("watches: %d", code)
	}
	if code, _ := m.do(t, h, "GET", "/m/api/whatever", ""); code != 404 {
		t.Fatalf("unknown: %d", code)
	}
	// a machine that isn't the session's current one gets nothing
	r.st.Do(func(d *persisted) { d.Sessions["sA"].MachineID = "" })
	if code, _ := m.do(t, h, "GET", "/m/api/sessions/sA/wakeups", ""); code != 403 {
		t.Fatalf("stale machine: %d", code)
	}
}

func TestMachineAPIForwardsToJarvis1(t *testing.T) {
	var seen *http.Request
	var seenBody string
	j1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		seen, seenBody = req, string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"status":"granted"}`))
	}))
	defer j1.Close()
	t.Setenv("JARVIS1_URL", j1.URL)
	t.Setenv("JARVIS1_SERVICES_ID", "cid")
	t.Setenv("JARVIS1_SERVICES_SECRET", "csec")
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()

	code, out := m.do(t, h, "POST", "/m/api/sessions/sA/leases/iphone", `{"purpose":"x"}`)
	if code != 201 || out["status"] != "granted" {
		t.Fatalf("%d %v", code, out)
	}
	if seen.URL.Path != "/api/sessions/sA/leases/iphone" || seen.Header.Get("CF-Access-Client-Id") != "cid" || seen.Header.Get("X-Jarvis2-Session") != "sA" ||
		seen.Header.Get("X-Sig") != "" || seenBody != `{"purpose":"x"}` {
		t.Fatalf("forwarded %s %v %q", seen.URL, seen.Header, seenBody)
	}
	if code, _ := m.do(t, h, "GET", "/m/api/search?q=hello+world&n=5", ""); code != 201 || seen.URL.RawQuery != "q=hello+world&n=5" {
		t.Fatalf("%d %s", code, seen.URL)
	}
	// a session-scoped Jarvis 1 path for another session: refused before forwarding
	seen = nil
	if code, _ := m.do(t, h, "GET", "/m/api/sessions/sOther/content", ""); code != 403 || seen != nil {
		t.Fatalf("%d", code)
	}
	// a Jarvis 1 path that isn't on the list: not forwarded
	if code, _ := m.do(t, h, "POST", "/m/api/search/reindex", ""); code != 404 || seen != nil {
		t.Fatalf("%d", code)
	}
}

func TestAppWakeupRoutesAndResumePrompt(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	h := r.Handler()
	call := func(method, path, body string) (int, map[string]any) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := call("POST", "/api/sessions/sA/wakeups", `{"delaySeconds": 60, "prompt": "x"}`); code != 200 || out["ok"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := call("DELETE", "/api/sessions/sA/wakeup?all=1", ""); code != 200 || len(out["cancelled"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := call("GET", "/api/sessions/nope/crons", ""); code != 404 {
		t.Fatal(code)
	}
	if code, _ := call("POST", "/api/sessions/sA/resume", `{"prompt": "`+strings.Repeat("a", resumePromptMax+1)+`"}`); code != 400 {
		t.Fatalf("too long: %d", code)
	}
}

func TestSessionAPIEnv(t *testing.T) {
	e := map[string]string{}
	sessionAPIEnv(e, "claude")
	if e["JARVIS_URL"] != machineAPIURL || e["CF_ACCESS_CLIENT_ID"] == "" || e["SESSION_API_TOKEN"] == "" {
		t.Fatal(e)
	}
	e = map[string]string{}
	sessionAPIEnv(e, "opencode")
	if _, ok := e["CF_ACCESS_CLIENT_ID"]; ok {
		t.Fatal("no CF placeholders for opencode")
	}
}
