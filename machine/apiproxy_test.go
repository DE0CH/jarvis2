package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a fake router: checks the machine signature the way requireMachine does (decoded path, no query)
func fakeRouter(t *testing.T, key tkey, handle func(w http.ResponseWriter, req *http.Request, body []byte)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		sum := sha256.Sum256(body)
		msg := req.Method + " " + req.URL.Path + " " + req.Header.Get("X-Time") + " " + hex.EncodeToString(sum[:])
		if req.Header.Get("X-Machine") != "m1" || !verify(key.pub(), []byte(msg), req.Header.Get("X-Sig")) {
			w.WriteHeader(401)
			return
		}
		handle(w, req, body)
	}))
}

func TestProxyForwardsSigned(t *testing.T) {
	t.Setenv("JARVIS2_SESSION_ID", "s1")
	key := newKey()
	var got *http.Request
	var gotBody string
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, body []byte) {
		got, gotBody = req, string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":[]}`))
	})
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	p := httptest.NewServer(apiProxyHandler(c))
	defer p.Close()

	req, _ := http.NewRequest("PUT", p.URL+"/api/sessions/s1/content/my%20store/file?path=a%2Fb.txt", strings.NewReader("data"))
	req.Header.Set("CF-Access-Client-Id", "placeholder")
	req.Header.Set("Authorization", "Bearer placeholder")
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	if got.URL.Path != "/m/api/sessions/s1/content/my store/file" || got.URL.RawQuery != "path=a%2Fb.txt" || gotBody != "data" ||
		got.Header.Get("Authorization") != "" || got.Header.Get("CF-Access-Client-Id") != "" || got.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("forwarded %s ? %s %v %q", got.URL.Path, got.URL.RawQuery, got.Header, gotBody)
	}
	// secrets and changes for another session are refused locally
	resp, _ = http.Get(p.URL + "/api/sessions/sX/secrets")
	if resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
}

func TestProxyArmingAllowsTheScheduler(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("JARVIS2_SESSION_ID", "s1")
	old := currentCert
	currentCert = func() (Cert, error) { return Cert{Line: "m1"}, nil }
	t.Cleanup(func() { currentCert = old })
	key, sched := newKey(), newKey()
	at := time.Now().Add(2 * time.Hour).UnixMilli()
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, body []byte) {
		switch req.URL.Path {
		case "/m/holders":
			json.NewEncoder(w).Encode(map[string]string{"scheduler": sched.pub()})
		case "/m/api/sessions/s1/wakeup":
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "wakeup": map[string]any{"name": "default", "at": at}})
		default:
			w.WriteHeader(404)
		}
	})
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	p := httptest.NewServer(apiProxyHandler(c))
	defer p.Close()
	resp, err := http.Post(p.URL+"/api/sessions/s1/wakeup", "application/json", strings.NewReader(`{"delaySeconds":7200,"prompt":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) || !strings.Contains(string(b), "allowed until") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	list := readAllow()
	if len(list) != 1 || list[0].Name != "scheduler" || list[0].Holder != sched.pub() {
		t.Fatalf("%+v", list)
	}
	u, _ := time.Parse(time.RFC3339, list[0].Until)
	if d := u.Sub(time.UnixMilli(at)); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("until %v", u)
	}
	// the machine then runs the scheduler's commands without a grant
	e := sched.req(ExecRequest{ID: "x1", Session: "m1", Holder: sched.pub(), Cmd: "true", Timeout: 5, At: time.Now().Unix()})
	if _, err := authorise(e, time.Now()); err != nil {
		t.Fatal(err)
	}
	// never shortened
	if err := extendAllow(c, "scheduler", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if l := readAllow(); len(l) != 1 || l[0].Until != list[0].Until {
		t.Fatalf("shortened: %+v", l)
	}
	if err := extendAllow(c, "scheduler", u.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if l := readAllow(); len(l) != 1 || l[0].Until == list[0].Until {
		t.Fatalf("not extended: %+v", l)
	}
}

func TestAllowUntil(t *testing.T) {
	now := time.Now()
	u, ok := allowUntil(map[string]any{"cron": map[string]any{"nextAt": float64(now.Add(time.Hour).UnixMilli()), "everySeconds": float64(86400)}}, now)
	if !ok || u.Sub(now) < 30*24*time.Hour {
		t.Fatalf("cron %v", u.Sub(now))
	}
	u, ok = allowUntil(map[string]any{"cron": map[string]any{"nextAt": float64(now.Add(time.Hour).UnixMilli()), "everySeconds": float64(60 * 86400)}}, now)
	if !ok || u.Sub(now) < 120*24*time.Hour {
		t.Fatalf("long cron %v", u.Sub(now))
	}
	if _, ok := allowUntil(map[string]any{"ok": true}, now); ok {
		t.Fatal("nothing to allow")
	}
}

func TestRepoChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	ws := t.TempDir()
	d := filepath.Join(ws, "r")
	run := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", d}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	os.MkdirAll(d, 0o755)
	run("init", "-q")
	os.WriteFile(filepath.Join(d, "a"), []byte("x"), 0o644)
	got := repoChanges(ws)
	if len(got) != 1 || got[0].Name != "r" || got[0].Uncommitted != 1 || got[0].Unpushed != -1 {
		t.Fatalf("%+v", got)
	}
}
