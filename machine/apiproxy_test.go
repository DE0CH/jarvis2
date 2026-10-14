package main

import (
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

	"github.com/DE0CH/jarvis2/core/kernel"
)

func proxy(t *testing.T, x *world) *httptest.Server {
	p := httptest.NewServer(apiProxyHandler(x.g))
	t.Cleanup(p.Close)
	return p
}

func TestProxyForwardsSigned(t *testing.T) {
	x := newWorld(t)
	p := proxy(t, x)
	req, _ := http.NewRequest("PUT", p.URL+"/api/sessions/s1/content/my%20store/file?path=a%2Fb.txt", strings.NewReader("data"))
	req.Header.Set("CF-Access-Client-Id", "placeholder")
	req.Header.Set("Authorization", "Bearer placeholder")
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	h := x.headers["/m/api/sessions/s1/content/my store/file"]
	if string(x.forwarded["/m/api/sessions/s1/content/my store/file"]) != "data" || h.Get("Authorization") != "" ||
		h.Get("CF-Access-Client-Id") != "" || h.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("forwarded %v %v", x.forwarded, h)
	}
	// secrets and changes for another session are refused locally
	for _, u := range []string{"/api/sessions/sX/secrets", "/api/sessions/sX/changes"} {
		if resp, _ := http.Get(p.URL + u); resp.StatusCode != 403 {
			t.Fatal(u, resp.StatusCode)
		}
	}
}

// a wakeup's prompt stays on the machine: the router gets the schedule and the guard's id, never the text
func TestArmingKeepsTheTextOnTheMachine(t *testing.T) {
	x := newWorld(t)
	p := proxy(t, x)
	post := func(path, body string) (int, string) {
		resp, err := http.Post(p.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if st, b := post("/api/sessions/s1/wakeup", `{"delaySeconds":60,"name":"release","prompt":"ship the release"}`); st != 200 {
		t.Fatal(st, b)
	}
	if st, b := post("/api/sessions/s1/crons", `{"everySeconds":3600,"name":"tick","prompt":"check the queue"}`); st != 200 {
		t.Fatal(st, b)
	}
	if st, b := post("/api/sessions/s1/watches", `{"name":"ci","script":"exit 0","prompt":"CI is done","failPrompt":"CI never finished"}`); st != 200 {
		t.Fatal(st, b)
	}
	if st, b := post("/api/sessions/s1/leases/iphone", `{"purpose":"x","prompt":"tap the button"}`); st != 200 {
		t.Fatal(st, b)
	}
	for path, raw := range x.forwarded {
		var m map[string]any
		json.Unmarshal(raw, &m)
		if m["prompt"] != nil || m["failPrompt"] != nil || strings.Contains(string(raw), "ship the release") || strings.Contains(string(raw), "tap the button") {
			t.Fatalf("%s carried the text to the router: %s", path, raw)
		}
		if id, _ := m["id"].(string); !textIDRE.MatchString(id) {
			t.Fatalf("%s carried no id: %s", path, raw)
		}
	}
	var w map[string]any
	json.Unmarshal(x.forwarded["/m/api/sessions/s1/watches"], &w)
	if w["script"] != "exit 0" {
		t.Fatal("the watch's script (the router's runner runs it) didn't go")
	}
	r := x.g.rec.read()
	if len(r.Wakeups) != 1 || len(r.Crons) != 1 || len(r.Watches) != 1 || r.Leases["iphone"] != "tap the button" {
		t.Fatalf("records %+v", r)
	}
	// another session's, or a wakeup with no text, is refused locally
	if st, _ := post("/api/sessions/sX/wakeup", `{"prompt":"x"}`); st != 403 {
		t.Fatal(st)
	}
	if st, _ := post("/api/sessions/s1/wakeup", `{"delaySeconds":5}`); st != 400 {
		t.Fatal(st)
	}
	// the router refuses: the record goes again
	x.apiAnswer = func(string, []byte) (int, string) { return 409, `{"error":"no"}` }
	if st, _ := post("/api/sessions/s1/wakeup", `{"name":"later","prompt":"p"}`); st != 409 {
		t.Fatal(st)
	}
	if len(x.g.rec.read().Wakeups) != 1 {
		t.Fatal("a refused wakeup stayed in the records")
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

// a content file is taken only with the log notary's challenge over exactly its bytes
func TestProxyTakesAContentFileOnlyWithItsChallenge(t *testing.T) {
	x := newWorld(t)
	p := proxy(t, x)
	var hdr string
	x.apiAnswer = func(path string, _ []byte) (int, string) { return 200, "hello" }
	// the fake's apiAnswer can't set headers: wrap the server
	inner := x.srv.Config.Handler
	x.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hdr != "" {
			w.Header().Set("X-Jarvis2-Challenge", hdr)
		}
		inner.ServeHTTP(w, r)
	})
	ch := func(key, subject, about string, at time.Time) string {
		d, _ := kernel.Sign(x.w.Keys[key], kernel.Challenge{Kind: "challenge", At: at.Format(time.RFC3339Nano), Subject: subject, About: about,
			Nonce: "00112233445566778899aabbccddeeff"})
		b, _ := json.Marshal(d)
		return string(b)
	}
	get := func() int {
		resp, err := http.Get(p.URL + "/api/sessions/s1/content/notes/file?path=a.txt")
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	for _, h := range []string{"", "not json", ch("notarizer", sha("hello"), "content", x.clock), ch("notary", sha("other"), "content", x.clock),
		ch("notary", sha("hello"), "shell", x.clock), ch("notary", sha("hello"), "content", x.clock.Add(-time.Hour))} {
		hdr = h
		if code := get(); code != 502 {
			t.Fatalf("taken without a matching challenge (%q): %d", h, code)
		}
	}
	hdr = ch("notary", sha("hello"), "content", x.clock)
	if code := get(); code != 200 {
		t.Fatal(code)
	}
}

// jarvis2-request: a filing is kept by a filing id and forwarded with it, body unchanged
func TestProxyKeepsAFiling(t *testing.T) {
	x := newWorld(t)
	p := proxy(t, x)
	in := `{"summary":"two","items":[{"intent":"add-store","store":"gmail"},{"intent":"terminal","minutes":5}]}`
	resp, err := http.Post(p.URL+"/api/requests/batch", "application/json", strings.NewReader(in))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	if string(x.forwarded["/m/api/requests/batch"]) != in {
		t.Fatalf("forwarded %q", x.forwarded["/m/api/requests/batch"])
	}
	id := x.headers["/m/api/requests/batch"].Get("X-Jarvis2-Filing")
	if f, ok := x.g.rec.read().Filings[id]; !ok || f.Path != "/api/requests/batch" {
		t.Fatalf("filing %q not kept", id)
	}
}
