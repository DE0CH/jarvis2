package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

func TestBusyInState(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	unlock, err := r.lock("sA", "pausing")
	if err != nil {
		t.Fatal(err)
	}
	_, out := appDo(t, r, "GET", "/api/state", "")
	ss := out["sessions"].([]any)
	b, _ := ss[0].(map[string]any)["busy"].(map[string]any)
	if b == nil || b["kind"] != "pausing" {
		t.Fatalf("%v", ss[0])
	}
	if _, err := r.lock("sA", "starting"); err != errBusy {
		t.Fatal("a second action got the lock")
	}
	unlock()
	_, out = appDo(t, r, "GET", "/api/state", "")
	if _, ok := out["sessions"].([]any)[0].(map[string]any)["busy"]; ok {
		t.Fatal("still busy")
	}
}

// pausedSession: a session through its first machine to paused (its machine snapshots)
func (g *krig) pausedSession() string {
	g.t.Helper()
	sid, m := g.newSession()
	m.boot()
	go func() {
		for i := 0; i < 200; i++ {
			if hasWord(m.commands(), "snapshot") {
				m.snapshot([]byte("ws"))
				return
			}
		}
	}()
	if err := g.r.Pause(sid); err != nil {
		g.t.Fatal(err)
	}
	g.waitState(sid, "paused")
	return sid
}

// the size is the spawn's (no phone); a model or the API proxy is in the source: a new phone-made source
func TestResumeWithSizeAndModel(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	r := g.r
	sid := g.pausedSession()
	if code, _ := appDo(t, r, "POST", "/api/sessions/"+sid+"/resume", `{"size":"huge"}`); code != 400 {
		t.Fatal("a bad size was accepted")
	}
	if code, _ := appDo(t, r, "POST", "/api/sessions/"+sid+"/resume", `{"model":"gpt-9"}`); code != 400 {
		t.Fatal("an unknown model was accepted")
	}
	if code, out := appDo(t, r, "POST", "/api/sessions/"+sid+"/resume", `{"size":"small"}`); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	s := g.waitState(sid, "initialising")
	if s.Size != "small" {
		t.Fatal(s.Size)
	}
	r.st.Do(func(d *persisted) {
		for _, a := range d.Approvals {
			t.Fatalf("a size change asked the phone: %+v", a)
		}
	})
	g.vm(s.MachineID).boot()
	sid2 := g.pausedSession()
	if code, out := appDo(t, r, "POST", "/api/sessions/"+sid2+"/resume", `{"model":"claude-fable-5-1"}`); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	a := g.approval(sid2, "resume-upgrade")
	var c kernel.Succession
	json.Unmarshal([]byte(a.Drafts[0].Payload), &c)
	var st SessionSettings
	json.Unmarshal([]byte(c.Successor.Settings), &st)
	if st.Model != "claude-fable-5-1" || st.Prompt != "" {
		t.Fatalf("%+v", st)
	}
}

// a restart: pause (the snapshot), then a resume with a prompt and a rollback: the phone signs the new source
func TestRestartWithPromptAndRollback(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	sid, m := g.newSession()
	m.boot()
	go func() {
		for i := 0; i < 400; i++ {
			if hasWord(m.commands(), "snapshot") {
				m.snapshot([]byte("ws"))
				return
			}
		}
	}()
	opsPoll = time.Millisecond
	if _, err := g.r.Restart(sid, RestartRequest{Prompt: "go on", Rollback: &struct {
		DropFromMarker string `json:"dropFromMarker"`
	}{"marker text"}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the approval", func() bool {
		ok := false
		g.r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				ok = ok || a.Kind == "resume-upgrade"
			}
		})
		return ok
	})
	a := g.approval(sid, "resume-upgrade")
	var c kernel.Succession
	json.Unmarshal([]byte(a.Drafts[0].Payload), &c)
	var st SessionSettings
	json.Unmarshal([]byte(c.Successor.Settings), &st)
	if st.Prompt != "go on" || st.Rollback != "marker text" || c.Successor.Snapshot == "" {
		t.Fatalf("%+v %+v", st, c.Successor)
	}
	if _, err := g.r.Restart(sid, RestartRequest{Rollback: &struct {
		DropFromMarker string `json:"dropFromMarker"`
	}{"ab"}}); err == nil {
		t.Fatal("a short marker")
	}
}

// the first prompt's attachments: staged, bound to one session, named in its source's settings by sha256 and size,
// fetched by its machine once
func TestIdempotentCreateAndAttachments(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	r := g.r
	for _, f := range []struct{ name, body string }{{"my photo.png", "PNG"}, {"notes.txt", "text"}} {
		code, out := appDo(t, r, "POST", "/api/uploads", f.body, "x-upload-id", "up1", "x-upload-name", f.name)
		if code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	if code, _ := appDo(t, r, "POST", "/api/uploads", "x", "x-upload-id", "../bad"); code != 400 {
		t.Fatal("a bad upload id was accepted")
	}
	req := `{"requestId":"req-1","label":"x","harness":"claude","prompt":"look","apiProxy":true,
		"attachments":{"uploadId":"up1","files":[{"name":"my photo.png"},{"name":"notes.txt"}]}}`
	code, out := appDo(t, r, "POST", "/api/sessions", req)
	if code != 200 || out["id"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	if code, out := appDo(t, r, "POST", "/api/sessions", req); code != 200 || out["id"] != id {
		t.Fatalf("a repeat made another session: %d %v", code, out)
	}
	a := g.approval(id, "new-session")
	if a.Options["attachments"] != "2 file(s)" || a.Options["apiProxy"] != "on" {
		t.Fatalf("%+v", a.Options)
	}
	var c kernel.Succession
	json.Unmarshal([]byte(a.Drafts[0].Payload), &c)
	var st SessionSettings
	json.Unmarshal([]byte(c.Successor.Settings), &st)
	if len(st.Attachments) != 2 || st.Attachments[0].Name != "my_photo.png" || st.Attachments[0].Sha256 != sha256Hex("PNG") ||
		st.Attachments[0].Size != 3 || !st.APIProxy {
		t.Fatalf("%+v", st)
	}
	if code, out := appDo(t, r, "POST", "/api/sessions", `{"requestId":"req-2","attachments":{"uploadId":"up1","files":[{"name":"notes.txt"}]}}`); code != 400 {
		t.Fatalf("%d %v", code, out)
	}
	if _, err := r.Respond(a.ID, g.sign("phone", a)); err != nil {
		t.Fatal(err)
	}
	s := g.waitState(id, "initialising")
	m := g.vm(s.MachineID)
	if code, body, _ := m.call("GET", "/m/attachments/my_photo.png", nil); code != 200 || string(body) != "PNG" {
		t.Fatalf("%d %q", code, body)
	}
	if code, _, _ := m.call("GET", "/m/attachments/other.txt", nil); code != 404 {
		t.Fatal(code)
	}
	if code, _, _ := m.call("DELETE", "/m/attachments", nil); code != 200 {
		t.Fatal(code)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.DataDir, "uploads", "up1")); !os.IsNotExist(err) {
		t.Fatal("the staged files are still there")
	}
}

func TestSweepUploads(t *testing.T) {
	r := newTestRouter(t)
	r.StageUpload("old", "a.txt", strings.NewReader("a"))
	r.StageUpload("new", "b.txt", strings.NewReader("b"))
	r.StageUpload("orphan", "c.txt", strings.NewReader("c"))
	r.st.Do(func(d *persisted) {
		d.Uploads["old"].Created = time.Now().Add(-25 * time.Hour)
		d.Uploads["orphan"].Session = "sGone"
	})
	r.sweepUploads(time.Now())
	r.st.Do(func(d *persisted) {
		if d.Uploads["old"] != nil || d.Uploads["orphan"] != nil || d.Uploads["new"] == nil {
			t.Fatalf("%v", d.Uploads)
		}
	})
	if _, err := r.StageUpload("big", "x.bin", io.LimitReader(zeros{}, attachMaxBytes+10)); err == nil {
		t.Fatal("an oversize file was accepted")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { return len(p), nil }

func TestReposAndGitHub(t *testing.T) {
	r := newTestRouter(t)
	// a stand-in secrets: the begin is relayed as asked; a finish answers what secrets signs
	var begun map[string]any
	answer := `{"kind":"deploy-key-added","repo":"DE0CH/jarvis2","store":"github-jarvis2","sensitive":true,"fingerprint":"SHA256:abc"}`
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		switch req.URL.Path {
		case "/deploy-keys/begin":
			json.Unmarshal(b, &begun)
			w.Write([]byte(`{"payload":"{\"kind\":\"deploy-key-begin\"}","sig":"s"}`))
		case "/deploy-keys/finish":
			p, _ := json.Marshal(answer)
			w.Write([]byte(`{"payload":` + string(p) + `,"sig":"s"}`))
		default:
			http.NotFound(w, req)
		}
	}))
	defer core.Close()
	r.k = &Kernel{URLs: map[string]string{"secrets": core.URL}, HTTP: http.DefaultClient}
	if code, _ := appDo(t, r, "POST", "/api/repos/key/begin", `{"action":"add","repo":"https://github.com/DE0CH/jarvis2.git"}`); code != 200 || begun["repo"] != "DE0CH/jarvis2" || begun["action"] != "add" {
		t.Fatal(code, begun)
	}
	for _, b := range []string{`{"action":"add","repo":"gitlab.com/x/y"}`, `{"action":"rotate","repo":"DE0CH/x"}`, `{"action":"add","repo":"DE0CH/.."}`} {
		if code, _ := appDo(t, r, "POST", "/api/repos/key/begin", b); code != 400 {
			t.Fatal("accepted", b)
		}
	}
	// the list follows secrets' answer only
	if _, out := appDo(t, r, "GET", "/api/repos", ""); len(out["repos"].([]any)) != 0 {
		t.Fatal("a begin added to the list")
	}
	if code, _ := appDo(t, r, "POST", "/api/repos/key/finish", `{"pending":"p"}`); code != 200 {
		t.Fatal(code)
	}
	_, out := appDo(t, r, "GET", "/api/state", "")
	rs := out["repos"].([]any)
	if len(rs) != 1 || rs[0].(map[string]any)["name"] != "jarvis2" || rs[0].(map[string]any)["store"] != "github-jarvis2" ||
		rs[0].(map[string]any)["sensitive"] != true || rs[0].(map[string]any)["url"] != "https://github.com/DE0CH/jarvis2.git" {
		t.Fatalf("%v", rs)
	}
	answer = `{"kind":"deploy-key-removed","repo":"DE0CH/jarvis2","store":"github-jarvis2"}`
	appDo(t, r, "POST", "/api/repos/key/finish", `{"pending":"p"}`)
	if _, out := appDo(t, r, "GET", "/api/repos", ""); len(out["repos"].([]any)) != 0 {
		t.Fatalf("%v", out)
	}
	// entries that aren't GitHub repos (an older list) are left off
	os.WriteFile(r.reposPath(), []byte(`[{"name":"a","url":"https://gitlab.com/x/a.git"},{"name":"b","url":"https://github.com/DE0CH/b.git"}]`), 0o600)
	if rs := r.Repos(); len(rs) != 1 || rs[0].Repo != "DE0CH/b" || rs[0].Store != "github-b" {
		t.Fatalf("%+v", rs)
	}
	// the same store names as secrets' RepoStore (core/kernel/secrets/deploykeys.go)
	for in, want := range map[string]string{"DE0CH/claude-env": "github-claude-env", "DE0CH/china_train": "github-china-train",
		"de0ch/Jarvis2": "github-jarvis2", "someone/Thing.js": "github-someone-thing-js"} {
		if got := repoStore(in); got != want {
			t.Errorf("repoStore(%s) = %s, want %s", in, got, want)
		}
	}

	t.Setenv("GITHUB_READ_TOKEN", "")
	if code, out := appDo(t, r, "GET", "/api/github/repos", ""); code != 503 || out["configured"] != false {
		t.Fatalf("%d %v", code, out)
	}
	var auth string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth = req.Header.Get("Authorization")
		w.Write([]byte(`[{"full_name":"DE0CH/jarvis2","clone_url":"https://github.com/DE0CH/jarvis2.git","private":false,"pushed_at":"2026-10-09T00:00:00Z","owner":{"login":"DE0CH"}}]`))
	}))
	defer gh.Close()
	old := githubAPI
	githubAPI = gh.URL
	defer func() { githubAPI = old }()
	t.Setenv("GITHUB_READ_TOKEN", "read-only")
	code, out := appDo(t, r, "GET", "/api/github/repos", "")
	if code != 200 || auth != "Bearer read-only" || out["repos"].([]any)[0].(map[string]any)["fullName"] != "DE0CH/jarvis2" {
		t.Fatalf("%d %v %q", code, out, auth)
	}
	if strings.Contains(strings.ToLower(jsonString(out)), "read-only") {
		t.Fatal("the token leaked into the answer")
	}
}

// TestWebRequestTakesSensitiveStores: the web page proposes any store, sensitive ones included (Deyao, 2026-10-13;
// docs/DECISIONS.md 161): the request becomes an approval holding them, filed as the web's, for the phone to review;
// the reserved store and the deploy-key token's store are still refused.
func TestWebRequestTakesSensitiveStores(t *testing.T) {
	g := newKRig(t)
	r := g.r
	code, out := appDo(t, r, "POST", "/api/sessions", `{"requestId":"web-sens","harness":"claude","stores":["default","identity","github-jarvis2"]}`)
	if code != 200 || out["id"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	waitFor(t, "approval", func() bool {
		var ok bool
		r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				ok = ok || (a.Session == id && a.Kind == "new-session" && a.Origin != nil && a.Origin.Caller.Kind == "web")
			}
		})
		return ok
	})
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil || !containsString(s.Stores, "identity") || !containsString(s.Stores, "github-jarvis2") {
			t.Fatalf("the sensitive stores didn't reach the request: %+v", s)
		}
	})
	for _, bad := range []string{flyStore, deployKeyTokenStore} {
		if code, out := appDo(t, r, "POST", "/api/sessions", `{"requestId":"web-`+bad+`","harness":"claude","stores":["`+bad+`"]}`); code == 200 {
			t.Fatalf("store %s was accepted: %v", bad, out)
		}
	}
}
