package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTruncateAtMarker(t *testing.T) {
	body := []byte("a\nb\nc MARK here\nd\n")
	kept, before, after, cut := truncateAtMarker(body, "MARK")
	if !cut || string(kept) != "a\nb\n" || before != 4 || after != 2 {
		t.Fatalf("%q %d %d %v", kept, before, after, cut)
	}
	kept, before, after, cut = truncateAtMarker(body, "nowhere")
	if cut || string(kept) != string(body) || before != after {
		t.Fatalf("%q %v", kept, cut)
	}
	if kept, _, after, _ := truncateAtMarker([]byte("MARK first\nx\n"), "MARK"); len(kept) != 0 || after != 0 {
		t.Fatalf("%q", kept)
	}
}

func TestApplyRollback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	proj := filepath.Join(home, ".claude", "projects", "-home-claude-workspace")
	os.MkdirAll(filepath.Join(proj, "conv", "subagents"), 0o755)
	conv := filepath.Join(proj, "conv.jsonl")
	sub := filepath.Join(proj, "conv", "subagents", "agent.jsonl")
	other := filepath.Join(proj, "other.jsonl")
	write := func() {
		os.WriteFile(conv, []byte(`{"n":1}`+"\n"+`{"n":2,"text":"bad turn XYZZY"}`+"\n"+`{"n":3}`+"\n"), 0o600)
		os.WriteFile(sub, []byte(`{"text":"XYZZY"}`+"\n"), 0o600)
		os.WriteFile(other, []byte(`{"n":1}`+"\n"), 0o600)
	}
	write()

	// another predecessor's rollback: ignored
	t.Setenv("JARVIS2_ROLLBACK", "XYZZY")
	t.Setenv("JARVIS2_ROLLBACK_PRED", "m-old")
	applyRollback("m-new")
	if b, _ := os.ReadFile(conv); !strings.Contains(string(b), "XYZZY") {
		t.Fatal("a rollback for another predecessor was applied")
	}

	applyRollback("m-old")
	if b, _ := os.ReadFile(conv); string(b) != `{"n":1}`+"\n" {
		t.Fatalf("conversation: %q", b)
	}
	if fi, _ := os.Stat(conv); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if b, _ := os.ReadFile(sub); !strings.Contains(string(b), "XYZZY") {
		t.Fatal("a subagent transcript was touched")
	}
	if b, _ := os.ReadFile(other); string(b) != `{"n":1}`+"\n" {
		t.Fatalf("other: %q", b)
	}

	// no marker: nothing happens
	write()
	t.Setenv("JARVIS2_ROLLBACK", "")
	applyRollback("m-old")
	if b, _ := os.ReadFile(conv); !strings.Contains(string(b), "XYZZY") {
		t.Fatal("rolled back without a marker")
	}
	if _, err := rollbackTranscripts(home, "ab"); err == nil {
		t.Fatal("a 2-character marker was accepted")
	}
}

func TestFetchAttachments(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	files := map[string]string{"photo 1.png": "PNG", "notes%.txt": "text"}
	deleted := false
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, body []byte) {
		switch {
		case req.Method == "GET" && req.URL.Path == "/m/attachments":
			w.Write([]byte(`{"files":[{"name":"photo 1.png","isImage":true},{"name":"notes%.txt"}]}`))
		case req.Method == "GET" && strings.HasPrefix(req.URL.Path, "/m/attachments/"):
			b, ok := files[strings.TrimPrefix(req.URL.Path, "/m/attachments/")]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write([]byte(b))
		case req.Method == "DELETE" && req.URL.Path == "/m/attachments":
			deleted = true
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(404)
		}
	})
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}

	t.Setenv("SESSION_ATTACHMENTS_JSON", "")
	if env := fetchAttachments(c); env != nil {
		t.Fatalf("no attachments, env %v", env)
	}
	t.Setenv("SESSION_ATTACHMENTS_JSON", `[{"name":"photo 1.png","isImage":true}]`)
	env := fetchAttachments(c)
	for n, want := range files {
		if b, err := os.ReadFile(filepath.Join(home, attachStaging, n)); err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", n, b, err)
		}
	}
	if !deleted {
		t.Fatal("the router's copy wasn't dropped")
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "SESSION_ATTACH_DAV_BASE=file://"+home+"\n") || !strings.Contains(joined, "SESSION_ATTACH_DIR="+attachStaging) {
		t.Fatalf("env %v", env)
	}
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`} {
		if plainName(bad) {
			t.Fatalf("%q passed", bad)
		}
	}
}
