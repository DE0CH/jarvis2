package main

import (
	"crypto/sha256"
	"encoding/hex"
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

	// the env asks for one: nothing happens (only the cert's one-time inputs do: vouch.go)
	t.Setenv("JARVIS2_ROLLBACK", "XYZZY")
	t.Setenv("JARVIS2_ROLLBACK_PRED", "m-old")
	applyRollback("")
	if b, _ := os.ReadFile(conv); !strings.Contains(string(b), "XYZZY") {
		t.Fatal("a rollback from the env was applied")
	}

	applyRollback("XYZZY")
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
	applyRollback("")
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

	refs := []AttachmentRef{}
	for n, b := range files {
		refs = append(refs, AttachmentRef{Name: n, Sha256: hexSum(b), Size: int64(len(b))})
	}
	// a file other than the cert names: refused, nothing kept
	bad := append([]AttachmentRef{}, refs...)
	bad[0].Sha256 = hexSum("other bytes")
	if env := fetchAttachments(c, bad); env != nil {
		t.Fatalf("an attachment the cert doesn't name was taken: %v", env)
	}
	if _, err := os.Stat(filepath.Join(home, attachStaging)); err == nil {
		t.Fatal("a refused attachment was left on disk")
	}
	env := fetchAttachments(c, refs)
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

func hexSum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
