package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func contentDo(t *testing.T, h http.Handler, method, target, body string) (int, map[string]any, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Body.Bytes()
}

func TestContentPath(t *testing.T) {
	for _, ok := range []string{"a.txt", "dir/b.json", "/x/y/", "数据.txt"} {
		if _, err := contentPath(ok); err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../x", "a/../b", "a//b", "a\\b", "a/./b", "a\x00b", "x\ny"} {
		if _, err := contentPath(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	for _, bad := range []string{"", "A", "-a", "a-", "a_b", "a/b", strings.Repeat("a", 43)} {
		if _, err := contentName(bad); err == nil {
			t.Fatalf("name %q accepted", bad)
		}
	}
}

func TestContentStoresAppAndSession(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.cfg.NoAccess = true
	invalidateContent()
	h := r.Handler()

	// Deyao: create, upload (nested), list, download, delete
	if code, out, _ := contentDo(t, h, "POST", "/api/content", `{"name": "notes"}`); code != 200 || out["ok"] != true {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, _, _ := contentDo(t, h, "POST", "/api/content", `{"name": "notes"}`); code != 409 {
		t.Fatalf("create twice: %d", code)
	}
	contentDo(t, h, "POST", "/api/content", `{"name": "other"}`)
	if code, out, _ := contentDo(t, h, "POST", "/api/content/notes/file?path=dir/a.txt", "hello"); code != 200 || out["size"] != 5.0 {
		t.Fatalf("upload: %d %v", code, out)
	}
	contentDo(t, h, "POST", "/api/content/notes/file?path=top.md", "# top")
	if code, out, _ := contentDo(t, h, "GET", "/api/content/notes/files", ""); code != 200 || len(out["files"].([]any)) != 2 ||
		out["files"].([]any)[0].(map[string]any)["path"] != "dir/a.txt" {
		t.Fatalf("files: %d %v", code, out)
	}
	if code, out, _ := contentDo(t, h, "GET", "/api/content?fresh=1", ""); code != 200 || len(out["stores"].([]any)) != 2 ||
		out["stores"].([]any)[0].(map[string]any)["files"] != 2.0 || out["stores"].([]any)[0].(map[string]any)["bytes"] != 10.0 {
		t.Fatalf("stores: %d %v", code, out)
	}
	if code, _, b := contentDo(t, h, "GET", "/api/content/notes/file?path=dir/a.txt", ""); code != 200 || string(b) != "hello" {
		t.Fatalf("download: %d %q", code, b)
	}
	if code, _, _ := contentDo(t, h, "GET", "/api/content/notes/file?path=../x", ""); code != 400 {
		t.Fatalf("bad path: %d", code)
	}

	// a session whose cert names "notes": reads and writes it, not "other"
	cfg, _ := json.Marshal(SessionConfig{V: 1, Content: []string{"notes"}})
	cert := rg.core.key.doc(map[string]any{"kind": "succession-cert", "machine": map[string]string{"id": "mC"},
		"options": map[string]any{"harness": "claude", "config": string(cfg)}})
	r.st.Do(func(d *persisted) {
		d.Sessions["sC"] = &Session{ID: "sC", State: "started", MachineID: "mC", Harness: "claude"}
		d.Machines["mC"] = "sC"
		d.Certs["mC"] = cert
	})
	m := newTestMachine(r, "mC")
	mh := r.MachineHandler()
	code, out := m.do(t, mh, "GET", "/m/api/sessions/sC/content", "")
	if code != 200 || len(out["stores"].(map[string]any)) != 1 || len(out["stores"].(map[string]any)["notes"].([]any)) != 2 {
		t.Fatalf("session listing: %d %v", code, out)
	}
	// the file comes with the core's attestation
	req := httptest.NewRequest("GET", "/m/api/sessions/sC/content/notes/file?path=dir/a.txt", nil)
	w := mxRaw(t, m, mh, req)
	if w.Code != 200 || w.Body.String() != "hello" || w.Header().Get("X-Jarvis2-Attest") == "" {
		t.Fatalf("session file: %d %q attest=%q", w.Code, w.Body.String(), w.Header().Get("X-Jarvis2-Attest"))
	}
	if code, out := m.do(t, mh, "PUT", "/m/api/sessions/sC/content/notes/file?path=new/b.txt", "pushed"); code != 200 || out["size"] != 6.0 {
		t.Fatalf("session put: %d %v", code, out)
	}
	if got := rg.dav.get(contentRoot + "/notes/new/b.txt"); string(got) != "pushed" {
		t.Fatalf("on the box: %q", got)
	}
	if code, _ := m.do(t, mh, "DELETE", "/m/api/sessions/sC/content/notes/file?path=new/b.txt", ""); code != 200 {
		t.Fatalf("session delete: %d", code)
	}
	if code, _ := m.do(t, mh, "PUT", "/m/api/sessions/sC/content/other/file?path=x", "no"); code != 403 {
		t.Fatalf("a store the cert doesn't name: %d", code)
	}
	if code, _ := m.do(t, mh, "GET", "/m/api/sessions/s1/content", ""); code != 403 {
		t.Fatalf("another session's path: %d", code)
	}

	// New session: the content stores go into the signed config; an unknown one is refused
	if _, err := r.CreateSession(NewSession{Label: "x", Content: []string{"nope"}}); err == nil || !strings.Contains(err.Error(), "no content store") {
		t.Fatalf("unknown store: %v", err)
	}
	s := &Session{Label: "x", Content: []string{"notes"}}
	c, err := r.sessionConfig(s)
	if err != nil || !strings.Contains(c, `"content":["notes"]`) {
		t.Fatalf("config: %v %s", err, c)
	}

	// delete a store
	if code, _, _ := contentDo(t, h, "DELETE", "/api/content/other", ""); code != 200 {
		t.Fatalf("delete store: %d", code)
	}
	if code, _, _ := contentDo(t, h, "DELETE", "/api/content/other", ""); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
}

func TestParseMultistatusHetzner(t *testing.T) {
	// as the Storage Box (Apache mod_dav) answers, with lp1: prefixes and an absolute href
	body := `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>/claude-records/.content/email/</D:href>
<D:propstat><D:prop><lp1:resourcetype><D:collection/></lp1:resourcetype><lp1:getlastmodified>Fri, 02 Oct 2026 06:07:22 GMT</lp1:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
</D:response>
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>/claude-records/.content/email/address%20one.txt</D:href>
<D:propstat><D:prop><lp1:resourcetype/><lp1:getcontentlength>38</lp1:getcontentlength><lp1:getlastmodified>Fri, 02 Oct 2026 06:07:22 GMT</lp1:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
</D:response>
</D:multistatus>`
	es, err := parseMultistatus([]byte(body))
	if err != nil || len(es) != 2 || !es[0].Dir || es[0].Name != "email" || es[1].Dir || es[1].Name != "address one.txt" || es[1].Size != 38 ||
		es[1].Modified != "2026-10-02T06:07:22Z" {
		t.Fatalf("%v %+v", err, es)
	}
}
