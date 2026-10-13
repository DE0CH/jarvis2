package main

// The Jarvis 1 import, end to end: a fake paused Jarvis 1 session served the way the Storage Box serves it (WebDAV:
// PROPFIND depth 1 + GET), at JARVIS1_PAUSED_URL (infra/e2e.sh points the test router at it); the router prepares and
// imports it, the phone approves the new line (its cert's restore = the Jarvis 1 id + the manifest's sha256), and the
// machine restores the workspace, the artifacts, the transcript under the right project, ~/.claude.json's machine id,
// fixes the repo remote, resumes the conversation, and re-arms the record's wakeup (passed: fires soon) and cron.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	e2eJ1ID   = "e2ej1import0001"
	e2eJ1UUID = "e2e10000-1111-4222-8333-444455556666"
)

func e2eTgz(files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	dirs := []string{}
	for n := range files {
		if strings.HasSuffix(n, "/") {
			dirs = append(dirs, n)
		}
	}
	sort.Strings(dirs)
	for _, n := range dirs {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Typeflag: tar.TypeDir, ModTime: time.Now()})
	}
	for n, body := range files {
		if strings.HasSuffix(n, "/") {
			continue
		}
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg, ModTime: time.Now()})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// serveJarvis1: the fake Storage Box, at the address JARVIS1_PAUSED_URL names
func serveJarvis1(addr string) {
	nextCron := time.Now().Add(6 * time.Hour).UnixMilli()
	meta := map[string]string{
		"wake_default": fmt.Sprintf(`{"name":"default","at":%d,"prompt":"e2e jarvis1 wakeup"}`, time.Now().Add(-time.Hour).UnixMilli()),
		"cron_e2e":     fmt.Sprintf(`{"name":"e2e","prompt":"e2e jarvis1 cron","every":86400,"tz":"Asia/Shanghai","nextAt":%d}`, nextCron),
	}
	rec, _ := json.Marshal(map[string]any{"id": e2eJ1ID, "title": "e2e jarvis1 import", "label": "", "model": "claude-opus-5-5", "size": "small",
		"harness": "claude", "permissionMode": "auto", "autoPause": "on", "repos": "", "pausedAt": "2026-10-12T10:00:00Z", "metadata": meta})
	gitConfig := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://x-access-token:old@github.com/DE0CH/jarvis2\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	files := map[string][]byte{
		"session.json":           rec,
		"manifest.txt":           []byte(e2eJ1UUID + ".jsonl\n"),
		"claude.json":            []byte(`{"machineID":"e2e-j1-machine","userID":"old","oauthAccount":{"emailAddress":"old@example.com"}}`),
		e2eJ1UUID + ".jsonl":     []byte(`{"type":"user","sessionId":"` + e2eJ1UUID + `","message":{"role":"user","content":"e2e jarvis1 conversation"}}` + "\n"),
		"workspace.tar.gz":       e2eTgz(map[string]string{"workspace/": "", "workspace/proj/": "", "workspace/proj/.git/": "", "workspace/proj/.git/objects/": "", "workspace/proj/.git/refs/": "", "workspace/proj/.git/refs/heads/": "", "workspace/proj/README.md": "from jarvis 1", "workspace/proj/.git/config": gitConfig, "workspace/proj/.git/HEAD": "ref: refs/heads/main\n"}),
		"artifacts.tar.gz":       e2eTgz(map[string]string{"artifacts/": "", "artifacts/record.md": "# jarvis 1 record"}),
		"changes.txt":            []byte("proj 0 0\n"),
		"artifacts-manifest.txt": []byte("ignored\n"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		p := strings.Trim(req.URL.Path, "/")
		switch req.Method {
		case "PROPFIND":
			if p != e2eJ1ID {
				w.WriteHeader(404)
				return
			}
			var b strings.Builder
			b.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/` + p + `/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response>`)
			for n, body := range files {
				fmt.Fprintf(&b, `<D:response><D:href>/%s/%s</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>%d</D:getcontentlength></D:prop></D:propstat></D:response>`, p, n, len(body))
			}
			b.WriteString(`</D:multistatus>`)
			w.WriteHeader(207)
			w.Write([]byte(b.String()))
		case "GET", "HEAD":
			dir, name, _ := strings.Cut(p, "/")
			body, ok := files[name]
			if dir != e2eJ1ID || !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(body)
		default:
			w.WriteHeader(405)
		}
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("the fake Jarvis 1 Storage Box: %v", err)
	}
	go http.Serve(ln, mux)
}

func jarvis1ImportStep(p *phone) {
	step("a Jarvis 1 import: prepared (every file hashed), approved on the phone as a new line naming the manifest's hash, restored and resumed")
	u := os.Getenv("E2E_JARVIS1_ADDR")
	if u == "" {
		log.Fatal("E2E_JARVIS1_ADDR isn't set (infra/e2e.sh sets it with the router's JARVIS1_PAUSED_URL)")
	}
	serveJarvis1(u)
	must2(call(router, "POST", "/api/jarvis1/paused/"+e2eJ1ID+"/prepare", nil, nil))
	var st struct {
		Prepare struct{ State, Error, Sha256 string }
		Sha256  string
	}
	for i := 0; ; i++ {
		must2(call(router, "GET", "/api/jarvis1/paused/"+e2eJ1ID, nil, &st))
		if st.Prepare.State == "ready" {
			break
		}
		if st.Prepare.State == "failed" || i > 60 {
			log.Fatalf("prepare: %+v", st.Prepare)
		}
		time.Sleep(time.Second)
	}
	var imp struct{ ID string }
	must2(call(router, "POST", "/api/jarvis1/paused/"+e2eJ1ID+"/import", map[string]any{"stores": []string{"e2e"}, "explanation": "e2e import"}, &imp))
	a := waitApproval("new-session", imp.ID)
	checkChallenge(a, []string{"e2e"}, "")
	var ch struct {
		Request struct {
			Options struct{ Config string }
		}
	}
	verify(*a.Challenge, &ch)
	var cfg struct {
		Label, Prompt string
		Restore       struct{ Machine, Sha256 string }
	}
	json.Unmarshal([]byte(ch.Request.Options.Config), &cfg)
	if cfg.Restore.Machine != e2eJ1ID || cfg.Restore.Sha256 != st.Sha256 || cfg.Label != "e2e jarvis1 import" || !strings.Contains(cfg.Prompt, "moved from Jarvis 1") {
		log.Fatalf("the signed config doesn't name the import: %s", ch.Request.Options.Config)
	}
	unlock(p, "e2e", nonceOf(*a.Challenge))
	id := approve(p, a)
	waitState(id, "started", 8*time.Minute)
	m := machineOf(id)
	expectOnMachine(m, "cat /home/claude/workspace/proj/README.md /home/claude/artifacts/record.md", "from jarvis 1\n# jarvis 1 record")
	expectOnMachine(m, "ls /home/claude/.claude/projects/-home-claude-workspace-proj/ | grep -c "+e2eJ1UUID, "1")
	expectOnMachine(m, "python3 -c \"import json;d=json.load(open('/home/claude/.claude.json'));print(d['machineID'], d.get('userID')=='old')\"", "e2e-j1-machine False")
	expectOnMachine(m, "git -C /home/claude/workspace/proj config remote.origin.url", "https://github.com/DE0CH/jarvis2.git")
	expectOnMachine(m, "grep -c 'passed while paused' /home/claude/artifacts/jarvis1-import/rearmed.txt", "1")
	expectOnMachine(m, "for i in $(seq 1 60); do ps -eo args | grep -q '[-]-resume "+e2eJ1UUID+"' && break; sleep 2; done; ps -eo args | grep -q '[-]-resume "+e2eJ1UUID+"' && echo resumed", "resumed")
	var wk struct{ Wakeups []map[string]any }
	must2(call(router, "GET", "/api/sessions/"+id+"/wakeups", nil, &wk))
	var cr struct{ Crons []map[string]any }
	must2(call(router, "GET", "/api/sessions/"+id+"/crons", nil, &cr))
	if len(wk.Wakeups) != 1 || wk.Wakeups[0]["name"] != "default" || len(cr.Crons) != 1 || cr.Crons[0]["name"] != "e2e" {
		log.Fatalf("re-armed: wakeups %v, crons %v", wk.Wakeups, cr.Crons)
	}
	must2(call(router, "DELETE", "/api/sessions/"+id+"/wakeups/default", nil, nil))
	must2(call(router, "DELETE", "/api/sessions/"+id+"/crons/e2e", nil, nil))
	must2(call(router, "POST", "/api/sessions/"+id+"/destroy?force=1", nil, nil))
	for i := 0; session(id) != nil; i++ {
		if i > 240 {
			log.Fatal("the imported session wasn't destroyed")
		}
		time.Sleep(3 * time.Second)
	}
}
