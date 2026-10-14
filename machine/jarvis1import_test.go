package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tentry struct {
	name, body, link string
	typ              byte
}

func tgz(t *testing.T, ents []tentry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Linkname: e.link, ModTime: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func shaHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

const tUUID = "0fa81372-5d1c-49af-b680-25a842f5df96"

// importWorld: a world whose router serves one import: the manifest as the snapshot, its files at /m/import-file/<name>
func importWorld(t *testing.T, build func(home string) (map[string][]byte, []string, map[string][]byte)) (*world, []byte) {
	t.Helper()
	x := newWorld(t)
	home, _ := os.UserHomeDir()
	files, order, tamper := build(home)
	man := j1Manifest{Kind: "jarvis1-import", V: 1, Session: "j1abc"}
	for _, n := range order {
		man.Files = append(man.Files, j1File{Name: n, Sha256: shaHex(files[n]), Size: int64(len(files[n]))})
	}
	mb, _ := json.Marshal(man)
	x.snapshot = mb
	inner := x.srv.Config.Handler
	x.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n, ok := strings.CutPrefix(r.URL.Path, "/m/import-file/"); ok {
			if b, ok := tamper[n]; ok {
				w.Write(b)
				return
			}
			w.Write(files[n])
			return
		}
		inner.ServeHTTP(w, r)
	})
	return x, mb
}

func j1Files(t *testing.T, home string) (map[string][]byte, []string) {
	ws := tgz(t, []tentry{
		{name: "workspace/", typ: tar.TypeDir},
		{name: "workspace/claude-env/", typ: tar.TypeDir},
		{name: "workspace/claude-env/README.md", body: "readme"},
		{name: "workspace/claude-env/link", link: "README.md", typ: tar.TypeSymlink},
		{name: "workspace/claude-env/hard", link: "workspace/claude-env/README.md", typ: tar.TypeLink},
		{name: "workspace/escape", link: home + "/.ssh", typ: tar.TypeSymlink},
		{name: "workspace/escape/authorized_keys", body: "through a symlink"},
		{name: "../evil", body: "outside"},
		{name: ".bashrc", body: "outside the root"},
	})
	art := tgz(t, []tentry{{name: "artifacts/record.md", body: "# record"}})
	rec := `{"id":"j1abc","title":"T","metadata":{` +
		`"wake_default":"{\"name\":\"default\",\"at\":1000,\"prompt\":\"warm up\"}",` +
		`"cron_owcs-tix":"{\"name\":\"owcs-tix\",\"prompt\":\"check tickets\",\"every\":86400,\"tz\":\"Asia/Shanghai\",\"nextAt\":` + jsonInt(time.Now().Add(-2*time.Hour).UnixMilli()) + `,\"until\":` + jsonInt(time.Now().Add(30*24*time.Hour).UnixMilli()) + `}",` +
		`"watch_x":"{}"}}`
	files := map[string][]byte{
		"session.json":     []byte(rec),
		"manifest.txt":     []byte(tUUID + ".jsonl\n"),
		"claude.json":      []byte(`{"machineID":"m-old","oauthAccount":{"emailAddress":"x"},"userID":"u","projects":{"/home/claude/workspace/claude-env":{}}}`),
		tUUID + ".jsonl":   []byte(`{"type":"user","message":{"content":"hello"}}` + "\n"),
		"workspace.tar.gz": ws,
		"artifacts.tar.gz": art,
	}
	return files, []string{"session.json", "manifest.txt", "claude.json", tUUID + ".jsonl", "artifacts.tar.gz", "workspace.tar.gz"}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestJarvis1ImportRestoresWhatTheSourceNames(t *testing.T) {
	x, mb := importWorld(t, func(home string) (map[string][]byte, []string, map[string][]byte) {
		f, o := j1Files(t, home)
		return f, o, nil
	})
	home, _ := os.UserHomeDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	if err := restoreSnapshot(x.g, shaHex(mb)); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string { b, _ := os.ReadFile(filepath.Join(home, rel)); return string(b) }
	if read("workspace/claude-env/README.md") != "readme" || read("artifacts/record.md") != "# record" {
		t.Fatal("tarballs not in place")
	}
	if l, _ := os.Readlink(filepath.Join(home, "workspace/claude-env/link")); l != "README.md" {
		t.Fatalf("symlink %q", l)
	}
	if read("workspace/claude-env/hard") != "readme" {
		t.Fatal("hard link")
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh/authorized_keys")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); err == nil {
		t.Fatal("wrote outside the tarball's root")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(home), "evil")); err == nil {
		t.Fatal("wrote outside home")
	}
	var cj map[string]any
	json.Unmarshal([]byte(read(".claude.json")), &cj)
	if cj["machineID"] != "m-old" || cj["oauthAccount"] != nil || cj["userID"] != nil || cj["projects"] == nil {
		t.Fatalf("claude.json %v", cj)
	}
	// the transcripts wait for the repos, then go under the working dir's project
	placeImportedTranscripts()
	if read(".claude/projects/-"+strings.ReplaceAll(strings.Trim(home, "/"), "/", "-")+"-workspace-claude-env/"+tUUID+".jsonl") == "" {
		ents, _ := filepath.Glob(filepath.Join(home, ".claude/projects/*/*"))
		t.Fatalf("transcript not placed: %v", ents)
	}
	// the record's wakeup (long past) fires soon; the cron keeps its period and time of day; its missed run fires soon
	rearmJarvis1(x.g)
	r := x.g.rec.read()
	if len(r.Wakeups) != 2 || len(r.Crons) != 1 {
		t.Fatalf("armed %+v", r)
	}
	wk, cr := string(x.forwarded["/m/api/sessions/s1/wakeups"]), string(x.forwarded["/m/api/sessions/s1/crons"])
	if !strings.Contains(cr, `"everySeconds":86400`) || !strings.Contains(cr, `"tz":"Asia/Shanghai"`) || strings.Contains(cr, "check tickets") ||
		!strings.Contains(wk, `"delaySeconds":300`) || strings.Contains(wk, "warm up") || strings.Contains(wk, "check tickets") {
		t.Fatalf("armed %s %s", wk, cr)
	}
	note := read("artifacts/jarvis1-import/rearmed.txt")
	if !strings.Contains(note, "passed while paused") || !strings.Contains(note, "watch_x") || read("artifacts/jarvis1-import/session.json") == "" {
		t.Fatalf("rearmed.txt %s", note)
	}
	if _, err := os.Stat(filepath.Join(home, j1StageDir)); err == nil {
		t.Fatal("staging dir left")
	}
}

func TestJarvis1ImportRefusesOtherBytes(t *testing.T) {
	for _, n := range []string{"workspace.tar.gz", tUUID + ".jsonl", "claude.json"} {
		x, mb := importWorld(t, func(home string) (map[string][]byte, []string, map[string][]byte) {
			files, order := j1Files(t, home)
			other := map[string][]byte{n: append(append([]byte{}, files[n]...), 'x')}
			if n == "workspace.tar.gz" {
				other[n] = tgz(t, []tentry{{name: "workspace/claude-env/README.md", body: "swapped"}})
			}
			return files, order, other
		})
		home, _ := os.UserHomeDir()
		if err := restoreSnapshot(x.g, shaHex(mb)); err == nil || !strings.Contains(err.Error(), "not the bytes the manifest names") {
			t.Fatalf("%s: %v", n, err)
		}
		if n == "workspace.tar.gz" {
			if _, err := os.Stat(filepath.Join(home, "workspace/claude-env/README.md")); err == nil {
				t.Fatal("swapped workspace moved into place")
			}
		}
	}
	// a manifest whose hash isn't the source's: refused before anything is fetched
	x, _ := importWorld(t, func(home string) (map[string][]byte, []string, map[string][]byte) {
		f, o := j1Files(t, home)
		return f, o, nil
	})
	if err := restoreSnapshot(x.g, strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "isn't the one the source names") {
		t.Fatal(err)
	}
}

func TestJ1FixURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://x-access-token:ghp_abc@github.com/DE0CH/claude-env.git": "https://github.com/DE0CH/claude-env.git",
		"https://github.com/de0ch/claude-env":                            "https://github.com/de0ch/claude-env.git",
		"https://github.com/DE0CH/YCC.git":                               "https://github.com/DE0CH/YCC.git",
		"git@github.com:DE0CH/x.git":                                     "git@github.com:DE0CH/x.git",
		"https://gitlab.com/a/b":                                         "https://gitlab.com/a/b",
	} {
		if got := j1FixURL(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
	if _, err := exec.LookPath("git"); err != nil {
		return
	}
	ws := t.TempDir()
	repo := filepath.Join(ws, "r")
	exec.Command("git", "init", "-q", repo).Run()
	exec.Command("git", "-C", repo, "remote", "add", "origin", "https://u:secret@github.com/DE0CH/r").Run()
	j1FixRemotes(ws)
	out, _ := exec.Command("git", "-C", repo, "remote", "get-url", "origin").Output()
	if strings.TrimSpace(string(out)) != "https://github.com/DE0CH/r.git" {
		t.Fatalf("remote %s", out)
	}
}

func TestJ1ScheduleKeepsFutureTimes(t *testing.T) {
	now := time.Date(2026, 10, 13, 2, 0, 0, 0, time.UTC)
	at := now.Add(3 * time.Hour).UnixMilli()
	next := now.Add(10 * time.Hour).UnixMilli()
	rec := `{"metadata":{"wake_a":"{\"name\":\"a\",\"at\":` + jsonInt(at) + `,\"prompt\":\"p\"}",` +
		`"cron_c":"{\"name\":\"c\",\"prompt\":\"q\",\"every\":86400,\"nextAt\":` + jsonInt(next) + `,\"until\":` + jsonInt(now.Add(-time.Hour).UnixMilli()) + `}",` +
		`"cron_d":"{\"name\":\"d\",\"prompt\":\"q\",\"every\":3600,\"nextAt\":` + jsonInt(next) + `}"}}`
	arms, notes := j1Schedule([]byte(rec), "s1", now)
	if len(arms) != 2 || arms[0].Body["name"] != "d" || arms[0].Body["at"] != next || arms[0].Body["until"] != nil || arms[1].Body["at"] != at {
		t.Fatalf("%+v", arms)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], `cron "c": ended`) {
		t.Fatalf("%v", notes)
	}
}
