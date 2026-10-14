package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// restoreCore: secrets' restore primitives as the router sees them (core/kernel/secrets/history.go does the real checks)
type restoreCore struct {
	mu           sync.Mutex
	key          key
	refuse       int  // answer finish with this status
	badBackup    bool // a backup whose hash isn't the receipt's
	calls        []string
	bucket       *rBucket
	putsAtCommit int
}

func (c *restoreCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := io.ReadAll(req.Body)
	c.calls = append(c.calls, req.URL.Path)
	switch req.URL.Path {
	case "/identity":
		writeJSON(w, 200, map[string]any{"role": "secrets", "signingKey": c.key.pub()})
	case "/stores/restore/finish":
		if c.refuse != 0 {
			writeJSON(w, c.refuse, c.key.doc(map[string]string{"error": "the iPhone's signature doesn't cover this restore"}))
			return
		}
		var in struct{ Pending string }
		json.Unmarshal(b, &in)
		sha := backupSha("BE", "BD")
		if c.badBackup {
			sha = backupSha("X", "Y")
		}
		writeJSON(w, 200, map[string]any{
			"receipt": c.key.doc(map[string]any{"kind": "store-restore-approved", "pending": in.Pending, "store": "default", "from": 4, "to": 2,
				"put":    []map[string]string{{"key": "A", "e": "E", "dataSha256": "d", "backupSha256": sha}},
				"remove": []string{"Z"}, "begin": "{}", "phoneSig": "S"}),
			"backups": map[string]any{"A": map[string]string{"e": "BE", "data": "BD", "sha256": backupSha("BE", "BD")}}})
	case "/stores/restore/commit":
		c.bucket.mu.Lock()
		c.putsAtCommit = len(c.bucket.puts)
		c.bucket.mu.Unlock()
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "store-restored", "store": "default", "from": 2, "seq": 5}))
	case "/stores/versions":
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "store-versions", "store": "default"}))
	default:
		http.NotFound(w, req)
	}
}

// rBucket: the backup bucket's PUTs, kept (down: refuses them)
type rBucket struct {
	mu   sync.Mutex
	puts []string
	objs map[string][]byte
	down bool
}

func (b *rBucket) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.down {
		w.WriteHeader(503)
		return
	}
	body, _ := io.ReadAll(req.Body)
	k := strings.TrimPrefix(req.URL.Path, "/bkt/")
	b.puts = append(b.puts, k)
	b.objs[k] = body
}

func restoreRouter(t *testing.T) (*Router, *restoreCore, *rBucket) {
	t.Helper()
	r := newTestRouter(t)
	fb := &rBucket{objs: map[string][]byte{}}
	bs := httptest.NewServer(fb)
	t.Cleanup(bs.Close)
	for k, v := range map[string]string{"BACKUP_READ_ACCESS_KEY": "a", "BACKUP_READ_SECRET_KEY": "b", "BACKUP_ENDPOINT": bs.URL, "BACKUP_BUCKET": "bkt"} {
		t.Setenv(k, v)
	}
	c := &restoreCore{key: newTestKey(), bucket: fb}
	cs := httptest.NewServer(c)
	t.Cleanup(cs.Close)
	r.k = &Kernel{URLs: map[string]string{"secrets": cs.URL}, HTTP: http.DefaultClient}
	return r, c, fb
}

const finishBody = `{"pending":"p1","signature":"sig","shares":{"A":{"e":"x","data":"y"}}}`

// the phone's approval: secrets' backups into the bucket first, then the commit; the machines whose grant names the
// store pull, and a restore request for the store leaves the Inbox
func TestARestoreWritesItsBackupsBeforeTheCommit(t *testing.T) {
	r, c, fb := restoreRouter(t)
	addSession(r, "sA", "started", "mA", false)
	holdStores(r, "sA", "store:default")
	if code, out := appDo(t, r, "POST", "/api/requests/restore", `{"store":"default","seq":2}`); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, out := appDo(t, r, "POST", "/api/stores/restore/finish", finishBody)
	if code != 200 || out["restored"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	if c.putsAtCommit != 2 || strings.Join(fb.puts, ",") != "keys/default/A.json,keys/default/Z.json" {
		t.Fatalf("puts %v (at commit %d)", fb.puts, c.putsAtCommit)
	}
	var a, z map[string]any
	json.Unmarshal(fb.objs["keys/default/A.json"], &a)
	json.Unmarshal(fb.objs["keys/default/Z.json"], &z)
	w := a["writer"].(map[string]any)
	if a["kind"] != "key-backup" || a["deleted"] != false || a["backupSha256"] != backupSha("BE", "BD") || w["by"] != "restore" || w["receipt"] == nil || a["secrets"] == nil {
		t.Fatalf("A: %v", a)
	}
	if z["deleted"] != true || z["sealed"] != nil {
		t.Fatalf("Z: %v", z)
	}
	if pulled, _ := out["pulled"].([]any); len(pulled) != 1 || pulled[0] != "sA" {
		t.Fatalf("pulled %v", out["pulled"])
	}
	for _, it := range r.Inbox() {
		if it.Kind == requestKindRestore {
			t.Fatalf("the restore request stayed: %+v", it)
		}
	}
}

func TestARestoreWithoutItsBackupsCommitsNothing(t *testing.T) {
	for name, set := range map[string]func(*restoreCore, *rBucket){
		"the bucket is down":                 func(_ *restoreCore, b *rBucket) { b.down = true },
		"a backup that isn't the receipt's":  func(c *restoreCore, _ *rBucket) { c.badBackup = true },
		"secrets refuses the phone's answer": func(c *restoreCore, _ *rBucket) { c.refuse = 403 },
	} {
		r, c, fb := restoreRouter(t)
		set(c, fb)
		if code, _ := appDo(t, r, "POST", "/api/stores/restore/finish", finishBody); code == 200 {
			t.Fatalf("%s: restored", name)
		}
		for _, p := range c.calls {
			if p == "/stores/restore/commit" {
				t.Fatalf("%s: committed", name)
			}
		}
		if c.refuse != 0 && len(fb.puts) != 0 {
			t.Fatalf("%s: backups written", name)
		}
	}
}

// who may ask for a restore: the web page, the app, the setup session — never a session, never in a batch
func TestWhoMayAskForARestore(t *testing.T) {
	r, _, _ := restoreRouter(t)
	addSession(r, "sA", "started", "mA", false)
	if code, out := appDo(t, r, "POST", "/setup/requests/restore", `{"store":"default","seq":2,"explanation":"put the keys back"}`); code != 200 {
		t.Fatalf("setup: %d %v", code, out)
	}
	if code, _ := appDo(t, r, "POST", "/api/requests/restore", `{"store":"default"}`); code != 400 {
		t.Fatal("a restore with no version was filed")
	}
	if code, _ := appDo(t, r, "POST", "/api/requests/restore", `{"store":"core","seq":1}`); code != 400 {
		t.Fatal("a restore of the reserved store was filed")
	}
	m := newTestMachine(r, "mA")
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/api/requests/restore", `{"store":"default","seq":2,"explanation":"x"}`); code == 200 {
		t.Fatal("a session filed a restore")
	}
	if code, _ := appDo(t, r, "POST", "/setup/requests/batch", `{"summary":"s","items":[{"intent":"restore","store":"default","seq":2}]}`); code == 200 {
		t.Fatal("a restore went into a batch")
	}
	var found bool
	for _, it := range r.Inbox() {
		if it.Kind == requestKindRestore {
			o := it.Open["options"].(map[string]any)
			found = it.Open["kind"] == "restore" && o["store"] == "default" && o["seq"] == 2 && it.Call.Args["seq"] == 2
		}
	}
	if !found {
		t.Fatal("the restore request isn't in the Inbox with its store and version")
	}
	if code, _ := appDo(t, r, "POST", "/setup/stores/versions", `{"store":"default","nonce":"n"}`); code != 200 {
		t.Fatal("setup versions")
	}
	if code, _ := appDo(t, r, "POST", "/api/secrets/stores/versions", `{"store":"default","nonce":"n"}`); code != 200 {
		t.Fatal("app versions")
	}
}
