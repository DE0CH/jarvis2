package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// snapTestState: the snapshot globals of one test, put back afterwards
func snapTestState(t *testing.T, key tkey) func() {
	run := t.TempDir()
	oldF, oldS, oldK, oldZ, oldT, oldC := finalSnapshot, finalSnapshotSig, snapshotKey, freezeSession, thawSession, carriedRun
	finalSnapshot, finalSnapshotSig, carriedRun = filepath.Join(run, "f.tar.gz"), filepath.Join(run, "f.sig"), filepath.Join(run, "carried")
	snapshotKey = func() (*ecdh.PrivateKey, error) { return key.k, nil }
	freezeSession, thawSession = func() {}, func() {}
	signedSum, signedSig, committed = "", "", false
	return func() {
		finalSnapshot, finalSnapshotSig, snapshotKey, freezeSession, thawSession, carriedRun = oldF, oldS, oldK, oldZ, oldT, oldC
		signedSum, signedSig, committed = "", "", false
		frozen.Store(false)
	}
}

// snapRouter: the router's side of router/snapstream.go, checking the machine's signatures
type snapRouter struct {
	srv        *httptest.Server
	mu         sync.Mutex
	pending    string
	commits    []string
	failed     []string
	carried    []string
	noStream   bool
	streamFail bool
	failCommit bool
	streamed   int
	legacy     int
}

func newSnapRouter(t *testing.T, key tkey) *snapRouter {
	fr := &snapRouter{}
	fr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fr.mu.Lock()
		defer fr.mu.Unlock()
		tm := req.Header.Get("X-Time")
		switch req.URL.Path {
		case "/m/snapshot-stream":
			if fr.noStream {
				w.WriteHeader(404)
				return
			}
			if fr.streamFail {
				io.Copy(io.Discard, req.Body)
				w.WriteHeader(507)
				return
			}
			if !verify(key.pub(), []byte("POST /m/snapshot-stream "+tm+" stream"), req.Header.Get("X-Sig")) {
				w.WriteHeader(401)
				return
			}
			h := sha256.New()
			n, _ := io.Copy(h, req.Body)
			fr.pending, fr.streamed = hex.EncodeToString(h.Sum(nil)), fr.streamed+1
			json.NewEncoder(w).Encode(map[string]any{"sha256": fr.pending, "bytes": n})
		case "/m/snapshot-commit", "/m/snapshot-carry", "/m/snapshot-failed":
			b, _ := io.ReadAll(req.Body)
			sum := sha256.Sum256(b)
			if !verify(key.pub(), []byte("POST "+req.URL.Path+" "+tm+" "+hex.EncodeToString(sum[:])), req.Header.Get("X-Sig")) {
				w.WriteHeader(401)
				return
			}
			var in map[string]string
			json.Unmarshal(b, &in)
			switch req.URL.Path {
			case "/m/snapshot-failed":
				fr.failed = append(fr.failed, in["error"])
			case "/m/snapshot-carry":
				if !verify(key.pub(), []byte(in["sha256"]), in["sig"]) {
					w.WriteHeader(403)
					return
				}
				fr.carried = append(fr.carried, in["sha256"])
			default:
				if fr.failCommit {
					fr.failCommit = false
					w.WriteHeader(500)
					return
				}
				if !verify(key.pub(), []byte(in["sha256"]), in["sig"]) || (in["sha256"] != fr.pending && len(fr.commits) == 0) {
					w.WriteHeader(409)
					return
				}
				fr.commits = append(fr.commits, in["sha256"]+" "+in["sig"])
			}
			w.Write([]byte(`{"ok":true}`))
		case "/m/snapshot":
			io.Copy(io.Discard, req.Body)
			fr.legacy++
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	return fr
}

// the final snapshot needs no free disk: it streams into the request, and nothing but the tiny signature lands on
// the machine's disk (2026-10-15: "no space left on device" lost a session)
func TestTheFinalSnapshotStreamsWithoutALocalCopy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	defer snapTestState(t, key)()
	fr := newSnapRouter(t, key)
	defer fr.srv.Close()
	c := &client{base: fr.srv.URL, me: "m1", sig: key.k, http: fr.srv.Client()}
	os.MkdirAll(filepath.Join(home, "workspace"), 0o755)
	os.WriteFile(filepath.Join(home, "workspace", "big"), []byte(strings.Repeat("x", 1<<20)), 0o644)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(finalSnapshot); err == nil {
		t.Fatal("a local copy of the snapshot was written")
	}
	if fr.streamed != 1 || len(fr.commits) != 1 || !strings.HasPrefix(fr.commits[0], fr.pending+" ") || fr.legacy != 0 {
		t.Fatalf("streamed %d, commits %v", fr.streamed, fr.commits)
	}
	// a commit that didn't reach the router: the frozen files are streamed again and committed under the same signature
	signedSum, signedSig, committed = "", "", false
	os.Remove(finalSnapshotSig)
	os.Remove(finalSnapshotSig + ".sha256")
	fr.failCommit = true
	if err := uploadSnapshot(c); err == nil {
		t.Fatal("a failed commit went unnoticed")
	}
	first := signedSig
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if signedSig != first || fr.streamed != 3 {
		t.Fatalf("signed again (%v) or not streamed again (%d)", signedSig != first, fr.streamed)
	}
	// files that changed after the signature: no second signature, the snapshot fails
	signedMu.Lock()
	committed = false
	signedMu.Unlock()
	os.WriteFile(filepath.Join(home, "workspace", "big"), []byte("changed"), 0o644)
	if err := uploadSnapshot(c); err == nil || !strings.Contains(err.Error(), "no second") {
		t.Fatalf("a second snapshot: %v", err)
	}
}

// a router from before streaming gets the old whole-file upload
func TestAnOlderRouterGetsTheFileUpload(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	defer snapTestState(t, key)()
	fr := newSnapRouter(t, key)
	fr.noStream = true
	defer fr.srv.Close()
	c := &client{base: fr.srv.URL, me: "m1", sig: key.k, http: fr.srv.Client()}
	os.MkdirAll(filepath.Join(home, "workspace"), 0o755)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if fr.legacy != 1 {
		t.Fatal("no whole-file upload")
	}
}

// a snapshot that can't be taken is reported at once, and with nothing signed the session goes on
func TestAFailedSnapshotIsReportedAndThawed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	defer snapTestState(t, key)()
	thawed := 0
	thawSession = func() { thawed++ }
	fr := newSnapRouter(t, key)
	defer fr.srv.Close()
	fr.streamFail = true
	c := &client{base: fr.srv.URL, me: "m1", sig: key.k, http: fr.srv.Client()}
	err := uploadSnapshot(c)
	if err == nil {
		t.Fatal("no error from a router that refuses the stream")
	}
	if frozen.Load() || thawed != 1 || signedSum != "" {
		t.Fatalf("frozen %v, thawed %d, signed %q", frozen.Load(), thawed, signedSum)
	}
	reportSnapshotFailed(c, err)
	if len(fr.failed) != 1 {
		t.Fatal("not reported")
	}
}

// asked while booting, a successor's state is its predecessor's snapshot: it carries that one over (signed once) and
// the boot stops; the line's first machine still has nothing to snapshot
func TestABootingMachineCarriesItsPredecessorsSnapshot(t *testing.T) {
	key, core := newKey(), newKey()
	defer snapTestState(t, key)()
	oldCert := certFile
	defer func() { certFile = oldCert }()
	certFile = filepath.Join(t.TempDir(), "cert.json")
	fr := newSnapRouter(t, key)
	defer fr.srv.Close()
	c := &client{base: fr.srv.URL, me: "m2", sig: key.k, http: fr.srv.Client()}
	sum := strings.Repeat("cd", 32)
	doc := core.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m1", "snapshot": sum, "machine": map[string]string{"id": "m2"}})
	raw, _ := json.Marshal(doc)
	os.WriteFile(certFile, raw, 0o644)
	if err := bootingSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if len(fr.carried) != 1 || fr.carried[0] != sum || signedSum != sum {
		t.Fatalf("carried %v, signed %q", fr.carried, signedSum)
	}
	if _, err := os.Stat(carriedRun); err != nil {
		t.Fatal("the boot would go on")
	}
}
