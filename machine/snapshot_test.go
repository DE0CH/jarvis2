package main

// The final snapshot streams to the router and needs no disk (2026-10-15: a session whose work filled its root disk
// lost everything when the snapshot couldn't be written to /run/jarvis2 first).

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
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

// snapRouter: the router's two snapshot steps, as router/http.go does them (stream → hash; commit → kept)
type snapRouter struct {
	mu        sync.Mutex
	pending   map[string][]byte // sha256 → bytes streamed
	commits   []string          // "sha256 sig" per commit
	streams   int
	failed    []string
	failNext  int // HTTP status for the next stream (0 = fine)
	headers   []http.Header
	lastBytes []byte
}

func newSnapRouter() *snapRouter { return &snapRouter{pending: map[string][]byte{}} }

func (f *snapRouter) forget() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = map[string][]byte{}
}

func (f *snapRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, r.Header.Clone())
	switch r.URL.Path {
	case "/m/snapshot/stream":
		if r.ContentLength > 0 {
			http.Error(w, "a stream has no Content-Length", 400)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if f.failNext != 0 {
			w.WriteHeader(f.failNext)
			f.failNext = 0
			return
		}
		f.streams++
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		f.pending[h], f.lastBytes = b, b
		json.NewEncoder(w).Encode(map[string]any{"sha256": h, "size": len(b)})
	case "/m/snapshot/commit":
		var in struct{ Sha256, Sig string }
		json.NewDecoder(r.Body).Decode(&in)
		if f.pending[in.Sha256] == nil {
			w.WriteHeader(404)
			return
		}
		f.commits = append(f.commits, in.Sha256+" "+in.Sig)
	case "/m/snapshot/failed":
		b, _ := io.ReadAll(r.Body)
		f.failed = append(f.failed, string(b))
	case "/m/snapshot":
		io.Copy(io.Discard, r.Body)
	default:
		w.WriteHeader(404)
	}
}

func snapRig(t *testing.T) (home, run string, key tkey, fr *snapRouter, c *client) {
	home, run = t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	key = newKey()
	oldS, oldK, oldZ, oldR := finalSnapshotSig, snapshotKey, freezeSession, restoredSnapshot
	t.Cleanup(func() {
		finalSnapshotSig, snapshotKey, freezeSession, restoredSnapshot = oldS, oldK, oldZ, oldR
		frozen.Store(false)
	})
	finalSnapshotSig, restoredSnapshot = filepath.Join(run, "f.sig"), filepath.Join(run, "restored")
	snapshotKey = func() (*ecdh.PrivateKey, error) { return key.k, nil }
	freezeSession = func() {}
	fr = newSnapRouter()
	srv := httptest.NewServer(fr)
	t.Cleanup(srv.Close)
	c = &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	return
}

func TestTheFinalSnapshotNeedsNoDisk(t *testing.T) {
	home, run, key, fr, c := snapRig(t)
	os.MkdirAll(filepath.Join(home, "workspace"), 0o755)
	big := make([]byte, 4<<20)
	rand.Read(big) // incompressible: the snapshot is at least this big
	os.WriteFile(filepath.Join(home, "workspace", "big"), big, 0o644)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	// nothing on the machine but the hash and the signature
	var total int64
	filepath.Walk(run, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	if total > 1024 {
		t.Fatalf("the snapshot left %d bytes on the machine's disk", total)
	}
	if len(fr.lastBytes) < len(big) || len(fr.commits) != 1 {
		t.Fatalf("streamed %d bytes, %d commits", len(fr.lastBytes), len(fr.commits))
	}
	// the commit carries the machine's signature over the hash of exactly the bytes the router received
	sum := sha256.Sum256(fr.lastBytes)
	parts := strings.Fields(fr.commits[0])
	if parts[0] != hex.EncodeToString(sum[:]) || !verify(key.pub(), []byte(parts[0]), parts[1]) {
		t.Fatalf("the commit doesn't sign the streamed bytes: %v", parts)
	}
	// and the stream's request signature names "stream", not a hash nobody knew yet
	h := fr.headers[0]
	msg := "POST /m/snapshot/stream " + h.Get("X-Time") + " " + streamedBody
	if !verify(key.pub(), []byte(msg), h.Get("X-Sig")) {
		t.Fatal("the stream request isn't signed over \"stream\"")
	}
	// the bytes unpack to the files
	t.Setenv("HOME", t.TempDir())
	if _, err := unpackReader(bytes.NewReader(fr.lastBytes)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), "workspace", "big"))
	if !bytes.Equal(got, big) {
		t.Fatal("the streamed snapshot doesn't hold the workspace")
	}
}

func TestTheSameFrozenFilesGiveTheSameSnapshot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, "workspace", "d"), 0o755)
	os.WriteFile(filepath.Join(home, "workspace", "d", "f"), []byte("x"), 0o644)
	os.Symlink("d/f", filepath.Join(home, "workspace", "l"))
	a, _, err := makeSnapshotTo(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := makeSnapshotTo(io.Discard) // reading changed the access times
	if a != b {
		t.Fatalf("two snapshots of the same files differ: %s %s", a, b)
	}
}

// a snapshot the router can't take is reported with its reason, so the router keeps the machine and says why
func TestAFailedSnapshotIsReported(t *testing.T) {
	_, _, _, fr, c := snapRig(t)
	fr.failNext = 507
	err := uploadSnapshot(c)
	if err == nil || !strings.Contains(err.Error(), "507") {
		t.Fatalf("err = %v", err)
	}
	snapshotFailed(c, err)
	if len(fr.failed) != 1 || !strings.Contains(fr.failed[0], "507") {
		t.Fatalf("reported %v", fr.failed)
	}
	// nothing was signed: the next command takes it again and commits it
	if err := uploadSnapshot(c); err != nil || len(fr.commits) != 1 {
		t.Fatalf("retry: %v %v", err, fr.commits)
	}
}

// a machine still booting that restored its predecessor's snapshot answers with that snapshot, signed by itself
func TestABootingMachineAnswersWithTheSnapshotItRestored(t *testing.T) {
	_, _, key, fr, c := snapRig(t)
	if err := noSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if h := fr.headers[0]; h.Get("X-Snapshot-None") == "" || h.Get("X-Snapshot-Same") != "" {
		t.Fatalf("no restore yet: %v", h)
	}
	sum := strings.Repeat("ab", 32)
	os.WriteFile(restoredSnapshot, []byte(sum), 0o600)
	if err := noSnapshot(c); err != nil {
		t.Fatal(err)
	}
	h := fr.headers[1]
	if h.Get("X-Snapshot-Same") != sum || !verify(key.pub(), []byte(sum), h.Get("X-Snapshot-Sig")) {
		t.Fatalf("headers %v", h)
	}
}
