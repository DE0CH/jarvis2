package main

// The guard against the real kernel parts (core/kernel: the mover, the merger, the identity signer), so the formats
// the guard reads are the ones the kernel writes: a new session's grant moved out of root's ⊤ on the sink, and a
// terminal added to the running machine (identity edge + merge) and taken away again after its until.

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

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/identitysigner"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
	"github.com/DE0CH/jarvis2/core/kernel/merger"
	"github.com/DE0CH/jarvis2/core/kernel/mover"
)

func TestGrantsTheKernelMakes(t *testing.T) {
	x := newWorld(t)
	mv := mover.New(x.w.Keys["mover"], x.w.Roster)
	mg := merger.New(x.w.Keys["merger"], x.w.Roster)
	id := identitysigner.New(x.w.Keys["identity"])
	move := func(g kernel.SignedDoc, c kernel.NotarizedCert) kernel.SignedDoc {
		t.Helper()
		out, err := mv.Move(g, c)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// new session: the phone signs (sink, source, P), the spawner (source, M, ⊤); root's ⊤ moves along both
	chain, src := x.chainFor(settingsJSON, "")
	p := kernel.Pair{Allowed: kernel.Only("store:default"), Conditions: kernel.CanonConditions("session:s1")}
	origin := x.w.Notarize(t, x.w.Cert(t, "phone", "phone", ktest.SinkObj(), src, p))
	chain.Source = origin
	onSource := move(x.w.RootGrant(t), origin)
	if err := x.g.acceptGrant(onSource); err == nil {
		t.Fatal("took a grant on the source (it names no machine)")
	}
	main := move(onSource, chain.Spawn)
	if err := x.g.acceptGrant(main); err != nil {
		t.Fatal(err)
	}
	if _, err := x.g.authoriseShell(sha("id")); err == nil {
		t.Fatal("the main grant has no shell")
	}
	// adding a terminal until T: the phone signs (sink, source-x, P_add) and (source-x, M, ⊤); the main grant moves
	// along M's identity edge to the same conditions; the merger joins them
	until := "until:2026-10-14T12:10:00Z"
	add := ktest.Source("", "")
	addCert := x.w.Notarize(t, x.w.Cert(t, "phone", "phone", ktest.SinkObj(), add, kernel.Pair{Allowed: kernel.Only("shell"), Conditions: kernel.CanonConditions("session:s1", until)}))
	toM := x.w.Notarize(t, x.w.Cert(t, "phone", "phone", add, x.me, kernel.Top()))
	terminal := move(move(x.w.RootGrant(t), addCert), toM)
	ident, err := id.Sign(x.me, kernel.Pair{Allowed: kernel.Everything(), Conditions: kernel.CanonConditions(until)})
	if err != nil {
		t.Fatal(err)
	}
	narrowed := move(main, x.w.Notarize(t, ident))
	merged, err := mg.Merge(narrowed, terminal)
	if err != nil {
		t.Fatal(err)
	}
	// the terminal alone (with the router choosing it) and the merged grant both hold shell until T
	for _, g := range []kernel.SignedDoc{terminal, merged} {
		if err := x.g.acceptGrant(g); err != nil {
			t.Fatal(err)
		}
		if _, err := x.g.authoriseShell(sha("id")); err != nil {
			t.Fatal(err)
		}
	}
	// after T: the merged grant holds nothing; the router hands the main grant back, which never had shell
	x.clock = x.clock.Add(11 * time.Minute)
	if _, err := x.g.authoriseShell(sha("id")); err == nil {
		t.Fatal("shell after the terminal's until")
	}
	if err := x.g.acceptGrant(merged); err == nil {
		t.Fatal("took the merged grant after its until")
	}
	if err := x.g.acceptGrant(main); err != nil {
		t.Fatal(err)
	}
	if _, err := x.g.authoriseShell(sha("id")); err == nil {
		t.Fatal("the main grant gained shell")
	}
}

// the machine signs one snapshot in its life, after stopping the session, and answers every later snapshot command
// with that one: a router that kept an earlier snapshot has none to roll a successor back to
func TestTheMachineSignsOneFinalSnapshot(t *testing.T) {
	useRunDir(t)
	home, _ := os.UserHomeDir()
	key := newKey()
	oldK, oldZ := snapshotKey, freezeSession
	defer func() { snapshotKey, freezeSession = oldK, oldZ }()
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
	os.WriteFile(filepath.Join(home, "workspace", "a"), []byte("two"), 0o644)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != got[1] || froze != 1 {
		t.Fatalf("a second, different snapshot was signed: %v (froze %d)", got, froze)
	}
	sum, sig, _ := finalSnapshotSum()
	if !kernel.Verify(b64.EncodeToString(key.k.PublicKey().Bytes()), []byte(sum), sig) {
		t.Fatal("the snapshot claim isn't the machine's signature over its sha256 (what the spawner's kill checks)")
	}
	if err := notFrozen(); err == nil {
		t.Fatal("a stopped session takes input")
	}
}

// put-key seals only to keys secrets signed: the router can't hand the machine a key of its own
func TestPutKeySealsOnlyToSecretsKeys(t *testing.T) {
	x := newWorld(t)
	phone, agreement := newKey(), newKey()
	storeKey := addPoints(phone.pub(), agreement.pub())
	if storeKey == "" {
		t.Fatal("no point sum")
	}
	sign := func(role string, v any) kernel.SignedDoc {
		d, _ := kernel.Sign(x.w.Keys[role], v)
		return d
	}
	state := sign("secrets", map[string]any{"kind": "secrets-state", "master": newKey().pub(), "bundle": "keys",
		"phone": map[string]string{"signingKey": newKey().pub(), "agreementKey": phone.pub()}})
	sk := sign("secrets", map[string]any{"kind": "store-key", "phone": phone.pub(), "storeKey": storeKey})
	tg, err := checkSealTargets(x.w.Roster, state, sk, agreement.pub())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkSealTargets(x.w.Roster, state, sk, newKey().pub()); err == nil {
		t.Fatal("sealed live to an agreement key that isn't secrets'")
	}
	if _, err := checkSealTargets(x.w.Roster, sign("notary", map[string]any{"kind": "secrets-state", "master": "m", "phone": map[string]string{"agreementKey": phone.pub()}}), sk, agreement.pub()); err == nil {
		t.Fatal("took a state not signed by secrets")
	}
	if _, err := checkSealTargets(x.w.Roster, state, sign("secrets", map[string]any{"kind": "store-key", "phone": newKey().pub(), "storeKey": storeKey}), agreement.pub()); err == nil {
		t.Fatal("took a store key for another phone")
	}
	req, err := keyWriteRequest(tg, "default", "API_KEY", []byte("v"), false, "for x")
	if err != nil {
		t.Fatal(err)
	}
	live := req["live"].(kernel.Sealed)
	if v, err := kernel.OpenSealed(agreement.k, live, "jarvis2/live-key\ndefault\nAPI_KEY"); err != nil || string(v) != "v" {
		t.Fatalf("live: %q %v", v, err)
	}
	if !strings.HasPrefix(req["writerText"].(string), "jarvis2-store-key\ndefault\nAPI_KEY\n") {
		t.Fatal(req["writerText"])
	}
}
