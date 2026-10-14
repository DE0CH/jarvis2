package spawner

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

const url = "http://jarvis2-test._peer.internal:8081"

func newS(t *testing.T) (*Spawner, *FakeFly, *ktest.World) {
	t.Helper()
	w := ktest.New(t)
	f := NewFakeFly()
	sp, err := New(w.Keys["spawner"], w.Roster, f, url)
	if err != nil {
		t.Fatal(err)
	}
	return sp, f, w
}

// newSource: (sink, source) by the phone, notarized
func newSource(t *testing.T, w *ktest.World, image string) (kernel.NotarizedCert, kernel.Object) {
	t.Helper()
	src := ktest.Source(image, `{"harness":"claude","permissionMode":"auto"}`)
	return w.Notarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), src, ktest.P([]string{"store:claude"}))), src
}

// created(t)(sp.Spawn(…)): the created machine's id
func created(t *testing.T) func(kernel.SignedDoc, error) string {
	return func(d kernel.SignedDoc, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var c struct{ Machine string }
		json.Unmarshal([]byte(d.Payload), &c)
		return c.Machine
	}
}

func spawn(t *testing.T, sp *Spawner, w *ktest.World) (kernel.NotarizedCert, kernel.Succession, kernel.Object) {
	t.Helper()
	nc, src := newSource(t, w, ktest.Image)
	id := created(t)(sp.Spawn(nc, "lhr", "small"))
	d, err := sp.Init(id)
	if err != nil {
		t.Fatal(err)
	}
	s, err := kernel.OpenSuccession(w.Roster, d)
	if err != nil {
		t.Fatal(err)
	}
	return w.Notarize(t, d), s, src
}

func TestSpawnIsOneCreateThenInitSignsSourceToMachineTop(t *testing.T) {
	sp, f, w := newS(t)
	f.Booting = true
	nc, src := newSource(t, w, ktest.Image)
	id := created(t)(sp.Spawn(nc, "lhr", "medium"))
	if _, err := sp.Init(id); err == nil || err.(*kernel.Err).Status != 409 {
		t.Fatalf("init while booting: %v", err)
	}
	f.SetState(id, "started")
	d, err := sp.Init(id)
	if err != nil {
		t.Fatal(err)
	}
	s, err := kernel.OpenSuccession(w.Roster, d)
	if err != nil {
		t.Fatal(err)
	}
	fm := f.Machines[id]
	if s.Signer != "spawner" || s.Predecessor != src || s.Successor.ID != id ||
		s.Successor.EncryptionKey != kernel.B64.EncodeToString(fm.Enc.PublicKey().Bytes()) ||
		s.Successor.SigningKey != kernel.B64.EncodeToString(fm.Sig.PublicKey().Bytes()) {
		t.Fatalf("%+v", s)
	}
	if !s.Pair().Leq(kernel.Top()) || !kernel.Top().Leq(s.Pair()) {
		t.Fatal("the spawner's P is ⊤")
	}
	// the machine's env is the spawner's alone: its key, the kernel roster (the guard checks against it) and the router
	var roster kernel.Roster
	if len(fm.Env) != 3 || fm.Env[SpawnerKeyEnv] != w.Keys["spawner"].PublicKey() || fm.Env[RouterURLEnv] != url ||
		json.Unmarshal([]byte(fm.Env[RosterEnv]), &roster) != nil || roster != w.Roster {
		t.Fatalf("env %v", fm.Env)
	}
	// init happens once
	if _, err := sp.Init(id); err == nil {
		t.Fatal("init twice")
	}
}

// Forbidden: a spawn from anything but a source with a valid notarized cert, with a pinned image
func TestSpawnRefusals(t *testing.T) {
	sp, _, w := newS(t)
	src := ktest.Source(ktest.Image, "")
	notNotarized := w.Notarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), src, kernel.Top()))
	notNotarized.Notarization, _ = kernel.Sign(w.Keys["gullible"], kernel.Notarization{Kind: "notarization", Cert: notNotarized.Cert.ID(), Challenge: notNotarized.Challenge.ID()})
	m := ktest.NewMachine(t, "m1").Obj
	unpinned, _ := newSource(t, w, "ghcr.io/de0ch/jarvis2-session:latest")
	other, _ := newSource(t, w, "docker.io/evil/image@sha256:"+strings.Repeat("1", 64))
	noImage := w.Notarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), ktest.Source("", ""), kernel.Top()))
	for name, nc := range map[string]kernel.NotarizedCert{
		"no notarized cert":          {Cert: w.Cert(t, "phone", "phone", ktest.SinkObj(), src, kernel.Top())},
		"notarized by another key":   notNotarized,
		"a cert ending in a machine": w.Notarize(t, w.Cert(t, "identity", "identity", m, m, kernel.Top())),
		"a cert ending in the sink":  w.Notarize(t, w.Cert(t, "gullible", "gullible", src, ktest.SinkObj(), kernel.Top())),
		"an image not pinned":        unpinned,
		"an image of another repo":   other,
		"a source with no image":     noImage,
	} {
		if _, err := sp.Spawn(nc, "lhr", "small"); err == nil {
			t.Fatalf("%s: spawned", name)
		}
	}
	good, _ := newSource(t, w, ktest.Image)
	if _, err := sp.Spawn(good, "lhr", "huge"); err == nil {
		t.Fatal("a size not offered")
	}
	created(t)(sp.Spawn(good, "lhr", "small"))
	if _, err := sp.Spawn(good, "lhr", "small"); err == nil {
		t.Fatal("a source spawned twice")
	}
	// without MACHINE_URL nothing starts
	sp2, _ := New(w.Keys["spawner"], w.Roster, NewFakeFly(), "")
	g2, _ := newSource(t, w, ktest.Image)
	if _, err := sp2.Spawn(g2, "lhr", "small"); err == nil || err.(*kernel.Err).Status != 503 {
		t.Fatalf("spawned without MACHINE_URL: %v", err)
	}
}

// A machine running another digest than its source's is destroyed and never certified
func TestADigestMismatchDestroysTheMachine(t *testing.T) {
	sp, f, w := newS(t)
	f.SwapDigest = "sha256:" + strings.Repeat("2", 64)
	nc, _ := newSource(t, w, ktest.Image)
	id := created(t)(sp.Spawn(nc, "lhr", "small"))
	if _, err := sp.Init(id); err == nil {
		t.Fatal("certified a machine on another digest")
	}
	if f.Machines[id].State != "destroyed" {
		t.Fatal("not destroyed")
	}
}

func snapClaim(t *testing.T, f *FakeFly, id, sum string) *SnapshotClaim {
	t.Helper()
	k := f.Machines[id].Sig
	priv, err := ecdsa.ParseRawPrivateKey(ellipticP256(), k.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(sum))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, h[:])
	return &SnapshotClaim{Sha256: sum, Sig: kernel.B64.EncodeToString(sig)}
}

func TestKillSignsMachineToAFreshSourceWithTheSnapshot(t *testing.T) {
	sp, f, w := newS(t)
	nc, s, src := spawn(t, sp, w)
	id := s.Successor.ID
	sum := strings.Repeat("ab", 32)
	d, err := sp.Kill(nc, snapClaim(t, f, id, sum))
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.OpenSuccession(w.Roster, d)
	if err != nil {
		t.Fatal(err)
	}
	y := k.Successor
	if k.Signer != "spawner" || k.Predecessor != s.Successor || y.Kind() != kernel.KindSource || y.ID == src.ID ||
		y.Image != src.Image || y.Settings != src.Settings || y.Snapshot != sum || !kernel.Top().Leq(k.Pair()) {
		t.Fatalf("%+v", k)
	}
	if f.Machines[id].State != "destroyed" {
		t.Fatal("not destroyed")
	}
	// asked again: the same cert
	again, err := sp.Kill(nc, nil)
	if err != nil || again != d {
		t.Fatalf("second kill: %v", err)
	}
	// and the kill's source spawns again (a resume)
	resume := w.Notarize(t, d)
	id2 := created(t)(sp.Spawn(resume, "lhr", "small"))
	d2, err := sp.Init(id2)
	if err != nil {
		t.Fatal(err)
	}
	if s2, _ := kernel.OpenSuccession(w.Roster, d2); s2.Predecessor != y {
		t.Fatal("the resume starts from the kill's source")
	}
}

// A slow destroy: 409 until Fly confirms, then the cert; the snapshot is the first call's
func TestKillWaitsForFlysConfirmation(t *testing.T) {
	sp, f, w := newS(t)
	f.SlowKill = true
	nc, s, _ := spawn(t, sp, w)
	id := s.Successor.ID
	sum := strings.Repeat("cd", 32)
	if _, err := sp.Kill(nc, snapClaim(t, f, id, sum)); err == nil || err.(*kernel.Err).Status != 409 {
		t.Fatalf("killed before Fly confirmed: %v", err)
	}
	f.SlowKill = false
	f.SetState(id, "destroying")
	d, err := sp.Kill(nc, nil)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := kernel.OpenSuccession(w.Roster, d)
	if k.Successor.Snapshot != sum {
		t.Fatal("the snapshot of the first call")
	}
}

// Forbidden: killing from anything but the machine's spawn cert, a machine not alive, a snapshot not the machine's
func TestKillRefusals(t *testing.T) {
	sp, f, w := newS(t)
	nc, s, _ := spawn(t, sp, w)
	m := s.Successor
	phoneCert := w.Notarize(t, w.Cert(t, "phone", "phone", ktest.Source("", ""), m, kernel.Top()))
	idCert := w.Notarize(t, w.Cert(t, "identity", "identity", m, m, kernel.Top()))
	unNotarized := nc
	unNotarized.Notarization = kernel.SignedDoc{}
	for name, c := range map[string]kernel.NotarizedCert{
		"the phone's (source, M)": phoneCert,
		"M's identity edge":       idCert,
		"not notarized":           unNotarized,
	} {
		if _, err := sp.Kill(c, nil); err == nil {
			t.Fatalf("%s: killed", name)
		}
	}
	// a snapshot signed by another key
	other := ktest.NewMachine(t, "x")
	h := strings.Repeat("ef", 32)
	sig, _ := other.SigKey.Sign([]byte(h))
	if _, err := sp.Kill(nc, &SnapshotClaim{Sha256: h, Sig: sig}); err == nil {
		t.Fatal("a snapshot signed by another key")
	}
	if f.Machines[m.ID].State != "started" {
		t.Fatal("a refused kill touched the machine")
	}
	// a machine that is not alive (crashed, destroyed outside the spawner)
	nc2, s2, _ := spawn(t, sp, w)
	f.SetState(s2.Successor.ID, "destroyed")
	if _, err := sp.Kill(nc2, nil); err == nil {
		t.Fatal("killed a machine that wasn't alive")
	}
}

func TestTheFlyTokenArrivesSealed(t *testing.T) {
	sp, f, _ := newS(t)
	s, _ := kernel.SealTo(sp.AgreementKey(), []byte(`{"FLY_API_TOKEN":"fly-secret"}`), infoFlyToken)
	if _, err := sp.SetFlyToken(s); err != nil || f.Token != "fly-secret" {
		t.Fatalf("%v %q", err, f.Token)
	}
	bad, _ := kernel.SealTo(sp.AgreementKey(), []byte(`{"FLY_API_TOKEN":"x"}`), "jarvis2/other")
	if _, err := sp.SetFlyToken(bad); err == nil {
		t.Fatal("a token sealed under another info")
	}
	empty, _ := kernel.SealTo(sp.AgreementKey(), []byte(`{}`), infoFlyToken)
	if _, err := sp.SetFlyToken(empty); err == nil {
		t.Fatal("no token")
	}
}
