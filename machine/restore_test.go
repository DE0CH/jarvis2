package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckRestoreCert(t *testing.T) {
	core, other := newKey(), newKey()
	old := Cert{Kind: "succession-cert", Machine: &Machine{ID: "old", SigningKey: other.pub()}, Line: "old"}
	plain := &Cert{Sensitive: false}
	if _, err := checkRestoreCert(core.pub(), "new", plain, core.doc(old)); err != nil {
		t.Fatal(err)
	}
	if _, err := checkRestoreCert(core.pub(), "new", plain, other.doc(old)); err == nil {
		t.Fatal("accepted a cert the core didn't sign")
	}
	if _, err := checkRestoreCert(core.pub(), "old", plain, core.doc(old)); err == nil {
		t.Fatal("accepted a cert naming this machine")
	}
	notCert := old
	notCert.Kind = "burn-cert"
	if _, err := checkRestoreCert(core.pub(), "new", plain, core.doc(notCert)); err == nil {
		t.Fatal("accepted another kind of document")
	}
	sens := old
	sens.Sensitive = true
	if _, err := checkRestoreCert(core.pub(), "new", plain, core.doc(sens)); err == nil {
		t.Fatal("a sensitive line's snapshot went into a line without one")
	}
	if _, err := checkRestoreCert(core.pub(), "new", &Cert{Sensitive: true}, core.doc(sens)); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotSigAndUnpack(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	m := newKey()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "artifacts/x.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("hi"))
	tw.Close()
	gz.Close()
	body := buf.Bytes()
	sum := sha256.Sum256(body)
	sig, _ := sign(m.k, []byte(hex.EncodeToString(sum[:])))
	if err := checkSnapshotSig(m.pub(), body, sig); err != nil {
		t.Fatal(err)
	}
	if err := checkSnapshotSig(newKey().pub(), body, sig); err == nil {
		t.Fatal("another key's signature passed")
	}
	if n, err := unpack(body); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	home, _ := os.UserHomeDir()
	if b, _ := os.ReadFile(filepath.Join(home, "artifacts/x.txt")); string(b) != "hi" {
		t.Fatal(string(b))
	}
	// a bad path is refused
	buf.Reset()
	gz = gzip.NewWriter(&buf)
	tw = tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "../evil", Mode: 0o644, Typeflag: tar.TypeReg})
	tw.Close()
	gz.Close()
	if _, err := unpack(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "bad path") {
		t.Fatal(err)
	}
}

func TestRestoreArchivedOnlyWhenTheCertNamesIt(t *testing.T) {
	t.Setenv("JARVIS2_RESTORE_CERT", "{}") // the env asking: ignored
	if err := restoreArchived(nil, "", "me", &Cert{}, Vouched{}); err != nil {
		t.Fatal(err)
	}
	if err := restoreArchived(nil, "", "me", &Cert{}, Vouched{}); err != nil {
		t.Fatal("restored with no restore in the cert")
	}
	ref := &RestoreRef{Machine: "old", Sha256: strings.Repeat("a", 64)}
	if err := restoreArchived(nil, "", "me", &Cert{PredID: "pred"}, Vouched{Config: SessionConfig{Restore: ref}}); err != nil {
		t.Fatal("a successor acted on a restore")
	}
}

// The harnesses' own state (Paseo pairings, OpenCode sessions, the OpenClaw gateway's state) travels in the
// snapshot, so the OpenCode/OpenClaw apps stay paired across a pause; their logs, pid files and caches don't.
func TestSnapshotCarriesHarnessState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	files := map[string]bool{ // path → kept
		".paseo/config.json": true, ".paseo/agents/a.json": true, ".claude/.paseo-agent": true,
		".local/share/opencode/storage/session/s.json": true, ".openclaw/openclaw.json": true,
		".openclaw/jarvis-remote.json": true, ".openclaw/devices/paired.json": true, "workspace/w.txt": true,
		".paseo/models/big.bin": false, ".paseo/runtime/x": false, ".paseo/paseo.pid": false, ".paseo/daemon.out": false,
		".paseo/a.log": false, ".local/share/opencode/log/x.log": false, ".local/share/opencode/bin/rg": false,
		".openclaw/logs/l": false, ".openclaw/tmp/t": false, ".openclaw/gateway.out": false, ".openclaw/gateway.pid": false,
		".openclaw/.hold": false, ".config/other/x": false,
	}
	for p := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(home, p)), 0o755)
		os.WriteFile(filepath.Join(home, p), []byte(p), 0o600)
	}
	snap := filepath.Join(t.TempDir(), "s.tar.gz")
	if _, _, err := makeSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	next := t.TempDir()
	t.Setenv("HOME", next)
	if _, err := unpackFile(snap); err != nil {
		t.Fatal(err)
	}
	for p, kept := range files {
		b, err := os.ReadFile(filepath.Join(next, p))
		if kept && string(b) != p {
			t.Errorf("%s not restored (%v)", p, err)
		}
		if !kept && err == nil {
			t.Errorf("%s travelled in the snapshot", p)
		}
	}
}

// an archive from an earlier core restores through the master key's claim of that core (core continuity)
func TestARestoreFromAnEarlierCoreGoesThroughTheMastersClaim(t *testing.T) {
	now, earlier, master, other := newKey(), newKey(), newKey(), newKey()
	old := Cert{Kind: "succession-cert", Machine: &Machine{ID: "old", SigningKey: newKey().pub()}, Line: "old"}
	certDoc := earlier.doc(old)
	state := now.doc(map[string]string{"kind": "core-state", "master": master.pub()})
	claim := func(k tkey, v map[string]any) *struct {
		Statement string `json:"statement"`
		MasterSig string `json:"masterSig"`
	} {
		b, _ := json.Marshal(v)
		s, _ := sign(k.k, b)
		return &struct {
			Statement string `json:"statement"`
			MasterSig string `json:"masterSig"`
		}{string(b), s}
	}
	rc := restoreCertDocs{Cert: certDoc, CoreState: state,
		CoreCert: claim(master, map[string]any{"kind": "claim", "master": master.pub(), "core": map[string]string{"signingKey": earlier.pub()}})}
	if k, err := restoreSigner(now.pub(), rc); err != nil || k != earlier.pub() {
		t.Fatalf("%q %v", k, err)
	}
	// a seeded claim names the derived key as its identity
	rc.CoreCert = claim(master, map[string]any{"kind": "claim", "master": master.pub(), "core": map[string]string{"signingKey": other.pub()},
		"identity": map[string]string{"signingKey": earlier.pub()}})
	if k, err := restoreSigner(now.pub(), rc); err != nil || k != earlier.pub() {
		t.Fatalf("identity: %q %v", k, err)
	}
	// a claim another key signed, a state another core signed, a claim naming another core: refused
	rc.CoreCert = claim(other, map[string]any{"kind": "claim", "master": master.pub(), "core": map[string]string{"signingKey": earlier.pub()}})
	if _, err := restoreSigner(now.pub(), rc); err == nil {
		t.Fatal("a claim the master didn't sign")
	}
	rc.CoreCert = claim(master, map[string]any{"kind": "claim", "master": master.pub(), "core": map[string]string{"signingKey": earlier.pub()}})
	rc.CoreState = other.doc(map[string]string{"kind": "core-state", "master": master.pub()})
	if _, err := restoreSigner(now.pub(), rc); err == nil {
		t.Fatal("a state this machine's core didn't sign")
	}
	rc.CoreState = state
	rc.CoreCert = claim(master, map[string]any{"kind": "claim", "master": master.pub(), "core": map[string]string{"signingKey": other.pub()}})
	if _, err := restoreSigner(now.pub(), rc); err == nil {
		t.Fatal("a claim of another core")
	}
	// the running core's own cert needs nothing else
	rc.Cert = now.doc(old)
	if k, err := restoreSigner(now.pub(), restoreCertDocs{Cert: rc.Cert}); err != nil || k != now.pub() {
		t.Fatal(err)
	}
}
