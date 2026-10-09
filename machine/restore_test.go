package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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

func TestRestoreArchivedOnlyWhenAsked(t *testing.T) {
	t.Setenv("JARVIS2_RESTORE_CERT", "")
	if err := restoreArchived(nil, "", "me", &Cert{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JARVIS2_RESTORE_CERT", "{}")
	if err := restoreArchived(nil, "", "me", &Cert{PredID: "pred"}); err != nil {
		t.Fatal("a successor acted on a restore cert")
	}
}
