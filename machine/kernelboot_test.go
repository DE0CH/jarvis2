package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis2/kernel/gv"
	"github.com/DE0CH/jarvis2/kernel/kerneltest"
	"github.com/DE0CH/jarvis2/kernel/sig"
)

const kImage = "ghcr.io/de0ch/jarvis2-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111"

func bootDocs(t *testing.T, k *kerneltest.Kernel) (kernelBootDocs, *kerneltest.FakeMachine) {
	settings := json.RawMessage(`{"v":1,"harness":"claude","permissionMode":"auto","config":{"v":1,"label":"x","model":"claude-opus-5-5"}}`)
	m, fm := k.Line(t, "s1", kImage, settings, "default", "tunnel")
	raw, _ := json.Marshal(m)
	var b kernelBootDocs
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return b, fm
}

func fmKeys(fm *kerneltest.FakeMachine) map[string]string {
	return map[string]string{"signingKey": fm.Sig.PublicKey(), "encryptionKey": sig.B64.EncodeToString(fm.Enc.PublicKey().Bytes())}
}

// the documents a kernel machine boots from check, and give the settings, stores and session the source names
func TestAKernelMachineReadsItsDocuments(t *testing.T) {
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	b, fm := bootDocs(t, k)
	cert, trust, err := checkKernelBoot(b, k.Box.PublicKey(), fm.Env["JARVIS2_SOURCE"], fm.ID, fmKeys(fm))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Options.Harness != "claude" || cert.Options.PermissionMode != "auto" || !strings.Contains(cert.Options.Config, `"label":"x"`) ||
		strings.Join(cert.Stores, ",") != "default,tunnel" || cert.Line != "s1" || cert.PredID != "" || cert.Snapshot != "" {
		t.Fatalf("%+v", cert)
	}
	if v, err := vouch(cert); err != nil || v.Config.Label != "x" || v.Config.Model != "claude-opus-5-5" {
		t.Fatal(err, v.Config)
	}
	if trust.Machine != "fly-"+fm.ID || trust.Box != k.Box.PublicKey() {
		t.Fatalf("%+v", trust)
	}
}

// ✱ what a router could hand a kernel machine instead: another machine's documents, another source, another box,
// a grant from elsewhere, a cert not notarized
func TestAKernelMachineRefusesOtherDocuments(t *testing.T) {
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	b, fm := bootDocs(t, k)
	b2, fm2 := bootDocs(t, k)
	box, src, keys := k.Box.PublicKey(), fm.Env["JARVIS2_SOURCE"], fmKeys(fm)
	refuse := func(name string, d kernelBootDocs, box, src, me string, keys map[string]string) {
		t.Helper()
		if _, _, err := checkKernelBoot(d, box, src, me, keys); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	refuse("another machine's documents", b2, box, src, fm.ID, keys)
	refuse("another source", b, box, fm2.Env["JARVIS2_SOURCE"], fm.ID, keys)
	other, _ := sig.NewSigner()
	refuse("another box", b, other.PublicKey(), src, fm.ID, keys)
	refuse("other keys", b, box, src, fm.ID, fmKeys(fm2))
	x := b
	x.Grant = b2.Grant
	refuse("another machine's grant", x, box, src, fm.ID, keys)
	x = b
	x.MachineNotarized = b2.MachineNotarized
	refuse("a notarization of another cert", x, box, src, fm.ID, keys)
	x = b
	x.SourceCert, x.SourceNotarized = b2.SourceCert, b2.SourceNotarized
	refuse("another source's cert", x, box, src, fm.ID, keys)
	x = b
	fake, _ := sig.NewComponent("mover", other)
	g := b.Grant
	g.Signer = &fake.Identity
	x.Grant = gv.Signed(g)
	refuse("a mover the box never vouched for", x, box, src, fm.ID, keys)
	if _, _, err := checkKernelBoot(b, box, src, fm.ID, keys); err != nil {
		t.Fatal(err)
	}
}

// the clean env keeps a kernel machine's box key and source, and refuses a machine with neither
func TestCleanEnvKeepsTheKernelsKeys(t *testing.T) {
	key := strings.Repeat("A", 87) + "="
	env, err := cleanEnv([]string{"JARVIS2_KERNEL_BOX=" + key, "JARVIS2_SOURCE=source-" + strings.Repeat("ab", 16), "EVIL=1"}, nil)
	if err != nil || !strings.Contains(strings.Join(env, "\n"), "JARVIS2_SOURCE=source-") || strings.Contains(strings.Join(env, "\n"), "EVIL") {
		t.Fatal(err, env)
	}
	if _, err := cleanEnv([]string{"JARVIS2_KERNEL_BOX=" + key, "JARVIS2_SOURCE=nope"}, nil); err == nil {
		t.Fatal("a bad source accepted")
	}
}
