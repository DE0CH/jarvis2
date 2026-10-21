package main

// A machine the kernel's spawner started (DESIGN "Target design", docs/PLAN-grants.md §4): its Fly config carries the
// box public key (JARVIS2_KERNEL_BOX) and its source (JARVIS2_SOURCE) instead of the old core's key. At boot it reads
// its documents from the router (GET /m/kernel/boot) and believes them only as far as they check:
//
//   - every component identity is the box key's for its role;
//   - the spawner's cert (source, fly-<this machine>, ⊤) names this machine's own keys and its source, and the
//     notarizer notarized it;
//   - the cert into the source is notarized too: the source's image, settings and snapshot hash are what the
//     notarizer's table let through (the phone signed a new one; the spawner, at its machine's kill, the snapshot);
//   - the grant, signed by the mover or the merger, is on this machine and its keys.
//
// From them it builds the Cert the rest of boot reads (settings, stores, the snapshot to restore), and keeps the box
// and secrets' keys for its pulls. The snapshot is restored by its hash alone: the spawner checked the predecessor's
// signature over it before it named it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/DE0CH/jarvis2/kernel/doc"
	"github.com/DE0CH/jarvis2/kernel/gv"
	"github.com/DE0CH/jarvis2/kernel/sig"
)

const (
	kernelBoxEnv    = "JARVIS2_KERNEL_BOX"
	kernelSourceEnv = "JARVIS2_SOURCE"
)

var kernelTrustPath = dir + "/kernel.json"

// kernelTrust: what a kernel machine checks later answers with
type kernelTrust struct {
	Box     string `json:"box"`
	Secrets string `json:"secrets"` // secrets' signing key (its pull answers)
	Machine string `json:"machine"` // "fly-<id>": the object its grant and pulls name
}

func readKernelTrust() (kernelTrust, bool) {
	var t kernelTrust
	b, err := os.ReadFile(kernelTrustPath)
	return t, err == nil && json.Unmarshal(b, &t) == nil && t.Box != ""
}

type kernelBootDocs struct {
	Grant            gv.Signed    `json:"grant"`
	MachineCert      sig.Doc      `json:"machineCert"`
	MachineNotarized sig.Doc      `json:"machineNotarized"`
	SourceCert       sig.Doc      `json:"sourceCert"`
	SourceNotarized  sig.Doc      `json:"sourceNotarized"`
	Notary           sig.Identity `json:"notary"`
	Notarizer        sig.Identity `json:"notarizer"`
	Mover            sig.Identity `json:"mover"`
	Merger           sig.Identity `json:"merger"`
	Spawner          sig.Identity `json:"spawner"`
	Secrets          sig.Identity `json:"secrets"`
}

// kernelSettings: a source's settings (router/kernelline.go kernelSettings)
type kernelSettings struct {
	V              int             `json:"v"`
	Harness        string          `json:"harness"`
	PermissionMode string          `json:"permissionMode"`
	Config         json.RawMessage `json:"config"`
}

// checkKernelBoot: the documents → the Cert boot reads, and what later pulls are checked with
func checkKernelBoot(b kernelBootDocs, box, source, me string, keys map[string]string) (Cert, kernelTrust, error) {
	var cert Cert
	for role, id := range map[string]sig.Identity{"notary": b.Notary, "notarizer": b.Notarizer, "mover": b.Mover,
		"merger": b.Merger, "spawner": b.Spawner, "secrets": b.Secrets} {
		if err := sig.CheckIdentity(id, role, box); err != nil {
			return cert, kernelTrust{}, err
		}
	}
	notarized := func(c sig.Doc, nz sig.Doc) error {
		var n doc.Notarized
		if err := nz.Open(b.Notarizer.SigningKey, &n); err != nil || n.Kind != "notarized" || n.Cert != c.ID() {
			return fmt.Errorf("not notarized (%v)", err)
		}
		return nil
	}
	self := doc.Object("fly-" + me)
	mc, err := doc.OpenCert(b.MachineCert, b.Spawner.SigningKey)
	if err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the spawner's cert: %w", err)
	}
	if mc.Succ != self || mc.Machine == nil || mc.Machine.SigningKey != keys["signingKey"] || mc.Machine.EncryptionKey != keys["encryptionKey"] {
		return cert, kernelTrust{}, errors.New("the spawner's cert names another machine or other keys")
	}
	if string(mc.Pred) != source {
		return cert, kernelTrust{}, fmt.Errorf("the spawner's cert comes from %s, this machine's Fly config says %s", mc.Pred, source)
	}
	if err := notarized(b.MachineCert, b.MachineNotarized); err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the spawner's cert: %w", err)
	}
	sc, err := doc.PeekCert(b.SourceCert)
	if err != nil || sc.Succ != mc.Pred || sc.Source == nil {
		return cert, kernelTrust{}, errors.New("the source's cert isn't the cert into this machine's source")
	}
	if err := notarized(b.SourceCert, b.SourceNotarized); err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the source's cert: %w", err)
	}
	if reportedDigestOf(mc.Machine.Image) != reportedDigestOf(sc.Source.Image) {
		return cert, kernelTrust{}, errors.New("this machine runs another image than its source's")
	}
	g, err := gv.Open(b.Grant, box)
	if err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the grant: %w", err)
	}
	if g.Machine != self || g.Keys != mc.Machine.Keys {
		return cert, kernelTrust{}, errors.New("the grant is on another machine")
	}
	var st kernelSettings
	d := json.NewDecoder(strings.NewReader(string(sc.Source.Settings)))
	d.DisallowUnknownFields()
	if err := d.Decode(&st); err != nil || st.V != 1 {
		return cert, kernelTrust{}, fmt.Errorf("the source's settings: %v", err)
	}
	cert.Kind = "succession-cert"
	cert.Machine = &Machine{ID: me, EncryptionKey: keys["encryptionKey"], SigningKey: keys["signingKey"]}
	cert.Options.Harness, cert.Options.PermissionMode = st.Harness, st.PermissionMode
	if len(st.Config) > 0 && string(st.Config) != "{}" && string(st.Config) != "null" {
		cert.Options.Config = string(st.Config)
	}
	if g.Pair.Allowed.Only != nil {
		for _, a := range g.Pair.Allowed.Only {
			if s, ok := strings.CutPrefix(a, "store:"); ok {
				cert.Stores = append(cert.Stores, s)
			}
		}
	}
	for _, c := range g.Pair.Conditions {
		if s, ok := strings.CutPrefix(c, "session:"); ok {
			cert.Line = s
		}
	}
	if sc.Pred.Kind() == "fly" {
		cert.PredID = sc.Pred.FlyID()
	}
	cert.Snapshot = sc.Source.Snapshot
	return cert, kernelTrust{Box: box, Secrets: b.Secrets.SigningKey, Machine: string(self)}, nil
}

func reportedDigestOf(ref string) string {
	if i := strings.LastIndex(ref, "@sha256:"); i >= 0 {
		return ref[i+1:]
	}
	return ""
}

// kernelBootCert: boot's step 1 for a kernel machine (prepare)
func kernelBootCert(c *client, me string, keys map[string]string) (Cert, error) {
	box, source := strings.TrimSpace(os.Getenv(kernelBoxEnv)), strings.TrimSpace(os.Getenv(kernelSourceEnv))
	var b kernelBootDocs
	var err error
	for i := 0; ; i++ {
		if err = c.json("GET", "/m/kernel/boot", nil, &b); err == nil {
			break
		}
		if i > 300 {
			return Cert{}, fmt.Errorf("no boot documents: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	cert, trust, err := checkKernelBoot(b, box, source, me, keys)
	if err != nil {
		return Cert{}, err
	}
	tb, _ := json.Marshal(trust)
	if err := os.WriteFile(kernelTrustPath, tb, 0o644); err != nil {
		return Cert{}, err
	}
	raw, _ := json.Marshal(cert)
	os.WriteFile(certPath, raw, 0o644) // the settings as boot read them (the supervisor reads the stores from it)
	return cert, nil
}

// kernelRestore: the predecessor's snapshot, the one whose hash the source names
func kernelRestore(c *client, want string) error {
	tmp := predecessorTmp
	defer os.Remove(tmp)
	sum, _, err := c.download("/m/snapshot", tmp)
	if err != nil {
		return err
	}
	if sum != want {
		return errors.New("the snapshot isn't the one the source names")
	}
	n, err := unpackFile(tmp)
	if err != nil {
		return err
	}
	log.Printf("restored the predecessor's snapshot (%d files)", n)
	return nil
}
