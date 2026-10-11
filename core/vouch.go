package main

// What a machine that receives secrets may be shaped by (docs/DESIGN.md "Inputs to a machine", Deyao 2026-10-11):
// only the cert and what it vouches for. This file holds the core's part of that rule:
//
//   - the image: the one session repository, pinned by digest; Fly must report that digest (certify);
//   - the machine's Fly config: no env from the caller. The core sets only its own key and the router's address
//     (MachineURL, a value of the core's own deployment, never a request's);
//   - the session's settings (Options.Config) and one machine's one-time inputs (Options.Once) travel inside the
//     cert, so the phone approved them, or an unattended resume carried them over unchanged;
//   - a resume restores exactly the snapshot the predecessor signed when it was killed: kill takes the
//     machine-signed snapshot hash, certify puts it into the successor's cert (Cert.Snapshot);
//   - every input a running machine takes later carries a core attestation (audit.go).

import (
	"os"
	"regexp"
	"strings"
)

// SessionRepo: the one image repository machines run (built by CI from git; images.yml). An approval names it
// pinned by digest, so nothing can be swapped between the approval and Fly's pull.
const SessionRepo = "ghcr.io/de0ch/jarvis2-session"

var imageRE = regexp.MustCompile(`^` + regexp.QuoteMeta(SessionRepo) + `(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@(sha256:[0-9a-f]{64})$`)

// imageDigest: the sha256:… of a pinned session image, "" when the reference isn't one
func imageDigest(ref string) string {
	m := imageRE.FindStringSubmatch(ref)
	if m == nil {
		return ""
	}
	return m[2]
}

// reportedDigest: the digest in what Fly reports a machine runs (registry/repository@sha256:…)
func reportedDigest(ref string) string {
	i := strings.LastIndex(ref, "@sha256:")
	if i < 0 || len(ref)-i-1 != len("sha256:")+64 {
		return ""
	}
	return ref[i+1:]
}

// machineURLEnv: the core's own setting for the router's address on Fly's private network (its deployment; the
// default is production's), set in every machine's config by the core alone
const machineURLEnv = "JARVIS2_URL"

const defaultMachineURL = "http://jarvis2-box._peer.internal:8081"

func machineURL() string {
	if u := strings.TrimSpace(os.Getenv("MACHINE_URL")); u != "" {
		return u
	}
	return defaultMachineURL
}

// machineEnv: the whole env a machine's Fly config gets (the request's is ignored)
func (c *Core) machineEnv() map[string]string {
	return map[string]string{coreKeyEnv: c.signer.PublicKey(), machineURLEnv: machineURL()}
}

const (
	maxConfig = 64 << 10 // the session's settings (the first prompt is the big part)
	maxOnce   = 16 << 10 // a resume's prompt and a rollback marker
)

// persistentOptions: what an unattended resume must keep exactly (Once is never carried over)
func persistentOptions(o Options) Options {
	o.Once = ""
	return o
}

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SnapshotClaim: what a machine signed over its snapshot (the hex sha256 of the tarball, as the machine signs it)
type SnapshotClaim struct {
	Sha256 string `json:"sha256"`
	Sig    string `json:"sig"`
}

// signCert: a cert, and its entry in the input log (a cert is an input too: it decides what a machine gets)
func (c *Core) signCert(cert Cert, by string) (SignedDoc, error) {
	d, err := c.sign(cert)
	if err != nil {
		return d, err
	}
	id := ""
	if cert.Machine != nil {
		id = cert.Machine.ID
	}
	if !auditWordRE.MatchString(by) {
		by = "core"
	}
	if _, err := c.appendAudit(id, "cert", by, sha256Hex(d.Payload)); err != nil {
		return SignedDoc{}, err
	}
	return d, nil
}
