package main

// The kernel's parts (docs/DESIGN.md "Target design", core/kernel/README.md "Endpoints"), each its own service at its
// own URL. The router is untrusted: it carries documents between the parts, stores them (docstore.go) and schedules;
// every document that matters is signed by a part, the phone or a machine and checked at the far end (the parts
// themselves, the guard, the app). Nothing here decides who gets what.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// the kernel's parts, by the role name the roster uses, and the env var naming each one's URL
var kernelParts = map[string]string{
	"notary":    "NOTARY_URL",
	"notarizer": "NOTARIZER_URL",
	"mover":     "MOVER_URL",
	"merger":    "MERGER_URL",
	"identity":  "IDENTITY_SIGNER_URL",
	"gullible":  "GULLIBLE_SIGNER_URL",
	"spawner":   "SPAWNER_URL",
	"secrets":   "SECRETS_URL",
}

// kernelDefaults: each part's address inside the cluster (namespace jarvis2-kernel), when its env var is unset
var kernelDefaults = map[string]string{
	"notary":    "http://notary.jarvis2-kernel.svc.cluster.local:8090",
	"notarizer": "http://notarizer.jarvis2-kernel.svc.cluster.local:8090",
	"mover":     "http://mover.jarvis2-kernel.svc.cluster.local:8090",
	"merger":    "http://merger.jarvis2-kernel.svc.cluster.local:8090",
	"identity":  "http://identity-signer.jarvis2-kernel.svc.cluster.local:8090",
	"gullible":  "http://gullible-signer.jarvis2-kernel.svc.cluster.local:8090",
	"spawner":   "http://spawner.jarvis2-kernel.svc.cluster.local:8090",
	"secrets":   "http://secrets.jarvis2-kernel.svc.cluster.local:8090",
}

// Kernel: one client per part
type Kernel struct {
	URLs map[string]string // role → base URL
	HTTP *http.Client
}

func kernelFromEnv() *Kernel {
	k := &Kernel{URLs: map[string]string{}, HTTP: &http.Client{Timeout: 5 * time.Minute}}
	for role, e := range kernelParts {
		k.URLs[role] = env(e, kernelDefaults[role])
	}
	return k
}

// KernelError: a part refused; Body is its signed error document (relayed as is)
type KernelError struct {
	Part   string
	Status int
	Body   []byte
	Msg    string
}

func (e *KernelError) Error() string { return e.Msg }

// errPartDown: the part couldn't be reached (a state, not a fault: the app shows it plainly)
var errPartDown = errors.New("a kernel part isn't running")

// Raw: one request to a part, the answer as it came
func (k *Kernel) Raw(part, method, path string, body []byte) (int, []byte, error) {
	base := k.URLs[part]
	if base == "" {
		return 0, nil, fmt.Errorf("%w: no URL for %s", errPartDown, part)
	}
	req, _ := http.NewRequest(method, strings.TrimSuffix(base, "/")+path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %s: %v", errPartDown, part, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, b, err
}

// call: POST in as JSON, the 200 answer into out; a refusal is a *KernelError carrying the part's own words
func (k *Kernel) call(part, path string, in, out any) error {
	body, _ := json.Marshal(in)
	status, b, err := k.Raw(part, "POST", path, body)
	if err != nil {
		return err
	}
	if status != 200 {
		msg := fmt.Sprintf("%s %s: HTTP %d", part, path, status)
		var d kernel.SignedDoc
		var e struct{ Error string }
		if json.Unmarshal(b, &d) == nil && json.Unmarshal([]byte(d.Payload), &e) == nil && e.Error != "" {
			msg = part + ": " + e.Error
		}
		return &KernelError{Part: part, Status: status, Body: b, Msg: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s %s: unreadable answer: %v", part, path, err)
	}
	return nil
}

func kernelStatus(err error) int {
	var ke *KernelError
	if errors.As(err, &ke) {
		return ke.Status
	}
	return 0
}

// Challenge: the log notary's challenge over subject (hex sha256) about a word
func (k *Kernel) Challenge(subject, about string) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("notary", "/challenge", map[string]string{"subject": subject, "about": about}, &d)
}

// Notarize: a signed succession cert and its challenge → the notarized cert
func (k *Kernel) Notarize(cert, challenge kernel.SignedDoc) (kernel.NotarizedCert, error) {
	var nc kernel.NotarizedCert
	return nc, k.call("notarizer", "/notarize", map[string]any{"cert": cert, "challenge": challenge}, &nc)
}

// NotarizeNew: a challenge for the cert, then the notarizer (for certs the kernel's own signers make)
func (k *Kernel) NotarizeNew(cert kernel.SignedDoc) (kernel.NotarizedCert, error) {
	ch, err := k.Challenge(cert.ID(), kernel.AboutSuccession)
	if err != nil {
		return kernel.NotarizedCert{}, err
	}
	return k.Notarize(cert, ch)
}

// Move: grant G along a notarized cert → (successor, G ⊓ P)
func (k *Kernel) Move(grant kernel.SignedDoc, nc kernel.NotarizedCert) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("mover", "/move", map[string]any{"grant": grant, "cert": nc}, &d)
}

// Merge: two grants on one machine with identical conditions → their union
func (k *Kernel) Merge(a, b kernel.SignedDoc) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("merger", "/merge", map[string]any{"a": a, "b": b}, &d)
}

// IdentitySign: (M, M, P), the router's P
func (k *Kernel) IdentitySign(m kernel.Object, p kernel.Pair) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("identity", "/sign", map[string]any{"machine": m, "allowed": p.Allowed, "conditions": condsOrEmpty(p.Conditions)}, &d)
}

// GullibleSign: any (X, Y, P); it counts only where the table takes any signer (ending a source)
func (k *Kernel) GullibleSign(pred, succ kernel.Object, p kernel.Pair) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("gullible", "/sign", map[string]any{"predecessor": pred, "successor": succ, "allowed": p.Allowed,
		"conditions": condsOrEmpty(p.Conditions)}, &d)
}

func condsOrEmpty(c kernel.Conditions) kernel.Conditions {
	if c == nil {
		return kernel.Conditions{}
	}
	return c
}

// Spawn: one Fly create from the source the notarized cert ends in → the new machine's id
func (k *Kernel) Spawn(nc kernel.NotarizedCert, region, size string) (string, error) {
	var d kernel.SignedDoc
	if err := k.call("spawner", "/spawn", map[string]any{"cert": nc, "region": region, "size": size}, &d); err != nil {
		return "", err
	}
	var c struct {
		Kind    string `json:"kind"`
		Machine string `json:"machine"`
	}
	if json.Unmarshal([]byte(d.Payload), &c) != nil || c.Kind != "created" || c.Machine == "" {
		return "", errors.New("spawner: not a created answer")
	}
	return c.Machine, nil
}

// Init: one try at the machine's keys → the spawn cert (source, M, ⊤); 409 while it boots
func (k *Kernel) Init(machine string) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("spawner", "/init", map[string]string{"machine": machine}, &d)
}

// SnapshotClaim: what a machine signed over its final snapshot
type SnapshotClaim struct {
	Sha256 string `json:"sha256"`
	Sig    string `json:"sig"`
}

// Kill: M's notarized spawn cert (and its snapshot claim) → (M, source-y, ⊤); 409 until Fly confirms
func (k *Kernel) Kill(nc kernel.NotarizedCert, snap *SnapshotClaim) (kernel.SignedDoc, error) {
	in := map[string]any{"cert": nc}
	if snap != nil {
		in["snapshot"] = snap
	}
	var d kernel.SignedDoc
	return d, k.call("spawner", "/kill", in, &d)
}

// Pull: the secrets component's signed answer for a grant
func (k *Kernel) Pull(grant kernel.SignedDoc) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("secrets", "/pull", map[string]any{"grant": grant}, &d)
}

// Identity: a part's GET /identity
func (k *Kernel) Identity(part string) (kernel.Identity, error) {
	var id kernel.Identity
	status, b, err := k.Raw(part, "GET", "/identity", nil)
	if err != nil {
		return id, err
	}
	if status != 200 {
		return id, fmt.Errorf("%s /identity: HTTP %d", part, status)
	}
	return id, json.Unmarshal(b, &id)
}

// SecretsDoc: one of secrets' signed documents (POST path with in)
func (k *Kernel) SecretsDoc(path string, in any) (kernel.SignedDoc, error) {
	var d kernel.SignedDoc
	return d, k.call("secrets", path, in, &d)
}

// Roster: the kernel parts' signing keys as they answer /identity ("" for a part that doesn't answer); the phone's and
// the root key aren't parts and aren't in it
func (k *Kernel) Roster() map[string]string {
	out := map[string]string{}
	for role := range kernelParts {
		if id, err := k.Identity(role); err == nil {
			out[role] = id.SigningKey
		} else {
			out[role] = ""
		}
	}
	return out
}

// payloadOf: a signed document's payload decoded loosely (the router reads what it needs; the parts check)
func payloadOf(d kernel.SignedDoc, out any) error { return json.Unmarshal([]byte(d.Payload), out) }

// successionOf: a cert's payload (unverified)
func successionOf(d kernel.SignedDoc) (kernel.Succession, error) {
	var s kernel.Succession
	err := payloadOf(d, &s)
	return s, err
}

// grantOf: a grant's payload (unverified)
func grantOf(d kernel.SignedDoc) (kernel.Grant, error) {
	var g kernel.Grant
	err := payloadOf(d, &g)
	return g, err
}

// Doc: a signed document as the router's own records carry it (the same JSON as kernel.SignedDoc)
type Doc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

func (d *Doc) Decode(out any) error { return json.Unmarshal([]byte(d.Payload), out) }

func docOf(s kernel.SignedDoc) *Doc { return &Doc{Payload: s.Payload, Sig: s.Sig} }
