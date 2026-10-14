// Package ktest: test helpers for the kernel's parts — fresh keys for every role, and documents signed directly with
// them (a cert as a signer makes it, a notarized cert, a grant), so each part's tests stand alone. Tests only.
package ktest

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// Image: a pinned session image
const Image = "ghcr.io/de0ch/jarvis2-session:1@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// Roles: every key the roster names
var Roles = []string{"notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "secrets", "phone", "root"}

type World struct {
	Keys   map[string]*kernel.Signer
	Roster kernel.Roster
	seq    int64
}

func New(t testing.TB) *World {
	t.Helper()
	w := &World{Keys: map[string]*kernel.Signer{}}
	for _, r := range Roles {
		s, err := kernel.NewSigner()
		if err != nil {
			t.Fatal(err)
		}
		w.Keys[r] = s
	}
	k := func(r string) string { return w.Keys[r].PublicKey() }
	w.Roster = kernel.Roster{Notary: k("notary"), Notarizer: k("notarizer"), Mover: k("mover"), Merger: k("merger"),
		Spawner: k("spawner"), Identity: k("identity"), Gullible: k("gullible"), Secrets: k("secrets"), Phone: k("phone"), Root: k("root")}
	return w
}

func sign(t testing.TB, k *kernel.Signer, v any) kernel.SignedDoc {
	t.Helper()
	d, err := kernel.Sign(k, v)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Cert: (pred, succ, p) as `role` names itself, signed with keyRole's key (normally the same role)
func (w *World) Cert(t testing.TB, role, keyRole string, pred, succ kernel.Object, p kernel.Pair) kernel.SignedDoc {
	t.Helper()
	if p.Conditions == nil {
		p.Conditions = kernel.Conditions{}
	}
	return sign(t, w.Keys[keyRole], kernel.Succession{Kind: "succession", Signer: role, Predecessor: pred, Successor: succ,
		Allowed: p.Allowed, Conditions: p.Conditions})
}

// Challenge: a log-notary challenge, signed with the notary's key directly
func (w *World) Challenge(t testing.TB, subject, about string) kernel.SignedDoc {
	t.Helper()
	n := make([]byte, 16)
	rand.Read(n)
	w.seq++
	return sign(t, w.Keys["notary"], kernel.Challenge{Kind: "challenge", Seq: w.seq, At: "2026-10-14T12:00:00Z",
		Subject: subject, About: about, Nonce: hex.EncodeToString(n)})
}

// Notarize: the cert with a challenge and a notarization signed directly (no table: the notarizer's tests check that)
func (w *World) Notarize(t testing.TB, cert kernel.SignedDoc) kernel.NotarizedCert {
	t.Helper()
	ch := w.Challenge(t, cert.ID(), kernel.AboutSuccession)
	n := sign(t, w.Keys["notarizer"], kernel.Notarization{Kind: "notarization", Cert: cert.ID(), Challenge: ch.ID()})
	return kernel.NotarizedCert{Cert: cert, Challenge: ch, Notarization: n}
}

// Grant: a grant made as `by`, signed with keyRole's key
func (w *World) Grant(t testing.TB, by, keyRole string, m kernel.Object, p kernel.Pair) kernel.SignedDoc {
	t.Helper()
	if p.Conditions == nil {
		p.Conditions = kernel.Conditions{}
	}
	return sign(t, w.Keys[keyRole], kernel.Grant{Kind: "grant", By: by, Machine: m, Allowed: p.Allowed,
		Conditions: p.Conditions, From: []string{}})
}

// RootGrant: ⊤ on the sink, by the root key
func (w *World) RootGrant(t testing.TB) kernel.SignedDoc {
	t.Helper()
	return sign(t, w.Keys["root"], kernel.RootGrant())
}

// Source: a fresh source with these contents
func Source(image, settings string) kernel.Object {
	b := make([]byte, 16)
	rand.Read(b)
	return kernel.Object{ID: "source-" + hex.EncodeToString(b), Image: image, Settings: settings}
}

func SinkObj() kernel.Object { return kernel.Object{ID: kernel.Sink} }

// Machine: a Fly machine object with fresh keys, and its private halves
type Machine struct {
	Obj    kernel.Object
	Enc    *ecdh.PrivateKey
	SigKey *kernel.Signer
}

func NewMachine(t testing.TB, id string) Machine {
	t.Helper()
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := kernel.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	return Machine{Obj: kernel.Object{ID: id, SigningKey: s.PublicKey(), EncryptionKey: kernel.B64.EncodeToString(e.PublicKey().Bytes())}, Enc: e, SigKey: s}
}

// P: a pair from finite allowed strings and conditions
func P(allowed []string, conds ...string) kernel.Pair {
	return kernel.Pair{Allowed: kernel.Only(allowed...), Conditions: kernel.CanonConditions(conds...)}
}

// Payload: a document's payload into out (no signature check), failing the test on a bad payload
func Payload(t testing.TB, d kernel.SignedDoc, out any) {
	t.Helper()
	if err := json.Unmarshal([]byte(d.Payload), out); err != nil {
		t.Fatal(err)
	}
}
