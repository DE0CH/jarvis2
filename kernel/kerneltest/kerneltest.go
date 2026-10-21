// Package kerneltest: the whole kernel for other modules' tests (the router's, the machine's). Every component
// runs in-process on its own httptest server, on a fake Fly whose machines have real key pairs, with a box key, a
// phone key and a root key the test holds, and secrets already claimed (Reset: no stores).
package kerneltest

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DE0CH/jarvis2/kernel/doc"
	"github.com/DE0CH/jarvis2/kernel/internal/serve"
	"github.com/DE0CH/jarvis2/kernel/merger"
	"github.com/DE0CH/jarvis2/kernel/mover"
	"github.com/DE0CH/jarvis2/kernel/notarizer"
	"github.com/DE0CH/jarvis2/kernel/notary"
	"github.com/DE0CH/jarvis2/kernel/perm"
	"github.com/DE0CH/jarvis2/kernel/secrets"
	"github.com/DE0CH/jarvis2/kernel/sig"
	"github.com/DE0CH/jarvis2/kernel/signers"
	"github.com/DE0CH/jarvis2/kernel/spawner"
)

// Kernel: the running components and the keys a test signs with
type Kernel struct {
	Box         *sig.Signer
	Phone, Root *sig.Signer
	PhoneAgree  *ecdh.PrivateKey
	URL         map[string]string // role → base URL
	Fly         *FakeFly
	Secrets     *secrets.Secrets
	servers     []*httptest.Server
	master      *sig.Signer
}

// URLFor: the base URL of a role (what the router's KERNEL_URL template gives)
func (k *Kernel) URLFor(role string) string { return k.URL[role] }

// Close: every server
func (k *Kernel) Close() {
	for _, s := range k.servers {
		s.Close()
	}
}

// Start: every component; machineEnv is what spawned machines' Fly config env gets
func Start(t testing.TB, machineEnv map[string]string) *Kernel {
	box, _ := sig.NewSigner()
	phone, _ := sig.NewSigner()
	root, _ := sig.NewSigner()
	pa, _ := ecdh.P256().GenerateKey(rand.Reader)
	k := &Kernel{Box: box, Phone: phone, Root: root, PhoneAgree: pa, URL: map[string]string{}, Fly: NewFakeFly()}
	dir := t.TempDir()
	for _, role := range []string{"notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible"} {
		c, err := sig.NewComponent(role, box)
		if err != nil {
			t.Fatal(err)
		}
		s := serve.New(c, box.PublicKey())
		switch role {
		case "notary":
			n, err := notary.Open(filepath.Join(dir, "notary"), c.Signer)
			if err != nil {
				t.Fatal(err)
			}
			notary.Register(s, n)
		case "notarizer":
			n, err := notarizer.Open(filepath.Join(dir, "notarizer"), c.Signer, box.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			notarizer.Register(s, n)
		case "mover":
			mover.Register(s, mover.New(c.Signer, box.PublicKey()))
		case "merger":
			merger.Register(s, merger.New(c.Signer, box.PublicKey()))
		case "spawner":
			sp, err := spawner.Open(filepath.Join(dir, "spawner"), c, box.PublicKey(), k.Fly, machineEnv)
			if err != nil {
				t.Fatal(err)
			}
			spawner.Register(s, sp)
		case "identity":
			signers.RegisterIdentity(s)
		case "gullible":
			signers.RegisterGullible(s)
		}
		srv := httptest.NewServer(s.Mux)
		k.servers = append(k.servers, srv)
		k.URL[role] = srv.URL
	}
	sc, err := secrets.New(box, nil)
	if err != nil {
		t.Fatal(err)
	}
	k.Secrets = sc
	srv := httptest.NewServer(secrets.Handler(sc))
	k.servers = append(k.servers, srv)
	k.URL["secrets"] = srv.URL
	if err := k.claim(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

// claim: secrets Reset by a fresh master key, naming the test's phone and root keys
func (k *Kernel) claim() error {
	master, _ := sig.NewSigner()
	id, err := k.Secrets.Identity()
	if err != nil {
		return err
	}
	plain := []byte(`{"format":"keys"}`)
	sum := sha256.Sum256(plain)
	st := map[string]any{"kind": "kernel-claim", "master": master.PublicKey(),
		"secrets": map[string]string{"signingKey": id["signingKey"].(string), "agreementKey": id["agreementKey"].(string)},
		"phone":   map[string]string{"signingKey": k.Phone.PublicKey(), "agreementKey": sig.B64.EncodeToString(k.PhoneAgree.PublicKey().Bytes())},
		"root":    k.Root.PublicKey(), "bundleSha256": hex.EncodeToString(sum[:])}
	sb, _ := json.Marshal(st)
	ms, _ := master.Sign(sb)
	bundle, err := secrets.SealTo(id["agreementKey"].(string), plain, "jarvis2/kernel-claim")
	if err != nil {
		return err
	}
	_, err = k.Secrets.Claim(string(sb), ms, bundle)
	return err
}

// RootTop: ⊤ on the sink, signed by the root key (what the app signs once after the claim)
func (k *Kernel) RootTop() sig.Doc {
	ik, _ := doc.IdealKeys(doc.Sink)
	d, _ := k.Root.SignJSON(doc.Grant{Kind: "grant", Machine: doc.Sink, Keys: ik, Pair: perm.Top(), From: []string{}, At: doc.Now()})
	return d
}

// ---- a fake Fly -----------------------------------------------------------------------------------------------

// FakeMachine: one machine, with the key pairs its image made
type FakeMachine struct {
	ID, Image, State string
	Env              map[string]string
	Sig              *sig.Signer
	Enc              *ecdh.PrivateKey
}

type FakeFly struct {
	mu       sync.Mutex
	n        int
	Machines map[string]*FakeMachine
	vols     map[string]bool
	// Booting: new machines stay "starting" until Up
	Booting bool
}

func NewFakeFly() *FakeFly {
	return &FakeFly{Machines: map[string]*FakeMachine{}, vols: map[string]bool{}}
}

func (f *FakeFly) Configure(string) {}

func (f *FakeFly) CreateVolume(string, int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	v := fmt.Sprintf("vol_%d", f.n)
	f.vols[v] = true
	return v, nil
}

func (f *FakeFly) Create(image, region string, guest map[string]any, env map[string]string, volume string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := fmt.Sprintf("%014x", f.n)
	s, _ := sig.NewSigner()
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	st := "started"
	if f.Booting {
		st = "starting"
	}
	f.Machines[id] = &FakeMachine{ID: id, Image: image, State: st, Env: env, Sig: s, Enc: e}
	return id, nil
}

// Up: a booting machine is started
func (f *FakeFly) Up(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.Machines[id]; m != nil {
		m.State = "started"
	}
}

// Machine: one by id
func (f *FakeFly) Machine(id string) *FakeMachine {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Machines[id]
}

func (f *FakeFly) Inspect(id string) (spawner.FlyMachine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.Machines[id]
	if m == nil {
		return spawner.FlyMachine{State: "destroyed"}, nil
	}
	return spawner.FlyMachine{State: m.State, Image: strings.Replace(m.Image, ":latest", "", 1)}, nil
}

func (f *FakeFly) Init(id string) (spawner.MachineKeys, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.Machines[id]
	if m == nil {
		return spawner.MachineKeys{}, fmt.Errorf("no machine %s", id)
	}
	return spawner.MachineKeys{SigningKey: m.Sig.PublicKey(), EncryptionKey: sig.B64.EncodeToString(m.Enc.PublicKey().Bytes())}, nil
}

func (f *FakeFly) Destroy(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.Machines[id]; m != nil {
		m.State = "destroyed"
	}
	return nil
}

func (f *FakeFly) DeleteVolume(v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.vols, v)
	return nil
}

func (f *FakeFly) ExtendVolume(string, int) (bool, error) { return false, nil }

// Secrets: one more secrets on its own server (the next colour, blue/green), and its URL
func (k *Kernel) Secrets2(t testing.TB) (*secrets.Secrets, string) {
	sc, err := secrets.New(k.Box, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(secrets.Handler(sc))
	k.servers = append(k.servers, srv)
	return sc, srv.URL
}

// ClaimSeeded: a claim of sc with keys derived from seed (the same kit derives the same secrets), standby or not, by
// the test's master key (one per Kernel)
func (k *Kernel) ClaimSeeded(sc *secrets.Secrets, seed []byte, standby bool) error {
	if k.master == nil {
		k.master, _ = sig.NewSigner()
	}
	id, err := sc.Identity()
	if err != nil {
		return err
	}
	ds, da, err := secrets.SeedIdentity(seed)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]any{"format": "keys", "secretsSeed": sig.B64.EncodeToString(seed)})
	sum := sha256.Sum256(b)
	st := map[string]any{"kind": "kernel-claim", "master": k.master.PublicKey(),
		"secrets": map[string]string{"signingKey": id["signingKey"].(string), "agreementKey": id["agreementKey"].(string)},
		"phone":   map[string]string{"signingKey": k.Phone.PublicKey(), "agreementKey": sig.B64.EncodeToString(k.PhoneAgree.PublicKey().Bytes())},
		"root":    k.Root.PublicKey(), "bundleSha256": hex.EncodeToString(sum[:]),
		"identity": map[string]string{"signingKey": ds, "agreementKey": da}, "standby": standby}
	sb, _ := json.Marshal(st)
	ms, _ := k.master.Sign(sb)
	sealed, err := secrets.SealTo(id["agreementKey"].(string), b, "jarvis2/kernel-claim")
	if err != nil {
		return err
	}
	_, err = sc.Claim(string(sb), ms, sealed)
	return err
}
