package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// ---- fakes -------------------------------------------------------------------------------------

type fakeMachine struct {
	enc, sig  *ecdh.PrivateKey
	apiKey    string
	destroyed bool
	inited    bool
}

type fakeFly struct {
	n        int
	machines map[string]*fakeMachine
}

func newFakeFly() *fakeFly { return &fakeFly{machines: map[string]*fakeMachine{}} }

func (f *fakeFly) Create(r StartRequest) (string, string, error) {
	f.n++
	id := fmt.Sprintf("m%d", f.n)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, _ := ecdh.P256().GenerateKey(rand.Reader)
	f.machines[id] = &fakeMachine{enc: e, sig: s}
	return id, r.Image + "@sha256:abc", nil
}
func (f *fakeFly) ReadKeys(id string) (MachineKeys, error) {
	m := f.machines[id]
	return MachineKeys{b64.EncodeToString(m.enc.PublicKey().Bytes()), b64.EncodeToString(m.sig.PublicKey().Bytes())}, nil
}
func (f *fakeFly) WriteAPIKey(id, key string) error { f.machines[id].apiKey = key; return nil }
func (f *fakeFly) Init(id string) error              { f.machines[id].inited = true; return nil }
func (f *fakeFly) Destroy(id string) error {
	m, ok := f.machines[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	m.destroyed = true
	return nil
}
func (f *fakeFly) ConfirmDestroyed(id string) (bool, error) {
	m, ok := f.machines[id]
	return ok && m.destroyed, nil
}

// the iPhone: a signing key and a key-agreement key (the Enclave's, here in software)
type phone struct {
	sig *ecdsa.PrivateKey
	agr *ecdh.PrivateKey
}

func newPhone() *phone {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, _ := ecdh.P256().GenerateKey(rand.Reader)
	return &phone{s, a}
}
func (p *phone) signingKey() string {
	k, _ := p.sig.PublicKey.ECDH()
	return b64.EncodeToString(k.Bytes())
}
func (p *phone) agreementKey() string { return b64.EncodeToString(p.agr.PublicKey().Bytes()) }
func (p *phone) sign(payload string) string {
	h := sha256.Sum256([]byte(payload))
	s, _ := ecdsa.SignASN1(rand.Reader, p.sig, h[:])
	return b64.EncodeToString(s)
}

// the phone's share of an unlock: x(p·E), sealed to the core's one-off key T (what the shell does)
func (p *phone) share(begin SignedDoc) (string, Sealed) {
	var b struct{ Pending, E, T string }
	json.Unmarshal([]byte(begin.Payload), &b)
	eb, _ := b64.DecodeString(b.E)
	E, _ := ecdh.P256().NewPublicKey(eb)
	x, _ := p.agr.ECDH(E) // the Enclave returns only x
	s, _ := SealTo(b.T, x, infoShare)
	return b.Pending, s
}

// pl(t)(c.Primitive(...)): the answer's payload, failing the test on an error
func pl(t *testing.T) func(SignedDoc, error) map[string]any {
	return func(d SignedDoc, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		json.Unmarshal([]byte(d.Payload), &m)
		return m
	}
}

func setup(t *testing.T) (*Core, *fakeFly, *phone) {
	t.Helper()
	f := newFakeFly()
	c, err := NewCore(f)
	if err != nil {
		t.Fatal(err)
	}
	p := newPhone()
	if _, err := c.SetupPhone(p.signingKey(), p.agreementKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SeedStore("default", map[string]string{"A": "1", "B": "2"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SeedStore("gmail", map[string]string{"G": "secret"}, true); err != nil {
		t.Fatal(err)
	}
	return c, f, p
}

func unlock(t *testing.T, c *Core, p *phone, store string) string {
	t.Helper()
	b, err := c.UnlockBegin(store)
	if err != nil {
		t.Fatal(err)
	}
	id, s := p.share(b)
	m := pl(t)(c.UnlockFinish(id, s))
	return m["id"].(string)
}

func newLine(t *testing.T, c *Core, p *phone, stores ...string) (SignedDoc, string) {
	t.Helper()
	st := pl(t)(c.Start(StartRequest{Image: "ghcr.io/de0ch/jarvis2-session:1"}))
	id := st["machine"].(map[string]any)["id"].(string)
	ch, err := c.Succession(SuccessionInput{Machine: id, Stores: stores})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := c.RespondPhone(&ch, p.sign(ch.Payload))
	if err != nil {
		t.Fatal(err)
	}
	return cert, id
}

// ---- tests ---------------------------------------------------------------------------------------

func TestEverythingLeavingIsSignedByTheCore(t *testing.T) {
	c, _, _ := setup(t)
	d, err := c.Stores("n1")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyWith(c.Key()["signingKey"], []byte(d.Payload), d.Sig) {
		t.Fatal("stores answer not signed by the core")
	}
	if !strings.Contains(d.Payload, `"nonce":"n1"`) || !strings.Contains(d.Payload, `"sensitive":true`) {
		t.Fatal("nonce / sensitive mark missing: " + d.Payload)
	}
}

func TestPhoneKeysOnlyOnce(t *testing.T) {
	c, _, _ := setup(t)
	q := newPhone()
	if _, err := c.SetupPhone(q.signingKey(), q.agreementKey()); err == nil {
		t.Fatal("phone keys replaced")
	}
	if _, err := c.SeedStore("default", map[string]string{"X": "y"}, false); err == nil {
		t.Fatal("store replaced")
	}
}

func TestNewSessionUnlockAndPullSecrets(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default", "gmail")
	m := f.machines[id]
	if _, err := c.PullSecrets(&cert, m.apiKey); err == nil {
		t.Fatal("pulled while locked")
	}
	unlock(t, c, p, "default")
	unlock(t, c, p, "gmail")
	if _, err := c.PullSecrets(&cert, "wrong"); err == nil {
		t.Fatal("pulled with a wrong API key")
	}
	d, err := c.PullSecrets(&cert, m.apiKey)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Sealed Sealed }
	json.Unmarshal([]byte(d.Payload), &out)
	plain, err := OpenSealed(m.enc, out.Sealed, "jarvis2/secrets")
	if err != nil {
		t.Fatal(err)
	}
	var vals map[string]string
	json.Unmarshal(plain, &vals)
	if vals["A"] != "1" || vals["G"] != "secret" {
		t.Fatalf("got %v", vals)
	}
}

func TestAWrongPhoneShareDoesntUnlock(t *testing.T) {
	c, _, _ := setup(t)
	other := newPhone()
	b, _ := c.UnlockBegin("default")
	id, s := other.share(b)
	if _, err := c.UnlockFinish(id, s); err == nil {
		t.Fatal("another phone's share unlocked the store")
	}
	if _, err := c.UnlockFinish(id, s); err == nil {
		t.Fatal("a pending unlock was usable twice")
	}
}

func TestLockWipesWhenTheLastIDGoes(t *testing.T) {
	c, _, p := setup(t)
	a, b := unlock(t, c, p, "default"), unlock(t, c, p, "default")
	c.Lock(a)
	if _, ok := c.unlocked["default"]; !ok {
		t.Fatal("wiped with an id still open")
	}
	c.Lock(b)
	if _, ok := c.unlocked["default"]; ok {
		t.Fatal("plaintext kept after the last lock")
	}
	l := pl(t)(c.ListUnlocked("n"))
	if len(l["unlocked"].([]any)) != 0 {
		t.Fatal("list_unlocked not empty")
	}
}

func TestPhoneSignatureMustCoverExactlyTheChallenge(t *testing.T) {
	c, _, p := setup(t)
	st := pl(t)(c.Start(StartRequest{Image: "img"}))
	id := st["machine"].(map[string]any)["id"].(string)
	ch, _ := c.Succession(SuccessionInput{Machine: id, Stores: []string{"default"}})
	if _, err := c.RespondPhone(&ch, p.sign("something else")); err == nil {
		t.Fatal("accepted a signature over something else")
	}
	altered := SignedDoc{Payload: strings.Replace(ch.Payload, "default", "gmail", 1), Sig: ch.Sig}
	if _, err := c.RespondPhone(&altered, p.sign(altered.Payload)); err == nil {
		t.Fatal("accepted an altered challenge")
	}
	if _, err := c.RespondPhone(&ch, newPhone().sign(ch.Payload)); err == nil {
		t.Fatal("accepted another phone")
	}
	if _, err := c.Succession(SuccessionInput{Machine: id, Stores: []string{"nope"}}); err == nil {
		t.Fatal("accepted an unknown store")
	}
}

func TestResumeByDeadMachineExactlyOnce(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	next := func() string {
		st := pl(t)(c.Start(StartRequest{Image: "ghcr.io/de0ch/jarvis2-session:1"}))
		return st["machine"].(map[string]any)["id"].(string)
	}
	n1 := next()
	ch, _ := c.Succession(SuccessionInput{Predecessor: &cert, Machine: n1, Stores: []string{"default"}})
	if _, err := c.RespondDead(&ch); err == nil {
		t.Fatal("resumed from a live machine")
	}
	if _, err := c.Kill(old); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RespondDead(&ch); err != nil {
		t.Fatal(err)
	}
	// the same predecessor can't have a second successor (no fork), even if killed again
	c.Kill(old)
	n2 := next()
	ch2, _ := c.Succession(SuccessionInput{Predecessor: &cert, Machine: n2, Stores: []string{"default"}})
	if _, err := c.RespondDead(&ch2); err == nil {
		t.Fatal("forked: a used predecessor got a second successor")
	}
}

func TestDeadMachineResponderRefusesChanges(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	c.Kill(old)
	st := pl(t)(c.Start(StartRequest{Image: "ghcr.io/de0ch/jarvis2-session:1"}))
	n := st["machine"].(map[string]any)["id"].(string)
	ch, _ := c.Succession(SuccessionInput{Predecessor: &cert, Machine: n, Stores: []string{"default", "gmail"}})
	if _, err := c.RespondDead(&ch); err == nil {
		t.Fatal("added a store without the phone")
	}
	ch2, _ := c.Succession(SuccessionInput{Predecessor: &cert, Machine: n, Stores: []string{"default"}, Options: Options{Harness: "opencode"}})
	if _, err := c.RespondDead(&ch2); err == nil {
		t.Fatal("changed the harness without the phone")
	}
}

func TestBurnThenPhoneApprovesAChangedSuccessor(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	c.Kill(old)
	burn, _ := c.Succession(SuccessionInput{Predecessor: &cert})
	b := pl(t)(c.RespondDead(&burn))
	if b["kind"] != "burn-cert" {
		t.Fatalf("got %v", b["kind"])
	}
	st := pl(t)(c.Start(StartRequest{Image: "ghcr.io/de0ch/jarvis2-session:2"}))
	n := st["machine"].(map[string]any)["id"].(string)
	ch, _ := c.Succession(SuccessionInput{Predecessor: &cert, Machine: n, Stores: []string{"default"}})
	if _, err := c.RespondDead(&ch); err == nil {
		t.Fatal("the burnt machine resumed automatically")
	}
	if _, err := c.RespondPhone(&ch, p.sign(ch.Payload)); err != nil {
		t.Fatal(err)
	}
}

func TestKillRejectsNullAndUnconfirmed(t *testing.T) {
	c, _, _ := setup(t)
	if _, err := c.Kill("null"); err == nil {
		t.Fatal("killed null")
	}
	if _, err := c.Kill("ghost"); err == nil {
		t.Fatal("a machine Fly doesn't know counted as killed")
	}
}

func TestSensitiveMarkOnlyGrows(t *testing.T) {
	c, _, _ := setup(t)
	c.MarkSensitive("default")
	l := pl(t)(c.ListSensitive("n"))
	if fmt.Sprint(l["stores"]) != "[default gmail]" {
		t.Fatalf("got %v", l["stores"])
	}
}
