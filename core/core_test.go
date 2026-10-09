package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// ---- fakes -------------------------------------------------------------------------------------

type fakeMachine struct {
	enc, sig  *ecdh.PrivateKey
	destroyed bool
	inited    bool
}

type fakeFly struct {
	n          int
	machines   map[string]*fakeMachine
	token, app string
	failInit   bool
}

func newFakeFly() *fakeFly { return &fakeFly{machines: map[string]*fakeMachine{}} }

func (f *fakeFly) Configure(token, app string) { f.token, f.app = token, app }
func (f *fakeFly) Create(r StartRequest) (string, string, error) {
	f.n++
	id := fmt.Sprintf("m%d", f.n)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, _ := ecdh.P256().GenerateKey(rand.Reader)
	f.machines[id] = &fakeMachine{enc: e, sig: s}
	return id, strings.SplitN(r.Image, "@", 2)[0] + "@sha256:abc", nil
}
func (f *fakeFly) Init(id string) (MachineKeys, error) {
	if f.failInit {
		return MachineKeys{}, fmt.Errorf("exec failed")
	}
	m := f.machines[id]
	m.inited = true
	return MachineKeys{b64.EncodeToString(m.enc.PublicKey().Bytes()), b64.EncodeToString(m.sig.PublicKey().Bytes())}, nil
}
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

// a P-256 key holder: the iPhone (signing + the Enclave's key agreement, here in software), the master key,
// the setup key
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

const img = "ghcr.io/de0ch/jarvis2-session:1"

var testValues = map[string]map[string]string{
	"default":    {"A": "1", "B": "2"},
	"gmail":      {"G": "secret"},
	"claude":     {"CLAUDE_CREDENTIALS": "c"},
	"openrouter": {"OPENROUTER_API": "o"},
}

// writeStore: what the router's API (or the phone, in recovery) does OUTSIDE the core — the values under a
// fresh data key, that key wrapped to the combined key P + K
func writeStore(t *testing.T, c *Core, p *phone, name string, vals map[string]string) StoreBlob {
	t.Helper()
	dk := make([]byte, 32)
	rand.Read(dk)
	w, err := WrapToCombined(p.agreementKey(), c.agreement.PublicKey().Bytes(), dk)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(vals)
	return StoreBlob{Name: name, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, plain, []byte(name)))}
}

func newCore(t *testing.T) (*Core, *fakeFly, *phone) {
	t.Helper()
	f := newFakeFly()
	c, err := NewCore(f)
	if err != nil {
		t.Fatal(err)
	}
	master := newPhone()
	c.MasterKey = master.signingKey()
	return c, f, master
}

// recoveryFor: what the iPhone sends in recovery — a statement signed by the master key and the key store
// sealed to the core
func recoveryFor(c *Core, master, p *phone, flyToken string) (string, string, Sealed) {
	rb := recoveryBundle{NotSensitive: []string{"default", "claude", "openrouter"}}
	rb.Stores = append(rb.Stores, storeData{Name: FlyStore, Values: map[string]string{"FLY_API_TOKEN": flyToken, "FLY_APP": "jarvis2-sessions"}})
	for _, n := range []string{"claude", "default", "gmail", "openrouter"} {
		rb.Stores = append(rb.Stores, storeData{Name: n, Values: testValues[n]})
	}
	plain, _ := json.Marshal(rb)
	sum := sha256.Sum256(plain)
	var st recoveryStatement
	st.Kind = "recovery"
	k := c.Key()
	st.Core.SigningKey, st.Core.AgreementKey = k["signingKey"], k["agreementKey"]
	st.Phone.SigningKey, st.Phone.AgreementKey = p.signingKey(), p.agreementKey()
	st.BundleSha256 = hex.EncodeToString(sum[:])
	sb, _ := json.Marshal(st)
	bundle, _ := SealTo(k["agreementKey"], plain, infoRecover)
	return string(sb), master.sign(string(sb)), bundle
}

func setup(t *testing.T) (*Core, *fakeFly, *phone) {
	t.Helper()
	c, f, master := newCore(t)
	p := newPhone()
	s, sig, b := recoveryFor(c, master, p, "fly-secret")
	pl(t)(c.Recover(s, sig, b))
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

// approve: the iPhone answers a succession challenge
func approve(t *testing.T, c *Core, p *phone, in SuccessionInput) SignedDoc {
	t.Helper()
	ch, err := c.Succession(in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.ApproveByPhone(&ch, p.sign(ch.Payload))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// tryStart: what the router does with an approval — start a machine on the approved image, then certify it
func tryStart(c *Core, a SignedDoc) (SignedDoc, error) {
	var ap Approval
	json.Unmarshal([]byte(a.Payload), &ap)
	if ap.Request.Image == NullImage {
		return c.Certify(&a, "")
	}
	st, err := c.Start(StartRequest{Image: ap.Request.Image})
	if err != nil {
		return SignedDoc{}, err
	}
	var m struct{ Machine StartedMachine }
	json.Unmarshal([]byte(st.Payload), &m)
	return c.Certify(&a, m.Machine.ID)
}

func start(t *testing.T, c *Core, a SignedDoc) (SignedDoc, string) {
	t.Helper()
	cert, err := tryStart(c, a)
	if err != nil {
		t.Fatal(err)
	}
	var cc Cert
	json.Unmarshal([]byte(cert.Payload), &cc)
	return cert, cc.Machine.ID
}

func newLine(t *testing.T, c *Core, p *phone, stores ...string) (SignedDoc, string) {
	t.Helper()
	return start(t, c, approve(t, c, p, SuccessionInput{Image: img, Stores: stores}))
}

// ---- tests ---------------------------------------------------------------------------------------

func TestEverythingLeavingIsSignedByTheCore(t *testing.T) {
	c, _, _ := setup(t)
	d, err := c.ListUnlocked("n1")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyWith(c.Key()["signingKey"], []byte(d.Payload), d.Sig) {
		t.Fatal("list_unlocked answer not signed by the core")
	}
	if !strings.Contains(d.Payload, `"nonce":"n1"`) {
		t.Fatal("nonce missing: " + d.Payload)
	}
}

func TestRecoveryOnceOnlyWithTheMasterKey(t *testing.T) {
	c, f, master := newCore(t)
	p := newPhone()
	s, sig, b := recoveryFor(c, master, p, "fly-secret")
	if _, err := c.Recover(s, newPhone().sign(s), b); err == nil {
		t.Fatal("recovered without the master key")
	}
	other, _, _ := newCore(t)
	s2, _, b2 := recoveryFor(other, master, p, "fly-secret")
	if _, err := c.Recover(s2, master.sign(s2), b2); err == nil {
		t.Fatal("recovered with a statement naming another core")
	}
	_, _, b3 := recoveryFor(c, master, p, "another")
	if _, err := c.Recover(s, sig, b3); err == nil {
		t.Fatal("recovered a key store the master didn't sign")
	}
	if _, err := c.CoreCert(); err == nil {
		t.Fatal("a core cert before recovery")
	}
	pl(t)(c.Recover(s, sig, b))
	if f.token != "fly-secret" || f.app != "jarvis2-sessions" {
		t.Fatal("the core store's Fly token wasn't taken")
	}
	if _, err := c.Recover(s, sig, b); err == nil {
		t.Fatal("recovered twice")
	}
	cc, err := c.CoreCert()
	if err != nil || !VerifyWith(c.MasterKey, []byte(cc.Statement), cc.MasterSig) {
		t.Fatal("no master-signed core cert after recovery")
	}
	if len(c.unlocked) != 0 {
		t.Fatal("recovery left plaintext in memory")
	}
	if _, ok := c.stores[FlyStore]; ok {
		t.Fatal("the Fly store is kept as a session store")
	}
	l := pl(t)(c.Stores("n"))
	if fmt.Sprint(l["stores"]) != "[map[empty:false name:claude sensitive:false unlocked:false] map[empty:false name:default sensitive:false unlocked:false] map[empty:false name:gmail sensitive:true unlocked:false] map[empty:false name:openrouter sensitive:false unlocked:false]]" {
		t.Fatalf("got %v", l["stores"])
	}
}

func TestIdentityWords(t *testing.T) {
	c, _, _ := newCore(t)
	k := c.Key()
	w := IdentityWords(k["signingKey"], k["agreementKey"])
	if len(strings.Fields(w)) != 8 || w != IdentityWords(k["signingKey"], k["agreementKey"]) {
		t.Fatalf("got %q", w)
	}
	if len(words) != 2048 || words[0] != "abandon" || words[2047] != "zoo" {
		t.Fatal("not the BIP39 English list")
	}
}

func TestNewSessionUnlockAndPullSecrets(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "claude", "default", "gmail")
	m := f.machines[id]
	if !m.inited {
		t.Fatal("the machine wasn't inited through Fly")
	}
	if _, err := c.PullSecrets(&cert); err == nil {
		t.Fatal("pulled while locked")
	}
	unlock(t, c, p, "default")
	unlock(t, c, p, "gmail")
	unlock(t, c, p, "claude")
	d, err := c.PullSecrets(&cert)
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
	if vals["A"] != "1" || vals["G"] != "secret" || vals["CLAUDE_CREDENTIALS"] != "c" {
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
	// a blob whose name was changed outside the core doesn't decrypt
	c2, _, p2 := setup(t)
	blob := writeStore(t, c2, p2, "default", testValues["default"])
	blob.Name = "gmail"
	pl(t)(c2.WriteStore(blob))
	b2, _ := c2.UnlockBegin("gmail")
	id2, s2 := p2.share(b2)
	if _, err := c2.UnlockFinish(id2, s2); err == nil {
		t.Fatal("a renamed store blob unlocked")
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
	ch, _ := c.Succession(SuccessionInput{Image: img, Stores: []string{"default"}})
	if _, err := c.ApproveByPhone(&ch, p.sign("something else")); err == nil {
		t.Fatal("accepted a signature over something else")
	}
	altered := SignedDoc{Payload: strings.Replace(ch.Payload, "default", "gmail", 1), Sig: ch.Sig}
	if _, err := c.ApproveByPhone(&altered, p.sign(altered.Payload)); err == nil {
		t.Fatal("accepted an altered challenge")
	}
	if _, err := c.ApproveByPhone(&ch, newPhone().sign(ch.Payload)); err == nil {
		t.Fatal("accepted another phone")
	}
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("a new line was answered without the phone")
	}
}

func TestAnApprovalMakesOneMachine(t *testing.T) {
	c, f, p := setup(t)
	a := approve(t, c, p, SuccessionInput{Image: img, Stores: []string{"default"}})
	f.failInit = true
	if _, err := c.Start(StartRequest{Image: img}); err == nil {
		t.Fatal("started without the machine's keys")
	}
	if !f.machines["m1"].destroyed {
		t.Fatal("a machine whose init failed was left running")
	}
	f.failInit = false
	other := pl(t)(c.Start(StartRequest{Image: "ghcr.io/de0ch/other:1"}))["machine"].(map[string]any)["id"].(string)
	if _, err := c.Certify(&a, other); err == nil {
		t.Fatal("certified a machine running another image")
	}
	_, id := start(t, c, a)
	if _, err := tryStart(c, a); err == nil {
		t.Fatal("one approval made two machines")
	}
	b := approve(t, c, p, SuccessionInput{Image: img, Stores: []string{"gmail"}})
	if _, err := c.Certify(&b, id); err == nil {
		t.Fatal("one machine got two lines")
	}
	forged := SignedDoc{Payload: a.Payload, Sig: newPhone().sign(a.Payload)}
	if _, err := tryStart(c, forged); err == nil {
		t.Fatal("certified with an approval the core didn't sign")
	}
}

func TestResumeByDeadMachineExactlyOnce(t *testing.T) {
	c, f, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	image := f.machines // keep vet quiet about f
	_ = image
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	in := SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}}
	ch, _ := c.Succession(in)
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("resumed from a live machine")
	}
	if _, err := c.Kill(old); err != nil {
		t.Fatal(err)
	}
	a := pl(t)(c.ApproveByDeadMachine(&ch))
	if a["kind"] != "approval" || a["by"] != "dead-machine" {
		t.Fatalf("got %v", a)
	}
	ad, _ := c.ApproveByDeadMachine(&ch)
	start(t, c, ad)
	// the same predecessor can't have a second successor (no fork), even if killed again
	c.Kill(old)
	ch2, _ := c.Succession(in)
	if _, err := c.ApproveByDeadMachine(&ch2); err == nil {
		t.Fatal("forked: a used predecessor got a second approval")
	}
	ad2, _ := c.ApproveByPhone(&ch2, p.sign(ch2.Payload))
	if _, err := tryStart(c, ad2); err == nil {
		t.Fatal("forked: a used predecessor got a second machine")
	}
}

func TestApproveByDeadMachineRefusesChanges(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	c.Kill(old)
	for _, in := range []SuccessionInput{
		{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default", "gmail"}},
		{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}, Options: Options{Harness: "opencode"}},
		{Predecessor: &cert, Image: "ghcr.io/de0ch/jarvis2-session:2", Stores: []string{"default"}},
	} {
		ch, _ := c.Succession(in)
		if _, err := c.ApproveByDeadMachine(&ch); err == nil {
			t.Fatalf("changed %+v without the phone", in)
		}
	}
}

func TestUpgradeIsApprovedBeforeTheOldMachineGoes(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	// the iPhone approves the new image before the old machine is killed
	a := approve(t, c, p, SuccessionInput{Predecessor: &cert, Image: "ghcr.io/de0ch/jarvis2-session:2", Stores: []string{"default"}})
	if _, err := tryStart(c, a); err == nil {
		t.Fatal("started a successor while the predecessor runs")
	}
	c.Kill(old)
	start(t, c, a)
	a2 := approve(t, c, p, SuccessionInput{Predecessor: &cert, Image: "ghcr.io/de0ch/jarvis2-session:2", Stores: []string{"default"}})
	if _, err := tryStart(c, a2); err == nil {
		t.Fatal("a used predecessor got a second successor")
	}
}

func TestBurnIsASuccessionToTheNullImage(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	burn := SuccessionInput{Predecessor: &cert, Image: NullImage}
	for _, bad := range []SuccessionInput{
		{Image: NullImage},
		{Predecessor: &cert, Image: NullImage, Stores: []string{"default"}},
		{Predecessor: &cert, Image: NullImage, Options: Options{Harness: "claude"}},
	} {
		if _, err := c.Succession(bad); err == nil {
			t.Fatalf("accepted a burn with %+v", bad)
		}
	}
	ch, _ := c.Succession(burn)
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("burned a live machine")
	}
	c.Kill(old)
	a, err := c.ApproveByDeadMachine(&ch)
	if err != nil {
		t.Fatal(err)
	}
	b := pl(t)(tryStart(c, a))
	if b["kind"] != "burn-cert" || b["predecessorId"] != old {
		t.Fatalf("got %v", b)
	}
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	ch2, _ := c.Succession(SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}})
	if _, err := c.ApproveByDeadMachine(&ch2); err == nil {
		t.Fatal("a burnt machine resumed")
	}
	a2 := approve(t, c, p, SuccessionInput{Predecessor: &cert, Image: img, Stores: []string{"default"}})
	if _, err := tryStart(c, a2); err == nil {
		t.Fatal("a burnt machine got a successor")
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

func TestAddAStoreToARunningSession(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default")
	set := []string{"default", "gmail"}
	// succession(machine → same machine, old set + one): only the iPhone answers it, and it is a cert at once
	ch := pl(t)(c.Succession(SuccessionInput{Predecessor: &cert, Machine: id, Stores: set}))
	if ch["request"].(map[string]any)["addedStore"] != "gmail" {
		t.Fatal("challenge doesn't name the added store")
	}
	chd, _ := c.Succession(SuccessionInput{Predecessor: &cert, Machine: id, Stores: set})
	if _, err := c.ApproveByDeadMachine(&chd); err == nil {
		t.Fatal("approve_by_dead_machine added a store")
	}
	cert2 := pl(t)(c.ApproveByPhone(&chd, p.sign(chd.Payload)))
	if cert2["kind"] != "succession-cert" || cert2["machine"].(map[string]any)["id"] != id {
		t.Fatalf("got %v", cert2)
	}
	c2, _ := c.ApproveByPhone(&chd, p.sign(chd.Payload))
	unlock(t, c, p, "default")
	unlock(t, c, p, "gmail")
	if _, err := c.PullSecrets(&c2); err != nil {
		t.Fatal(err)
	}
	// not zero, not two, not a swap, not a different harness
	for _, bad := range []SuccessionInput{
		{Predecessor: &cert, Machine: id, Stores: []string{"default"}},
		{Predecessor: &c2, Machine: id, Stores: []string{"claude", "default", "gmail", "openrouter"}},
		{Predecessor: &cert, Machine: id, Stores: []string{"gmail"}},
		{Predecessor: &cert, Machine: id, Stores: set, Options: Options{Harness: "opencode"}},
	} {
		if ch, err := c.Succession(bad); err == nil {
			if _, err := c.ApproveByPhone(&ch, p.sign(ch.Payload)); err == nil {
				t.Fatalf("accepted %v", bad.Stores)
			}
		}
	}
	// a killed machine can't grow its set, and a resume from it keeps the grown set automatically
	c.Kill(id)
	chr, _ := c.Succession(SuccessionInput{Predecessor: &c2, Image: f.machineImage(c, &c2), Stores: set})
	a, err := c.ApproveByDeadMachine(&chr)
	if err != nil {
		t.Fatal(err)
	}
	start(t, c, a)
}

func (f *fakeFly) machineImage(c *Core, cert *SignedDoc) string {
	var cc Cert
	json.Unmarshal([]byte(cert.Payload), &cc)
	return cc.Machine.Image
}

func TestSensitivityOnlyGrows(t *testing.T) {
	c, _, p := setup(t)
	// create: once, empty, not sensitive; a write keeps it so
	pl(t)(c.CreateStore("notes"))
	if _, err := c.CreateStore("notes"); err == nil {
		t.Fatal("created a store twice")
	}
	if _, err := c.CreateStore("gmail"); err == nil {
		t.Fatal("re-created a sensitive store as not sensitive")
	}
	if _, err := c.CreateStore(FlyStore); err == nil {
		t.Fatal("created the Fly store")
	}
	if _, err := c.UnlockBegin("notes"); err == nil {
		t.Fatal("unlocked an empty store")
	}
	if w := pl(t)(c.WriteStore(writeStore(t, c, p, "notes", map[string]string{"N": "1"}))); w["sensitive"] != false {
		t.Fatalf("got %v", w)
	}
	// a store the core never created is sensitive
	if w := pl(t)(c.WriteStore(writeStore(t, c, p, "fresh", map[string]string{"F": "1"}))); w["sensitive"] != true {
		t.Fatalf("got %v", w)
	}
	// the one-way upgrade
	pl(t)(c.MarkSensitive("notes"))
	if _, err := c.MarkSensitive("notes"); err == nil {
		t.Fatal("upgraded twice")
	}
	if _, err := c.CreateStore("notes"); err == nil {
		t.Fatal("downgraded by re-creating")
	}
	ch := pl(t)(c.Succession(SuccessionInput{Image: img, Stores: []string{"default", "gmail", "notes"}}))
	if fmt.Sprint(ch["request"].(map[string]any)["sensitive"]) != "[gmail notes]" {
		t.Fatalf("got %v", ch["request"])
	}
	if _, err := c.WriteStore(writeStore(t, c, p, FlyStore, map[string]string{"FLY_API_TOKEN": "evil"})); err == nil {
		t.Fatal("wrote the Fly store")
	}
	if _, err := c.Succession(SuccessionInput{Image: img, Stores: []string{FlyStore}}); err == nil {
		t.Fatal("the Fly store went to a session")
	}
}

// the machine's side of a downgrade: a new key pair, and the challenge signed with its current key
func TestDowngradeInPlace(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default", "gmail")
	unlock(t, c, p, "default")
	unlock(t, c, p, "gmail")
	m := f.machines[id]
	oldSigner := &phone{sig: ecdsaFromECDH(m.sig)}
	nEnc, _ := ecdh.P256().GenerateKey(rand.Reader)
	nSig, _ := ecdh.P256().GenerateKey(rand.Reader)
	in := SuccessionInput{Predecessor: &cert, Machine: id, Stores: []string{"default"},
		NewEncryptionKey: b64.EncodeToString(nEnc.PublicKey().Bytes()), NewSigningKey: b64.EncodeToString(nSig.PublicKey().Bytes())}
	for _, bad := range []SuccessionInput{
		{Predecessor: &cert, Machine: id, Stores: []string{"default", "claude"}, NewEncryptionKey: in.NewEncryptionKey, NewSigningKey: in.NewSigningKey},
		{Predecessor: &cert, Machine: id, Stores: []string{"default"}, NewEncryptionKey: m2k(m.enc), NewSigningKey: m2k(m.sig)},
	} {
		if _, err := c.Succession(bad); err == nil {
			t.Fatalf("accepted %+v", bad.Stores)
		}
	}
	ch, err := c.Succession(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApproveByOldKey(&ch, newPhone().sign(ch.Payload)); err == nil {
		t.Fatal("a downgrade to someone else's keys was accepted")
	}
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("approve_by_dead_machine approved a downgrade")
	}
	cert2, err := c.ApproveByOldKey(&ch, oldSigner.sign(ch.Payload))
	if err != nil {
		t.Fatal(err)
	}
	// the new cert pulls only the subset, sealed to the new key
	d := pl(t)(c.PullSecrets(&cert2))
	var out struct{ Sealed Sealed }
	b, _ := json.Marshal(d)
	json.Unmarshal(b, &out)
	plain, err := OpenSealed(nEnc, out.Sealed, "jarvis2/secrets")
	if err != nil {
		t.Fatal("not sealed to the new key")
	}
	if strings.Contains(string(plain), "secret") {
		t.Fatal("gmail still came through")
	}
	// a further downgrade must be signed with the NEW key (the one in the cert it continues)
	n2, _ := ecdh.P256().GenerateKey(rand.Reader)
	n3, _ := ecdh.P256().GenerateKey(rand.Reader)
	ch2, err := c.Succession(SuccessionInput{Predecessor: &cert2, Machine: id, Stores: []string{}, NewEncryptionKey: m2k(n2), NewSigningKey: m2k(n3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApproveByOldKey(&ch2, oldSigner.sign(ch2.Payload)); err == nil {
		t.Fatal("the old key signed for a cert that names the new one")
	}
	if _, err := c.ApproveByOldKey(&ch2, (&phone{sig: ecdsaFromECDH(nSig)}).sign(ch2.Payload)); err != nil {
		t.Fatal(err)
	}
}

func m2k(k *ecdh.PrivateKey) string { return b64.EncodeToString(k.PublicKey().Bytes()) }

func ecdsaFromECDH(k *ecdh.PrivateKey) *ecdsa.PrivateKey {
	x, y := elliptic.Unmarshal(elliptic.P256(), k.PublicKey().Bytes())
	d := new(big.Int).SetBytes(k.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}
