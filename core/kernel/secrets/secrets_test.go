package secrets

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// ---- the phone, the app and the writers, outside secrets ------------------------------------------------

// phone: the iPhone (signing + the Enclave's key agreement, here in software); also the master key
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

// shareOf: the phone's x(p·E), sealed to the one-off T
func (p *phone) shareOf(e, t string) kernel.Sealed {
	eb, _ := b64.DecodeString(e)
	E, _ := ecdh.P256().NewPublicKey(eb)
	x, _ := p.agr.ECDH(E)
	s, _ := kernel.SealTo(t, x, infoShare)
	return s
}

func pl(t *testing.T) func(kernel.SignedDoc, error) map[string]any {
	return func(d kernel.SignedDoc, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		json.Unmarshal([]byte(d.Payload), &m)
		return m
	}
}

// sealKey: one key's value under a fresh data key, wrapped to P + K (what a writer does)
func sealKey(t *testing.T, c *Secrets, p *phone, store, key, value string) KeyEntry {
	t.Helper()
	pb, _ := b64.DecodeString(p.agreementKey())
	combined, err := AddPoints(pb, c.agreement.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	dk := make([]byte, 32)
	rand.Read(dk)
	w, err := WrapToPoint(combined, dk)
	if err != nil {
		t.Fatal(err)
	}
	return KeyEntry{Store: store, Key: key, Wrapped: w, Data: b64.EncodeToString(kernel.GCMSeal(dk, []byte(value), KeyAAD(store, key)))}
}

// write: a key written as `writer`, with its live copy sealed to secrets
func write(t *testing.T, c *Secrets, p *phone, writer, store, key, value string) (kernel.SignedDoc, error) {
	t.Helper()
	x := sealKey(t, c, p, store, key, value)
	live, _ := kernel.SealTo(c.AgreementKey(), []byte(value), LiveInfo(store, key))
	in := WriteKeyInput{Store: store, Key: key, Wrapped: x.Wrapped, Data: x.Data, Live: &live, Writer: writer}
	switch writer {
	case "setup":
		in.Sig = "c2ln"
	case "machine":
		in.Machine = "e286"
	}
	return c.WriteKey(in)
}

var testValues = map[string]map[string]string{
	"default": {"A": "1", "B": "2"},
	"gmail":   {"G": "secret"},
	"claude":  {"CLAUDE_CREDENTIALS": "c"},
}

// claimFor: the statement naming the master key, secrets and the phone, and the bundle sealed to secrets
func claimFor(c *Secrets, master, p *phone, b claimBundle) (string, string, kernel.Sealed) {
	plain, _ := json.Marshal(b)
	sum := sha256.Sum256(plain)
	var st claimStatement
	st.Kind, st.Master = "claim", master.signingKey()
	st.Core.SigningKey, st.Core.AgreementKey = c.signer.PublicKey(), c.AgreementKey()
	st.Phone.SigningKey, st.Phone.AgreementKey = p.signingKey(), p.agreementKey()
	st.BundleSha256 = hex.EncodeToString(sum[:])
	sb, _ := json.Marshal(st)
	bundle, _ := kernel.SealTo(c.AgreementKey(), plain, infoClaim)
	return string(sb), master.sign(string(sb)), bundle
}

func recoverBundle(t *testing.T, c *Secrets, p *phone) claimBundle {
	b := claimBundle{Format: "keys", NotSensitive: []string{"default", "claude"}}
	for _, n := range sortedKeys(testValues) {
		b.Stores = append(b.Stores, n)
		for _, k := range sortedKeys(testValues[n]) {
			b.Keys = append(b.Keys, sealKey(t, c, p, n, k, testValues[n][k]))
		}
	}
	return b
}

type env struct {
	c         *Secrets
	w         *ktest.World
	p, master *phone
	gh        *FakeGitHub
}

func newSecrets(t *testing.T) env {
	t.Helper()
	w := ktest.New(t)
	gh := NewFakeGitHub()
	c, err := New(w.Keys["secrets"], w.Roster, gh)
	if err != nil {
		t.Fatal(err)
	}
	return env{c: c, w: w, p: newPhone(), master: newPhone(), gh: gh}
}

func setup(t *testing.T) env {
	t.Helper()
	e := newSecrets(t)
	s, sig, b := claimFor(e.c, e.master, e.p, recoverBundle(t, e.c, e.p))
	pl(t)(e.c.Claim(s, sig, b))
	return e
}

// unlock: begin, the phone's shares, finish → the unlock id
func unlock(t *testing.T, e env, store string) string {
	t.Helper()
	b, err := e.c.UnlockBegin(store)
	if err != nil {
		t.Fatal(err)
	}
	return finishUnlock(t, e, b)
}

func finishUnlock(t *testing.T, e env, b kernel.SignedDoc) string {
	t.Helper()
	var bg struct {
		Pending, T string
		Keys       []struct{ Key, E string }
	}
	json.Unmarshal([]byte(b.Payload), &bg)
	shares := map[string]kernel.Sealed{}
	for _, k := range bg.Keys {
		shares[k.Key] = e.p.shareOf(k.E, bg.T)
	}
	return pl(t)(e.c.UnlockFinish(bg.Pending, shares))["id"].(string)
}

type answer struct {
	Kind     string
	Grant    string
	Machine  kernel.Object
	Stores   []string
	Locked   []string
	Missing  []string
	Withheld []string
	Sealed   kernel.Sealed
}

// pull: the grant's answer, checked as secrets-signed, opened with the machine's key (nil = don't open)
func pull(t *testing.T, e env, g kernel.SignedDoc, enc *ecdh.PrivateKey) (answer, map[string]map[string]string) {
	t.Helper()
	d, err := e.c.Pull(g)
	if err != nil {
		t.Fatal(err)
	}
	var a answer
	if err := kernel.Open(e.w.Keys["secrets"].PublicKey(), d, &struct {
		*answer
		Conditions kernel.Conditions `json:"conditions"`
		Versions   map[string]string `json:"versions"`
	}{answer: &a}); err != nil {
		t.Fatal(err)
	}
	if enc == nil {
		return a, nil
	}
	plain, err := kernel.OpenSealed(enc, a.Sealed, "jarvis2/secrets")
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]map[string]string{}
	json.Unmarshal(plain, &vals)
	return a, vals
}

// ---- claim and wipe ----------------------------------------------------------------------------------

func TestRecoverOnceOnlyOnAnEmptySecrets(t *testing.T) {
	e := newSecrets(t)
	s, sig, b := claimFor(e.c, e.master, e.p, recoverBundle(t, e.c, e.p))
	// forbidden: another key's signature, a statement for another secrets, a bundle not the signed one
	if _, err := e.c.Claim(s, newPhone().sign(s), b); err == nil {
		t.Fatal("claimed with another master's signature")
	}
	other := newSecrets(t)
	s2, sig2, b2 := claimFor(other.c, e.master, e.p, claimBundle{Format: "keys"})
	if _, err := e.c.Claim(s2, sig2, b2); err == nil {
		t.Fatal("claimed with a statement naming another secrets")
	}
	_, _, b3 := claimFor(e.c, e.master, e.p, claimBundle{Format: "keys"})
	if _, err := e.c.Claim(s, sig, b3); err == nil {
		t.Fatal("claimed with a bundle the master key didn't sign")
	}
	pl(t)(e.c.Claim(s, sig, b))
	if _, err := e.c.Claim(s, sig, b); err == nil {
		t.Fatal("claimed twice")
	}
	st := pl(t)(e.c.State())
	if st["master"] != e.master.signingKey() {
		t.Fatal("state names the master key")
	}
	// a store named "core" never exists
	f := newSecrets(t)
	s4, sig4, b4 := claimFor(f.c, f.master, f.p, claimBundle{Format: "keys", Stores: []string{"core"}})
	if _, err := f.c.Claim(s4, sig4, b4); err == nil {
		t.Fatal("a store named core claimed")
	}
}

func TestWipeOnlyByTheCurrentMasterKey(t *testing.T) {
	e := setup(t)
	exited := make(chan bool, 1)
	e.c.SetExit(func() { exited <- true })
	st, _ := json.Marshal(map[string]string{"kind": "wipe", "core": e.c.signer.PublicKey()})
	if _, err := e.c.Wipe(string(st), newPhone().sign(string(st))); err == nil {
		t.Fatal("wiped by another key")
	}
	other, _ := json.Marshal(map[string]string{"kind": "wipe", "core": "someone else"})
	if _, err := e.c.Wipe(string(other), e.master.sign(string(other))); err == nil {
		t.Fatal("a wipe naming another secrets")
	}
	pl(t)(e.c.Wipe(string(st), e.master.sign(string(st))))
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("no exit")
	}
}

// ---- writing, unlocking, pulling -----------------------------------------------------------------------

// grantFor: a mover-made grant on a machine naming these allowed strings
func grantFor(e env, t *testing.T, m kernel.Object, allowed ...string) kernel.SignedDoc {
	return e.w.Grant(t, "mover", "mover", m, ktest.P(allowed, "session:s1"))
}

func TestAGrantPullsTheStoresItNamesSealedToItsMachine(t *testing.T) {
	e := setup(t)
	m := ktest.NewMachine(t, "m1")
	unlock(t, e, "default")
	unlock(t, e, "claude")
	a, vals := pull(t, e, grantFor(e, t, m.Obj, "store:default", "store:claude", "store:gmail", "store:nope", "shell"), m.Enc)
	if a.Machine != m.Obj || len(a.Stores) != 2 || vals["default"]["A"] != "1" || vals["claude"]["CLAUDE_CREDENTIALS"] != "c" {
		t.Fatalf("%+v %v", a, vals)
	}
	if len(a.Locked) != 1 || a.Locked[0] != "gmail" || len(a.Missing) != 1 || a.Missing[0] != "nope" {
		t.Fatalf("locked %v missing %v", a.Locked, a.Missing)
	}
	if _, ok := vals["gmail"]; ok {
		t.Fatal("a locked store served")
	}
	// another machine's key doesn't open it
	if _, err := kernel.OpenSealed(ktest.NewMachine(t, "m2").Enc, a.Sealed, "jarvis2/secrets"); err == nil {
		t.Fatal("opened by another machine")
	}
	// a merged grant pulls too; a cofinite grant names every store it doesn't leave out
	merged := e.w.Grant(t, "merger", "merger", m.Obj, kernel.Pair{Allowed: kernel.Except("store:claude"), Conditions: kernel.Conditions{}})
	a2, vals2 := pull(t, e, merged, m.Enc)
	if len(a2.Stores) != 1 || a2.Stores[0] != "default" || vals2["claude"] != nil || len(a2.Locked) != 1 {
		t.Fatalf("%+v", a2)
	}
}

// Forbidden: a grant not made by the mover or the merger
func TestSecretsRefusesGrantsNotMadeByTheMoverOrMerger(t *testing.T) {
	e := setup(t)
	unlock(t, e, "default")
	m := ktest.NewMachine(t, "m1").Obj
	p := ktest.P([]string{"store:default"})
	for name, g := range map[string]kernel.SignedDoc{
		"root's ⊤ on the sink":               e.w.RootGrant(t),
		"by the mover's name, gullible key":  e.w.Grant(t, "mover", "gullible", m, p),
		"by the merger's name, identity key": e.w.Grant(t, "merger", "identity", m, p),
		"by the spawner":                     e.w.Grant(t, "spawner", "spawner", m, p),
		"by the phone":                       e.w.Grant(t, "phone", "phone", m, p),
		"by the root key on a machine":       e.w.Grant(t, "root", "root", m, kernel.Top()),
	} {
		if _, err := e.c.Pull(g); err == nil {
			t.Fatalf("%s: pulled", name)
		}
	}
	alt := grantFor(e, t, m, "store:gmail")
	alt.Payload = alt.Payload[:len(alt.Payload)-1] + ` ` + "}"
	if _, err := e.c.Pull(alt); err == nil {
		t.Fatal("an altered grant pulled")
	}
}

// A grant on a source or the sink seals to its hash-to-curve key, which nobody can open
func TestAGrantOnASourceOrTheSinkSealsToNobody(t *testing.T) {
	e := setup(t)
	unlock(t, e, "default")
	var to []string
	e.c.SetSeal(func(r string, plain []byte, info string) (kernel.Sealed, error) {
		to = append(to, r)
		return kernel.SealTo(r, plain, info)
	})
	src := ktest.Source(ktest.Image, "")
	for _, o := range []kernel.Object{src, ktest.SinkObj()} {
		a, _ := pull(t, e, grantFor(e, t, o, "store:default"), nil)
		if len(a.Stores) != 1 {
			t.Fatal("served (sealed to nobody)")
		}
	}
	if to[0] != kernel.HashToKey("jarvis2 "+src.ID+" encryption") || to[1] != kernel.HashToKey("jarvis2 sink encryption") {
		t.Fatalf("sealed to %v", to)
	}
}

// The deploy-key token store and the reserved name are never served, whatever a grant names
func TestWithheldStoresAreNeverServed(t *testing.T) {
	e := setup(t)
	pl(t)(write(t, e.c, e.p, "setup", DeployKeyTokenStore, DeployKeyTokenKey, "gh"))
	if _, err := e.c.UnlockBegin(DeployKeyTokenStore); err == nil {
		t.Fatal("the token store unlocked")
	}
	m := ktest.NewMachine(t, "m1")
	a, vals := pull(t, e, e.w.Grant(t, "mover", "mover", m.Obj, kernel.Top()), m.Enc)
	if len(vals) != 0 || len(a.Locked) != 3 {
		t.Fatalf("%+v %v", a, vals)
	}
	a, _ = pull(t, e, grantFor(e, t, m.Obj, "store:"+DeployKeyTokenStore, "store:core"), m.Enc)
	if len(a.Withheld) != 2 || len(a.Stores) != 0 {
		t.Fatalf("%+v", a)
	}
}

// D1: a key written after the unlock (by anyone) is served on the next pull, without a new unlock; a delete goes too
func TestAWrittenKeyIsServedOnTheNextPull(t *testing.T) {
	e := setup(t)
	m := ktest.NewMachine(t, "m1")
	g := grantFor(e, t, m.Obj, "store:default")
	unlock(t, e, "default")
	for i, writer := range []string{"setup", "router", "machine"} {
		v := []string{"x", "y", "z"}[i]
		pl(t)(write(t, e.c, e.p, writer, "default", "A", v))
		if _, vals := pull(t, e, g, m.Enc); vals["default"]["A"] != v || vals["default"]["B"] != "2" {
			t.Fatalf("after a %s write: %v", writer, vals)
		}
	}
	pl(t)(e.c.WriteKey(WriteKeyInput{Store: "default", Key: "B", Delete: true, Writer: "router"}))
	if _, vals := pull(t, e, g, m.Enc); vals["default"]["B"] != "" || len(vals["default"]) != 1 {
		t.Fatalf("after a delete: %v", vals)
	}
	// a write between an unlock's begin and its finish reaches it too
	b, err := e.c.UnlockBegin("gmail")
	if err != nil {
		t.Fatal(err)
	}
	pl(t)(write(t, e.c, e.p, "router", "gmail", "G2", "new"))
	finishUnlock(t, e, b)
	if _, vals := pull(t, e, grantFor(e, t, m.Obj, "store:gmail"), m.Enc); vals["gmail"]["G2"] != "new" || vals["gmail"]["G"] != "secret" {
		t.Fatalf("written during the unlock: %v", vals)
	}
	// a store that is locked stays locked after a write (its next unlock opens the written key)
	pl(t)(write(t, e.c, e.p, "router", "claude", "CLAUDE_CREDENTIALS", "new-login"))
	if a, _ := pull(t, e, grantFor(e, t, m.Obj, "store:claude"), nil); len(a.Locked) != 1 {
		t.Fatal("a write unlocked a store")
	}
	unlock(t, e, "claude")
	if _, vals := pull(t, e, grantFor(e, t, m.Obj, "store:claude"), m.Enc); vals["claude"]["CLAUDE_CREDENTIALS"] != "new-login" {
		t.Fatal("the next unlock opens the written key")
	}
}

// D2: an unlock never ends by itself — not after pulls, not with time; only a lock call ends it
func TestAnUnlockNeverLocksByItself(t *testing.T) {
	e := setup(t)
	now := time.Now()
	e.c.SetClock(func() time.Time { return now })
	m := ktest.NewMachine(t, "m1")
	g := grantFor(e, t, m.Obj, "store:default")
	id := unlock(t, e, "default")
	for i := 0; i < 3; i++ {
		pull(t, e, g, m.Enc)
	}
	now = now.Add(365 * 24 * time.Hour)
	if a, vals := pull(t, e, g, m.Enc); len(a.Stores) != 1 || vals["default"]["A"] != "1" {
		t.Fatal("the unlock lapsed")
	}
	list := pl(t)(e.c.ListUnlocked("n"))["unlocked"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["id"] != id {
		t.Fatalf("the phone sees the open unlock: %v", list)
	}
	// two unlocks of one store: the plaintext goes with the last
	id2 := unlock(t, e, "default")
	pl(t)(e.c.Lock(id))
	if a, _ := pull(t, e, g, nil); len(a.Stores) != 1 {
		t.Fatal("locked with an id still open")
	}
	pl(t)(e.c.Lock(id2))
	if a, _ := pull(t, e, g, nil); len(a.Locked) != 1 {
		t.Fatal("still served after the last lock")
	}
	if _, err := e.c.Lock(id2); err == nil {
		t.Fatal("locked twice")
	}
}

func TestAWrongPhoneShareDoesntUnlock(t *testing.T) {
	e := setup(t)
	b, _ := e.c.UnlockBegin("default")
	var bg struct {
		Pending, T string
		Keys       []struct{ Key, E string }
	}
	json.Unmarshal([]byte(b.Payload), &bg)
	shares := map[string]kernel.Sealed{}
	for _, k := range bg.Keys {
		shares[k.Key] = newPhone().shareOf(k.E, bg.T)
	}
	if _, err := e.c.UnlockFinish(bg.Pending, shares); err == nil {
		t.Fatal("unlocked with another phone's share")
	}
	if _, err := e.c.UnlockFinish(bg.Pending, shares); err == nil {
		t.Fatal("a pending unlock tried twice")
	}
}

// Forbidden writes
func TestWriteRefusals(t *testing.T) {
	e := setup(t)
	x := sealKey(t, e.c, e.p, "default", "A", "v")
	live, _ := kernel.SealTo(e.c.AgreementKey(), []byte("v"), LiveInfo("default", "A"))
	otherKey, _ := kernel.SealTo(e.c.AgreementKey(), []byte("v"), LiveInfo("default", "B"))
	stranger, _ := kernel.SealTo(ktest.NewMachine(t, "x").Obj.EncryptionKey, []byte("v"), LiveInfo("default", "A"))
	base := WriteKeyInput{Store: "default", Key: "A", Wrapped: x.Wrapped, Data: x.Data, Live: &live, Writer: "router"}
	for name, f := range map[string]func(*WriteKeyInput){
		"no live copy":                       func(in *WriteKeyInput) { in.Live = nil },
		"live for another key":               func(in *WriteKeyInput) { in.Live = &otherKey },
		"live sealed to someone else":        func(in *WriteKeyInput) { in.Live = &stranger },
		"the reserved store":                 func(in *WriteKeyInput) { in.Store = "core" },
		"a bad key name":                     func(in *WriteKeyInput) { in.Key = "1A" },
		"an unknown writer":                  func(in *WriteKeyInput) { in.Writer = "phone" },
		"setup without its signature":        func(in *WriteKeyInput) { in.Writer = "setup" },
		"machine without an id":              func(in *WriteKeyInput) { in.Writer = "machine" },
		"router into the token store":        func(in *WriteKeyInput) { in.Store = DeployKeyTokenStore },
		"an entry for another store":         func(in *WriteKeyInput) { in.Store = "gmail" },
		"a delete of a key that's not there": func(in *WriteKeyInput) { in.Delete, in.Key = true, "NOPE" },
	} {
		in := base
		f(&in)
		if _, err := e.c.WriteKey(in); err == nil {
			t.Fatalf("%s: written", name)
		}
	}
	pl(t)(e.c.WriteKey(base))
}

func TestStoresListAndSensitivity(t *testing.T) {
	e := setup(t)
	pl(t)(e.c.CreateStore("fresh"))
	if _, err := e.c.CreateStore("fresh"); err == nil {
		t.Fatal("created twice")
	}
	for _, bad := range []string{"core", DeployKeyTokenStore, "Bad", ""} {
		if _, err := e.c.CreateStore(bad); err == nil {
			t.Fatalf("%q created", bad)
		}
	}
	pl(t)(e.c.MarkSensitive("fresh"))
	if _, err := e.c.MarkSensitive("fresh"); err == nil {
		t.Fatal("sensitive twice")
	}
	unlock(t, e, "default")
	rows := pl(t)(e.c.Stores("n"))["stores"].([]any)
	got := map[string]map[string]any{}
	for _, r := range rows {
		got[r.(map[string]any)["name"].(string)] = r.(map[string]any)
	}
	if got["default"]["unlocked"] != true || got["gmail"]["unlocked"] != false || got["gmail"]["sensitive"] != true ||
		got["default"]["sensitive"] != false || got["fresh"]["sensitive"] != true || got["fresh"]["empty"] != true {
		t.Fatalf("%v", got)
	}
	// a setup write makes a new store, sensitive
	pl(t)(write(t, e.c, e.p, "setup", "brand-new", "K", "v"))
	if pl(t)(e.c.Stores("n"))["stores"].([]any)[0].(map[string]any)["name"] != "brand-new" {
		t.Fatal("sorted list")
	}
}

// ---- restore -------------------------------------------------------------------------------------

func TestARestorePutsAVersionBackAndReachesOpenUnlocks(t *testing.T) {
	e := setup(t)
	m := ktest.NewMachine(t, "m1")
	g := grantFor(e, t, m.Obj, "store:default")
	unlock(t, e, "default")
	pl(t)(e.c.WriteKey(WriteKeyInput{Store: "default", Key: "A", Delete: true, Writer: "router"}))
	pl(t)(write(t, e.c, e.p, "router", "default", "B", "wrong"))
	var v struct {
		Versions []struct{ Seq int }
	}
	d, _ := e.c.Versions("default", "n")
	json.Unmarshal([]byte(d.Payload), &v)
	first := v.Versions[len(v.Versions)-1].Seq // the Recover's
	begin, err := e.c.RestoreBegin("default", first)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Pending, T string
		Put        []struct{ Key, E string }
	}
	json.Unmarshal([]byte(begin.Payload), &b)
	shares := map[string]kernel.Sealed{}
	for _, k := range b.Put {
		shares[k.Key] = e.p.shareOf(k.E, b.T)
	}
	// forbidden: without the phone's signature
	if _, err := e.c.RestoreFinish(b.Pending, newPhone().sign(begin.Payload), shares); err == nil {
		t.Fatal("restored without the phone")
	}
	begin, _ = e.c.RestoreBegin("default", first)
	json.Unmarshal([]byte(begin.Payload), &b)
	for _, k := range b.Put {
		shares[k.Key] = e.p.shareOf(k.E, b.T)
	}
	if _, err := e.c.RestoreFinish(b.Pending, e.p.sign(begin.Payload), shares); err != nil {
		t.Fatal(err)
	}
	if _, vals := pull(t, e, g, m.Enc); vals["default"]["B"] != "wrong" {
		t.Fatal("nothing changes before commit")
	}
	pl(t)(e.c.RestoreCommit(b.Pending))
	if _, vals := pull(t, e, g, m.Enc); vals["default"]["A"] != "1" || vals["default"]["B"] != "2" {
		t.Fatalf("the open unlock after the restore: %v", vals)
	}
}

// ---- deploy keys ---------------------------------------------------------------------------------

func sshKey() string {
	w := append([]byte("\x00\x00\x00\x0bssh-ed25519"), 0, 0, 0, 32)
	k := make([]byte, 32)
	rand.Read(k)
	binary.BigEndian.PutUint32(w[15:19], 32)
	return "ssh-ed25519 " + b64.EncodeToString(append(w, k...))
}

func TestDeployKeyAddAndRemoveNeedThePhone(t *testing.T) {
	e := setup(t)
	pl(t)(write(t, e.c, e.p, "setup", DeployKeyTokenStore, DeployKeyTokenKey, "gh-token"))
	repo, store := "DE0CH/china-train", "github-china-train"
	req := DeployKeyRequest{Action: "add", Repo: repo, Store: store, Title: "jarvis2 " + store, PublicKey: sshKey(),
		Keys: []KeyEntry{sealKey(t, e.c, e.p, store, DeployKeyPrefix+EnvSlug(repo), "PRIVATE")}}
	answer := func(begin kernel.SignedDoc, signer *phone) (string, kernel.Sealed, string) {
		var b struct{ Pending, E, T string }
		json.Unmarshal([]byte(begin.Payload), &b)
		return b.Pending, e.p.shareOf(b.E, b.T), signer.sign(begin.Payload)
	}
	begin, err := e.c.DeployKeyBegin(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.DeployKeyFinish(answer(begin, newPhone())); err == nil {
		t.Fatal("a deploy key without the phone")
	}
	begin, _ = e.c.DeployKeyBegin(req)
	pl(t)(e.c.DeployKeyFinish(answer(begin, e.p)))
	if len(e.gh.Keys["de0ch/china-train"]) != 1 || e.c.stores[store] == nil {
		t.Fatal("added")
	}
	// forbidden: a router or machine write into the repo's store
	if _, err := write(t, e.c, e.p, "router", store, "X", "y"); err == nil {
		t.Fatal("a router write into a deploy-key store")
	}
	unlock(t, e, store)
	m := ktest.NewMachine(t, "m1")
	if _, vals := pull(t, e, grantFor(e, t, m.Obj, "store:"+store), m.Enc); vals[store][DeployKeyPrefix+EnvSlug(repo)] != "PRIVATE" {
		t.Fatal("the repo's store pulls")
	}
	req.Action, req.Keys, req.PublicKey = "remove", nil, ""
	begin, _ = e.c.DeployKeyBegin(req)
	pl(t)(e.c.DeployKeyFinish(answer(begin, e.p)))
	if len(e.gh.Keys["de0ch/china-train"]) != 0 || e.c.stores[store] != nil || e.c.unlocked[store] != nil {
		t.Fatal("removed")
	}
}

// ---- HTTP ---------------------------------------------------------------------------------------

func TestRoutesAreStrict(t *testing.T) {
	e := setup(t)
	r := e.c.Routes()
	if _, err := r["POST /pull"]([]byte(`{"grant":{"payload":"","sig":""},"cert":{}}`)); err == nil {
		t.Fatal("an unknown field accepted")
	}
	if _, err := r["POST /unlock/begin"]([]byte(`{"store":"default","for":"x"}`)); err == nil {
		t.Fatal("an unlock for one session (the old shape) accepted")
	}
	if _, err := r["POST /stores"]([]byte(`{"nonce":"n"}`)); err != nil {
		t.Fatal(err)
	}
}
