package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// challengeNonce: the nonce of a core-signed challenge (what an unlock for a Start names)
func challengeNonce(ch SignedDoc) string {
	var m struct{ Nonce string }
	json.Unmarshal([]byte(ch.Payload), &m)
	return m.Nonce
}

// startWithUnlocks: a Start as the app does it — the challenge, its locked stores unlocked for that challenge
// only, the phone's approval, the machine, its cert
func startWithUnlocks(t *testing.T, c *Core, p *phone, stores ...string) (SignedDoc, string) {
	t.Helper()
	ch, err := routerSuccession(c, SuccessionInput{Image: img, Stores: stores})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range stores {
		unlockFor(t, c, p, n, challengeNonce(ch))
	}
	a, err := c.ApproveByPhone(&ch, p.sign(ch.Payload), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return start(t, c, a)
}

type pulled struct {
	Kind, Machine string
	Sealed        Sealed
	Carry         string
}

func pull(t *testing.T, c *Core, cert SignedDoc, carry string) pulled {
	t.Helper()
	d, err := c.PullSecrets(&cert, carry)
	if err != nil {
		t.Fatal(err)
	}
	var out pulled
	json.Unmarshal([]byte(d.Payload), &out)
	if out.Carry == "" {
		t.Fatal("no carry blob in the answer")
	}
	return out
}

func values(t *testing.T, k *ecdh.PrivateKey, out pulled) map[string]string {
	t.Helper()
	plain, err := OpenSealed(k, out.Sealed, "jarvis2/secrets")
	if err != nil {
		t.Fatal("not sealed to that machine's key")
	}
	v := map[string]string{}
	json.Unmarshal(plain, &v)
	return v
}

func locked(t *testing.T, err error, store string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "store "+store+" is locked") || err.(*Err).Status != 423 {
		t.Fatalf("want 423 store %s is locked, got %v", store, err)
	}
}

func TestAStartsUnlockIsForThatSessionAndLocksAgainOnceItPulled(t *testing.T) {
	c, f, p := setup(t)
	// another session holding the same store, approved before: the Start's unlock is not for it
	other, _ := newLine(t, c, p, "default")
	cert, id := startWithUnlocks(t, c, p, "default", "gmail")
	if _, err := c.PullSecrets(&other, ""); err == nil {
		t.Fatal("an unlock for one session opened the store to another")
	}
	st := pl(t)(c.Stores("n"))
	for _, r := range st["stores"].([]any) {
		if r.(map[string]any)["unlocked"] == true {
			t.Fatalf("an unlock for one session shows as open to all: %v", r)
		}
	}
	ul := pl(t)(c.ListUnlocked("n"))["unlocked"].([]any)
	if len(ul) != 2 || ul[0].(map[string]any)["for"] == "" {
		t.Fatalf("the unlocked list doesn't name what they are for: %v", ul)
	}
	out := pull(t, c, cert, "")
	if v := values(t, f.machines[id].enc, out); v["A"] != "1" || v["G"] != "secret" {
		t.Fatalf("got %v", v)
	}
	if len(c.unlocked) != 0 {
		t.Fatal("the stores stayed unlocked after the session pulled")
	}
	if len(pl(t)(c.ListUnlocked("n"))["unlocked"].([]any)) != 0 {
		t.Fatal("list_unlocked not empty")
	}
	// the same machine pulls again (a restart of its boot, jarvis2 add-store's re-pull): from its carry blob
	if _, err := c.PullSecrets(&cert, ""); err == nil {
		t.Fatal("pulled with no unlock and no carry")
	}
	again := pull(t, c, cert, out.Carry)
	if v := values(t, f.machines[id].enc, again); v["G"] != "secret" {
		t.Fatalf("got %v", v)
	}
	// another line can't read this line's blob
	_, err := c.PullSecrets(&other, out.Carry)
	locked(t, err, "default")
}

func TestAStandingUnlockStaysOpenAfterAPull(t *testing.T) {
	c, _, p := setup(t)
	id := unlock(t, c, p, "default")
	cert, _ := newLine(t, c, p, "default")
	pull(t, c, cert, "")
	if !c.standing("default") {
		t.Fatal("a pull locked a standing unlock")
	}
	pl(t)(c.Lock(id))
	if len(c.unlocked) != 0 {
		t.Fatal("not locked")
	}
}

func TestAnUnusedUnlockForOneSessionLapses(t *testing.T) {
	c, _, p := setup(t)
	ch, _ := routerSuccession(c, SuccessionInput{Image: img, Stores: []string{"default"}})
	unlockFor(t, c, p, "default", challengeNonce(ch))
	now := time.Now()
	c.now = func() time.Time { return now.Add(scopedUnlockTTL + time.Minute) }
	if len(pl(t)(c.ListUnlocked("n"))["unlocked"].([]any)) != 0 || len(c.unlocked) != 0 {
		t.Fatal("an unused unlock for one session didn't lapse")
	}
	if _, err := c.UnlockBegin("default", "not-a-nonce"); err == nil {
		t.Fatal("an unlock for something that isn't a nonce")
	}
}

func TestAResumeCarriesTheSecretsWithNoStoreUnlocked(t *testing.T) {
	c, f, p := setup(t)
	cert, id := startWithUnlocks(t, c, p, "default", "gmail")
	out := pull(t, c, cert, "")
	pl(t)(c.KillWithSnapshot(id, nil))
	ch, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: f.machineImage(c, &cert), Stores: []string{"default", "gmail"}})
	a := pl(t)(c.ApproveByDeadMachine(&ch))
	if a["kind"] != "approval" {
		t.Fatal(a)
	}
	ad, _ := c.ApproveByDeadMachine(&ch)
	cert2, id2 := startCarry(t, c, ad, out.Carry) // the router hands certify the line's blob
	if len(c.unlocked) != 0 {
		t.Fatal("a store is unlocked")
	}
	// the predecessor's blob opens for the certified successor, sealed to the successor's key
	v := values(t, f.machines[id2].enc, pull(t, c, cert2, out.Carry))
	if v["A"] != "1" || v["G"] != "secret" {
		t.Fatalf("got %v", v)
	}
	// certify answered it rebound to the successor at once, beside the cert
	if cp, err := c.openCarry(cert2.Carry); err != nil || cp.Machine != id2 || len(cp.Stores) != 2 {
		t.Fatalf("rebound carry: %+v %v", cp, err)
	}
	pull(t, c, cert2, cert2.Carry)
	// the dead predecessor's own cert gets nothing from it
	_, err := c.PullSecrets(&cert, out.Carry)
	locked(t, err, "default")
	// the next resume carries on from the successor's blob; the old one is no longer this line's newest machine's
	pl(t)(c.KillWithSnapshot(id2, nil))
	ch3, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert2, Image: f.machineImage(c, &cert2), Stores: []string{"default", "gmail"}})
	a3, _ := c.ApproveByDeadMachine(&ch3)
	cert3, _ := start(t, c, a3)
	_, err = c.PullSecrets(&cert3, out.Carry)
	locked(t, err, "default")
	pull(t, c, cert3, cert2.Carry)
}

func TestAResumedMachineThatNeverPulledKeepsTheChain(t *testing.T) {
	c, f, p := setup(t)
	cert, id := startWithUnlocks(t, c, p, "default")
	out := pull(t, c, cert, "")
	pl(t)(c.KillWithSnapshot(id, nil))
	ch, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: f.machineImage(c, &cert), Stores: []string{"default"}})
	a, _ := c.ApproveByDeadMachine(&ch)
	cert2, id2 := startCarry(t, c, a, out.Carry) // rebound beside the cert
	pl(t)(c.KillWithSnapshot(id2, nil))          // it died before it pulled
	ch3, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert2, Image: f.machineImage(c, &cert2), Stores: []string{"default"}})
	a3, _ := c.ApproveByDeadMachine(&ch3)
	cert3, id3 := start(t, c, a3)
	if v := values(t, f.machines[id3].enc, pull(t, c, cert3, cert2.Carry)); v["A"] != "1" {
		t.Fatalf("got %v", v)
	}
}

func TestOnlyThisCoreOpensACarryBlob(t *testing.T) {
	c, _, p := setup(t)
	cert, _ := startWithUnlocks(t, c, p, "default")
	out := pull(t, c, cert, "")
	other, _, _ := setup(t)
	if _, err := other.openCarry(out.Carry); err == nil {
		t.Fatal("another core (a restart, a Recover) opened the blob")
	}
	raw, _ := b64.DecodeString(out.Carry)
	raw[len(raw)-1] ^= 1
	if _, err := c.openCarry(b64.EncodeToString(raw)); err == nil {
		t.Fatal("an altered blob opened")
	}
	// a blob made with any other key (a forgery) doesn't open
	k := make([]byte, 32)
	rand.Read(k)
	forged, _ := json.Marshal(carryPayload{Kind: "carry", Machine: "x", Stores: map[string]map[string]string{"default": {"A": "evil"}}})
	if _, err := c.openCarry(b64.EncodeToString(gcmSeal(k, forged, []byte(carryAAD)))); err == nil {
		t.Fatal("a forged blob opened")
	}
	if cert.Carry != "" {
		t.Fatal("a carry beside a cert certified with none")
	}
}

func TestADowngradeDropsItsStoresFromTheCarry(t *testing.T) {
	c, f, p := setup(t)
	cert, id := startWithUnlocks(t, c, p, "default", "gmail")
	out := pull(t, c, cert, "")
	m := f.machines[id]
	nEnc, _ := ecdh.P256().GenerateKey(rand.Reader)
	nSig, _ := ecdh.P256().GenerateKey(rand.Reader)
	ch, err := routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: []string{"default"}, NewEncryptionKey: m2k(nEnc), NewSigningKey: m2k(nSig)})
	if err != nil {
		t.Fatal(err)
	}
	cert2, err := c.ApproveByOldKey(&ch, (&phone{sig: ecdsaFromECDH(m.sig)}).sign(ch.Payload), out.Carry)
	if err != nil {
		t.Fatal(err)
	}
	cp, _ := c.openCarry(cert2.Carry)
	if _, ok := cp.Stores["gmail"]; ok || len(cp.Stores) != 1 {
		t.Fatalf("the downgrade's carry kept %v", cp.Stores)
	}
	v := values(t, nEnc, pull(t, c, cert2, cert2.Carry))
	if v["A"] != "1" || v["G"] != "" {
		t.Fatalf("got %v", v)
	}
}

func TestAnAddedStoreIsUnlockedForItsChallengeOnly(t *testing.T) {
	c, f, p := setup(t)
	cert, id := startWithUnlocks(t, c, p, "default")
	out := pull(t, c, cert, "")
	ch, err := routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: []string{"default", "gmail"}})
	if err != nil {
		t.Fatal(err)
	}
	unlockFor(t, c, p, "gmail", challengeNonce(ch))
	cert2, err := c.ApproveByPhone(&ch, p.sign(ch.Payload), out.Carry, nil)
	if err != nil {
		t.Fatal(err)
	}
	// the machine's carry, rebound beside its new cert: its stores so far (the added one comes from its unlock)
	if cp, err := c.openCarry(cert2.Carry); err != nil || len(cp.Stores) != 1 || cp.Stores["default"] == nil {
		t.Fatalf("rebound carry %+v %v", cp, err)
	}
	v := values(t, f.machines[id].enc, pull(t, c, cert2, cert2.Carry))
	if v["A"] != "1" || v["G"] != "secret" {
		t.Fatalf("got %v", v)
	}
	if len(c.unlocked) != 0 {
		t.Fatal("the added store stayed unlocked")
	}
}

func TestDestroyEndsTheCarry(t *testing.T) {
	c, f, p := setup(t)
	cert, id := startWithUnlocks(t, c, p, "default")
	out := pull(t, c, cert, "")
	pl(t)(c.KillWithSnapshot(id, nil))
	ch, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: NullImage})
	a, _ := c.ApproveByDeadMachine(&ch)
	pl(t)(c.Certify(&a, nil, ""))
	// the line is burnt: no successor can be certified, and the dead machine's own cert gets nothing
	ch2, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: f.machineImage(c, &cert), Stores: []string{"default"}})
	if _, err := c.ApproveByDeadMachine(&ch2); err == nil {
		t.Fatal("a burnt line resumed")
	}
	_, err := c.PullSecrets(&cert, out.Carry)
	locked(t, err, "default")
}
