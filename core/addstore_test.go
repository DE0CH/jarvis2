package main

// Two add-stores for one running machine, both filed before either is answered (2026-10-13: `identity` and `yyc`
// for one session, approved close together; the session ended with only the one answered last). Each challenge is
// made from the cert the machine had when it was filed, so the second answer continued a cert the first had
// replaced. Whatever order and timing the phone answers in, the machine ends with every store it approved, and
// nothing a downgrade dropped comes back.

import (
	"sort"
	"testing"
)

// addStoreChallenge: what the router files for "add store X to this machine", from the cert the machine has now
func addStoreChallenge(t *testing.T, c *Core, cert SignedDoc, id, store string) SignedDoc {
	t.Helper()
	stores := append(append([]string{}, certOf(t, cert).Stores...), store)
	ch, err := routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: sortedCopy(stores)})
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func TestTwoPendingAddStoresBothApprovedEndWithBoth(t *testing.T) {
	for _, order := range [][2]string{{"gmail", "openrouter"}, {"openrouter", "gmail"}} {
		c, f, p := setup(t)
		cert0, id := startWithUnlocks(t, c, p, "default")
		x0 := pull(t, c, cert0, "")
		// both filed against cert0 (each store unlocked for its own challenge, as the app does)
		ch := map[string]SignedDoc{}
		for _, s := range order {
			ch[s] = addStoreChallenge(t, c, cert0, id, s)
			unlockFor(t, c, p, s, challengeNonce(ch[s]))
		}
		sig := map[string]string{order[0]: p.sign(ch[order[0]].Payload), order[1]: p.sign(ch[order[1]].Payload)}
		cert1, err := c.ApproveByPhone(ptr(ch[order[0]]), sig[order[0]], x0.Carry, &cert0)
		if err != nil {
			t.Fatal(err)
		}
		// the second answer: the router sends the machine's newest cert beside it
		cert2, err := c.ApproveByPhone(ptr(ch[order[1]]), sig[order[1]], cert1.Carry, &cert1)
		if err != nil {
			t.Fatalf("%v: the second approval was refused: %v", order, err)
		}
		got := certOf(t, cert2)
		if !equalStrings(got.Stores, []string{"default", "gmail", "openrouter"}) {
			t.Fatalf("%v: the session ends with %v", order, got.Stores)
		}
		if got.Machine.ID != id || got.Machine.SigningKey != certOf(t, cert1).Machine.SigningKey || got.PredCert != certOf(t, cert1).Nonce {
			t.Fatalf("%v: not the machine's newest cert continued: %+v", order, got)
		}
		v := values(t, f.machines[id].enc, pull(t, c, cert2, cert2.Carry))
		if v["A"] != "1" || v["G"] != "secret" || v["OPENROUTER_API"] != "o" {
			t.Fatalf("%v: pulled %v", order, v)
		}
		// each answered once: replays (with or without a newest cert beside them) get nothing
		for _, s := range order {
			for _, cur := range []*SignedDoc{nil, &cert2} {
				if _, err := c.ApproveByPhone(ptr(ch[s]), sig[s], "", cur); err == nil {
					t.Fatalf("%v: %s answered twice", order, s)
				}
			}
		}
		// the older certs pull nothing
		for _, old := range []SignedDoc{cert0, cert1} {
			if _, err := c.PullSecrets(&old, ""); err == nil {
				t.Fatal("a superseded cert pulled")
			}
		}
	}
}

// The stale challenge is answered only onto the machine's real newest cert: not without one, not onto an older
// one, not onto another machine's.
func TestAStaleAddStoreTakesOnlyTheMachinesNewestCert(t *testing.T) {
	c, _, p := setup(t)
	cert0, id := newLine(t, c, p, "default")
	other, _ := newLine(t, c, p, "default", "gmail")
	chG := addStoreChallenge(t, c, cert0, id, "gmail")
	chO := addStoreChallenge(t, c, cert0, id, "openrouter")
	cert1 := pl2(t)(c.ApproveByPhone(&chG, p.sign(chG.Payload), "", &cert0))
	sigO := p.sign(chO.Payload)
	for name, cur := range map[string]*SignedDoc{"none": nil, "the stale one": &cert0, "another machine's": &other} {
		if _, err := c.ApproveByPhone(&chO, sigO, "", cur); err == nil {
			t.Fatalf("answered onto %s", name)
		}
	}
	if _, err := c.ApproveByPhone(&chO, sigO, "", &cert1); err != nil {
		t.Fatal(err)
	}
}

// A downgrade between filing and answering: the added store goes onto the downgraded cert — its new keys, and the
// dropped store stays dropped.
func TestAnAddStoreAfterADowngradeKeepsTheDowngrade(t *testing.T) {
	c, f, p := setup(t)
	cert0, id := newLine(t, c, p, "default", "gmail")
	chO := addStoreChallenge(t, c, cert0, id, "openrouter")
	cert1, _, _, nEnc := downgradeTo(t, c, f, cert0, id, "", "default") // gmail dropped, new keys
	cert2, err := c.ApproveByPhone(&chO, p.sign(chO.Payload), "", &cert1)
	if err != nil {
		t.Fatal(err)
	}
	got := certOf(t, cert2)
	if !equalStrings(got.Stores, []string{"default", "openrouter"}) {
		t.Fatalf("got %v", got.Stores)
	}
	if got.Machine.EncryptionKey != m2k(nEnc) {
		t.Fatal("the old key pair came back")
	}
}

// The same store asked for twice from the same cert is the same challenge (the nonce is the request's MAC), answered
// once; asked again from a later cert it is refused (TestAnAddStoreOfAHeldStoreIsRefused).
func TestTheSameStoreAddedTwice(t *testing.T) {
	c, _, p := setup(t)
	cert0, id := newLine(t, c, p, "default")
	a := addStoreChallenge(t, c, cert0, id, "gmail")
	b := addStoreChallenge(t, c, cert0, id, "gmail")
	if a.Payload != b.Payload {
		t.Fatal("two challenges for the same store from the same cert differ")
	}
	cert1 := pl2(t)(c.ApproveByPhone(&a, p.sign(a.Payload), "", &cert0))
	if _, err := c.ApproveByPhone(&b, p.sign(b.Payload), "", &cert1); err == nil {
		t.Fatal("the same challenge was answered twice")
	}
}

func ptr(d SignedDoc) *SignedDoc { return &d }

func pl2(t *testing.T) func(SignedDoc, error) SignedDoc {
	return func(d SignedDoc, err error) SignedDoc {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
}

// One rule, no branch (Deyao, 2026-10-13: the core doesn't decide; a call made wrong is refused): every add-store is
// answered onto the machine's newest cert, which the caller always sends. Without it, even a challenge that is
// still fresh is refused.
func TestAnAddStoreAlwaysTakesTheNewestCert(t *testing.T) {
	c, _, p := setup(t)
	cert0, id := newLine(t, c, p, "default")
	ch := addStoreChallenge(t, c, cert0, id, "gmail")
	sig := p.sign(ch.Payload)
	if _, err := c.ApproveByPhone(&ch, sig, "", nil); err == nil {
		t.Fatal("an add-store was answered with no newest cert beside it")
	}
	cert1, err := c.ApproveByPhone(&ch, sig, "", &cert0)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(certOf(t, cert1).Stores, []string{"default", "gmail"}) {
		t.Fatalf("got %v", certOf(t, cert1).Stores)
	}
}

// A store the newest cert already holds isn't refused: the answer keeps the same stores (no duplicate) and is the
// machine's newest cert, which reads the add-store's fresh unlock.
func TestAnAddStoreOfAHeldStoreKeepsTheSameStores(t *testing.T) {
	c, _, p := setup(t)
	cert0, id := newLine(t, c, p, "default")
	a := addStoreChallenge(t, c, cert0, id, "gmail")
	o := addStoreChallenge(t, c, cert0, id, "openrouter")
	cert1 := pl2(t)(c.ApproveByPhone(&o, p.sign(o.Payload), "", &cert0))
	g := addStoreChallenge(t, c, cert1, id, "gmail")
	cert2 := pl2(t)(c.ApproveByPhone(&g, p.sign(g.Payload), "", &cert1))
	cert3 := pl2(t)(c.ApproveByPhone(&a, p.sign(a.Payload), "", &cert2))
	if got := certOf(t, cert3).Stores; !equalStrings(got, []string{"default", "gmail", "openrouter"}) {
		t.Fatalf("got %v", got)
	}
	if c.latest[id] != certOf(t, cert3).Nonce {
		t.Fatal("the answer isn't the machine's newest cert")
	}
}
