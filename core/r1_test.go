package main

// The audit's R1 findings against the core (2026-10-11): each test attempts the forbidden thing and expects a refusal.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

// downgrade in place: the new cert, the machine's old signing key answering the challenge
func downgradeTo(t *testing.T, c *Core, f *fakeFly, cert SignedDoc, id, carry string, keep ...string) (SignedDoc, SignedDoc, string, *ecdh.PrivateKey) {
	t.Helper()
	nEnc, _ := ecdh.P256().GenerateKey(rand.Reader)
	nSig, _ := ecdh.P256().GenerateKey(rand.Reader)
	ch, err := routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: keep, NewEncryptionKey: m2k(nEnc), NewSigningKey: m2k(nSig)})
	if err != nil {
		t.Fatal(err)
	}
	sig := (&phone{sig: ecdsaFromECDH(f.machines[id].sig)}).sign(ch.Payload)
	cert2, err := c.ApproveByOldKey(&ch, sig, carry)
	if err != nil {
		t.Fatal(err)
	}
	return cert2, ch, sig, nEnc
}

// Finding: a downgrade was reversible without the phone — the killed machine's older cert accepted as the
// predecessor, and the carry blob from before the downgrade still opened.
func TestADowngradeCantBeUndoneWithAnOlderCertOrBlob(t *testing.T) {
	c, f, p := setup(t)
	cert1, id := startWithUnlocks(t, c, p, "default", "gmail")
	x1 := pull(t, c, cert1, "") // the blob with gmail in it
	cert2, ch, sig, _ := downgradeTo(t, c, f, cert1, id, x1.Carry, "default")
	x2 := cert2.Carry

	// the older cert pulls nothing any more
	if _, err := c.PullSecrets(&cert1, x1.Carry); err == nil {
		t.Fatal("a superseded cert pulled")
	}
	// the downgrade challenge answered again gets nothing (and doesn't put the old keys back)
	if _, err := c.ApproveByOldKey(&ch, sig, ""); err == nil {
		t.Fatal("a downgrade was answered twice")
	}
	pl(t)(c.KillWithSnapshot(id, nil))
	// the router resumes from the cert before the downgrade: refused at succession…
	if _, err := routerSuccession(c, SuccessionInput{Predecessor: &cert1, Image: f.machineImage(c, &cert1), Stores: []string{"default", "gmail"}}); err == nil {
		t.Fatal("an older cert of the killed machine was taken as the predecessor")
	}
	// …and the honest resume from the newest cert can't reopen gmail from the old blob
	ch3, err := routerSuccession(c, SuccessionInput{Predecessor: &cert2, Image: f.machineImage(c, &cert2), Stores: []string{"default"}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.ApproveByDeadMachine(&ch3)
	if err != nil {
		t.Fatal(err)
	}
	cert3, id3 := startCarry(t, c, a, x1.Carry)
	if _, err := c.PullSecrets(&cert3, x1.Carry); err == nil {
		t.Fatal("the blob from before the downgrade opened for the successor")
	}
	if cert3.Carry != "" {
		t.Fatal("the blob from before the downgrade was rebound beside the successor's cert")
	}
	v := values(t, f.machines[id3].enc, pull(t, c, cert3, x2))
	if v["A"] != "1" || v["G"] != "" {
		t.Fatalf("the successor got %v", v)
	}
}

// Finding: add-store approvals weren't single-use — a saved challenge + phone signature answered again after a
// downgrade gave a cert with the dropped store back.
func TestAnAddStoreApprovalCantBeReplayedAfterADowngrade(t *testing.T) {
	c, f, p := setup(t)
	cert1, id := newLine(t, c, p, "default")
	ch, err := routerSuccession(c, SuccessionInput{Predecessor: &cert1, Machine: id, Stores: []string{"default", "gmail"}})
	if err != nil {
		t.Fatal(err)
	}
	phoneSig := p.sign(ch.Payload)
	cert2, err := c.ApproveByPhone(&ch, phoneSig, "")
	if err != nil {
		t.Fatal(err)
	}
	downgradeTo(t, c, f, cert2, id, "", "default") // the session drops gmail again
	if _, err := c.ApproveByPhone(&ch, phoneSig, ""); err == nil {
		t.Fatal("the add-store approval was answered again after the downgrade")
	}
}

// Finding: the router chose sensitivity by calling the open create_store before the writer, or before the claim.
func TestCreateBeforeTheClaimLeavesNoTrace(t *testing.T) {
	c, _, master := newCore(t)
	if _, err := c.CreateStore("infra"); err == nil {
		t.Fatal("a store was created on an empty core")
	}
	if _, err := c.WriteStore(StoreBlob{Name: "infra", Wrapped: WrappedKey{E: "x"}, Data: "y"}); err == nil {
		t.Fatal("a store was written on an empty core")
	}
	// even if one got in somehow, the claim sets the non-sensitive set to exactly the bundle's
	c.notSensitive["gmail"] = true
	p := newPhone()
	s, sig, bundle := claimFor(c, master, p, recoverBundle(t, c, p, "t"))
	pl(t)(c.Claim(s, sig, bundle))
	if c.notSensitive["gmail"] {
		t.Fatal("a name from before the claim stayed not sensitive")
	}
	// an empty store (whose writer hasn't settled its sensitivity) goes into no session
	pl(t)(c.CreateStore("tunnel"))
	if _, err := routerSuccession(c, SuccessionInput{Image: img, Stores: []string{"tunnel"}}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("a session named an empty store: %v", err)
	}
}

// Finding: github-deploy-keys (the deploy-key admin token) could be given to a session or standing-unlocked.
func TestTheDeployKeyTokenNeverGoesToASessionOrAnUnlock(t *testing.T) {
	c, _, p := setup(t)
	pl(t)(c.WriteStore(writeStore(t, c, p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: "ghp"})))
	if _, err := routerSuccession(c, SuccessionInput{Image: img, Stores: []string{"default", DeployKeyTokenStore}}); err == nil {
		t.Fatal("a session was offered the deploy-key token")
	}
	if _, err := c.UnlockBegin(DeployKeyTokenStore, ""); err == nil {
		t.Fatal("the deploy-key token store was unlocked (standing)")
	}
	if _, err := c.CreateStore(DeployKeyTokenStore); err == nil {
		t.Fatal("the deploy-key token store was created not sensitive")
	}
}

// Finding: open write_store let the router replace a store; the phone now sees who wrote the blob it unlocks.
func TestUnlockNamesTheWriter(t *testing.T) {
	c, _, p := setup(t)
	b := writeStore(t, c, p, "gmail", map[string]string{"G": "x"})
	b.Writer = "core" // a writer can't pass itself off as the core
	pl(t)(c.WriteStore(b))
	d, err := c.UnlockBegin("gmail", "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(d.Payload), &m)
	if m["writer"] != nil {
		t.Fatalf("an unsigned blob was shown as written by %v", m["writer"])
	}
	b.WriterSig = "c2ln"
	pl(t)(c.WriteStore(b))
	d, _ = c.UnlockBegin("gmail", "")
	json.Unmarshal([]byte(d.Payload), &m)
	if w, _ := m["writer"].(map[string]any); w["by"] != "setup" || w["sig"] != "c2ln" || m["dataSha256"] != sha256Hex(b.Data) {
		t.Fatalf("got %v", m)
	}
	d, _ = c.UnlockBegin("default", "") // claimed from a Recover: the core wrapped it
	json.Unmarshal([]byte(d.Payload), &m)
	if w, _ := m["writer"].(map[string]any); w["by"] != "core" {
		t.Fatalf("got %v", m)
	}
	if st := pl(t)(c.Stores("n")); st["writers"] != true {
		t.Fatal("the store list doesn't say unlocks name their writer")
	}
}
