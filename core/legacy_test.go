package main

import (
	"encoding/hex"
	"testing"
)

// the release of core continuity: sessions certified by the random-key core before it go on, each taken over at its
// kill (running ones at their pause, paused ones at once)
func TestASeededCoreTakesOverTheLinesOfAnEarlierCoreTheMasterClaimed(t *testing.T) {
	t.Setenv("MACHINE_URL", testMachineURL)
	old, f, master := newCore(t)
	p := newPhone()
	st, sig, b := claimFor(old, master, p, recoverBundle(t, old, p, "fly-secret"))
	pl(t)(old.Claim(st, sig, b))
	claim := &struct {
		Statement string `json:"statement"`
		MasterSig string `json:"masterSig"`
	}{st, sig}
	// a running session (it pauses after the release) and a paused one (killed by the old core before it)
	certR, idR := startWithUnlocks(t, old, p, "default", "gmail")
	pull(t, old, certR, "")
	certP, idP := startWithUnlocks(t, old, p, "default")
	pull(t, old, certP, "")
	snapP := hex.EncodeToString(make([]byte, 32))
	pl(t)(old.KillWithSnapshot(idP, &SnapshotClaim{Sha256: snapP, Sig: machineSign(f.machines[idP].sig, snapP)}))

	// the release: a core from the seed (the same master, the same phone)
	c := newSeededCore(t, f, master, p, nil)
	snapR := hex.EncodeToString([]byte("running-snapshot-0123456789abcde"))
	snap := &SnapshotClaim{Sha256: snapR, Sig: machineSign(f.machines[idR].sig, snapR)}
	// a pause (required) is refused, the machine kept: no claim, a claim another master signed, no snapshot, a
	// snapshot another key signed
	req := &SnapshotClaim{Sha256: snapR, Sig: snap.Sig, Required: true}
	if _, err := c.Kill(idR, req, &LegacyCert{Cert: &certR}); err == nil {
		t.Fatal("taken over without the master's claim")
	}
	other := newPhone()
	if _, err := c.Kill(idR, req, &LegacyCert{Cert: &certR, CoreCert: &struct {
		Statement string `json:"statement"`
		MasterSig string `json:"masterSig"`
	}{st, other.sign(st)}}); err == nil {
		t.Fatal("taken over with a claim another key signed")
	}
	if _, err := c.Kill(idR, &SnapshotClaim{Required: true}, &LegacyCert{Cert: &certR, CoreCert: claim}); err == nil {
		t.Fatal("taken over without a snapshot")
	}
	if _, err := c.Kill(idR, &SnapshotClaim{Sha256: snapR, Sig: other.sign(snapR), Required: true}, &LegacyCert{Cert: &certR, CoreCert: claim}); err == nil {
		t.Fatal("taken over with a snapshot the machine didn't sign")
	}
	if f.machines[idR].destroyed {
		t.Fatal("a refused pause destroyed the machine")
	}
	// the running session pauses: its kill takes the line over
	d := pl(t)(c.Kill(idR, snap, &LegacyCert{Cert: &certR, CoreCert: claim}))
	if d["snapshot"] != snapR || d["adopted"] == nil {
		t.Fatalf("kill: %v", d)
	}
	adoptedR := *c.adopted[idR]
	if adoptedR.Payload != certR.Payload || !VerifyWith(c.signer.PublicKey(), []byte(adoptedR.Payload), adoptedR.Sig) {
		t.Fatal("the cert isn't the same cert, signed by this core")
	}
	// again: the same answer, nothing new
	if d2 := pl(t)(c.Kill(idR, snap, &LegacyCert{Cert: &certR, CoreCert: claim})); d2["adopted"] == nil {
		t.Fatal("a second kill lost the takeover")
	}
	// the paused one, taken over at once (Fly destroyed it long ago)
	adoptedP := pl2(t)(c.Kill(idP, &SnapshotClaim{Sha256: snapP, Sig: machineSign(f.machines[idP].sig, snapP)}, &LegacyCert{Cert: &certP, CoreCert: claim}))
	_ = adoptedP
	// both resume unattended (the dead-machine responder); their first pull waits for one unlock (the earlier core's
	// carry doesn't open here), then the secrets come
	for _, x := range []struct {
		id    string
		cert  SignedDoc
		store []string
		snap  string
	}{{idR, adoptedR, []string{"default", "gmail"}, snapR}, {idP, *c.adopted[idP], []string{"default"}, snapP}} {
		ch, err := routerSuccession(c, SuccessionInput{Predecessor: &x.cert, Image: f.machineImage(c, &x.cert), Stores: x.store})
		if err != nil {
			t.Fatal(err)
		}
		a, err := c.ApproveByDeadMachine(&ch)
		if err != nil {
			t.Fatalf("resume of a taken-over line: %v", err)
		}
		cert2, id2 := start(t, c, a)
		if cc := certOf(t, cert2); cc.Snapshot != x.snap || cc.PredID != x.id {
			t.Fatalf("the successor's cert: %+v", cc)
		}
		_, err = c.PullSecrets(&cert2, "")
		locked(t, err, "default")
		for _, n := range x.store {
			unlockFor(t, c, p, n, certOf(t, cert2).Nonce)
		}
		if v := values(t, f.machines[id2].enc, pull(t, c, cert2, "")); v["A"] != "1" {
			t.Fatalf("got %v", v)
		}
		// and the line can't fork
		if _, err := c.ApproveByDeadMachine(&ch); err == nil {
			t.Fatal("a taken-over predecessor continued twice")
		}
	}
	// a line state carries the takeovers
	line := lineOf(t, c)
	c2 := newSeededCore(t, f, master, p, line)
	if c2.adopted[idR] == nil {
		t.Fatal("the takeover didn't survive a Recover")
	}
}
