package main

// Core continuity (continuity.go): a core restart + Recover with the same kit is the same core to its sessions.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// appWrapTo: a store's keys wrapped to the store key P + K for the core point `core` (the derived one at a Recover)
func appWrapTo(t *testing.T, c *Core, p *phone, name string, vals map[string]string, core string) []KeyEntry {
	t.Helper()
	sk := pl(t)(c.StoreKey(p.agreementKey(), core))
	if core != "" && sk["core"] != core {
		t.Fatalf("store key for another core point: %v", sk)
	}
	C, _ := b64.DecodeString(sk["storeKey"].(string))
	out := []KeyEntry{}
	for _, k := range sortedKeys(vals) {
		dk := make([]byte, 32)
		rand.Read(dk)
		w, err := WrapToPoint(C, dk)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, KeyEntry{Store: name, Key: k, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, []byte(vals[k]), KeyAAD(name, k)))})
	}
	return out
}

// seededClaim: the new app's Recover on an empty core: the seed from the master key, the derived identity in the
// statement, every store wrapped to the derived K, and the line state the router kept
func seededClaim(t *testing.T, c *Core, master, p *phone, line *LineStateDoc, identity func(*claimStatement)) (SignedDoc, error) {
	t.Helper()
	seed, err := CoreSeedFromKey(master.sig)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := DeriveCoreKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	agr := b64.EncodeToString(dk.agreement.PublicKey().Bytes())
	rb := claimBundle{Format: "keys", NotSensitive: []string{"default", "claude", "openrouter"}, FlyToken: "fly-secret",
		CoreSeed: b64.EncodeToString(seed), LineState: line}
	for _, n := range []string{"claude", "default", "gmail", "openrouter"} {
		rb.Stores = append(rb.Stores, n)
		rb.Keys = append(rb.Keys, appWrapTo(t, c, p, n, testValues[n], agr)...)
	}
	plain, _ := json.Marshal(rb)
	sum := sha256.Sum256(plain)
	var st claimStatement
	st.Kind, st.Master = "claim", master.signingKey()
	k := c.Key()
	st.Core.SigningKey, st.Core.AgreementKey = k["signingKey"], k["agreementKey"]
	st.Phone.SigningKey, st.Phone.AgreementKey = p.signingKey(), p.agreementKey()
	st.BundleSha256 = hex.EncodeToString(sum[:])
	st.Identity = &struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	}{dk.signer.PublicKey(), agr}
	if identity != nil {
		identity(&st)
	}
	sb, _ := json.Marshal(st)
	bundle, _ := SealTo(k["agreementKey"], plain, infoClaim)
	return c.Claim(string(sb), master.sign(string(sb)), bundle)
}

func newSeededCore(t *testing.T, f *fakeFly, master, p *phone, line *LineStateDoc) *Core {
	t.Helper()
	c, err := NewCore(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seededClaim(t, c, master, p, line, nil); err != nil {
		t.Fatal(err)
	}
	c.syncLine()
	return c
}

func lineOf(t *testing.T, c *Core) *LineStateDoc {
	t.Helper()
	d, err := c.LineState()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTheSameKitDerivesTheSameCore(t *testing.T) {
	t.Setenv("MACHINE_URL", testMachineURL)
	f, master, p := newFakeFly(), newPhone(), newPhone()
	c1 := newSeededCore(t, f, master, p, nil)
	c2 := newSeededCore(t, f, master, p, nil)
	if c1.signer.PublicKey() != c2.signer.PublicKey() || string(c1.agreement.Bytes()) != string(c2.agreement.Bytes()) ||
		string(c1.carryKey) != string(c2.carryKey) || string(c1.nonceKey) != string(c2.nonceKey) {
		t.Fatal("two Recovers with one kit made different cores")
	}
	other := newSeededCore(t, f, newPhone(), p, nil)
	if other.signer.PublicKey() == c1.signer.PublicKey() {
		t.Fatal("another kit made the same core")
	}
	id, _ := c1.Identity()
	if id["continuity"] != 1 || id["signingKey"] != c1.signer.PublicKey() {
		t.Fatalf("identity: %v", id)
	}
	var st map[string]any
	json.Unmarshal([]byte(id["state"].(SignedDoc).Payload), &st)
	if st["derived"] != true || st["lineSeq"].(float64) < 1 {
		t.Fatalf("state: %v", st)
	}
}

func TestAClaimWhoseIdentityIsntTheSeedsIsRefused(t *testing.T) {
	c, _, master := newCore(t)
	p := newPhone()
	_, err := seededClaim(t, c, master, p, nil, func(st *claimStatement) { st.Identity.SigningKey = newPhone().signingKey() })
	if err == nil || err.(*Err).Status != 403 {
		t.Fatalf("want 403, got %v", err)
	}
	if c.MasterKey != "" {
		t.Fatal("the core took the claim")
	}
	// no identity with a seed: refused too
	_, err = seededClaim(t, c, master, p, nil, func(st *claimStatement) { st.Identity = nil })
	if err == nil {
		t.Fatal("a seed without an identity was taken")
	}
}

func TestACoreWithoutASeedKeepsNoLineState(t *testing.T) {
	c, _, _ := setup(t)
	c.syncLine()
	if _, err := c.LineState(); err == nil || err.(*Err).Status != 404 {
		t.Fatalf("want 404, got %v", err)
	}
	if c.LineSeq() != 0 {
		t.Fatal("a line seq on a core with boot keys")
	}
}

func TestARecoveredCoreKeepsEverySession(t *testing.T) {
	t.Setenv("MACHINE_URL", testMachineURL)
	f, master, p := newFakeFly(), newPhone(), newPhone()
	c1 := newSeededCore(t, f, master, p, nil)
	key := c1.signer.PublicKey()

	// A: running, then one more store (its first cert is superseded)
	certA0, idA := startWithUnlocks(t, c1, p, "default")
	xA := pull(t, c1, certA0, "")
	chA := addStoreChallenge(t, c1, certA0, idA, "gmail")
	unlockFor(t, c1, p, "gmail", challengeNonce(chA))
	certA, err := c1.ApproveByPhone(&chA, p.sign(chA.Payload), xA.Carry, &certA0)
	if err != nil {
		t.Fatal(err)
	}
	xA = pull(t, c1, certA, certA.Carry)
	// B: paused (killed with its carry kept by the router)
	certB, idB := startWithUnlocks(t, c1, p, "default", "gmail")
	xB := pull(t, c1, certB, "")
	pl(t)(c1.KillWithSnapshot(idB, nil))
	// C: ended (killed and burnt)
	certC, idC := startWithUnlocks(t, c1, p, "default")
	pl(t)(c1.KillWithSnapshot(idC, nil))
	burn, _ := routerSuccession(c1, SuccessionInput{Predecessor: &certC, Image: NullImage})
	pl(t)(tryStart(c1, pl2(t)(c1.ApproveByDeadMachine(&burn))))
	// a deploy-key store (no backup): as deploy_key_finish leaves it
	repo := appWrapTo(t, c1, p, "github-x", map[string]string{"GITHUB_DEPLOY_KEY_DE0CH_X": "k", "GITHUB_DEPLOY_REPO_DE0CH_X": "DE0CH/x"}, "")
	c1.mu.Lock()
	c1.stores["github-x"] = map[string]*KeyEntry{}
	for i := range repo {
		x := repo[i]
		x.Writer = &EntryWriter{By: "core"}
		c1.stores["github-x"][x.Key] = &x
	}
	c1.repoOwner["github-x"] = "DE0CH/x"
	c1.mu.Unlock()
	c1.syncLine()
	// an input attested: the log's chain goes on from it
	att := pl(t)(c1.Attest(idA, "wakeup", "router", hex.EncodeToString(make([]byte, 32))))
	c1.syncLine()
	line := lineOf(t, c1)

	// the restart: an empty core, Recovered with the same kit and the line state the router kept
	c2 := newSeededCore(t, f, master, p, line)
	if c2.signer.PublicKey() != key {
		t.Fatal("the recovered core has another key")
	}
	if c2.LineSeq() <= line.headSeq(t) {
		t.Fatalf("seq %d doesn't go on from %d", c2.LineSeq(), line.headSeq(t))
	}
	// A pulls with its newest cert and its carry; its superseded cert gets nothing
	if v := values(t, f.machines[idA].enc, pull(t, c2, certA, xA.Carry)); v["A"] != "1" || v["G"] != "secret" {
		t.Fatalf("A got %v", v)
	}
	if _, err := c2.PullSecrets(&certA0, xA.Carry); err == nil {
		t.Fatal("a superseded cert pulled after the Recover")
	}
	// the store list is signed by the same key (the machine's `jarvis2 stores` check)
	sl, _ := c2.Stores("n")
	if !VerifyWith(key, []byte(sl.Payload), sl.Sig) {
		t.Fatal("the store list isn't signed by the key the machines trust")
	}
	// A adds a store
	chA2 := addStoreChallenge(t, c2, certA, idA, "openrouter")
	unlockFor(t, c2, p, "openrouter", challengeNonce(chA2))
	certA2, err := c2.ApproveByPhone(&chA2, p.sign(chA2.Payload), xA.Carry, &certA)
	if err != nil {
		t.Fatalf("add-store after the Recover: %v", err)
	}
	if v := values(t, f.machines[idA].enc, pull(t, c2, certA2, certA2.Carry)); v["OPENROUTER_API"] != "o" || v["G"] != "secret" {
		t.Fatalf("A after add-store got %v", v)
	}
	// B resumes unattended, with its carry, exactly once
	chB, _ := routerSuccession(c2, SuccessionInput{Predecessor: &certB, Image: f.machineImage(c2, &certB), Stores: []string{"default", "gmail"}})
	aB, err := c2.ApproveByDeadMachine(&chB)
	if err != nil {
		t.Fatalf("resume after the Recover: %v", err)
	}
	certB2, idB2 := startCarry(t, c2, aB, xB.Carry)
	if v := values(t, f.machines[idB2].enc, pull(t, c2, certB2, certB2.Carry)); v["G"] != "secret" {
		t.Fatalf("B got %v", v)
	}
	if _, err := tryStart(c2, aB); err == nil {
		t.Fatal("one approval made two machines")
	}
	// C stays ended
	chC, _ := routerSuccession(c2, SuccessionInput{Predecessor: &certC, Image: f.machineImage(c2, &certC), Stores: []string{"default"}})
	if _, err := c2.ApproveByDeadMachine(&chC); err == nil {
		t.Fatal("a burnt line continued after the Recover")
	}
	// the deploy-key store came back, still the repo's
	if len(c2.stores["github-x"]) != 2 || c2.repoOwner["github-x"] != "DE0CH/x" {
		t.Fatalf("deploy-key store: %v %v", c2.stores["github-x"], c2.repoOwner)
	}
	// the input log goes on from its head
	if c2.auditSeq < int(att["seq"].(float64))+1 || c2.auditHead == "" {
		t.Fatalf("the input log started again (seq %d)", c2.auditSeq)
	}
	// destroying A on the recovered core: kill + burn
	pl(t)(c2.KillWithSnapshot(idA, nil))
	burnA, _ := routerSuccession(c2, SuccessionInput{Predecessor: &certA2, Image: NullImage})
	pl(t)(tryStart(c2, pl2(t)(c2.ApproveByDeadMachine(&burnA))))
}

func TestALineStateFromAnotherKitOrPhoneIsntTaken(t *testing.T) {
	t.Setenv("MACHINE_URL", testMachineURL)
	f, master, p := newFakeFly(), newPhone(), newPhone()
	c1 := newSeededCore(t, f, master, p, nil)
	repo := appWrapTo(t, c1, p, "github-x", map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_X": "DE0CH/x"}, "")
	c1.mu.Lock()
	c1.stores["github-x"] = map[string]*KeyEntry{repo[0].Key: &repo[0]}
	c1.repoOwner["github-x"] = "DE0CH/x"
	c1.mu.Unlock()
	line := lineOf(t, c1)
	// another kit: its derived key didn't sign the head
	c2, _ := NewCore(f)
	if _, err := seededClaim(t, c2, newPhone(), p, line, nil); err == nil {
		t.Fatal("a line state from another kit was taken")
	}
	// the same kit, another phone: the lines come back, the deploy-key store (wrapped for the old phone) doesn't
	c3 := newSeededCore(t, f, master, newPhone(), line)
	if _, ok := c3.stores["github-x"]; ok {
		t.Fatal("a deploy-key store wrapped for another phone came back")
	}
	// an altered sealed state
	bad := *line
	raw, _ := b64.DecodeString(bad.Sealed)
	raw[len(raw)-1] ^= 1
	bad.Sealed = b64.EncodeToString(raw)
	c4, _ := NewCore(f)
	if _, err := seededClaim(t, c4, master, p, &bad, nil); err == nil {
		t.Fatal("an altered line state was taken")
	}
}

func TestKillingAMachineAnEarlierCoreMadeNamesNoSnapshot(t *testing.T) {
	c, f, p := setup(t)
	_, id := newLine(t, c, p, "default")
	c2, _ := NewCore(f) // knows nothing of id
	c2.MasterKey = "x"
	d := pl(t)(c2.KillWithSnapshot(id, &SnapshotClaim{Sha256: hex.EncodeToString(make([]byte, 32)), Sig: "AAAA"}))
	if d["kind"] != "killed" || d["snapshot"] != "" {
		t.Fatalf("got %v", d)
	}
}

// helpers

func (d *LineStateDoc) headSeq(t *testing.T) int {
	var h lineHead
	json.Unmarshal([]byte(d.Head.Payload), &h)
	return h.Seq
}

func TestEveryAnswerNamesTheLineSeqAndLineStateServesIt(t *testing.T) {
	t.Setenv("MACHINE_URL", testMachineURL)
	f, master, p := newFakeFly(), newPhone(), newPhone()
	c := newSeededCore(t, f, master, p, nil)
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/stores", "application/json", strings.NewReader(`{"nonce":"n"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get(lineSeqHeader) != strconv.Itoa(c.LineSeq()) || c.LineSeq() == 0 {
		t.Fatalf("header %q, seq %d", resp.Header.Get(lineSeqHeader), c.LineSeq())
	}
	resp, err = http.Get(srv.URL + "/line-state")
	if err != nil {
		t.Fatal(err)
	}
	var d LineStateDoc
	json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if d.headSeq(t) != c.LineSeq() || !VerifyWith(c.signer.PublicKey(), []byte(d.Head.Payload), d.Head.Sig) {
		t.Fatalf("line state %+v", d)
	}
	// nothing changed: the same number
	before := c.LineSeq()
	c.syncLine()
	if c.LineSeq() != before {
		t.Fatal("the seq moved with nothing changed")
	}
}

// call: one HTTP call to a core's handler → status and the decoded body
func call(t *testing.T, srv *httptest.Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestAtMostOneCoreWithTheseKeysServes(t *testing.T) {
	t.Setenv("MACHINE_URL", testMachineURL)
	f, master, p := newFakeFly(), newPhone(), newPhone()
	blue := newSeededCore(t, f, master, p, nil)
	bs := httptest.NewServer(Handler(blue))
	defer bs.Close()
	cert0, id := startWithUnlocks(t, blue, p, "default")
	x0 := pull(t, blue, cert0, "")
	recovered := lineOf(t, blue)

	// green: Recovered with the same kit, standing by
	green, _ := NewCore(f)
	if _, err := seededClaim(t, green, master, p, recovered, func(st *claimStatement) { st.Standby = true }); err != nil {
		t.Fatal(err)
	}
	gs := httptest.NewServer(Handler(green))
	defer gs.Close()
	if st, _ := call(t, gs, "POST", "/stores", `{"nonce":"n"}`); st != 409 {
		t.Fatalf("a standing-by core answered the store list: %d", st)
	}
	if st, _ := call(t, gs, "GET", "/identity", ""); st != 200 {
		t.Fatalf("identity: %d", st)
	}
	// blue serves on meanwhile: one more store for the running machine, one key written
	ch := addStoreChallenge(t, blue, cert0, id, "gmail")
	unlockFor(t, blue, p, "gmail", challengeNonce(ch))
	cert1, err := blue.ApproveByPhone(&ch, p.sign(ch.Payload), x0.Carry, &cert0)
	if err != nil {
		t.Fatal(err)
	}
	x1 := pull(t, blue, cert1, cert1.Carry)
	pl(t)(setupWrite(blue, sealKey(t, blue, p, "default", "NEW", "n")))
	// a non-final state doesn't start green
	if _, err := green.Takeover(lineOf(t, blue)); err == nil {
		t.Fatal("green took over from a state blue still serves after")
	}
	// blue hands off: final, and nothing more
	st, fin := call(t, bs, "POST", "/handoff", "")
	if st != 200 {
		t.Fatalf("handoff: %d %v", st, fin)
	}
	if st, _ := call(t, bs, "POST", "/stores", `{"nonce":"n"}`); st != 409 {
		t.Fatalf("a core that handed off answered: %d", st)
	}
	final, _ := blue.Handoff() // again: the same final state
	var fh lineHead
	json.Unmarshal([]byte(final.Head.Payload), &fh)
	if !fh.Final || fh.Seq != blue.LineSeq() {
		t.Fatalf("final head %+v", fh)
	}
	// green takes over and serves the newest of everything
	b, _ := json.Marshal(map[string]any{"lineState": final})
	if st, m := call(t, gs, "POST", "/takeover", string(b)); st != 200 {
		t.Fatalf("takeover: %d %v", st, m)
	}
	if v := values(t, f.machines[id].enc, pull(t, green, cert1, x1.Carry)); v["G"] != "secret" {
		t.Fatalf("after the takeover: %v", v)
	}
	if _, err := green.PullSecrets(&cert0, x1.Carry); err == nil {
		t.Fatal("the cert blue superseded after green's Recover pulled on green")
	}
	if _, ok := green.stores["default"]["NEW"]; !ok {
		t.Fatal("the key blue wrote after green's Recover isn't on green")
	}
	if green.LineSeq() <= fh.Seq {
		t.Fatal("green's line state doesn't go on from the final one")
	}
	if _, err := green.Takeover(final); err == nil {
		t.Fatal("a serving core took over twice")
	}

	// a standby Recovered from a NEWER state than a final one refuses that final state
	newer := lineOf(t, green)
	late, _ := NewCore(f)
	if _, err := seededClaim(t, late, master, p, newer, func(st *claimStatement) { st.Standby = true }); err != nil {
		t.Fatal(err)
	}
	if _, err := late.Takeover(final); err == nil {
		t.Fatal("a standby took a final state older than the one it was Recovered with")
	}

	// a Recover whose bundle carries a final state serves at once, with that state's stores
	gfinal, err := green.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	next, _ := NewCore(f)
	if _, err := seededClaim(t, next, master, p, gfinal, nil); err != nil {
		t.Fatal(err)
	}
	if next.Mode() != modeServing || next.stores["default"]["NEW"] == nil {
		t.Fatalf("mode %q, stores %v", next.Mode(), next.stores["default"])
	}
	pull(t, next, cert1, x1.Carry)
}
