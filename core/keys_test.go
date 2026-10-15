package main

// Stores made of keys (keys.go): a key is written alone, by the setup session or by any running session's machine,
// and the store's other keys are never read or touched. A session whose copy of a store is behind a write learns it at
// its next pull (stale), and only a new unlock (the phone) brings the new value.

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

// machineWrite: what a session's machine sends — one key sealed to the store key, signed with its own signing key
func machineWrite(t *testing.T, c *Core, f *fakeFly, p *phone, cert SignedDoc, id, store, key, value, backup string) (SignedDoc, error) {
	t.Helper()
	x := sealKey(t, c, p, store, key, value)
	text := WriterText(store, key, x.Wrapped.E, x.Data, backup)
	sig := (&phone{sig: ecdsaFromECDH(f.machines[id].sig)}).sign(text)
	return c.WriteKey(WriteKeyInput{Store: store, Key: key, Wrapped: x.Wrapped, Data: x.Data, BackupSha256: backup, Writer: "machine", Sig: sig, Cert: &cert})
}

func storeOf(t *testing.T, c *Core, p *phone, name string) map[string]string {
	t.Helper()
	return storeValues(t, c, p, name)
}

func TestWritingOneKeyKeepsTheOthers(t *testing.T) {
	c, _, p := setup(t)
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "A", "new")))
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "C", "3")))
	if v := storeOf(t, c, p, "default"); v["A"] != "new" || v["B"] != "2" || v["C"] != "3" || len(v) != 3 {
		t.Fatalf("got %v", v)
	}
	pl(t)(c.WriteKey(WriteKeyInput{Store: "default", Key: "B", Delete: true, Writer: "setup", Sig: "c2ln"}))
	if v := storeOf(t, c, p, "default"); v["B"] != "" || len(v) != 2 {
		t.Fatalf("got %v", v)
	}
	if _, err := c.WriteKey(WriteKeyInput{Store: "default", Key: "B", Delete: true, Writer: "setup", Sig: "c2ln"}); err == nil {
		t.Fatal("a missing key was deleted")
	}
	for name, in := range map[string]WriteKeyInput{
		"the core's store": {Store: FlyStore, Key: "FLY_API_TOKEN"},
		"a bad key name":   {Store: "default", Key: "1A"},
		"a bad store name": {Store: "Default", Key: "A"},
	} {
		x := sealKey(t, c, p, in.Store, in.Key, "v")
		in.Wrapped, in.Data, in.Writer, in.Sig = x.Wrapped, x.Data, "setup", "c2ln"
		if _, err := c.WriteKey(in); err == nil {
			t.Fatalf("%s: written", name)
		}
	}
	// the setup writer's first key makes a store, sensitive
	pl(t)(setupWrite(c, sealKey(t, c, p, "brand-new", "K", "v")))
	if c.notSensitive["brand-new"] {
		t.Fatal("a store made by a write came out not sensitive")
	}
}

func TestASessionWritesAKeyIntoAStoreItDoesntHold(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default")
	backup := sha256Hex("the sealed backup")
	r := pl(t)(machineWrite(t, c, f, p, cert, id, "gmail", "G2", "from the session", backup))
	w, _ := r["writer"].(map[string]any)
	if r["kind"] != "key-written" || r["backupSha256"] != backup || w["by"] != "machine" || w["machine"] != id || w["line"] != certOf(t, cert).Line {
		t.Fatalf("receipt %v", r)
	}
	if v := storeOf(t, c, p, "gmail"); v["G"] != "secret" || v["G2"] != "from the session" {
		t.Fatalf("got %v", v)
	}
	// the phone sees which machine wrote it
	d := pl2(t)(c.UnlockBegin("gmail", ""))
	var m struct {
		Keys []struct {
			Key    string
			Writer EntryWriter
		}
	}
	json.Unmarshal([]byte(d.Payload), &m)
	for _, k := range m.Keys {
		if k.Key == "G2" && (k.Writer.By != "machine" || k.Writer.Machine != id) {
			t.Fatalf("got %+v", k)
		}
	}
}

// A session's write may make a new store (sensitive: it reaches no session without the phone); the router writes the
// Claude account stores only, named as the router on every unlock.
func TestNewStoresAndTheRoutersWrites(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default")
	pl(t)(machineWrite(t, c, f, p, cert, id, "notes-new", "K", "v", ""))
	if c.notSensitive["notes-new"] || storeOf(t, c, p, "notes-new")["K"] != "v" {
		t.Fatal("a session's new store isn't sensitive, or lost its key")
	}
	pl(t)(c.CreateStore("claude-work"))
	x := sealKey(t, c, p, "claude-work", "CLAUDE_CREDENTIALS", "pair")
	r := pl(t)(c.WriteKey(WriteKeyInput{Store: "claude-work", Key: "CLAUDE_CREDENTIALS", Wrapped: x.Wrapped, Data: x.Data, Writer: "router"}))
	if w, _ := r["writer"].(map[string]any); w["by"] != "router" || r["sensitive"] != false {
		t.Fatalf("receipt %v", r)
	}
	d := pl2(t)(c.UnlockBegin("claude-work", ""))
	if !strings.Contains(d.Payload, `"by":"router"`) {
		t.Fatalf("the unlock doesn't name the router: %s", d.Payload)
	}
	for _, store := range []string{"default", "gmail", DeployKeyTokenStore, "claude"} {
		x := sealKey(t, c, p, store, "K", "v")
		if _, err := c.WriteKey(WriteKeyInput{Store: store, Key: "K", Wrapped: x.Wrapped, Data: x.Data, Writer: "router"}); err == nil {
			t.Fatalf("the router wrote %s", store)
		}
	}
}

func TestAMachineWriteIsRefusedUnlessItIsALiveMachinesOwn(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default")
	other, oid := newLine(t, c, p, "default")
	// signed by another machine's key, under this machine's cert
	x := sealKey(t, c, p, "default", "K", "v")
	sig := (&phone{sig: ecdsaFromECDH(f.machines[oid].sig)}).sign(WriterText("default", "K", x.Wrapped.E, x.Data, ""))
	if _, err := c.WriteKey(WriteKeyInput{Store: "default", Key: "K", Wrapped: x.Wrapped, Data: x.Data, Writer: "machine", Sig: sig, Cert: &cert}); err == nil {
		t.Fatal("another machine's signature wrote")
	}
	// a signature over another value
	if _, err := c.WriteKey(WriteKeyInput{Store: "default", Key: "K", Wrapped: x.Wrapped, Data: sealKey(t, c, p, "default", "K", "w").Data, Writer: "machine",
		Sig: (&phone{sig: ecdsaFromECDH(f.machines[id].sig)}).sign(WriterText("default", "K", x.Wrapped.E, x.Data, "")), Cert: &cert}); err == nil {
		t.Fatal("a signature over another value wrote")
	}
	for name, store := range map[string]string{"the deploy-key token store": DeployKeyTokenStore, "a repo store that doesn't exist": "github-nope"} {
		if _, err := machineWrite(t, c, f, p, cert, id, store, "K", "v", ""); err == nil {
			t.Fatalf("%s: written", name)
		}
	}
	c.repoOwner["default"] = "DE0CH/x"
	if _, err := machineWrite(t, c, f, p, cert, id, "default", "K", "v", ""); err == nil {
		t.Fatal("a repo's deploy-key store was written by a machine")
	}
	delete(c.repoOwner, "default")
	// a superseded cert (an add-store answered since), then a killed machine
	ch := addStoreChallenge(t, c, cert, id, "gmail")
	cert2 := pl2(t)(c.ApproveByPhone(&ch, p.sign(ch.Payload), "", &cert))
	if _, err := machineWrite(t, c, f, p, cert, id, "default", "K", "v", ""); err == nil {
		t.Fatal("a superseded cert wrote")
	}
	pl(t)(machineWrite(t, c, f, p, cert2, id, "default", "K", "v", ""))
	pl(t)(c.KillWithSnapshot(oid, nil))
	if _, err := machineWrite(t, c, f, p, other, oid, "default", "K", "v", ""); err == nil {
		t.Fatal("a killed machine wrote")
	}
	if _, err := c.WriteKey(WriteKeyInput{Store: "default", Key: "K", Delete: true, Writer: "machine"}); err == nil {
		t.Fatal("a machine delete with no cert went through")
	}
}

// A store written after a session got it: its next pull says the copy is behind (the router asks the phone for a fresh
// unlock), the values stay the ones the phone released, and a new unlock brings the new value.
func TestAPullSaysWhichStoresAreBehind(t *testing.T) {
	c, f, p := setup(t)
	cert, id := startWithUnlocks(t, c, p, "default", "gmail")
	x := pull(t, c, cert, "")
	if len(x.Stale) != 0 {
		t.Fatalf("fresh stores called behind: %v", x.Stale)
	}
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "A", "rotated")))
	y := pull(t, c, cert, x.Carry)
	if v := values(t, f.machines[id].enc, y); v["A"] != "1" || len(y.Stale) != 1 || y.Stale[0] != "default" {
		t.Fatalf("got %v, behind %v", v, y.Stale)
	}
	unlockFor(t, c, p, "default", certOf(t, cert).Nonce)
	z := pull(t, c, cert, y.Carry)
	if v := values(t, f.machines[id].enc, z); v["A"] != "rotated" || len(z.Stale) != 0 {
		t.Fatalf("got %v, behind %v", v, z.Stale)
	}
	// the carried copy is the fresh one from now on (a resume brings it)
	if w := pull(t, c, cert, z.Carry); len(w.Stale) != 0 || values(t, f.machines[id].enc, w)["A"] != "rotated" {
		t.Fatal("the carry kept the old copy")
	}
}

// An unlock opens exactly the keys it began with: a key written between begin and finish isn't in it, and the store
// counts as behind.
func TestAnUnlockOpensWhatItBeganWith(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default")
	b := pl2(t)(c.UnlockBegin("default", certOf(t, cert).Nonce))
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "C", "3")))
	pid, shares := p.share(b)
	pl(t)(c.UnlockFinish(pid, shares))
	out := pull(t, c, cert, "")
	if v := values(t, f.machines[id].enc, out); v["C"] != "" || v["A"] != "1" || len(out.Stale) != 1 {
		t.Fatalf("got %v, behind %v", v, out.Stale)
	}
	// a share missing for one key: refused
	b2 := pl2(t)(c.UnlockBegin("default", ""))
	pid2, shares2 := p.share(b2)
	delete(shares2, "A")
	if _, err := c.UnlockFinish(pid2, shares2); err == nil {
		t.Fatal("an unlock went through without a share for every key")
	}
	_ = rand.Reader
}
