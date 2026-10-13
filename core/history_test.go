package main

// Restoring a store to an earlier version (history.go): the versions are listed, a restore is the phone's signature
// over the core's exact begin document plus its shares of the keys put back, the core seals each put-back key's backup
// to the master public key, and the store changes only at commit, if it is still the version the phone saw.

import (
	"crypto/ecdh"
	"encoding/json"
	"testing"
)

func setupWithMaster(t *testing.T) (*Core, *phone, *phone) {
	t.Helper()
	c, _, master := newCore(t)
	p := newPhone()
	s, sig, b := claimFor(c, master, p, recoverBundle(t, c, p, "fly-secret"))
	pl(t)(c.Claim(s, sig, b))
	return c, p, master
}

type versionsDoc struct {
	Current  string
	Versions []struct {
		Seq     int
		Version string
		Cause   VersionCause
		Keys    []struct{ Name string }
	}
}

func versions(t *testing.T, c *Core, store string) versionsDoc {
	t.Helper()
	var v versionsDoc
	d := pl2(t)(c.Versions(store, "n"))
	json.Unmarshal([]byte(d.Payload), &v)
	return v
}

// restoreShares: the phone's signature over the begin document and its share of every key put back
func restoreShares(p *phone, begin SignedDoc) (string, string, map[string]Sealed) {
	var b struct {
		Pending, T string
		Put        []struct{ Key, E string }
	}
	json.Unmarshal([]byte(begin.Payload), &b)
	out := map[string]Sealed{}
	for _, k := range b.Put {
		out[k.Key] = p.shareOf(k.E, b.T)
	}
	return b.Pending, p.sign(begin.Payload), out
}

// openBackup: what Recover does with a key's backup — the master key's private half opens it
func openBackup(t *testing.T, master *phone, store, key string, b KeyBackup) string {
	t.Helper()
	priv, err := master.sig.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := b64.DecodeString(b.E)
	E, err := ecdh.P256().NewPublicKey(eb)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := priv.ECDH(E)
	d, _ := b64.DecodeString(b.Data)
	plain, err := gcmOpen(kdf(x, infoBackup), d, KeyAAD(store, key))
	if err != nil {
		t.Fatalf("%s: the backup doesn't open with the master key: %v", key, err)
	}
	if sha256Hex(b.E+"\n"+b.Data) != b.Sha256 {
		t.Fatalf("%s: backup hash", key)
	}
	return string(plain)
}

// The incident of 2026-10-13, on a core made of keys: a store loses most of its keys; Deyao puts the version before
// back with one Face ID, no kit.
func TestARestorePutsAnEarlierVersionBack(t *testing.T) {
	c, p, master := setupWithMaster(t)
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "C", "3")))
	before := versions(t, c, "default")
	if len(before.Versions) != 2 || before.Versions[0].Cause.Kind != "write" || before.Versions[1].Cause.Kind != "recover" {
		t.Fatalf("versions %+v", before.Versions)
	}
	good := before.Versions[0]
	for _, k := range []string{"A", "B"} {
		pl(t)(c.WriteKey(WriteKeyInput{Store: "default", Key: k, Delete: true, Writer: "setup", Sig: "c2ln"}))
	}
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "C", "overwritten")))
	if v := storeOf(t, c, p, "default"); len(v) != 1 || v["C"] != "overwritten" {
		t.Fatalf("wiped: %v", v)
	}

	b := pl2(t)(c.RestoreBegin("default", good.Seq))
	var bd struct {
		Kind   string
		Put    []struct{ Key string }
		Remove []string
		To     struct{ Seq int }
	}
	json.Unmarshal([]byte(b.Payload), &bd)
	if bd.Kind != "store-restore-begin" || len(bd.Put) != 3 || len(bd.Remove) != 0 || bd.To.Seq != good.Seq {
		t.Fatalf("begin %s", b.Payload)
	}
	id, sig, shares := restoreShares(p, b)
	out, err := c.RestoreFinish(id, sig, shares)
	if err != nil {
		t.Fatal(err)
	}
	// nothing changed yet: the router writes the backups first
	if v := storeOf(t, c, p, "default"); len(v) != 1 {
		t.Fatalf("restored before commit: %v", v)
	}
	backups := out["backups"].(map[string]KeyBackup)
	want := map[string]string{"A": "1", "B": "2", "C": "3"}
	for k, v := range want {
		if got := openBackup(t, master, "default", k, backups[k]); got != v {
			t.Fatalf("backup %s = %q", k, got)
		}
	}
	rc := out["receipt"].(SignedDoc)
	var r struct {
		Kind, Begin, PhoneSig string
		Put                   []struct{ Key, BackupSha256 string }
	}
	if c.verifyOwn(&rc, &r) != nil || r.Kind != "store-restore-approved" || r.Begin != b.Payload || !VerifyWith(p.signingKey(), []byte(r.Begin), r.PhoneSig) {
		t.Fatalf("receipt %s", rc.Payload)
	}
	for _, x := range r.Put {
		if backups[x.Key].Sha256 != x.BackupSha256 {
			t.Fatalf("receipt names another backup for %s", x.Key)
		}
	}
	done := pl(t)(c.RestoreCommit(id))
	if done["kind"] != "store-restored" {
		t.Fatalf("commit %v", done)
	}
	if v := storeOf(t, c, p, "default"); len(v) != 3 || v["A"] != "1" || v["B"] != "2" || v["C"] != "3" {
		t.Fatalf("restored: %v", v)
	}
	after := versions(t, c, "default")
	if after.Versions[0].Cause.Kind != "restore" || after.Versions[0].Cause.From != good.Seq || after.Versions[0].Version != good.Version || after.Current != good.Version {
		t.Fatalf("after %+v", after.Versions[0])
	}
	// committed once
	if _, err := c.RestoreCommit(id); err == nil {
		t.Fatal("committed twice")
	}
	// the restore is itself a version: putting the wiped one back removes keys again
	wiped := after.Versions[1]
	b2 := pl2(t)(c.RestoreBegin("default", wiped.Seq))
	json.Unmarshal([]byte(b2.Payload), &bd)
	if len(bd.Remove) != 2 || len(bd.Put) != 1 {
		t.Fatalf("undo begin %s", b2.Payload)
	}
}

func TestARestoreNeedsThePhone(t *testing.T) {
	c, p, _ := setupWithMaster(t)
	first := versions(t, c, "default").Versions[0]
	pl(t)(c.WriteKey(WriteKeyInput{Store: "default", Key: "A", Delete: true, Writer: "setup", Sig: "c2ln"}))

	// no signature, another key's signature, a signature over something else: refused, and the begin is spent
	for name, signer := range map[string]func(string) string{
		"no signature":     func(string) string { return "" },
		"another phone":    newPhone().sign,
		"the master key":   func(s string) string { return newPhone().sign(s) },
		"another document": func(string) string { return p.sign("{}") },
	} {
		b := pl2(t)(c.RestoreBegin("default", first.Seq))
		id, _, shares := restoreShares(p, b)
		if _, err := c.RestoreFinish(id, signer(b.Payload), shares); err == nil {
			t.Fatalf("%s: approved", name)
		}
		if _, err := c.RestoreFinish(id, p.sign(b.Payload), shares); err == nil {
			t.Fatalf("%s: a spent begin was approved", name)
		}
		if _, err := c.RestoreCommit(id); err == nil {
			t.Fatalf("%s: committed", name)
		}
	}
	// a commit without a finish
	b := pl2(t)(c.RestoreBegin("default", first.Seq))
	id, sig, shares := restoreShares(p, b)
	if _, err := c.RestoreCommit(id); err == nil {
		t.Fatal("committed with no approval")
	}
	// a missing share
	delete(shares, "A")
	if _, err := c.RestoreFinish(id, sig, shares); err == nil {
		t.Fatal("approved without every share")
	}
	if v := storeOf(t, c, p, "default"); v["A"] != "" {
		t.Fatalf("restored: %v", v)
	}
}

// A write between the phone's review and the commit: nothing is restored (the phone approved a change from the store as
// it was).
func TestARestoreIsRefusedWhenTheStoreMovedOn(t *testing.T) {
	c, p, _ := setupWithMaster(t)
	first := versions(t, c, "default").Versions[0]
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "A", "new")))
	b := pl2(t)(c.RestoreBegin("default", first.Seq))
	id, sig, shares := restoreShares(p, b)
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "D", "4")))
	if _, err := c.RestoreFinish(id, sig, shares); err == nil {
		t.Fatal("finish after a write")
	}
	b = pl2(t)(c.RestoreBegin("default", first.Seq))
	id, sig, shares = restoreShares(p, b)
	if _, err := c.RestoreFinish(id, sig, shares); err != nil {
		t.Fatal(err)
	}
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "E", "5")))
	if _, err := c.RestoreCommit(id); err == nil {
		t.Fatal("committed after a write")
	}
	if v := storeOf(t, c, p, "default"); v["A"] != "new" || v["E"] != "5" {
		t.Fatalf("got %v", v)
	}
}

func TestWhatCantBeRestored(t *testing.T) {
	c, p, _ := setupWithMaster(t)
	cur := versions(t, c, "default").Versions[0]
	if _, err := c.RestoreBegin("default", cur.Seq); err == nil {
		t.Fatal("restored the version it already is")
	}
	if _, err := c.RestoreBegin("default", 999); err == nil {
		t.Fatal("a version never kept")
	}
	if _, err := c.RestoreBegin(FlyStore, 1); err == nil {
		t.Fatal("the core store")
	}
	if _, err := c.RestoreBegin("nope", 1); err == nil {
		t.Fatal("a store that doesn't exist")
	}
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "A", "x")))
	c.repoOwner["default"] = "DE0CH/x"
	if _, err := c.RestoreBegin("default", cur.Seq); err == nil {
		t.Fatal("a repo's deploy-key store")
	}
	if _, err := c.Versions("nope", "n"); err == nil {
		t.Fatal("versions of a store that doesn't exist")
	}
}

// Only the last historyMax versions are kept; a removed store leaves none
func TestHistoryIsBounded(t *testing.T) {
	c, p, _ := setupWithMaster(t)
	for i := 0; i < historyMax+10; i++ {
		pl(t)(setupWrite(c, sealKey(t, c, p, "default", "A", "v")))
	}
	v := versions(t, c, "default")
	if len(v.Versions) != historyMax || v.Versions[0].Seq != historyMax+11 || v.Versions[historyMax-1].Seq != 12 {
		t.Fatalf("kept %d, newest %d", len(v.Versions), v.Versions[0].Seq)
	}
	c.forget("default")
	if len(versions(t, c, "default").Versions) != 0 {
		t.Fatal("history kept")
	}
	pl(t)(c.CreateStore("fresh"))
	if v := versions(t, c, "fresh"); len(v.Versions) != 1 || v.Versions[0].Cause.Kind != "created" {
		t.Fatalf("%+v", v)
	}
}
