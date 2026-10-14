package main

// The restore of a store to an earlier version (core/kernel/secrets/history.go, router/storerestore.go), on the test's
// own secrets set up with the public TEST master key: keys written as the setup session, the store wiped by deletes (the
// 2026-10-13 incident), the versions listed, a restore refused without the phone's signature, then put back under the
// phone's signature and shares; secrets' backups land in the bucket (writer "restore") and open with the master key to
// the values written. Runs after secrets' setup (E2E_ONLY=restore runs only this, with no machines).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// setupKeyWrite: what infra/setup.py key_write sends for one key (value "" = a delete): the value wrapped to the store
// key, its backup sealed to the master key, and `live` sealed to secrets' agreement key (served on the next pull of an
// unlocked store). The test router has no setup key, and secrets only passes a setup writer's signature on (the phone
// checks it), so the signature is a stand-in.
func setupKeyWrite(storeKey, master, secretsAgreement, store, key, value string) {
	body := map[string]any{"delete": value == "", "sig": "c2lnbmF0dXJl", "explanation": "e2e restore test key"}
	if value != "" {
		w := wrapKey(storeKey, store, key, value)
		b := sealToAAD(master, []byte(value), "jarvis2/backup", []byte(store+"\n"+key))
		h := sha256.Sum256([]byte(b["e"] + "\n" + b["data"]))
		body["wrapped"], body["data"], body["backup"], body["backupSha256"] = w["wrapped"], w["data"], b, hex.EncodeToString(h[:])
		body["live"] = sealTo(secretsAgreement, []byte(value), "jarvis2/live-key\n"+store+"\n"+key)
	}
	must2(call(router, "POST", "/setup/stores/"+store+"/keys/"+key, body, nil))
}

// openMasterSealed: a key backup opened with the master key's private half (what Recover does)
func openMasterSealed(master *ecdsa.PrivateKey, sealed map[string]string, aad []byte) string {
	priv, err := master.ECDH()
	if err != nil {
		log.Fatal(err)
	}
	eb, _ := b64.DecodeString(sealed["e"])
	E, err := ecdh.P256().NewPublicKey(eb)
	if err != nil {
		log.Fatal(err)
	}
	x, _ := priv.ECDH(E)
	k, _ := hkdf.Key(sha256.New, x, nil, "jarvis2/backup", 32)
	d, _ := b64.DecodeString(sealed["data"])
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	plain, err := g.Open(nil, d[:g.NonceSize()], d[g.NonceSize():], aad)
	if err != nil {
		log.Fatalf("a restore backup doesn't open with the master key: %v", err)
	}
	return string(plain)
}

type versionRow struct {
	Seq     int
	Version string
	Cause   struct{ Kind, Key string }
	Keys    []struct{ Name string }
}

func storeVersions(store string) (current string, rows []versionRow) {
	var d Doc
	must2(call(router, "POST", "/api/secrets/stores/versions", map[string]string{"store": store, "nonce": "e2e-v"}, &d))
	var v struct {
		Kind, Store, Current string
		Versions             []versionRow
	}
	verify(d, &v)
	if v.Kind != "store-versions" || v.Store != store {
		log.Fatalf("versions: %+v", v)
	}
	return v.Current, v.Versions
}

func keyNamesOf(store string) []string {
	var out struct {
		Stores []struct {
			Name string
			Keys []string
		}
	}
	must2(call(router, "GET", "/api/stores", nil, &out))
	for _, s := range out.Stores {
		if s.Name == store {
			sort.Strings(s.Keys)
			return s.Keys
		}
	}
	return nil
}

// restoreBegin → (pending, the begin document, the phone's shares of every key put back)
func restoreBegin(p *phone, store string, seq int) (string, Doc, map[string]map[string]string) {
	var d Doc
	must2(call(router, "POST", "/api/secrets/stores/restore/begin", map[string]any{"store": store, "seq": seq}, &d))
	var b struct {
		Kind, Pending, Store, T string
		Put                     []struct{ Key, E string }
		Remove                  []string
	}
	verify(d, &b)
	if b.Kind != "store-restore-begin" || b.Store != store {
		log.Fatalf("restore begin: %s", d.Payload)
	}
	shares := map[string]map[string]string{}
	for _, k := range b.Put {
		eb, _ := b64.DecodeString(k.E)
		E, _ := ecdh.P256().NewPublicKey(eb)
		x, _ := p.agr.ECDH(E)
		shares[k.Key] = sealTo(b.T, x, "jarvis2/unlock-share")
	}
	return b.Pending, d, shares
}

func restoreStep(p *phone, master *ecdsa.PrivateKey, storeKey, secretsAgreement string) {
	mpub, _ := master.PublicKey.ECDH()
	mk := b64.EncodeToString(mpub.Bytes())
	store := "e2e"
	lockAll() // an unlock in force ends first, so the end opens the restored store afresh
	vals := map[string]string{"E2E_R1": "r1-" + hex.EncodeToString(randBytes(6)), "E2E_R2": "r2-" + hex.EncodeToString(randBytes(6))}

	step("restore: keys written one by one as the setup session; secrets lists each change as a version")
	for _, k := range []string{"E2E_R1", "E2E_R2"} {
		setupKeyWrite(storeKey, mk, secretsAgreement, store, k, vals[k])
	}
	_, rows := storeVersions(store)
	if len(rows) < 3 || rows[0].Cause.Kind != "write" || rows[0].Cause.Key != "E2E_R2" || rows[len(rows)-1].Cause.Kind != "recover" {
		log.Fatalf("versions: %+v", rows)
	}
	good := rows[0]
	want := keyNamesOf(store)

	step("restore: the store wiped (every key deleted, one stray written)")
	for _, k := range want {
		setupKeyWrite(storeKey, mk, secretsAgreement, store, k, "")
	}
	setupKeyWrite(storeKey, mk, secretsAgreement, store, "E2E_STRAY", "stray")
	if got := keyNamesOf(store); strings.Join(got, ",") != "E2E_STRAY" {
		log.Fatalf("not wiped: %v", got)
	}

	step("restore: an Inbox request from the web page; refused without the phone's signature (and the begin is spent)")
	must2(call(router, "POST", "/api/requests/restore", map[string]any{"store": store, "seq": good.Seq, "explanation": "put the keys back"}, nil))
	pending, d, shares := restoreBegin(p, store, good.Seq)
	other := &phone{sig: mustSigner(), agr: nil}
	if s, _ := call(router, "POST", "/api/stores/restore/finish", map[string]any{"pending": pending, "signature": other.sign(d.Payload), "shares": shares}, nil); s == 200 {
		log.Fatal("a restore went through without the phone's signature")
	}
	if s, _ := call(router, "POST", "/api/stores/restore/finish", map[string]any{"pending": pending, "signature": p.sign(d.Payload), "shares": shares}, nil); s == 200 {
		log.Fatal("a spent restore went through")
	}
	if got := keyNamesOf(store); strings.Join(got, ",") != "E2E_STRAY" {
		log.Fatalf("restored without the phone: %v", got)
	}

	step("restore: the phone signs secrets' begin document and shares the keys put back; backups first, then the commit")
	pending, d, shares = restoreBegin(p, store, good.Seq)
	var out struct {
		Restored Doc
	}
	must2(call(router, "POST", "/api/stores/restore/finish", map[string]any{"pending": pending, "signature": p.sign(d.Payload), "shares": shares}, &out))
	var done struct {
		Kind    string
		Version string
		From    int
	}
	verify(out.Restored, &done)
	if done.Kind != "store-restored" || done.From != good.Seq || done.Version != good.Version {
		log.Fatalf("restored: %+v", done)
	}
	if got := keyNamesOf(store); strings.Join(got, ",") != strings.Join(want, ",") {
		log.Fatalf("after the restore: %v, want %v", got, want)
	}
	cur, rows := storeVersions(store)
	if cur != good.Version || rows[0].Cause.Kind != "restore" {
		log.Fatalf("versions after the restore: %+v", rows[0])
	}
	var q struct{ Requests []struct{ Kind string } }
	must2(call(router, "GET", "/api/requests", nil, &q))
	for _, r := range q.Requests {
		if r.Kind == "restore" {
			log.Fatal("the restore request stayed in the Inbox")
		}
	}

	step("restore: the bucket's backups (writer restore) open with the test master key to the values written; the stray is a delete")
	dir := os.Getenv("E2E_S3_DIR")
	for k, v := range vals {
		var o struct {
			Deleted bool
			Sealed  map[string]string
			Writer  struct{ By string }
		}
		b, err := os.ReadFile(filepath.Join(dir, "keys", store, k+".json"))
		if err != nil || json.Unmarshal(b, &o) != nil {
			log.Fatalf("%s: no backup: %v", k, err)
		}
		if o.Writer.By != "restore" || o.Deleted {
			log.Fatalf("%s: %s", k, b)
		}
		if got := openMasterSealed(master, o.Sealed, []byte(store+"\n"+k)); got != v {
			log.Fatalf("%s: the backup holds another value", k)
		}
	}
	var stray struct {
		Deleted bool
		Writer  struct{ By string }
	}
	b, _ := os.ReadFile(filepath.Join(dir, "keys", store, "E2E_STRAY.json"))
	if json.Unmarshal(b, &stray) != nil || !stray.Deleted || stray.Writer.By != "restore" {
		log.Fatalf("the stray's backup: %s", b)
	}
	step("restore: an unlock opens the restored store (each key opens with the phone's share)")
	lockID(unlock(p, store))
}

func mustSigner() *kernel.Signer {
	k, err := kernel.NewSigner()
	if err != nil {
		log.Fatal(err)
	}
	return k
}
