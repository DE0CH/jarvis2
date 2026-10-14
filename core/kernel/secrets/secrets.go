// Package secrets holds the stores, the unlocks and a signed list of open unlocks (DESIGN "Secrets"; the held core's
// keys, history, restore and deploy-key code, carried over). Given a grant made by the grant mover or the grant merger,
// it returns the stores the grant's allowed set names (store:x), sealed to the grant's machine and signed. An unlock is
// per store and never locks by itself: no release after a pull, no timer; unlocks end with a lock call, and the phone
// sees the open ones. Any written key is served on the next pull, whoever wrote it.
//
// All of its state lives in memory: a restart is a new, empty secrets, set up again from the iPhone (Reset or Recover).
package secrets

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// ReservedStore: the name of the old core's own store (its Fly token, now the spawner's): never made, written or served
const ReservedStore = "core"

// StorePrefix: the allowed string that names a store in a grant
const StorePrefix = "store:"

type unlocked struct {
	values  map[string]string
	version string // the store's version at the unlock (what the phone's shares opened)
	ids     map[string]time.Time
}

type pendingUnlock struct {
	store   string
	entries map[string]KeyEntry // the store's keys at begin: what the phone's shares open
	version string
	t       *ecdh.PrivateKey
	// written: keys written or deleted (nil) since begin, with their live values, applied at finish
	written map[string]*string
}

type Secrets struct {
	mu        sync.Mutex
	signer    *kernel.Signer
	agreement *ecdh.PrivateKey // secrets' share K of every store's key; also what live copies are sealed to
	roster    kernel.Roster
	MasterKey string // the master public key it was claimed with ("" = empty, waiting for Reset or Recover)
	BoxSig    string
	exit      func() // Wipe ends the process (main: os.Exit; tests: a stub)

	phoneSigning, phoneAgreement string

	stores       map[string]map[string]*KeyEntry
	notSensitive map[string]bool // every store not in it is sensitive
	pending      map[string]*pendingUnlock
	unlocked     map[string]*unlocked
	pendingKeys  map[string]pendingDeployKey
	repoOwner    map[string]string

	history    map[string][]*storeVersionRec
	historySeq map[string]int
	restores   map[string]*pendingRestore

	github GitHub
	now    func() time.Time
	// seal: kernel.SealTo (tests watch which key a pull seals to)
	seal func(recipient string, plain []byte, info string) (kernel.Sealed, error)
}

func New(s *kernel.Signer, r kernel.Roster, gh GitHub) (*Secrets, error) {
	a, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Secrets{signer: s, agreement: a, roster: r, stores: map[string]map[string]*KeyEntry{}, notSensitive: map[string]bool{},
		pending: map[string]*pendingUnlock{}, unlocked: map[string]*unlocked{}, pendingKeys: map[string]pendingDeployKey{},
		repoOwner: map[string]string{}, github: gh, now: time.Now, seal: kernel.SealTo}, nil
}

// SetExit / SetClock / SetSeal: main and tests
func (c *Secrets) SetExit(f func())                                              { c.exit = f }
func (c *Secrets) SetClock(now func() time.Time)                                 { c.now = now }
func (c *Secrets) SetSeal(f func(string, []byte, string) (kernel.Sealed, error)) { c.seal = f }
func (c *Secrets) AgreementKey() string                                          { return b64.EncodeToString(c.agreement.PublicKey().Bytes()) }
func (c *Secrets) logf(f string, a ...any)                                       { log.Printf(f, a...) }
func (c *Secrets) sign(v any) (kernel.SignedDoc, error)                          { return kernel.Sign(c.signer, v) }

// State: secrets' own signed state — the master public key it was claimed with ("" while empty) and the phone's keys
func (c *Secrets) State() (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := map[string]any{"kind": "secrets-state", "master": c.MasterKey, "phone": nil, "bundle": "keys"}
	if c.phoneSigning != "" {
		st["phone"] = map[string]string{"signingKey": c.phoneSigning, "agreementKey": c.phoneAgreement}
	}
	return c.sign(st)
}

// ---- claim: an empty secrets takes a master key (Reset or Recover, both from the app) ------------------------

const infoClaim = "jarvis2/claim" // the claim's bundle, sealed to secrets by the phone

type claimStatement struct {
	Kind   string `json:"kind"` // "claim"
	Master string `json:"master"`
	Core   struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"core"` // secrets' keys (the claim names the part it sets up)
	Phone struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"phone"`
	BundleSha256 string `json:"bundleSha256"`
}

// claimBundle (format "keys"): every store and every key, wrapped by the app to the store key, the names of the stores
// that are NOT sensitive, and the deploy-key stores' repos. A Reset's has no stores.
type claimBundle struct {
	Format       string            `json:"format"`
	Stores       []string          `json:"stores"`
	Keys         []KeyEntry        `json:"keys"`
	NotSensitive []string          `json:"notSensitive"`
	Owners       map[string]string `json:"owners"`
}

// Claim: once, on an empty secrets. The statement names the master public key, secrets and the phone, signed by that
// master key; the bundle, sealed to secrets, carries the stores.
func (c *Secrets) Claim(statement, masterSig string, bundle kernel.Sealed) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey != "" {
		return kernel.SignedDoc{}, kernel.Fail(409, "secrets is already set up")
	}
	var st claimStatement
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "claim" {
		return kernel.SignedDoc{}, kernel.Fail(400, "not a claim statement")
	}
	if _, err := kernel.ParsePoint(st.Master); err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "bad master key: %v", err)
	}
	if !kernel.Verify(st.Master, []byte(statement), masterSig) {
		return kernel.SignedDoc{}, kernel.Fail(403, "the claim isn't signed by the master key it names")
	}
	if st.Core.SigningKey != c.signer.PublicKey() || st.Core.AgreementKey != c.AgreementKey() {
		return kernel.SignedDoc{}, kernel.Fail(403, "the claim names another secrets")
	}
	if _, err := kernel.ParsePoint(st.Phone.SigningKey); err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "bad phone signing key: %v", err)
	}
	if _, err := kernel.ParsePoint(st.Phone.AgreementKey); err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "bad phone agreement key: %v", err)
	}
	plain, err := kernel.OpenSealed(c.agreement, bundle, infoClaim)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "can't open the bundle")
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != st.BundleSha256 {
		return kernel.SignedDoc{}, kernel.Fail(403, "the bundle isn't the one the master key signed")
	}
	var b claimBundle
	if json.Unmarshal(plain, &b) != nil || b.Format != "keys" {
		return kernel.SignedDoc{}, kernel.Fail(400, "bad bundle")
	}
	stores := map[string]map[string]*KeyEntry{}
	for _, n := range b.Stores {
		if _, seen := stores[n]; !storeName(n) || n == ReservedStore || seen {
			return kernel.SignedDoc{}, kernel.Fail(400, "bad or repeated store %q in the bundle", n)
		}
		stores[n] = map[string]*KeyEntry{}
	}
	now := c.now().UTC().Format(time.RFC3339)
	for i := range b.Keys {
		x := b.Keys[i]
		keys, ok := stores[x.Store]
		if _, seen := keys[x.Key]; !ok || seen || !validEntry(&x, x.Store) {
			return kernel.SignedDoc{}, kernel.Fail(400, "bad or repeated key %q of store %q in the bundle", x.Key, x.Store)
		}
		x.Writer, x.At, x.BackupSha256 = &EntryWriter{By: "core"}, now, "" // the master key signed the bundle
		keys[x.Key] = &x
	}
	owners := map[string]string{}
	for s, repo := range b.Owners {
		if _, ok := stores[s]; ok && repoRE.MatchString(repo) {
			owners[s] = repo
		}
	}
	c.MasterKey, c.repoOwner = st.Master, owners
	c.phoneSigning, c.phoneAgreement = st.Phone.SigningKey, st.Phone.AgreementKey
	c.stores, c.notSensitive = stores, map[string]bool{}
	for _, n := range b.NotSensitive {
		if _, ok := c.stores[n]; ok {
			c.notSensitive[n] = true
		}
	}
	c.history, c.historySeq = nil, nil
	for _, n := range sortedKeys(c.stores) {
		c.record(n, VersionCause{Kind: "recover"})
	}
	c.logf("claimed: master key, phone keys, %d stores", len(c.stores))
	return c.sign(map[string]any{"kind": "claimed", "stores": len(c.stores)})
}

// Wipe: the current master key ends this secrets: it answers, then exits, and Kubernetes starts a new, empty one
func (c *Secrets) Wipe(statement, masterSig string) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return kernel.SignedDoc{}, kernel.Fail(409, "secrets is empty")
	}
	if !kernel.Verify(c.MasterKey, []byte(statement), masterSig) {
		return kernel.SignedDoc{}, kernel.Fail(403, "the wipe isn't signed by this secrets' master key")
	}
	var st struct {
		Kind string `json:"kind"`
		Core string `json:"core"` // secrets' signing key
	}
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "wipe" || st.Core != c.signer.PublicKey() {
		return kernel.SignedDoc{}, kernel.Fail(403, "the wipe names another secrets")
	}
	c.logf("wipe: the master key ends this secrets")
	d, err := c.sign(map[string]any{"kind": "wiping", "core": st.Core})
	if err == nil && c.exit != nil {
		go c.exit()
	}
	return d, err
}

// StoreKey: the store key C = P + K for the phone agreement key P, signed: what the app wraps a store's data keys to
func (c *Secrets) StoreKey(phone string) (kernel.SignedDoc, error) {
	pb, err := b64.DecodeString(phone)
	if err != nil || len(pb) != 65 {
		return kernel.SignedDoc{}, kernel.Fail(400, "phone: a P-256 public key (X9.63, base64)")
	}
	sum, err := AddPoints(pb, c.agreement.PublicKey().Bytes())
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "phone: %v", err)
	}
	return c.sign(map[string]any{"kind": "store-key", "phone": phone, "storeKey": b64.EncodeToString(sum)})
}

// ---- stores ----------------------------------------------------------------------------------------

func storeName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// CreateStore: once per name — an empty, non-sensitive store
func (c *Secrets) CreateStore(name string) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return kernel.SignedDoc{}, kernel.Fail(409, "secrets isn't set up yet")
	}
	if !storeName(name) || name == ReservedStore || name == DeployKeyTokenStore {
		return kernel.SignedDoc{}, kernel.Fail(400, "bad store name (%s is always sensitive)", DeployKeyTokenStore)
	}
	if _, ok := c.stores[name]; ok {
		return kernel.SignedDoc{}, kernel.Fail(409, "store %s exists", name)
	}
	c.stores[name], c.notSensitive[name] = map[string]*KeyEntry{}, true
	c.record(name, VersionCause{Kind: "created"})
	return c.sign(map[string]any{"kind": "store-created", "name": name})
}

// MarkSensitive: the one-way upgrade (anyone may: it only adds protection)
func (c *Secrets) MarkSensitive(name string) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.notSensitive[name] {
		return kernel.SignedDoc{}, kernel.Fail(409, "store %s is already sensitive", name)
	}
	delete(c.notSensitive, name)
	return c.sign(map[string]any{"kind": "marked-sensitive", "name": name})
}

// Stores: the signed list (names, sensitivity, empty, unlocked, each store's keys with who wrote them, its version)
func (c *Secrets) Stores(nonce string) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type row struct {
		Name      string   `json:"name"`
		Sensitive bool     `json:"sensitive"`
		Empty     bool     `json:"empty"`
		Unlocked  bool     `json:"unlocked"`
		Keys      []keyRow `json:"keys"`
		Version   string   `json:"version"`
	}
	out := []row{}
	for _, n := range sortedKeys(c.stores) {
		keys := c.stores[n]
		out = append(out, row{n, !c.notSensitive[n], len(keys) == 0, c.unlocked[n] != nil, keyRows(keys), storeVersion(keys)})
	}
	return c.sign(map[string]any{"kind": "stores", "nonce": nonce, "stores": out})
}

// ---- unlock / lock -------------------------------------------------------------------------------

const infoShare = "jarvis2/unlock-share"

// UnlockBegin: a one-off key pair for this unlock; the phone computes its share of every key from that key's E (shown
// here, signed, with the store's name, who wrote each key and the sha256 of its data)
func (c *Secrets) UnlockBegin(name string) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name == DeployKeyTokenStore {
		return kernel.SignedDoc{}, kernel.Fail(403, "%s is opened only by a deploy-key call, never unlocked", DeployKeyTokenStore)
	}
	keys := c.stores[name]
	if len(keys) == 0 {
		return kernel.SignedDoc{}, kernel.Fail(404, "no store %s with contents", name)
	}
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return kernel.SignedDoc{}, err
	}
	type keyBegin struct {
		Key          string       `json:"key"`
		E            string       `json:"e"`
		Writer       *EntryWriter `json:"writer"`
		DataSha256   string       `json:"dataSha256"`
		BackupSha256 string       `json:"backupSha256"`
		At           string       `json:"at"`
	}
	entries := copyEntries(keys)
	rows := []keyBegin{}
	for _, k := range sortedKeys(entries) {
		x := entries[k]
		rows = append(rows, keyBegin{k, x.Wrapped.E, entryWriter(&x), kernel.SHA256Hex(x.Data), x.BackupSha256, x.At})
	}
	id := randID()
	version := storeVersion(keys)
	c.pending[id] = &pendingUnlock{store: name, entries: entries, version: version, t: t, written: map[string]*string{}}
	return c.sign(map[string]any{"kind": "unlock-begin", "pending": id, "store": name, "t": b64.EncodeToString(t.PublicKey().Bytes()),
		"keys": rows, "version": version})
}

// UnlockFinish: the phone's share of every key unlock_begin named, each sealed to T (one try)
func (c *Secrets) UnlockFinish(pending string, shares map[string]kernel.Sealed) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[pending]
	if !ok {
		return kernel.SignedDoc{}, kernel.Fail(404, "no such pending unlock")
	}
	delete(c.pending, pending)
	if len(shares) != len(p.entries) {
		return kernel.SignedDoc{}, kernel.Fail(400, "one share for each of the %d keys", len(p.entries))
	}
	vals := map[string]string{}
	for k, x := range p.entries {
		sh, ok := shares[k]
		if !ok {
			return kernel.SignedDoc{}, kernel.Fail(400, "no share for key %s", k)
		}
		px, err := kernel.OpenSealed(p.t, sh, infoShare)
		if err != nil {
			return kernel.SignedDoc{}, kernel.Fail(400, "the share for %s isn't sealed to this unlock", k)
		}
		v, err := c.openEntry(&x, px)
		if err != nil {
			return kernel.SignedDoc{}, kernel.Fail(403, "%v", err)
		}
		vals[k] = v
	}
	for k, v := range p.written { // keys written since begin: their live values
		if v == nil {
			delete(vals, k)
		} else {
			vals[k] = *v
		}
	}
	u := c.unlocked[p.store]
	if u == nil {
		u = &unlocked{ids: map[string]time.Time{}}
		c.unlocked[p.store] = u
	}
	u.values, u.version = vals, p.version
	id := randID()
	u.ids[id] = c.now()
	c.logf("store %s unlocked (%s)", p.store, id)
	return c.sign(map[string]any{"kind": "unlocked", "id": id, "store": p.store, "version": p.version})
}

// noteWritten: a key written (value) or deleted (nil) reaches every pending unlock of the store (callers hold c.mu)
func (c *Secrets) noteWritten(store, key string, value *string) {
	for _, p := range c.pending {
		if p.store == store {
			p.written[key] = value
		}
	}
}

// Lock: one unlock id ends; the plaintext goes with the store's last id
func (c *Secrets) Lock(id string) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, u := range c.unlocked {
		if _, ok := u.ids[id]; ok {
			delete(u.ids, id)
			if len(u.ids) == 0 {
				delete(c.unlocked, name)
			}
			c.logf("unlock %s locked (%s)", id, name)
			return c.sign(map[string]any{"kind": "locked", "id": id, "store": name})
		}
	}
	return kernel.SignedDoc{}, kernel.Fail(404, "no such unlock id")
}

// ListUnlocked: the signed list of open unlocks (what the phone shows)
func (c *Secrets) ListUnlocked(nonce string) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type row struct {
		ID    string `json:"id"`
		Store string `json:"store"`
		Since string `json:"since"`
	}
	rows := []row{}
	for name, u := range c.unlocked {
		for id, since := range u.ids {
			rows = append(rows, row{id, name, since.UTC().Format(time.RFC3339)})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Since != rows[j].Since {
			return rows[i].Since < rows[j].Since
		}
		return rows[i].ID < rows[j].ID
	})
	return c.sign(map[string]any{"kind": "unlocked-list", "nonce": nonce, "unlocked": rows})
}

// ---- pull ---------------------------------------------------------------------------------------

// withheld: stores no grant ever gets
func withheld(n string) bool { return n == ReservedStore || n == DeployKeyTokenStore }

// Pull: a grant made by the grant mover or the grant merger → the stores its allowed set names (store:x; a cofinite set
// names every store it doesn't leave out), sealed to the grant machine's encryption key — a Fly machine's own, or for a
// source or the sink the hash-to-curve key nobody holds — and signed. Secrets doesn't read the conditions (the guard
// does). Each named store is served when unlocked, else listed as locked; a name with no store is listed as missing.
func (c *Secrets) Pull(grant kernel.SignedDoc) (kernel.SignedDoc, error) {
	g, err := kernel.OpenGrant(c.roster, grant, kernel.RoleMover, kernel.RoleMerger)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(403, "%v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	names := []string{}
	if g.Allowed.Finite() {
		for _, x := range g.Allowed.Elems() {
			if n, ok := strings.CutPrefix(x, StorePrefix); ok {
				names = append(names, n)
			}
		}
	} else {
		for _, n := range sortedKeys(c.stores) {
			if g.Allowed.Contains(StorePrefix + n) {
				names = append(names, n)
			}
		}
	}
	served, locked, missing, held := []string{}, []string{}, []string{}, []string{}
	plain := map[string]map[string]string{}
	versions := map[string]string{}
	for _, n := range names {
		_, exists := c.stores[n]
		u := c.unlocked[n]
		switch {
		case withheld(n):
			held = append(held, n)
		case !exists:
			missing = append(missing, n)
		case u == nil:
			locked = append(locked, n)
		default:
			served = append(served, n)
			plain[n] = u.values
			versions[n] = u.version
		}
	}
	b, _ := json.Marshal(plain)
	sealed, err := c.seal(g.Machine.EncryptionKeyOf(), b, "jarvis2/secrets")
	if err != nil {
		return kernel.SignedDoc{}, err
	}
	c.logf("secrets pulled for %s (%v; locked %v; missing %v)", g.Machine.ID, served, locked, missing)
	return c.sign(map[string]any{"kind": "secrets", "grant": grant.ID(), "machine": g.Machine, "conditions": g.Conditions,
		"stores": served, "versions": versions, "locked": locked, "missing": missing, "withheld": held, "sealed": sealed})
}

// ---- helpers ------------------------------------------------------------------------------------

func randID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
