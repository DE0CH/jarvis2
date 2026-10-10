package main

// The secrets-controller core (docs/DESIGN.md). Every answer that leaves it is signed; all of its state
// lives in memory (a restart = a new, empty core, set up again from the iPhone: Reset or Recover). It accepts or rejects
// — the orchestration (which approval applies, retries, the session flows) lives in the router outside it.

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Err struct {
	Status int
	Msg    string
}

func (e *Err) Error() string                    { return e.Msg }
func fail(status int, f string, a ...any) error { return &Err{status, fmt.Sprintf(f, a...)} }

// SignedDoc: what every answer is — the exact JSON text and the core's signature over it
type SignedDoc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// StoreBlob: a key store's contents: its values under a data key (the store's name as associated data, so a
// blob under another name doesn't decrypt), that key wrapped to the combined key P + K. Writing one is open
// (anyone, normally the router, which guards it): it can't reveal a secret, and the name binding means it
// can't move one store's values under another store's name.
type StoreBlob struct {
	Name    string     `json:"name"`
	Wrapped WrappedKey `json:"wrapped"` // the data key, to phone + core
	Data    string     `json:"data"`    // AES-GCM(json values) under the data key, the name as associated data
}

type StartedMachine struct {
	ID            string `json:"id"`
	Requested     string `json:"requested"`     // the image start was asked for (what an approval names)
	Image         string `json:"image"`         // what Fly reports the machine runs (ref@digest)
	EncryptionKey string `json:"encryptionKey"` // the machine's own keys, read through Fly exec
	SigningKey    string `json:"signingKey"`
}

type Options struct {
	Harness string `json:"harness"`
	// the harness's permission mode (auto | bypass): signed, so a resume that changes it — above all raising to
	// bypass — isn't approved by a dead machine and needs the phone (Deyao, 2026-10-09)
	PermissionMode string `json:"permissionMode,omitempty"`
}

// a succession request, made before any machine exists. Machine is set only when a running machine succeeds
// itself with one more store.
type Request struct {
	Kind        string          `json:"kind"`
	Predecessor *SignedDoc      `json:"predecessor"` // the predecessor's succession cert; nil = new line
	PredID      string          `json:"predecessorId"`
	Line        string          `json:"line,omitempty"` // the line's first machine; "" = a new line
	Machine     *StartedMachine `json:"machine,omitempty"`
	Image       string          `json:"image,omitempty"` // the image the new machine runs
	Stores      []string        `json:"stores"`
	Sensitive   []string        `json:"sensitive"` // the core's marks, for the phone's warning
	Options     Options         `json:"options"`
	AddedStore  string          `json:"addedStore,omitempty"` // set when the machine succeeds itself with one more store
	Downgrade   bool            `json:"downgrade,omitempty"`  // the machine succeeds itself with a subset of its stores and new keys
	// Salt: random, on a new line only, so two identical new-session requests get different nonces (the nonce is
	// the request's MAC, and an approval nonce is used once); a successor's nonce is already unique per predecessor
	Salt string `json:"salt,omitempty"`
}

// Approval: a challenge one of the approve_by_* primitives approved; certify() binds it to exactly one machine
type Approval struct {
	Kind    string  `json:"kind"` // "approval"
	Nonce   string  `json:"nonce"`
	Request Request `json:"request"`
	By      string  `json:"by"` // "phone" | "dead-machine"
}

type Cert struct {
	Kind     string          `json:"kind"` // "succession-cert"
	PredID   string          `json:"predecessorId"`
	Machine  *StartedMachine `json:"machine"`
	Stores   []string        `json:"stores"`
	Options  Options         `json:"options"`
	Nonce    string          `json:"nonce"`
	IssuedAt string          `json:"issuedAt"`
	// for the machine's own checks of grants (docs/DESIGN.md "Grants"): the phone's signing key, and whether
	// any of the stores is sensitive (then only a fresh phone grant opens a shell)
	Phone     string `json:"phone,omitempty"`
	Sensitive bool   `json:"sensitive"`
	Line      string `json:"line"` // the line's first machine: what grants name, stable across successions
}

// succession: the cert for a machine on a line (callers hold c.mu)
func (c *Core) succession(r Request, m *StartedMachine, nonce, now string) Cert {
	sensitive := false
	for _, n := range r.Stores {
		sensitive = sensitive || !c.notSensitive[n]
	}
	line := r.Line
	if line == "" {
		line = m.ID
	}
	return Cert{Kind: "succession-cert", PredID: r.PredID, Machine: m, Stores: r.Stores, Options: r.Options,
		Nonce: nonce, IssuedAt: now, Phone: c.phoneSigning, Sensitive: sensitive, Line: line}
}

type unlocked struct {
	values map[string]string
	ids    map[string]time.Time
}

type Core struct {
	mu        sync.Mutex
	signer    *Signer
	agreement *ecdh.PrivateKey // the core's share K of every store's key
	nonceKey  []byte
	MasterKey string // the master public key it was claimed with ("" = empty, waiting for Reset or Recover)
	BoxSig    string // the box key's signature over this core's identity
	exit      func() // Wipe ends the process (main: os.Exit; tests: a stub)

	phoneSigning, phoneAgreement string
	coreCert                     *MasterCert // the master's signature on this core (from the claim)

	approvalsUsed map[string]bool // approval nonces already certified
	certified     map[string]bool // started machines that already have a line

	started map[string]*StartedMachine
	killed  map[string]bool // approve_by_dead_machine's two sets
	used    map[string]bool

	stores       map[string]*StoreBlob // nil value = created, still empty
	notSensitive map[string]bool       // the only sensitivity state: every store not in it is sensitive
	pending      map[string]pendingUnlock
	unlocked     map[string]*unlocked
	pendingKeys  map[string]pendingDeployKey // deploy-key adds/removes waiting for the phone (deploykeys.go)

	fly    Fly
	github GitHub // deploy keys only, with the token the phone unlocks for that one call
	log    []string
	now    func() time.Time
}

type pendingUnlock struct {
	store StoreBlob
	t     *ecdh.PrivateKey
}

func NewCore(fly Fly) (*Core, error) {
	s, err := NewSigner()
	if err != nil {
		return nil, err
	}
	a, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nk := make([]byte, 32)
	rand.Read(nk)
	return &Core{signer: s, agreement: a, nonceKey: nk,
		approvalsUsed: map[string]bool{}, certified: map[string]bool{},
		started: map[string]*StartedMachine{}, killed: map[string]bool{}, used: map[string]bool{},
		stores: map[string]*StoreBlob{}, notSensitive: map[string]bool{}, pending: map[string]pendingUnlock{}, unlocked: map[string]*unlocked{}, pendingKeys: map[string]pendingDeployKey{},
		fly: fly, github: newGitHub(), now: time.Now}, nil
}

func (c *Core) logf(f string, a ...any) {
	c.log = append(c.log, c.now().UTC().Format(time.RFC3339)+" "+fmt.Sprintf(f, a...))
}

func (c *Core) sign(v any) (SignedDoc, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return SignedDoc{}, err
	}
	s, err := c.signer.Sign(b)
	if err != nil {
		return SignedDoc{}, err
	}
	return SignedDoc{Payload: string(b), Sig: s}, nil
}

// verifyOwn: the payload of a document only if this core signed it
func (c *Core) verifyOwn(d *SignedDoc, out any) error {
	if d == nil || !VerifyWith(c.signer.PublicKey(), []byte(d.Payload), d.Sig) {
		return fail(400, "not a document this core signed")
	}
	return json.Unmarshal([]byte(d.Payload), out)
}

func (c *Core) mac(parts ...string) string {
	m := hmac.New(sha256.New, c.nonceKey)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

// ---- identity ----------------------------------------------------------------------------------

func (c *Core) Key() map[string]string {
	pub := c.agreement.PublicKey().Bytes()
	return map[string]string{"signingKey": c.signer.PublicKey(), "agreementKey": b64.EncodeToString(pub)}
}

// IdentityText: what the box key signs (keys/box.pub checks it: the app, the setup session)
func IdentityText(signingKey, agreementKey string) string {
	return "jarvis2-core-identity " + signingKey + " " + agreementKey
}

// Identity: the core's public keys with the box key's signature over them (it travels as plain text), and
// the core's own signed state: the master public key it was claimed with ("" while empty) and the phone's
// keys. The app reads from it whether the core is empty and whose master key it holds; the setup session
// learns the master public key from it (after checking the box key, then this signature).
func (c *Core) Identity() (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := map[string]any{"kind": "core-state", "master": c.MasterKey, "phone": nil}
	if c.phoneSigning != "" {
		st["phone"] = map[string]string{"signingKey": c.phoneSigning, "agreementKey": c.phoneAgreement}
	}
	d, err := c.sign(st)
	if err != nil {
		return nil, err
	}
	k := c.Key()
	return map[string]any{"signingKey": k["signingKey"], "agreementKey": k["agreementKey"], "boxSig": c.BoxSig, "state": d}, nil
}

// ---- claim: an empty core takes a master key (Reset or Recover, both from the app) ------------------------

const (
	infoClaim    = "jarvis2/claim"     // the claim's bundle, sealed to the core by the phone
	infoFlyToken = "jarvis2/fly-token" // the Fly token, sealed to the core by the setup session
)

// MasterCert: the master key's signature over the claim statement (the archive keeps it next to a session's
// snapshot: master key → core key → cert)
type MasterCert struct {
	Statement string `json:"statement"`
	MasterSig string `json:"masterSig"`
}

type claimStatement struct {
	Kind   string `json:"kind"`   // "claim"
	Master string `json:"master"` // the master public key: it signs this statement; the core keeps it for its life
	Core   struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"core"`
	Phone struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"phone"`
	BundleSha256 string `json:"bundleSha256"`
}

// FlyStore: the key store holding the core's own Fly token (FLY_API_TOKEN). It arrives in a Recover bundle
// like any store (or through SetFlyToken), but the core keeps only the token, for its whole life, and the
// store itself never exists for a session.
const FlyStore = "core"

// the claim bundle: every store, and the names of the stores that are NOT sensitive — every other store comes
// back sensitive, since nothing can downgrade one later (the master key signed the bundle's hash). A Reset's
// bundle is empty.
type claimBundle struct {
	Stores       []storeData `json:"stores"`
	NotSensitive []string    `json:"notSensitive"`
}

type storeData struct {
	Name   string            `json:"name"`
	Values map[string]string `json:"values"`
}

// Claim: once per core, on an empty core. The statement names the master public key, this core and the
// phone, and is signed by that master key; from then on the core trusts that master key and that phone.
// The bundle, sealed to this core, carries the stores (Recover: every store from the backups, the Fly store
// among them; Reset: none). Who may claim is the router's business (Deyao's logged-in app only); the app
// refuses a core claimed with a master key that isn't its own. The plaintext stores live only inside this
// call: each is wrapped to phone + core at once and only the wrapped blob is kept.
func (c *Core) Claim(statement, masterSig string, bundle Sealed) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey != "" {
		return SignedDoc{}, fail(409, "this core is already set up")
	}
	var st claimStatement
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "claim" {
		return SignedDoc{}, fail(400, "not a claim statement")
	}
	if _, err := parseSigningKey(st.Master); err != nil {
		return SignedDoc{}, fail(400, "bad master key: %v", err)
	}
	if !VerifyWith(st.Master, []byte(statement), masterSig) {
		return SignedDoc{}, fail(403, "the claim isn't signed by the master key it names")
	}
	k := c.Key()
	if st.Core.SigningKey != k["signingKey"] || st.Core.AgreementKey != k["agreementKey"] {
		return SignedDoc{}, fail(403, "the claim names another core")
	}
	if _, err := parseSigningKey(st.Phone.SigningKey); err != nil {
		return SignedDoc{}, fail(400, "bad phone signing key: %v", err)
	}
	if b, err := b64.DecodeString(st.Phone.AgreementKey); err != nil || len(b) != 65 {
		return SignedDoc{}, fail(400, "bad phone agreement key")
	} else if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return SignedDoc{}, fail(400, "bad phone agreement key: %v", err)
	}
	plain, err := OpenSealed(c.agreement, bundle, infoClaim)
	if err != nil {
		return SignedDoc{}, fail(400, "can't open the bundle")
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != st.BundleSha256 {
		return SignedDoc{}, fail(403, "the bundle isn't the one the master key signed")
	}
	var b claimBundle
	if json.Unmarshal(plain, &b) != nil {
		return SignedDoc{}, fail(400, "bad bundle")
	}
	stores := map[string]*StoreBlob{}
	token := ""
	for _, sd := range b.Stores {
		if sd.Name == FlyStore {
			token = sd.Values["FLY_API_TOKEN"]
			continue
		}
		if _, seen := stores[sd.Name]; !storeName(sd.Name) || seen {
			return SignedDoc{}, fail(400, "bad or repeated store %q in the bundle", sd.Name)
		}
		blob, err := c.wrap(sd.Name, sd.Values, st.Phone.AgreementKey)
		if err != nil {
			return SignedDoc{}, err
		}
		stores[sd.Name] = blob
	}
	c.MasterKey = st.Master
	c.phoneSigning, c.phoneAgreement = st.Phone.SigningKey, st.Phone.AgreementKey
	c.stores = stores
	for _, n := range b.NotSensitive {
		if _, ok := c.stores[n]; ok {
			c.notSensitive[n] = true
		}
	}
	if token != "" {
		c.fly.Configure(token)
	}
	c.coreCert = &MasterCert{Statement: statement, MasterSig: masterSig}
	c.logf("claimed: master key, phone keys, %d stores, Fly token %v", len(c.stores), token != "")
	return c.sign(map[string]any{"kind": "claimed", "stores": len(c.stores)})
}

// Wipe: the current master key (from Deyao's kit) ends this core: it answers, then exits, and Kubernetes
// starts a new, empty core in its place (new keys, nothing kept — the same as an infra restart). Without the
// current master key a set-up core is never emptied from the app.
func (c *Core) Wipe(statement, masterSig string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "this core is empty")
	}
	if !VerifyWith(c.MasterKey, []byte(statement), masterSig) {
		return SignedDoc{}, fail(403, "the wipe isn't signed by this core's master key")
	}
	var st struct {
		Kind string `json:"kind"`
		Core string `json:"core"` // the core's signing key
	}
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "wipe" || st.Core != c.signer.PublicKey() {
		return SignedDoc{}, fail(403, "the wipe names another core")
	}
	c.logf("wipe: the master key ends this core")
	d, err := c.sign(map[string]any{"kind": "wiping", "core": st.Core})
	if err == nil && c.exit != nil {
		go c.exit()
	}
	return d, err
}

// SetFlyToken: the core's Fly token, sealed to this core. Open: the core calls Fly only for its own app
// (FlyApp), which only Deyao's Fly org reaches, so a wrong token can only fail. The setup session sends it
// after a Reset; a Recover brings it in the bundle.
func (c *Core) SetFlyToken(sealed Sealed) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "this core isn't set up yet")
	}
	plain, err := OpenSealed(c.agreement, sealed, infoFlyToken)
	if err != nil {
		return SignedDoc{}, fail(400, "can't open the Fly token")
	}
	var v struct {
		Token string `json:"FLY_API_TOKEN"`
	}
	if json.Unmarshal(plain, &v) != nil || v.Token == "" {
		return SignedDoc{}, fail(400, "no FLY_API_TOKEN")
	}
	c.fly.Configure(v.Token)
	c.logf("Fly token set")
	return c.sign(map[string]any{"kind": "fly-token-set"})
}

// CoreCert: the master's signature on this core (404 while empty)
func (c *Core) CoreCert() (*MasterCert, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.coreCert == nil {
		return nil, fail(404, "this core isn't set up yet")
	}
	return c.coreCert, nil
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

// wrap: values → a blob under a fresh data key wrapped to P + K (the claim only; writers outside do the same)
func (c *Core) wrap(name string, values map[string]string, phoneAgreement string) (*StoreBlob, error) {
	dk := make([]byte, 32)
	rand.Read(dk)
	w, err := WrapToCombined(phoneAgreement, c.agreement.PublicKey().Bytes(), dk)
	if err != nil {
		return nil, err
	}
	plain, _ := json.Marshal(values)
	return &StoreBlob{Name: name, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, plain, []byte(name)))}, nil
}

// CreateStore: once per name — an empty, non-sensitive store (the only way a store is ever not sensitive,
// besides a Recover bundle)
func (c *Core) CreateStore(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !storeName(name) || name == FlyStore {
		return SignedDoc{}, fail(400, "bad store name")
	}
	if _, ok := c.stores[name]; ok {
		return SignedDoc{}, fail(409, "store %s exists", name)
	}
	c.stores[name], c.notSensitive[name] = nil, true
	c.logf("store %s created (empty, not sensitive)", name)
	return c.sign(map[string]any{"kind": "store-created", "name": name})
}

// MarkSensitive: the one-way upgrade — the name leaves the non-sensitive set (anyone may: it only adds
// protection, and nothing puts a name back)
func (c *Core) MarkSensitive(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.notSensitive[name] {
		return SignedDoc{}, fail(409, "store %s is already sensitive", name)
	}
	delete(c.notSensitive, name)
	c.logf("store %s marked sensitive", name)
	return c.sign(map[string]any{"kind": "marked-sensitive", "name": name})
}

// WriteStore: a new blob for a store (open; the router guards it). A name the core never created is, like
// every store not in the non-sensitive set, sensitive. Unlocked plaintext of the old blob stays until locked.
func (c *Core) WriteStore(b StoreBlob) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !storeName(b.Name) || b.Name == FlyStore || b.Wrapped.E == "" || b.Data == "" {
		return SignedDoc{}, fail(400, "not a store blob")
	}
	c.stores[b.Name] = &b
	c.logf("store %s written (sensitive=%v)", b.Name, !c.notSensitive[b.Name])
	return c.sign(map[string]any{"kind": "store-written", "name": b.Name, "sensitive": !c.notSensitive[b.Name]})
}

// Stores: the signed list (names, sensitivity, empty, unlocked) — the phone learns sensitivity from the core
func (c *Core) Stores(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type row struct {
		Name      string `json:"name"`
		Sensitive bool   `json:"sensitive"`
		Empty     bool   `json:"empty"`
		Unlocked  bool   `json:"unlocked"`
	}
	out := []row{}
	for n, b := range c.stores {
		_, u := c.unlocked[n]
		out = append(out, row{n, !c.notSensitive[n], b == nil, u})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return c.sign(map[string]any{"kind": "stores", "nonce": nonce, "stores": out})
}

// ---- machines (the Fly API is used only here: start, kill) -----------------------------------------

type StartRequest struct {
	Image  string            `json:"image"`
	Region string            `json:"region"`
	Size   string            `json:"size"`
	Env    map[string]string `json:"env"` // non-secret settings (the router's), never secrets; the core adds its key
}

// Start: anyone may ask (normally the router): it makes a machine and reads its keys, nothing more — a
// machine without a cert gets no secrets. Creates the machine, runs the image's init command (its output is
// the machine's public keys) and records the started machine.
func (c *Core) Start(r StartRequest) (SignedDoc, error) {
	if r.Image == "" || r.Image == NullImage {
		return SignedDoc{}, fail(400, "start needs an image")
	}
	env := map[string]string{}
	for k, v := range r.Env {
		env[k] = v
	}
	env[coreKeyEnv] = c.signer.PublicKey() // the machine's one trust anchor, set by the core, never the router
	r.Env = env
	id, image, err := c.fly.Create(r)
	if err != nil {
		return SignedDoc{}, fail(502, "fly create: %v", err)
	}
	keys, err := c.fly.Init(id)
	if err != nil {
		c.fly.Destroy(id)
		return SignedDoc{}, fail(502, "fly exec init: %v", err)
	}
	m := &StartedMachine{ID: id, Requested: r.Image, Image: image, EncryptionKey: keys.EncryptionKey, SigningKey: keys.SigningKey}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started[id] = m
	c.logf("machine %s started (%s)", id, image)
	return c.sign(map[string]any{"kind": "started", "machine": m})
}

// Certify: an approval + a started machine running the approved image → the succession cert (the machine's
// only permission). One machine per approval, one line per machine, one successor per predecessor. An
// approval for the null image takes no machine and burns the predecessor.
func (c *Core) Certify(approval *SignedDoc, machine string) (SignedDoc, error) {
	var a Approval
	if err := c.verifyOwn(approval, &a); err != nil || a.Kind != "approval" {
		return SignedDoc{}, fail(400, "not an approval this core signed")
	}
	r := a.Request
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.approvalsUsed[a.Nonce] {
		return SignedDoc{}, fail(409, "this approval was already used")
	}
	if r.PredID != "" && (!c.killed[r.PredID] || c.used[r.PredID]) {
		return SignedDoc{}, fail(409, "predecessor %s is not a killed, unused machine", r.PredID)
	}
	now := c.now().UTC().Format(time.RFC3339)
	if r.Image == NullImage {
		if machine != "" {
			return SignedDoc{}, fail(400, "a burn takes no machine")
		}
		c.approvalsUsed[a.Nonce], c.used[r.PredID] = true, true
		c.logf("burned %s (%s)", r.PredID, a.By)
		return c.sign(Cert{Kind: "burn-cert", PredID: r.PredID, Stores: []string{}, Nonce: a.Nonce, IssuedAt: now})
	}
	m, ok := c.started[machine]
	if !ok || c.killed[machine] || c.certified[machine] {
		return SignedDoc{}, fail(409, "machine %s is not a started machine without a line", machine)
	}
	if m.Requested != r.Image {
		return SignedDoc{}, fail(409, "machine %s runs %s, the approval is for %s", machine, m.Requested, r.Image)
	}
	c.approvalsUsed[a.Nonce], c.certified[machine] = true, true
	if r.PredID != "" {
		c.used[r.PredID] = true
	}
	c.logf("certified %s for %s (%s) %s → %v", machine, a.Nonce[:12], a.By, orNull(r.PredID), r.Stores)
	return c.sign(c.succession(r, m, a.Nonce, now))
}

// Kill: Fly destroy, confirmed by Fly → killed
func (c *Core) Kill(id string) (SignedDoc, error) {
	if id == "" || id == "null" {
		return SignedDoc{}, fail(400, "kill rejects null")
	}
	if err := c.fly.Destroy(id); err != nil {
		return SignedDoc{}, fail(502, "fly destroy: %v", err)
	}
	if gone, err := c.fly.ConfirmDestroyed(id); err != nil || !gone {
		return SignedDoc{}, fail(502, "fly did not confirm %s destroyed: %v", id, err)
	}
	c.mu.Lock()
	c.killed[id] = true
	c.logf("machine %s killed", id)
	c.mu.Unlock()
	return c.sign(map[string]any{"kind": "killed", "id": id})
}

// NullImage: a succession to the null image burns the predecessor — start() makes no machine, only marks the
// predecessor used, so it can never be continued (what ending a session needs)
const NullImage = "null"

// ---- succession --------------------------------------------------------------------------------

type SuccessionInput struct {
	Predecessor *SignedDoc `json:"predecessor"` // nil = from null
	Machine     string     `json:"machine"`     // only when a running machine succeeds itself (add a store, downgrade)
	// downgrade only: the machine's new key pair
	NewEncryptionKey string   `json:"newEncryptionKey"`
	NewSigningKey    string   `json:"newSigningKey"`
	Image            string   `json:"image"`
	Stores           []string `json:"stores"`
	Options          Options  `json:"options"`
}

// Succession: a challenge derived from the request (nothing stored), before any machine exists
func (c *Core) Succession(in SuccessionInput) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	req := Request{Kind: "succession", Predecessor: in.Predecessor, Options: in.Options}
	if in.Image != NullImage && req.Options.Harness == "" {
		req.Options.Harness = "claude"
	}
	if in.Image != NullImage && req.Options.PermissionMode != "bypass" {
		req.Options.PermissionMode = "auto"
	}
	var pc Cert
	if in.Predecessor != nil {
		if err := c.verifyOwn(in.Predecessor, &pc); err != nil || pc.Kind != "succession-cert" || pc.Machine == nil {
			return SignedDoc{}, fail(400, "predecessor is not a succession cert this core signed")
		}
		req.PredID, req.Line = pc.Machine.ID, pc.Line
	}
	if in.Image == NullImage {
		if req.PredID == "" || len(in.Stores) != 0 || in.Options != (Options{}) || in.Machine != "" {
			return SignedDoc{}, fail(400, "a burn is a predecessor with no stores, no options and the null image")
		}
		req.Image, req.Stores = NullImage, []string{}
		b, _ := json.Marshal(req)
		return c.sign(map[string]any{"kind": "challenge", "nonce": c.mac("challenge", string(b)), "request": req})
	}
	set := map[string]bool{}
	for _, n := range in.Stores {
		if _, ok := c.stores[n]; !ok {
			return SignedDoc{}, fail(400, "unknown store %s", n)
		}
		if !set[n] {
			set[n] = true
			req.Stores = append(req.Stores, n)
			if !c.notSensitive[n] {
				req.Sensitive = append(req.Sensitive, n)
			}
		}
	}
	sort.Strings(req.Stores)
	sort.Strings(req.Sensitive)
	if req.Sensitive == nil {
		req.Sensitive = []string{}
	}
	if req.Stores == nil {
		req.Stores = []string{}
	}
	if in.Machine != "" {
		// a running machine succeeds itself from one of its certs: one more store (answered by the phone), or
		// a subset with a new key pair (a downgrade)
		if _, ok := c.started[in.Machine]; !ok || req.PredID != in.Machine {
			return SignedDoc{}, fail(400, "a machine succeeds itself from its own cert")
		}
		if c.killed[in.Machine] || pc.Options != req.Options {
			return SignedDoc{}, fail(400, "the same live machine with the same options")
		}
		m := pc.Machine
		if in.NewEncryptionKey != "" || in.NewSigningKey != "" {
			if !subset(req.Stores, pc.Stores) {
				return SignedDoc{}, fail(400, "a downgrade keeps a subset of the stores")
			}
			if _, err := parseSigningKey(in.NewSigningKey); err != nil {
				return SignedDoc{}, fail(400, "bad new signing key")
			}
			if b, err := b64.DecodeString(in.NewEncryptionKey); err != nil || len(b) != 65 {
				return SignedDoc{}, fail(400, "bad new encryption key")
			}
			if in.NewSigningKey == m.SigningKey || in.NewEncryptionKey == m.EncryptionKey {
				return SignedDoc{}, fail(400, "a downgrade needs a new key pair")
			}
			nm := *m
			nm.EncryptionKey, nm.SigningKey = in.NewEncryptionKey, in.NewSigningKey
			req.Machine, req.Downgrade = &nm, true
		} else {
			added, err := oneMore(pc.Stores, req.Stores)
			if err != nil {
				return SignedDoc{}, err
			}
			req.Machine, req.AddedStore = m, added
		}
	} else {
		if in.Image == "" {
			return SignedDoc{}, fail(400, "a new machine needs an image")
		}
		req.Image = in.Image
		if req.PredID == "" {
			salt := make([]byte, 16)
			if _, err := rand.Read(salt); err != nil {
				return SignedDoc{}, fail(500, "no randomness")
			}
			req.Salt = hex.EncodeToString(salt)
		}
	}
	b, _ := json.Marshal(req)
	return c.sign(map[string]any{"kind": "challenge", "nonce": c.mac("challenge", string(b)), "request": req})
}

// subset: every store of `a` is in `b`
func subset(a, b []string) bool {
	have := map[string]bool{}
	for _, n := range b {
		have[n] = true
	}
	for _, n := range a {
		if !have[n] {
			return false
		}
	}
	return true
}

// oneMore: `next` is `prev` plus exactly one store (both sorted, no duplicates) → that store
func oneMore(prev, next []string) (string, error) {
	have := map[string]bool{}
	for _, n := range prev {
		have[n] = true
	}
	added := ""
	for _, n := range next {
		if have[n] {
			delete(have, n)
		} else if added == "" {
			added = n
		} else {
			added = "\x00"
		}
	}
	if len(have) != 0 || added == "" || added == "\x00" {
		return "", fail(400, "a machine can succeed itself only with its store set plus exactly one store")
	}
	return added, nil
}

type challenge struct {
	Kind    string  `json:"kind"`
	Nonce   string  `json:"nonce"`
	Request Request `json:"request"`
}

func (c *Core) readChallenge(d *SignedDoc) (challenge, error) {
	var ch challenge
	if err := c.verifyOwn(d, &ch); err != nil || ch.Kind != "challenge" {
		return ch, fail(400, "not a challenge this core signed")
	}
	return ch, nil
}

// answer: what an approval turns a challenge into — for a machine succeeding itself the new cert at
// once, else an approval that certify() binds to one machine
func (c *Core) answer(ch challenge, by string) (SignedDoc, error) {
	r := ch.Request
	now := c.now().UTC().Format(time.RFC3339)
	if r.AddedStore != "" || r.Downgrade {
		return c.sign(c.succession(r, r.Machine, ch.Nonce, now))
	}
	return c.sign(Approval{Kind: "approval", Nonce: ch.Nonce, Request: r, By: by})
}

// ApproveByPhone: the iPhone's Secure Enclave signature over exactly the challenge text. The phone is the
// highest privilege: whatever challenge it signs is answered.
func (c *Core) ApproveByPhone(d *SignedDoc, sig string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	if c.phoneSigning == "" || !VerifyWith(c.phoneSigning, []byte(d.Payload), sig) {
		return SignedDoc{}, fail(403, "the iPhone's signature doesn't cover this challenge")
	}
	r := ch.Request
	c.logf("phone approved %s: %s → %v", ch.Nonce[:12], orNull(r.PredID), r.Stores)
	return c.answer(ch, "phone")
}

// ApproveByDeadMachine: automatic — predecessor killed (Fly-confirmed) and never used, and store set, image and
// options identical. Its approval marks the predecessor used when start() makes the machine.
func (c *Core) ApproveByDeadMachine(d *SignedDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	r := ch.Request
	if r.AddedStore != "" || r.Downgrade {
		return SignedDoc{}, fail(403, "a machine succeeding itself isn't approved by approve_by_dead_machine")
	}
	if r.PredID == "" || !c.killed[r.PredID] || c.used[r.PredID] {
		return SignedDoc{}, fail(403, "predecessor is not a killed, unused machine")
	}
	if r.Image == NullImage {
		c.logf("approve_by_dead_machine: burn of %s", r.PredID)
		return c.answer(ch, "dead-machine")
	}
	var pc Cert
	if err := c.verifyOwn(r.Predecessor, &pc); err != nil {
		return SignedDoc{}, err
	}
	if !equalStrings(pc.Stores, r.Stores) || pc.Options != r.Options || pc.Machine.Image != r.Image {
		return SignedDoc{}, fail(403, "store set, image or options differ from the predecessor's")
	}
	c.logf("approve_by_dead_machine: %s → a new machine", r.PredID)
	return c.answer(ch, "dead-machine")
}

// ApproveByOldKey: automatic — a succession of a machine to itself with a subset of its stores and a new key
// pair, answered when it is signed with the signing key named in the predecessor cert (without that, anyone
// could name their own keys and pull the remaining stores). Older certs keep pulling, sealed to keys that
// whoever downgraded has deleted.
func (c *Core) ApproveByOldKey(d *SignedDoc, sig string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	r := ch.Request
	if !r.Downgrade {
		return SignedDoc{}, fail(400, "not a downgrade")
	}
	var pc Cert
	if err := c.verifyOwn(r.Predecessor, &pc); err != nil || pc.Machine == nil || !VerifyWith(pc.Machine.SigningKey, []byte(d.Payload), sig) {
		return SignedDoc{}, fail(403, "not signed by the key in the predecessor cert")
	}
	c.logf("downgrade: %s keeps %v, new keys", r.Machine.ID, r.Stores)
	return c.answer(ch, "machine")
}

// ---- unlock / lock -------------------------------------------------------------------------------

// UnlockBegin: a one-off key pair for this unlock; the phone computes its share from the blob's E (shown
// here, signed, with the store's name)
func (c *Core) UnlockBegin(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	blob := c.stores[name]
	if blob == nil {
		return SignedDoc{}, fail(404, "no store %s with contents", name)
	}
	s := *blob
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	id := randID()
	c.pending[id] = pendingUnlock{store: s, t: t}
	return c.sign(map[string]any{"kind": "unlock-begin", "pending": id, "store": name, "e": s.Wrapped.E, "t": b64.EncodeToString(t.PublicKey().Bytes())})
}

const infoShare = "jarvis2/unlock-share"

func (c *Core) UnlockFinish(pending string, share Sealed) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[pending]
	if !ok {
		return SignedDoc{}, fail(404, "no such pending unlock")
	}
	delete(c.pending, pending) // one try; the one-off key is gone either way
	x, err := OpenSealed(p.t, share, infoShare)
	if err != nil {
		return SignedDoc{}, fail(400, "the share isn't sealed to this unlock")
	}
	s := p.store
	dk, err := UnwrapWithShares(s.Wrapped, x, c.agreement)
	if err != nil {
		return SignedDoc{}, fail(403, "%v", err)
	}
	data, _ := b64.DecodeString(s.Data)
	plain, err := gcmOpen(dk, data, []byte(s.Name))
	if err != nil {
		return SignedDoc{}, fail(403, "the store doesn't decrypt (a wrong or altered blob)")
	}
	vals := map[string]string{}
	json.Unmarshal(plain, &vals)
	u := c.unlocked[s.Name]
	if u == nil {
		u = &unlocked{values: vals, ids: map[string]time.Time{}}
		c.unlocked[s.Name] = u
	}
	id := randID()
	u.ids[id] = c.now()
	c.logf("store %s unlocked (%s)", s.Name, id)
	return c.sign(map[string]any{"kind": "unlocked", "id": id, "store": s.Name})
}

func (c *Core) Lock(id string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, u := range c.unlocked {
		if _, ok := u.ids[id]; ok {
			delete(u.ids, id)
			if len(u.ids) == 0 {
				delete(c.unlocked, name) // plaintext gone with the last id
			}
			c.logf("unlock %s released (%s)", id, name)
			return c.sign(map[string]any{"kind": "locked", "id": id, "store": name})
		}
	}
	return SignedDoc{}, fail(404, "no such unlock id")
}

func (c *Core) ListUnlocked(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type row struct {
		ID    string `json:"id"`
		Store string `json:"store"`
		Since string `json:"since"`
	}
	rows := []row{}
	for name, u := range c.unlocked {
		for id, t := range u.ids {
			rows = append(rows, row{id, name, t.UTC().Format(time.RFC3339)})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Since < rows[j].Since })
	return c.sign(map[string]any{"kind": "unlocked-list", "nonce": nonce, "unlocked": rows})
}

// ---- pull secrets ---------------------------------------------------------------------------------

// PullSecrets: the answer is sealed to the machine's encryption key from the cert, so only that machine
// can open it and nothing else needs to authenticate the caller
func (c *Core) PullSecrets(certDoc *SignedDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var cert Cert
	if err := c.verifyOwn(certDoc, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil {
		return SignedDoc{}, fail(400, "not a succession cert this core signed")
	}
	merged := map[string]string{}
	for _, n := range cert.Stores {
		u, ok := c.unlocked[n]
		if !ok {
			return SignedDoc{}, fail(423, "store %s is locked", n)
		}
		for k, v := range u.values {
			merged[k] = v
		}
	}
	plain, _ := json.Marshal(merged)
	sealed, err := SealTo(cert.Machine.EncryptionKey, plain, "jarvis2/secrets")
	if err != nil {
		return SignedDoc{}, err
	}
	c.logf("secrets pulled by %s (%v)", cert.Machine.ID, cert.Stores)
	return c.sign(map[string]any{"kind": "secrets", "machine": cert.Machine.ID, "sealed": sealed})
}

func (c *Core) Log(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sign(map[string]any{"kind": "log", "nonce": nonce, "entries": c.log})
}

// ---- helpers ------------------------------------------------------------------------------------

func randID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func orNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

var _ = errors.New
