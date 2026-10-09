package main

// The secrets-controller core (claude-env selfhost/SECRETS-CONTROLLER.md). Every answer that leaves it is
// signed; all of its state lives in memory (a restart = a new controller; recovery is undesigned). It
// accepts or rejects — the orchestration (which responder answers, retries, the session flows) lives in
// the router outside it.

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
	"strconv"
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

type Store struct {
	Name      string     `json:"name"`
	Keys      []string   `json:"keys"`
	Sensitive bool       `json:"sensitive"`
	Wrapped   WrappedKey `json:"wrapped"` // the data key, to phone + core
	Data      string     `json:"-"`       // AES-GCM(json values) under the data key
}

type StartedMachine struct {
	ID            string `json:"id"`
	Image         string `json:"image"`         // what Fly reports the machine runs (ref@digest)
	EncryptionKey string `json:"encryptionKey"` // the machine's own keys, read through Fly exec
	SigningKey    string `json:"signingKey"`
}

type Options struct {
	Harness string `json:"harness"`
}

// a succession request; Machine == "" means the null machine (a burn)
type Request struct {
	Kind        string          `json:"kind"`
	Predecessor *SignedDoc      `json:"predecessor"` // the predecessor's succession cert; nil = new line
	PredID      string          `json:"predecessorId"`
	Machine     *StartedMachine `json:"machine"`
	Stores      []string        `json:"stores"`
	Sensitive   []string        `json:"sensitive"`
	Options     Options         `json:"options"`
	AddedStore  string          `json:"addedStore,omitempty"` // set when the machine succeeds itself with one more store
}

type Cert struct {
	Kind     string          `json:"kind"` // "succession-cert"
	PredID   string          `json:"predecessorId"`
	Machine  *StartedMachine `json:"machine"`
	Stores   []string        `json:"stores"`
	Options  Options         `json:"options"`
	Nonce    string          `json:"nonce"`
	IssuedAt string          `json:"issuedAt"`
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
	SetupKey  string               // the setup session's public signing key (SETUP_KEY)
	setupSeen map[string]time.Time // setup signatures already used (replay guard)

	phoneSigning, phoneAgreement string

	stores  map[string]*Store
	started map[string]*StartedMachine
	killed  map[string]bool // respond-by-dead-machine's two sets
	used    map[string]bool

	pending  map[string]pendingUnlock
	unlocked map[string]*unlocked

	fly Fly
	log []string
	now func() time.Time
}

type pendingUnlock struct {
	store string
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
	return &Core{signer: s, agreement: a, nonceKey: nk, setupSeen: map[string]time.Time{},
		stores: map[string]*Store{}, started: map[string]*StartedMachine{}, killed: map[string]bool{}, used: map[string]bool{},
		pending: map[string]pendingUnlock{}, unlocked: map[string]*unlocked{}, fly: fly, now: time.Now}, nil
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

// ---- setup (the trusted setup session, signing with the setup key) ------------------------------------

const infoSetup = "jarvis2/setup"

// CoreStore holds the core's own secrets, seeded and unlocked like any other store: while it is
// unlocked the core can start and stop machines (FLY_API_TOKEN, FLY_APP); it never goes to a session.
const CoreStore = "core"

// checkSetupSig: a setup request must be signed by the setup key over
// "<METHOD> <path> <unix time> <sha256hex body>", within two minutes, and never seen before.
func (c *Core) checkSetupSig(method, path, t, sig string, body []byte) error {
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return fail(401, "setup signature required")
	}
	now := c.now()
	if d := now.Sub(time.Unix(ts, 0)); d > 2*time.Minute || d < -2*time.Minute {
		return fail(401, "X-Setup-Time too far off")
	}
	h := sha256.Sum256(body)
	msg := fmt.Sprintf("%s %s %d %s", method, path, ts, hex.EncodeToString(h[:]))
	if c.SetupKey == "" || !VerifyWith(c.SetupKey, []byte(msg), sig) {
		return fail(401, "bad setup signature")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for s, at := range c.setupSeen {
		if now.Sub(at) > 5*time.Minute {
			delete(c.setupSeen, s)
		}
	}
	if _, ok := c.setupSeen[sig]; ok {
		return fail(401, "setup signature already used")
	}
	c.setupSeen[sig] = now
	return nil
}

// OpenSetup: a secret the setup session sealed to the core's agreement key
func (c *Core) OpenSetup(s Sealed) ([]byte, error) {
	p, err := OpenSealed(c.agreement, s, infoSetup)
	if err != nil {
		return nil, fail(400, "can't open the sealed value")
	}
	return p, nil
}

func (c *Core) SetupPhone(signingKey, agreementKey string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phoneSigning != "" {
		return SignedDoc{}, fail(409, "the phone's keys are already set")
	}
	if _, err := parseSigningKey(signingKey); err != nil {
		return SignedDoc{}, fail(400, "bad phone signing key: %v", err)
	}
	if b, err := b64.DecodeString(agreementKey); err != nil || len(b) != 65 {
		return SignedDoc{}, fail(400, "bad phone agreement key")
	} else if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return SignedDoc{}, fail(400, "bad phone agreement key: %v", err)
	}
	c.phoneSigning, c.phoneAgreement = signingKey, agreementKey
	c.logf("phone keys set")
	return c.sign(map[string]string{"kind": "phone-set", "signingKey": signingKey, "agreementKey": agreementKey})
}

// SeedStore: a new store (never replaces one) with its values encrypted to phone + core
func (c *Core) SeedStore(name string, values map[string]string, sensitive bool) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phoneAgreement == "" {
		return SignedDoc{}, fail(409, "set the phone's keys first")
	}
	if name == "" || len(name) > 64 {
		return SignedDoc{}, fail(400, "bad store name")
	}
	if _, ok := c.stores[name]; ok {
		return SignedDoc{}, fail(409, "store %s exists; stores are never replaced", name)
	}
	dk := make([]byte, 32)
	rand.Read(dk)
	w, err := WrapToCombined(c.phoneAgreement, c.agreement.PublicKey().Bytes(), dk)
	if err != nil {
		return SignedDoc{}, err
	}
	plain, _ := json.Marshal(values)
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	c.stores[name] = &Store{Name: name, Keys: keys, Sensitive: sensitive, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, plain, []byte(name)))}
	c.logf("store %s seeded (%d keys, sensitive=%v)", name, len(keys), sensitive)
	return c.sign(map[string]any{"kind": "store-seeded", "name": name, "keys": len(keys), "sensitive": sensitive})
}

// ---- stores ------------------------------------------------------------------------------------

type storeView struct {
	Name      string   `json:"name"`
	Keys      []string `json:"keys"`
	Sensitive bool     `json:"sensitive"`
	Unlocked  bool     `json:"unlocked"`
}

func (c *Core) Stores(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []storeView{}
	for _, s := range c.stores {
		_, u := c.unlocked[s.Name]
		out = append(out, storeView{s.Name, s.Keys, s.Sensitive, u})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return c.sign(map[string]any{"kind": "stores", "nonce": nonce, "stores": out})
}

func (c *Core) ListSensitive(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []string{}
	for _, s := range c.stores {
		if s.Sensitive {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return c.sign(map[string]any{"kind": "sensitive", "nonce": nonce, "stores": out})
}

// MarkSensitive: anyone may (it only adds protection); there is no way to remove the mark
func (c *Core) MarkSensitive(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.stores[name]
	if !ok {
		return SignedDoc{}, fail(404, "unknown store %s", name)
	}
	s.Sensitive = true
	c.logf("store %s marked sensitive", name)
	return c.sign(map[string]any{"kind": "marked-sensitive", "name": name})
}

// ---- machines (the Fly API is used only here: start, init, kill) ----------------------------------

type StartRequest struct {
	Image  string            `json:"image"`
	Region string            `json:"region"`
	Size   string            `json:"size"`
	Env    map[string]string `json:"env"` // non-secret settings (the router's), never secrets
}

func (c *Core) Start(r StartRequest) (SignedDoc, error) {
	id, image, err := c.fly.Create(r)
	if err != nil {
		return SignedDoc{}, fail(502, "fly create: %v", err)
	}
	keys, err := c.fly.ReadKeys(id)
	if err != nil {
		return SignedDoc{}, fail(502, "reading the machine's keys through fly: %v", err)
	}
	// the machine's API key (it authenticates Pull secrets) and the core's signing key (the machine checks
	// its cert with it), delivered through Fly too
	if err := c.fly.WriteMachineFiles(id, c.mac("api", id), c.signer.PublicKey()); err != nil {
		return SignedDoc{}, fail(502, "fly exec: %v", err)
	}
	m := &StartedMachine{ID: id, Image: image, EncryptionKey: keys.EncryptionKey, SigningKey: keys.SigningKey}
	c.mu.Lock()
	c.started[id] = m
	c.logf("machine %s started (%s)", id, image)
	c.mu.Unlock()
	return c.sign(map[string]any{"kind": "started", "machine": m})
}

func (c *Core) Init(id string) (SignedDoc, error) {
	if err := c.fly.Init(id); err != nil {
		return SignedDoc{}, fail(502, "fly exec init: %v", err)
	}
	c.mu.Lock()
	c.logf("machine %s init", id)
	c.mu.Unlock()
	return c.sign(map[string]any{"kind": "init", "id": id})
}

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

// ---- succession --------------------------------------------------------------------------------

type SuccessionInput struct {
	Predecessor *SignedDoc `json:"predecessor"` // nil = from null
	Machine     string     `json:"machine"`     // "" = to null (burn)
	Stores      []string   `json:"stores"`
	Options     Options    `json:"options"`
}

// Succession: a challenge derived from the request (nothing stored)
func (c *Core) Succession(in SuccessionInput) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	req := Request{Kind: "succession", Predecessor: in.Predecessor, Options: in.Options}
	if req.Options.Harness == "" {
		req.Options.Harness = "claude"
	}
	if in.Predecessor != nil {
		var pc Cert
		if err := c.verifyOwn(in.Predecessor, &pc); err != nil || pc.Kind != "succession-cert" || pc.Machine == nil {
			return SignedDoc{}, fail(400, "predecessor is not a succession cert this core signed")
		}
		req.PredID = pc.Machine.ID
	}
	if in.Machine != "" {
		m, ok := c.started[in.Machine]
		if !ok {
			return SignedDoc{}, fail(404, "no such started machine")
		}
		req.Machine = m
		set := map[string]bool{}
		for _, n := range in.Stores {
			if n == CoreStore {
				return SignedDoc{}, fail(400, "the core store holds the core's own secrets and never goes to a session")
			}
			s, ok := c.stores[n]
			if !ok {
				return SignedDoc{}, fail(400, "unknown store %s", n)
			}
			if !set[n] {
				set[n] = true
				req.Stores = append(req.Stores, n)
				if s.Sensitive {
					req.Sensitive = append(req.Sensitive, n)
				}
			}
		}
		sort.Strings(req.Stores)
		sort.Strings(req.Sensitive)
		if req.PredID == in.Machine {
			// adding a store to a running session: succession(machine → same machine, old set + one)
			var pc Cert
			c.verifyOwn(in.Predecessor, &pc)
			added, err := oneMore(pc.Stores, req.Stores)
			if err != nil {
				return SignedDoc{}, err
			}
			if c.killed[in.Machine] || pc.Options != req.Options || *pc.Machine != *m {
				return SignedDoc{}, fail(400, "adding a store needs the same live machine with the same options")
			}
			req.AddedStore = added
		}
	}
	b, _ := json.Marshal(req)
	return c.sign(map[string]any{"kind": "challenge", "nonce": c.mac("challenge", string(b)), "request": req})
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

func (c *Core) issue(ch challenge) (SignedDoc, error) {
	cert := Cert{Kind: "succession-cert", PredID: ch.Request.PredID, Machine: ch.Request.Machine, Stores: ch.Request.Stores,
		Options: ch.Request.Options, Nonce: ch.Nonce, IssuedAt: c.now().UTC().Format(time.RFC3339)}
	if cert.Machine == nil {
		cert.Kind = "burn-cert"
	}
	return c.sign(cert)
}

// RespondPhone: the iPhone's Secure Enclave signature over exactly the challenge text
func (c *Core) RespondPhone(d *SignedDoc, sig string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	if c.phoneSigning == "" || !VerifyWith(c.phoneSigning, []byte(d.Payload), sig) {
		return SignedDoc{}, fail(403, "the iPhone's signature doesn't cover this challenge")
	}
	if ch.Request.Machine == nil {
		return SignedDoc{}, fail(400, "a burn is answered by the dead-machine responder")
	}
	if r := ch.Request; r.AddedStore != "" && c.killed[r.Machine.ID] {
		return SignedDoc{}, fail(403, "machine %s was killed", r.Machine.ID)
	}
	c.logf("phone approved %s: %s → %s %v", ch.Nonce[:12], orNull(ch.Request.PredID), ch.Request.Machine.ID, ch.Request.Stores)
	return c.issue(ch)
}

// RespondDead: automatic — predecessor killed (Fly-confirmed) and never used; for a successor
// (not a burn) its store set, image and options must be identical
func (c *Core) RespondDead(d *SignedDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	r := ch.Request
	if r.AddedStore != "" {
		return SignedDoc{}, fail(403, "adding a store is answered only by the iPhone")
	}
	if r.PredID == "" || !c.killed[r.PredID] || c.used[r.PredID] {
		return SignedDoc{}, fail(403, "predecessor is not a killed, unused machine")
	}
	if r.Machine != nil {
		var pc Cert
		if err := c.verifyOwn(r.Predecessor, &pc); err != nil {
			return SignedDoc{}, err
		}
		if !equalStrings(pc.Stores, r.Stores) || pc.Options != r.Options || pc.Machine.Image != r.Machine.Image {
			return SignedDoc{}, fail(403, "store set, image or options differ from the predecessor's")
		}
	}
	c.used[r.PredID] = true
	c.logf("dead-machine responder: %s → %s", r.PredID, orNull(machineID(r.Machine)))
	return c.issue(ch)
}

// ---- unlock / lock -------------------------------------------------------------------------------

func (c *Core) UnlockBegin(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.stores[name]
	if !ok {
		return SignedDoc{}, fail(404, "unknown store %s", name)
	}
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	id := randID()
	c.pending[id] = pendingUnlock{store: name, t: t}
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
	s := c.stores[p.store]
	dk, err := UnwrapWithShares(s.Wrapped, x, c.agreement)
	if err != nil {
		return SignedDoc{}, fail(403, "%v", err)
	}
	data, _ := b64.DecodeString(s.Data)
	plain, err := gcmOpen(dk, data, []byte(s.Name))
	if err != nil {
		return SignedDoc{}, fail(500, "store data didn't decrypt")
	}
	vals := map[string]string{}
	json.Unmarshal(plain, &vals)
	u := c.unlocked[s.Name]
	if u == nil {
		u = &unlocked{values: vals, ids: map[string]time.Time{}}
		c.unlocked[s.Name] = u
	}
	if s.Name == CoreStore {
		if vals["FLY_API_TOKEN"] == "" || vals["FLY_APP"] == "" {
			return SignedDoc{}, fail(400, "the core store needs FLY_API_TOKEN and FLY_APP")
		}
		c.fly.Configure(vals["FLY_API_TOKEN"], vals["FLY_APP"])
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
				if name == CoreStore {
					c.fly.Configure("", "")
				}
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

func (c *Core) PullSecrets(certDoc *SignedDoc, apiKey string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var cert Cert
	if err := c.verifyOwn(certDoc, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil {
		return SignedDoc{}, fail(400, "not a succession cert this core signed")
	}
	if !hmac.Equal([]byte(apiKey), []byte(c.mac("api", cert.Machine.ID))) {
		return SignedDoc{}, fail(403, "not this machine's API key")
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

func machineID(m *StartedMachine) string {
	if m == nil {
		return ""
	}
	return m.ID
}

var _ = errors.New
