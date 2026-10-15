package main

// Core continuity (Deyao, 2026-10-15: a core restart + Recover must be invisible to sessions). Two parts:
//
//  1. The core's long-lived keys come from the master key. The app derives a 32-byte seed from the kit's master
//     private key (CoreSeed) and sends it inside the claim bundle, which is sealed to this core's boot keys and whose
//     hash the master key signs. From the seed the core derives its signing key, its store share K, the carry key,
//     the nonce key and the line-state key (DeriveCoreKeys). So every Recover with the same kit brings back the same
//     core: the machines' JARVIS2_CORE_KEY, the certs, the carry blobs, the store key P + K and every signature the
//     app pinned stay valid. The claim statement names the derived public keys too (`identity`), so a core and an app
//     that derive differently refuse each other instead of drifting apart. A claim with no seed (an older app) keeps
//     the boot keys, as before: such a core's sessions end with it.
//
//  2. The line state: what the core must remember about lines so that keeping its key is safe — each machine's newest
//     cert (a superseded cert continues nothing), the machines it created and initialised (with their current signing
//     keys), the killed and used sets and the spent approvals (a line can't fork, a burnt line stays burnt), the input
//     log's head, and the deploy-key stores (no backup: they are wrapped to P + K, which a Recover on the same phone
//     keeps). After every call that changes it the core seals it under the line-state key (AES-256-GCM; nothing but a
//     core from the same kit opens it) and signs a head {seq, sha256}; every answer carries X-Line-Seq, and the router
//     fetches GET /line-state whenever the number moved and keeps the newest. At a Recover the app reads it from the
//     router, checks the head with the derived key and that its seq is at least the highest the app has seen, and
//     puts it into the bundle; the core restores it. The router can withhold it (the lines then end, as before) or
//     hand an older one, which the app's witness bounds (docs/DESIGN.md "Core continuity").

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

const (
	seedInfo      = "jarvis2/core-seed" // HKDF info: master private scalar → the core seed
	coreKeyInfo   = "jarvis2/core/"     // + signing | agreement | carry | nonce | line-state
	lineStateAAD  = "jarvis2/line-state"
	lineSeqHeader = "X-Line-Seq"
)

// CoreSeed: the seed the app derives from the master private key (its 32-byte scalar, CryptoKit's rawRepresentation)
func CoreSeed(masterScalar []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, masterScalar, nil, seedInfo, 32)
}

// CoreSeedFromKey: the same from a parsed master key (tests, e2e)
func CoreSeedFromKey(k *ecdsa.PrivateKey) ([]byte, error) {
	d, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	return CoreSeed(d)
}

// coreKeys: what DeriveCoreKeys makes
type coreKeys struct {
	signer    *Signer
	agreement *ecdh.PrivateKey
	carry     []byte
	nonce     []byte
	state     []byte
}

// deriveScalar: a valid P-256 scalar for the label — the first of label, label/1, label/2, … that is one (the first
// is, but for a chance of about 2^-32)
func deriveScalar(seed []byte, label string) ([]byte, error) {
	for i := 0; i < 16; i++ {
		info := coreKeyInfo + label
		if i > 0 {
			info += "/" + strconv.Itoa(i)
		}
		d, err := hkdf.Key(sha256.New, seed, nil, info, 32)
		if err != nil {
			return nil, err
		}
		if _, err := ecdh.P256().NewPrivateKey(d); err == nil {
			return d, nil
		}
	}
	return nil, fmt.Errorf("no valid scalar for %s", label)
}

// DeriveCoreKeys: the core's keys from the seed (the app derives the same public keys: CoreCrypto.swift)
func DeriveCoreKeys(seed []byte) (*coreKeys, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("the seed is 32 bytes")
	}
	sd, err := deriveScalar(seed, "signing")
	if err != nil {
		return nil, err
	}
	sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), sd)
	if err != nil {
		return nil, err
	}
	ad, err := deriveScalar(seed, "agreement")
	if err != nil {
		return nil, err
	}
	ak, err := ecdh.P256().NewPrivateKey(ad)
	if err != nil {
		return nil, err
	}
	k := &coreKeys{signer: &Signer{sk}, agreement: ak}
	for _, x := range []struct {
		label string
		out   *[]byte
	}{{"carry", &k.carry}, {"nonce", &k.nonce}, {"line-state", &k.state}} {
		if *x.out, err = hkdf.Key(sha256.New, seed, nil, coreKeyInfo+x.label, 32); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// ---- the line state ------------------------------------------------------------------------------------------

// lineState: everything about lines (and the stores, wrapped to P + K as the core holds them) the core must not forget
// across a Recover or a handoff
type lineState struct {
	Seq       int               `json:"seq"`
	Final     bool              `json:"final,omitempty"` // a handoff's: the core that sealed it serves nothing more
	Latest    map[string]string `json:"latest"`
	Created   map[string]string `json:"created"`
	Signing   map[string]string `json:"signing"`
	Killed    map[string]string `json:"killed"`
	Used      []string          `json:"used"`
	Approvals []string          `json:"approvals"`
	AuditHead string            `json:"auditHead"`
	AuditSeq  int               `json:"auditSeq"`
	// the stores as the core holds them (each key wrapped to P + K for this phone key), the deploy-key stores' repos and
	// the stores that aren't sensitive. A Recover takes back from it only the deploy-key stores (they have no backup;
	// the rest come from the backups); a takeover takes them all (they are newer than any backup the Recover read).
	Phone        string                          `json:"phone"`
	Stores       map[string]map[string]*KeyEntry `json:"stores"`
	RepoOwner    map[string]string               `json:"repoOwner"`
	NotSensitive []string                        `json:"notSensitive"`
	// volumes.go: each live machine's volume, each killed machine's backup, the volumes whose delete failed
	Volumes    map[string]*VolumeInfo `json:"volumes,omitempty"`
	Backups    map[string]*Backup     `json:"backups,omitempty"`
	VolOrphans []string               `json:"volumeOrphans,omitempty"`
}

// LineStateDoc: the sealed state and the core's signed head over it (what the router keeps and the app hands back)
type LineStateDoc struct {
	Head   SignedDoc `json:"head"`
	Sealed string    `json:"sealed"` // base64(nonce ‖ AES-GCM ciphertext)
}

type lineHead struct {
	Kind   string `json:"kind"` // "line-state-head"
	Seq    int    `json:"seq"`
	Final  bool   `json:"final,omitempty"`
	Sha256 string `json:"sha256"` // of the sealed bytes (base64-decoded)
	At     string `json:"at"`
}

func setList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// lineSnapshot: the current line state with seq 0 (callers hold c.mu)
func (c *Core) lineSnapshot() lineState {
	st := lineState{Latest: c.latest, Created: c.created, Signing: c.signing, Killed: c.killed, Used: setList(c.used),
		Approvals: setList(c.approvalsUsed), AuditHead: c.auditHead, AuditSeq: c.auditSeq, Phone: c.phoneAgreement,
		Stores: c.stores, RepoOwner: c.repoOwner, NotSensitive: setList(c.notSensitive),
		Volumes: c.vol.live, Backups: c.vol.backups, VolOrphans: setList(c.vol.orphans)}
	return st
}

// syncLine: after every call — when the line state changed, the next seq, sealed and signed (a serving core with
// derived keys only; callers don't hold c.mu)
func (c *Core) syncLine() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lineKey == nil || c.mode != modeServing {
		return
	}
	plain, err := json.Marshal(c.lineSnapshot())
	if err != nil {
		return
	}
	sum := sha256.Sum256(plain)
	h := hex.EncodeToString(sum[:])
	if h == c.lineHash && c.lineDoc != nil {
		return
	}
	if d, err := c.sealLine(false); err == nil {
		c.lineHash, c.lineDoc = h, d
	}
}

// sealLine: the state as it is now, numbered on (callers hold c.mu)
func (c *Core) sealLine(final bool) (*LineStateDoc, error) {
	st := c.lineSnapshot()
	st.Seq, st.Final = c.lineSeq+1, final
	full, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	sealed, err := gcmSealRandom(c.lineKey, full, []byte(lineStateAAD))
	if err != nil {
		return nil, err
	}
	ss := sha256.Sum256(sealed)
	head, err := c.sign(lineHead{Kind: "line-state-head", Seq: st.Seq, Final: final, Sha256: hex.EncodeToString(ss[:]), At: c.now().UTC().Format(time.RFC3339)})
	if err != nil {
		return nil, err
	}
	c.lineSeq = st.Seq
	return &LineStateDoc{Head: head, Sealed: b64.EncodeToString(sealed)}, nil
}

// LineState: the newest sealed line state (404 on a core without derived keys)
func (c *Core) LineState() (*LineStateDoc, error) {
	c.syncLine()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode == modeStandby {
		return nil, fail(409, "this core is standing by: it keeps no line state of its own yet")
	}
	if c.lineDoc == nil {
		return nil, fail(404, "this core keeps no line state (it wasn't set up with a seed)")
	}
	return c.lineDoc, nil
}

// LineSeq: the seq of the newest line state (0: none)
func (c *Core) LineSeq() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lineSeq
}

// openLineState: a line state this core's keys made (callers hold c.mu; keys = the derived keys about to be taken)
func openLineState(d *LineStateDoc, k *coreKeys) (lineState, error) {
	var st lineState
	var h lineHead
	if !VerifyWith(k.signer.PublicKey(), []byte(d.Head.Payload), d.Head.Sig) || json.Unmarshal([]byte(d.Head.Payload), &h) != nil || h.Kind != "line-state-head" {
		return st, fail(403, "the line state isn't this core's (its head isn't signed by the derived key)")
	}
	sealed, err := b64.DecodeString(d.Sealed)
	if err != nil {
		return st, fail(400, "line state: not base64")
	}
	ss := sha256.Sum256(sealed)
	if hex.EncodeToString(ss[:]) != h.Sha256 {
		return st, fail(403, "the line state isn't the one its head names")
	}
	plain, err := gcmOpenRandom(k.state, sealed, []byte(lineStateAAD))
	if err != nil {
		return st, fail(403, "the line state doesn't open with the derived key")
	}
	if json.Unmarshal(plain, &st) != nil || st.Seq != h.Seq {
		return st, fail(400, "bad line state")
	}
	return st, nil
}

// restoreLine: a line state taken back (callers hold c.mu; the claim already took the stores from the bundle). all =
// a final state (a handoff): its stores replace the bundle's, as they are newer; otherwise only a deploy-key store the
// bundle didn't bring comes back. Stores come back only when they are wrapped for the phone of this claim.
func (c *Core) restoreLine(st lineState, all bool) []string {
	orEmpty := func(m map[string]string) map[string]string {
		if m == nil {
			return map[string]string{}
		}
		return m
	}
	c.latest, c.created, c.signing, c.killed = orEmpty(st.Latest), orEmpty(st.Created), orEmpty(st.Signing), orEmpty(st.Killed)
	c.used, c.approvalsUsed = map[string]bool{}, map[string]bool{}
	for _, m := range st.Used {
		c.used[m] = true
	}
	for _, n := range st.Approvals {
		c.approvalsUsed[n] = true
	}
	c.auditHead, c.auditSeq = st.AuditHead, st.AuditSeq
	c.vol = newVolState() // volumes.go: the machines' volumes and backups go on with the line
	for m, v := range st.Volumes {
		c.vol.live[m] = v
	}
	for m, b := range st.Backups {
		c.vol.backups[m] = b
	}
	for _, v := range st.VolOrphans {
		c.vol.orphans[v] = true
	}
	c.lineSeq = st.Seq
	back := []string{}
	if st.Phone == "" || st.Phone != c.phoneAgreement {
		return back
	}
	ns := map[string]bool{}
	for _, n := range st.NotSensitive {
		ns[n] = true
	}
	valid := func(s string, keys map[string]*KeyEntry) bool {
		if !storeName(s) || s == FlyStore {
			return false
		}
		for k, x := range keys {
			if x == nil || x.Key != k || !validEntry(x, s) {
				return false
			}
		}
		return true
	}
	if all {
		stores := map[string]map[string]*KeyEntry{}
		owners := map[string]string{}
		notSensitive := map[string]bool{}
		for s, keys := range st.Stores {
			if !valid(s, keys) {
				continue
			}
			if keys == nil {
				keys = map[string]*KeyEntry{}
			}
			stores[s] = keys
			if repo := st.RepoOwner[s]; repo != "" && repoRE.MatchString(repo) {
				owners[s] = repo
			}
			if ns[s] {
				notSensitive[s] = true
			}
			back = append(back, s)
		}
		c.stores, c.repoOwner, c.notSensitive = stores, owners, notSensitive
		c.history, c.historySeq = nil, nil
		for _, n := range sortedKeys(c.stores) {
			c.record(n, VersionCause{Kind: "takeover"})
		}
		sort.Strings(back)
		return back
	}
	for s, repo := range st.RepoOwner {
		keys := st.Stores[s]
		if _, have := c.stores[s]; have || len(keys) == 0 || !repoRE.MatchString(repo) || !valid(s, keys) {
			continue
		}
		c.stores[s], c.repoOwner[s] = keys, repo
		if ns[s] {
			c.notSensitive[s] = true
		}
		c.record(s, VersionCause{Kind: "recover"})
		back = append(back, s)
	}
	sort.Strings(back)
	return back
}

// ---- handoff: at most one core with these keys serves (blue/green; Deyao, 2026-10-15) ---------------------------
//
// The router may run a second core and have Deyao Recover it with the same kit while the first still serves. Two
// cores with one identity must never both serve, or an untrusted router could fork a line or answer one approval
// twice. So the cores themselves hand over:
//   - handoff (the serving core, on the router's call): seals a FINAL line state, signs its head, and from then on
//     refuses every call but identity, line-state and handoff again (which answers the same final state);
//   - a Recover whose statement says standby (the master key signed it) serves nothing after its claim until takeover
//     gives it a final state, sealed by these keys, whose seq is at least the one it was Recovered with; it takes that
//     state whole (the lines and every store) and serves;
//   - a Recover whose bundle already carries a final state takes it whole and serves at once (the old core handed off
//     first). A Recover that is neither (a crash: the old core is gone and sealed nothing final) serves at once, from the
//     newest state the router kept: there the guarantee is the old core being gone (docs/DESIGN.md "Core continuity").

const (
	modeServing   = ""
	modeStandby   = "standby"
	modeHandedOff = "handed-off"
)

// Handoff: the final line state; this core serves nothing after it (idempotent: a second call answers the same)
func (c *Core) Handoff() (*LineStateDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.mode == modeHandedOff:
		return c.lineDoc, nil
	case c.lineKey == nil || c.MasterKey == "":
		return nil, fail(409, "only a core set up from the master key's seed hands off")
	case c.mode != modeServing:
		return nil, fail(409, "this core is standing by: it has nothing to hand off")
	}
	d, err := c.sealLine(true)
	if err != nil {
		return nil, err
	}
	c.mode, c.lineDoc, c.lineHash = modeHandedOff, d, ""
	c.unlocked, c.pending, c.pendingKeys, c.restores = map[string]*unlocked{}, map[string]pendingUnlock{}, map[string]pendingDeployKey{}, nil
	c.logf("handed off: final line state %d; serving nothing from now on", c.lineSeq)
	return d, nil
}

// Takeover: a standing-by core takes the final state its predecessor sealed (same keys, seq at least the one it was
// Recovered with) and serves
func (c *Core) Takeover(d *LineStateDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != modeStandby {
		return SignedDoc{}, fail(409, "this core isn't standing by")
	}
	if d == nil {
		return SignedDoc{}, fail(400, "takeover takes the final line state")
	}
	st, err := openLineState(d, &coreKeys{signer: c.signer, state: c.lineKey})
	if err != nil {
		return SignedDoc{}, err
	}
	if !st.Final {
		return SignedDoc{}, fail(403, "not a final line state: the serving core hands off first")
	}
	if st.Seq < c.standbyFrom {
		return SignedDoc{}, fail(403, "the final line state %d is older than the one this core was Recovered with (%d)", st.Seq, c.standbyFrom)
	}
	stores := c.restoreLine(st, true)
	c.mode, c.lineHash, c.lineDoc = modeServing, "", nil
	c.logf("took over at line state %d (%d stores); serving", st.Seq, len(stores))
	return c.sign(map[string]any{"kind": "took-over", "lineSeq": st.Seq, "stores": len(stores)})
}

// allowedIn: what a core that doesn't serve still answers
func allowedIn(mode, pattern string) bool {
	switch pattern {
	case "GET /identity", "GET /line-state", "POST /wipe":
		return true
	case "POST /handoff":
		return mode == modeHandedOff
	case "POST /takeover", "POST /store-key":
		return mode == modeStandby
	}
	return false
}

// ---- AES-GCM with a random nonce in front -----------------------------------------------------------------------

func gcmSealRandom(key, plain, aad []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, plain, aad), nil
}

func gcmOpenRandom(key, sealed, aad []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, fmt.Errorf("short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}

// Mode: serving, standby or handed-off
func (c *Core) Mode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode
}
