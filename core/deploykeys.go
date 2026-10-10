package main

// Deploy keys (Deyao, 2026-10-10): adding a repo in the app's Settings makes the core generate an SSH key
// pair, add its public half to that one repo on GitHub as a read/write deploy key, and keep the private half
// in a store of its own (`github-<repo>`), which sessions include to clone, pull and push that repo — and no
// other. Removing the repo deletes the deploy key on GitHub and the store.
//
// Both are phone-approved, and the box alone can never make a key: the GitHub token that may manage deploy
// keys lives only in the sensitive store `github-deploy-keys` (a fine-grained PAT with Repository
// "Administration: read and write" and nothing else). DeployKeyBegin answers, signed, exactly what will happen
// (the repo, the store, its sensitivity, add or remove) with the token store's E and a one-off T, as an unlock
// does. The phone shows it, and under one Face ID signs that text and computes its share of the token store;
// DeployKeyFinish checks the signature, opens the token store with the share for this call only (it never
// joins the unlocked set, and the plaintext is dropped when the call returns), talks to GitHub, and writes or
// deletes the repo's store. No other store is touched.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"strings"
)

const (
	// DeployKeyTokenStore: the store whose GitHub token may manage deploy keys; the only store this flow opens
	DeployKeyTokenStore = "github-deploy-keys"
	DeployKeyTokenKey   = "GITHUB_DEPLOY_KEYS_TOKEN"
	// a repo's store holds these two keys, each suffixed with the repo's env slug (EnvSlug)
	DeployRepoPrefix = "GITHUB_DEPLOY_REPO_" // "owner/name"
	DeployKeyPrefix  = "GITHUB_DEPLOY_KEY_"  // base64 of the OpenSSH private key file
)

// repos whose store is sensitive whatever the request says: a push to Jarvis 2's own repo reaches the core
var alwaysSensitiveRepos = map[string]bool{"de0ch/jarvis2": true}

var repoRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// RepoStore: the store a repo's deploy key lives in — github-<name> for Deyao's own repos (DE0CH), else
// github-<owner>-<name>; lower case, anything outside [a-z0-9-] becomes "-"
func RepoStore(repo string) string {
	owner, name, _ := strings.Cut(strings.ToLower(repo), "/")
	slug := name
	if owner != "de0ch" {
		slug = owner + "-" + name
	}
	b := []byte(slug)
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			b[i] = '-'
		}
	}
	return "github-" + strings.Trim(string(b), "-")
}

// EnvSlug: the suffix of a repo's two env keys — OWNER_NAME, upper case, anything outside [A-Z0-9] as "_"
func EnvSlug(repo string) string {
	b := []byte(strings.ToUpper(repo))
	for i, ch := range b {
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

type pendingDeployKey struct {
	payload   string // the signed begin document: what the phone signs
	action    string // "add" | "remove"
	repo      string
	store     string
	sensitive bool
	token     StoreBlob // the token store as it was at begin (its E is what the phone answers)
	t         *ecdh.PrivateKey
}

type deployKeyBegin struct {
	Kind       string `json:"kind"` // "deploy-key-begin"
	Pending    string `json:"pending"`
	Action     string `json:"action"`
	Repo       string `json:"repo"`
	Store      string `json:"store"`
	Sensitive  bool   `json:"sensitive"`
	Replaces   bool   `json:"replaces"` // add: the store exists and its contents are replaced
	Title      string `json:"title"`    // the deploy key's title on GitHub
	TokenStore string `json:"tokenStore"`
	E          string `json:"e"`
	T          string `json:"t"`
}

// DeployKeyBegin: a pending add or remove for one repo, signed, with the token store's E and a one-off T
func (c *Core) DeployKeyBegin(action, repo string, sensitive bool) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phoneSigning == "" {
		return SignedDoc{}, fail(409, "this core isn't set up yet")
	}
	if action != "add" && action != "remove" {
		return SignedDoc{}, fail(400, "action: add or remove")
	}
	if !repoRE.MatchString(repo) || strings.Contains(repo, "..") || strings.HasSuffix(repo, "/.") {
		return SignedDoc{}, fail(400, "repo: owner/name")
	}
	store := RepoStore(repo)
	if !storeName(store) || store == DeployKeyTokenStore || store == FlyStore {
		return SignedDoc{}, fail(400, "repo %s would use the store name %s, which isn't allowed", repo, store)
	}
	blob := c.stores[DeployKeyTokenStore]
	if blob == nil {
		return SignedDoc{}, fail(404, "no store %s with contents: the setup session writes its GitHub token (%s)", DeployKeyTokenStore, DeployKeyTokenKey)
	}
	old, exists := c.stores[store]
	if action == "remove" {
		sensitive = exists && !c.notSensitive[store]
	} else {
		// an existing sensitive store stays sensitive (nothing downgrades one); Jarvis 2's own repo always is
		sensitive = sensitive || alwaysSensitiveRepos[strings.ToLower(repo)] || (exists && !c.notSensitive[store])
	}
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	id := randID()
	b := deployKeyBegin{Kind: "deploy-key-begin", Pending: id, Action: action, Repo: repo, Store: store, Sensitive: sensitive,
		Replaces: action == "add" && exists && old != nil, Title: "jarvis2 " + store, TokenStore: DeployKeyTokenStore,
		E: blob.Wrapped.E, T: b64.EncodeToString(t.PublicKey().Bytes())}
	d, err := c.sign(b)
	if err != nil {
		return SignedDoc{}, err
	}
	if c.pendingKeys == nil {
		c.pendingKeys = map[string]pendingDeployKey{}
	}
	c.pendingKeys[id] = pendingDeployKey{payload: d.Payload, action: action, repo: repo, store: store, sensitive: sensitive, token: *blob, t: t}
	return d, nil
}

// DeployKeyFinish: the phone's signature over the begin document and its share of the token store, sealed to
// T. One try: the pending and its one-off key are gone either way.
func (c *Core) DeployKeyFinish(pending string, share Sealed, sig string) (SignedDoc, error) {
	p, token, err := c.openDeployKeyToken(pending, share, sig)
	if err != nil {
		return SignedDoc{}, err
	}
	// GitHub is called without the core's lock (it may take seconds); the token lives in this frame only
	title := "jarvis2 " + p.store
	keys, err := c.github.ListDeployKeys(token, p.repo)
	if err != nil {
		return SignedDoc{}, c.githubFailure(p, err)
	}
	removed := 0
	for _, k := range keys {
		if k.Title == title { // this store's earlier key (a re-add rotates it)
			if err := c.github.DeleteDeployKey(token, p.repo, k.ID); err != nil {
				return SignedDoc{}, c.githubFailure(p, err)
			}
			removed++
		}
	}
	if p.action == "remove" {
		token = ""
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.stores, p.store)
		delete(c.notSensitive, p.store)
		delete(c.unlocked, p.store)
		c.logf("deploy key: %s removed (%d key(s) deleted on GitHub), store %s deleted", p.repo, removed, p.store)
		return c.sign(map[string]any{"kind": "deploy-key-removed", "pending": pending, "repo": p.repo, "store": p.store, "deleted": removed})
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	wire := sshPublicWire(pub)
	k, err := c.github.AddDeployKey(token, p.repo, title, "ssh-ed25519 "+b64.EncodeToString(wire))
	token = ""
	if err != nil {
		return SignedDoc{}, c.githubFailure(p, err)
	}
	values := map[string]string{
		DeployRepoPrefix + EnvSlug(p.repo): p.repo,
		DeployKeyPrefix + EnvSlug(p.repo):  b64.EncodeToString(OpenSSHPrivateKey(priv, title)),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	blob, err := c.wrap(p.store, values, c.phoneAgreement)
	if err != nil {
		return SignedDoc{}, err
	}
	_, existed := c.stores[p.store]
	c.stores[p.store] = blob
	delete(c.unlocked, p.store) // an earlier key's plaintext: that key is gone on GitHub
	if p.sensitive {
		delete(c.notSensitive, p.store)
	} else if !existed {
		c.notSensitive[p.store] = true
	}
	sum := sha256.Sum256(wire)
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	c.logf("deploy key: %s added (%s, GitHub key %d, %d earlier deleted), store %s (sensitive=%v)", p.repo, fp, k.ID, removed, p.store, !c.notSensitive[p.store])
	return c.sign(map[string]any{"kind": "deploy-key-added", "pending": pending, "repo": p.repo, "store": p.store,
		"sensitive": !c.notSensitive[p.store], "title": title, "fingerprint": fp, "keyId": k.ID})
}

// openDeployKeyToken: the pending's checks (the phone signed exactly the begin document) and the token store
// opened with the phone's share — its plaintext only as the returned token
func (c *Core) openDeployKeyToken(pending string, share Sealed, sig string) (pendingDeployKey, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pendingKeys[pending]
	if !ok {
		return p, "", fail(404, "no such pending deploy-key request")
	}
	delete(c.pendingKeys, pending)
	if c.phoneSigning == "" || !VerifyWith(c.phoneSigning, []byte(p.payload), sig) {
		return p, "", fail(403, "the iPhone's signature doesn't cover this request")
	}
	x, err := OpenSealed(p.t, share, infoShare)
	if err != nil {
		return p, "", fail(400, "the share isn't sealed to this request")
	}
	dk, err := UnwrapWithShares(p.token.Wrapped, x, c.agreement)
	if err != nil {
		return p, "", fail(403, "%v", err)
	}
	data, _ := b64.DecodeString(p.token.Data)
	plain, err := gcmOpen(dk, data, []byte(p.token.Name))
	if err != nil {
		return p, "", fail(403, "the token store doesn't decrypt")
	}
	vals := map[string]string{}
	json.Unmarshal(plain, &vals)
	tok := vals[DeployKeyTokenKey]
	if tok == "" {
		return p, "", fail(400, "the store %s holds no %s", DeployKeyTokenStore, DeployKeyTokenKey)
	}
	c.logf("deploy key: %s %s approved by the phone; %s opened for this call", p.action, p.repo, DeployKeyTokenStore)
	return p, tok, nil
}

// githubFailure: GitHub refused or couldn't be reached. A 403/404 means the token can't manage this repo's
// deploy keys: the message says which permission it needs.
func (c *Core) githubFailure(p pendingDeployKey, err error) error {
	c.mu.Lock()
	c.logf("deploy key: %s %s failed: %v", p.action, p.repo, err)
	c.mu.Unlock()
	if ge, ok := err.(*GitHubError); ok && (ge.Status == 403 || ge.Status == 404) {
		return fail(502, "the GitHub token in %s can't manage deploy keys on %s (%s): it needs a fine-grained token with Repository permission \"Administration: read and write\" on that repo (all repositories)", DeployKeyTokenStore, p.repo, ge.Msg)
	}
	return fail(502, "%v", err)
}

// ---- SSH key formats -----------------------------------------------------------------------------------

func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// sshPublicWire: the public key blob (RFC 8709): string "ssh-ed25519", string key
func sshPublicWire(pub ed25519.PublicKey) []byte {
	return append(sshString([]byte("ssh-ed25519")), sshString(pub)...)
}

// OpenSSHPrivateKey: the key as an unencrypted OpenSSH private key file (PROTOCOL.key), what `ssh -i` reads
func OpenSSHPrivateKey(priv ed25519.PrivateKey, comment string) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	check := make([]byte, 4)
	rand.Read(check)
	var sec []byte
	sec = append(sec, check...)
	sec = append(sec, check...)
	sec = append(sec, sshString([]byte("ssh-ed25519"))...)
	sec = append(sec, sshString(pub)...)
	sec = append(sec, sshString(priv)...) // seed || public, 64 bytes
	sec = append(sec, sshString([]byte(comment))...)
	for i := byte(1); len(sec)%8 != 0; i++ {
		sec = append(sec, i)
	}
	var b []byte
	b = append(b, "openssh-key-v1\x00"...)
	b = append(b, sshString([]byte("none"))...)
	b = append(b, sshString([]byte("none"))...)
	b = append(b, sshString(nil)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, sshString(sshPublicWire(pub))...)
	b = append(b, sshString(sec)...)
	enc := b64.EncodeToString(b)
	var out strings.Builder
	out.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n-----END OPENSSH PRIVATE KEY-----\n")
	return []byte(out.String())
}
