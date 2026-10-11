package main

// Deploy keys (Deyao, 2026-10-10): adding a repo in the app's Settings adds an SSH public key to that one repo on
// GitHub as a read/write deploy key, and keeps the private half in a store of its own (`github-<repo>`), which
// sessions include to clone, pull and push that repo — and no other. The app makes the key pair and wraps the
// private half's store to the store key (store_key), so the core never sees it (R2). Removing the repo deletes
// the deploy key on GitHub and the store.
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
	"crypto/rand"
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

// Store names can collide (DE0CH/foo-bar and foo/bar both make github-foo-bar; my.repo, my_repo and My-Repo all
// make github-my-repo). The core knows which repo owns a deploy-key store (Core.repoOwner) and refuses an add or a
// remove for another repo with 409, so a second repo never silently replaces the first one's key and leaves that
// key orphaned on the first repo's GitHub. Re-adding the owning repo (a rotation) still works.

// ownerClash: another repo owns the store (callers hold c.mu)
func (c *Core) ownerClash(store, repo string) error {
	if o := c.repoOwner[store]; o != "" && !strings.EqualFold(o, repo) {
		return fail(409, "store %s belongs to %s", store, o)
	}
	return nil
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
	title     string
	publicKey string     // the app's key pair: the public half GitHub gets…
	blob      *StoreBlob // …and the private half's store, wrapped by the app to the store key
	sensitive bool
	token     StoreBlob // the token store as it was at begin (its E is what the phone answers)
	t         *ecdh.PrivateKey
}

type deployKeyBegin struct {
	Kind      string `json:"kind"` // "deploy-key-begin"
	Pending   string `json:"pending"`
	Action    string `json:"action"`
	Repo      string `json:"repo"`
	Store     string `json:"store"`
	Sensitive bool   `json:"sensitive"`
	Replaces  bool   `json:"replaces"` // add: the store exists and its contents are replaced
	Title     string `json:"title"`    // the deploy key's title on GitHub
	// add: the app's key pair — the public key GitHub gets, and the store blob holding the private half (its E and the
	// sha256 of its data), so the phone's signature covers exactly what the core adds and stores
	PublicKey  string `json:"publicKey,omitempty"`
	BlobE      string `json:"blobE,omitempty"`
	BlobSha256 string `json:"blobSha256,omitempty"`
	TokenStore string `json:"tokenStore"`
	// TokenWriter / TokenDataSha256: who wrote the token store's blob, as in unlock_begin (the phone checks it)
	TokenWriter     map[string]string `json:"tokenWriter"`
	TokenDataSha256 string            `json:"tokenDataSha256"`
	E               string            `json:"e"`
	T               string            `json:"t"`
}

// DeployKeyRequest: deploy_key_begin's input. The app names the store and the key's title, and for an add brings
// the key pair: PublicKey ("ssh-ed25519 <base64>") and Blob, the private half's store wrapped to the store key
// (store_key). Sensitivity is what the app asks for (the app itself insists on it for DE0CH/jarvis2); the core only
// keeps an existing sensitive store sensitive.
type DeployKeyRequest struct {
	Action    string     `json:"action"`
	Repo      string     `json:"repo"`
	Sensitive bool       `json:"sensitive"`
	Store     string     `json:"store"`
	Title     string     `json:"title"`
	PublicKey string     `json:"publicKey"`
	Blob      *StoreBlob `json:"blob"`
}

var titleRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._/:@-]{0,99}$`)

// sshEd25519 checks "ssh-ed25519 <base64 wire>" (RFC 8709: string "ssh-ed25519", string 32-byte key)
func sshEd25519(pub string) bool {
	alg, b, ok := strings.Cut(pub, " ")
	w, err := b64.DecodeString(b)
	return ok && alg == "ssh-ed25519" && err == nil && len(w) == 51 &&
		string(w[:15]) == "\x00\x00\x00\x0bssh-ed25519" && binary.BigEndian.Uint32(w[15:19]) == 32
}

// DeployKeyBegin: a pending add or remove for one repo, signed, with the token store's E and a one-off T
func (c *Core) DeployKeyBegin(in DeployKeyRequest) (SignedDoc, error) {
	action, repo, sensitive := in.Action, in.Repo, in.Sensitive
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
	store, title := in.Store, in.Title
	if !titleRE.MatchString(title) {
		return SignedDoc{}, fail(400, "title: a short line")
	}
	if action == "add" && (!sshEd25519(in.PublicKey) || in.Blob == nil || in.Blob.Name != store || in.Blob.Wrapped.E == "" || in.Blob.Wrapped.Wrapped == "" || in.Blob.Data == "") {
		return SignedDoc{}, fail(400, "an add brings the key pair: publicKey (ssh-ed25519) and the store blob for %s", store)
	}
	if !storeName(store) || store == DeployKeyTokenStore || store == FlyStore {
		return SignedDoc{}, fail(400, "store: %q isn't allowed", store)
	}
	blob := c.stores[DeployKeyTokenStore]
	if blob == nil {
		return SignedDoc{}, fail(404, "no store %s with contents: the setup session writes its GitHub token (%s)", DeployKeyTokenStore, DeployKeyTokenKey)
	}
	if err := c.ownerClash(store, repo); err != nil {
		return SignedDoc{}, err
	}
	old, exists := c.stores[store]
	if action == "remove" {
		sensitive = exists && !c.notSensitive[store]
	} else {
		sensitive = sensitive || (exists && !c.notSensitive[store]) // an existing sensitive store stays sensitive
	}
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	id := randID()
	b := deployKeyBegin{Kind: "deploy-key-begin", Pending: id, Action: action, Repo: repo, Store: store, Sensitive: sensitive,
		Replaces: action == "add" && exists && old != nil, Title: title, TokenStore: DeployKeyTokenStore,
		E: blob.Wrapped.E, T: b64.EncodeToString(t.PublicKey().Bytes()), TokenWriter: writerOf(blob), TokenDataSha256: sha256Hex(blob.Data)}
	var kb *StoreBlob
	if action == "add" {
		x := *in.Blob
		x.WriterSig, x.Writer = "", "core" // stored only after GitHub took the phone-signed key: the core vouches
		kb = &x
		b.PublicKey, b.BlobE, b.BlobSha256 = in.PublicKey, x.Wrapped.E, sha256Hex(x.Data)
	}
	d, err := c.sign(b)
	if err != nil {
		return SignedDoc{}, err
	}
	if c.pendingKeys == nil {
		c.pendingKeys = map[string]pendingDeployKey{}
	}
	c.pendingKeys[id] = pendingDeployKey{payload: d.Payload, action: action, repo: repo, store: store, title: title,
		publicKey: b.PublicKey, blob: kb, sensitive: sensitive, token: *blob, t: t}
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
	title := p.title
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
		delete(c.repoOwner, p.store)
		c.logf("deploy key: %s removed (%d key(s) deleted on GitHub), store %s deleted", p.repo, removed, p.store)
		return c.sign(map[string]any{"kind": "deploy-key-removed", "pending": pending, "repo": p.repo, "store": p.store, "deleted": removed})
	}
	k, err := c.github.AddDeployKey(token, p.repo, title, p.publicKey)
	if err != nil {
		return SignedDoc{}, c.githubFailure(p, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ownerClash(p.store, p.repo); err != nil {
		// another repo's add finished first while GitHub was called: take back the key just added
		c.mu.Unlock()
		derr := c.github.DeleteDeployKey(token, p.repo, k.ID)
		c.mu.Lock()
		c.logf("deploy key: %s lost %s to %s (key %d taken back: %v)", p.repo, p.store, c.repoOwner[p.store], k.ID, derr)
		return SignedDoc{}, err
	}
	token = ""
	_, existed := c.stores[p.store]
	c.stores[p.store] = p.blob
	c.repoOwner[p.store] = p.repo
	delete(c.unlocked, p.store) // an earlier key's plaintext: that key is gone on GitHub
	if p.sensitive {
		delete(c.notSensitive, p.store)
	} else if !existed {
		c.notSensitive[p.store] = true
	}
	c.logf("deploy key: %s added (GitHub key %d, %d earlier deleted), store %s (sensitive=%v)", p.repo, k.ID, removed, p.store, !c.notSensitive[p.store])
	return c.sign(map[string]any{"kind": "deploy-key-added", "pending": pending, "repo": p.repo, "store": p.store,
		"sensitive": !c.notSensitive[p.store], "title": title, "publicKey": p.publicKey, "keyId": k.ID})
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
	if err := c.ownerClash(p.store, p.repo); err != nil {
		return p, "", err
	}
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

// githubFailure: GitHub refused or couldn't be reached: "github: HTTP <status>: <GitHub's words>" (the router adds
// what a 403/404 means for the token)
func (c *Core) githubFailure(p pendingDeployKey, err error) error {
	c.mu.Lock()
	c.logf("deploy key: %s %s failed: %v", p.action, p.repo, err)
	c.mu.Unlock()
	if ge, ok := err.(*GitHubError); ok {
		return fail(502, "github: HTTP %d: %s", ge.Status, ge.Msg)
	}
	return fail(502, "github: %v", err)
}
