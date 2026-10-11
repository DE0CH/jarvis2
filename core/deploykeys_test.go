package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// a GitHub stand-in: deploy keys per repo; tokens other than the one it knows, and repos it was told to refuse,
// answer 403 like GitHub does for a token without Administration on the repo
type testGitHub struct {
	token  string
	n      int64
	keys   map[string][]DeployKey
	refuse map[string]bool
	seen   []string // every token it was called with
}

func newTestGitHub() *testGitHub {
	return &testGitHub{token: "gh-admin-token", keys: map[string][]DeployKey{}, refuse: map[string]bool{}}
}
func (g *testGitHub) check(token, repo string) error {
	g.seen = append(g.seen, token)
	if token != g.token || g.refuse[repo] {
		return &GitHubError{403, "GitHub: HTTP 403 Resource not accessible by personal access token"}
	}
	return nil
}
func (g *testGitHub) ListDeployKeys(token, repo string) ([]DeployKey, error) {
	if err := g.check(token, repo); err != nil {
		return nil, err
	}
	return append([]DeployKey{}, g.keys[repo]...), nil
}
func (g *testGitHub) AddDeployKey(token, repo, title, pub string) (DeployKey, error) {
	if err := g.check(token, repo); err != nil {
		return DeployKey{}, err
	}
	g.n++
	k := DeployKey{ID: g.n, Title: title, Key: pub}
	g.keys[repo] = append(g.keys[repo], k)
	return k, nil
}
func (g *testGitHub) DeleteDeployKey(token, repo string, id int64) error {
	if err := g.check(token, repo); err != nil {
		return err
	}
	var out []DeployKey
	for _, k := range g.keys[repo] {
		if k.ID != id {
			out = append(out, k)
		}
	}
	g.keys[repo] = out
	return nil
}

// a set-up core with the token store written (sensitive: the setup session never creates it)
func deployKeyCore(t *testing.T) (*Core, *testGitHub, *phone) {
	t.Helper()
	c, _, p := setup(t)
	g := newTestGitHub()
	c.github = g
	pl(t)(c.WriteStore(writeStore(t, c, p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: g.token})))
	return c, g, p
}

// what the shell does: check the begin document, sign it and share the token store, under one Face ID
func (p *phone) answerDeployKey(t *testing.T, begin SignedDoc) (string, Sealed, string) {
	t.Helper()
	id, s := p.share(begin)
	return id, s, p.sign(begin.Payload)
}

// keyRequest: what the app sends to deploy_key_begin — the store and title it names, and for an add the key pair it
// made (appKey)
func keyRequest(t *testing.T, c *Core, p *phone, action, repo string, sensitive bool) DeployKeyRequest {
	t.Helper()
	store := RepoStore(repo)
	r := DeployKeyRequest{Action: action, Repo: repo, Sensitive: sensitive, Store: store, Title: "jarvis2 " + store}
	if action == "add" && c.phoneSigning != "" {
		r.PublicKey, r.Blob, _ = appKey(t, c, p, repo, store)
	}
	return r
}

func deployKey(t *testing.T, c *Core, p *phone, action, repo string, sensitive bool) (map[string]any, error) {
	t.Helper()
	b, err := c.DeployKeyBegin(keyRequest(t, c, p, action, repo, sensitive))
	if err != nil {
		return nil, err
	}
	id, s, sig := p.answerDeployKey(t, b)
	d, err := c.DeployKeyFinish(id, s, sig)
	if err != nil {
		return nil, err
	}
	if !VerifyWith(c.Key()["signingKey"], []byte(d.Payload), d.Sig) {
		t.Fatal("the answer isn't core-signed")
	}
	var m map[string]any
	json.Unmarshal([]byte(d.Payload), &m)
	return m, nil
}

// storeValues: a store's contents, opened the way a session gets them (unlocked by the phone)
func storeValues(t *testing.T, c *Core, p *phone, name string) map[string]string {
	t.Helper()
	unlock(t, c, p, name)
	return c.unlocked[name].values
}

func TestDeployKeyAddMakesAKeyAStoreAndAGitHubKey(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)
	c, g, p := deployKeyCore(t)
	m, err := deployKey(t, c, p, "add", "DE0CH/china-train", false)
	if err != nil {
		t.Fatal(err)
	}
	if m["kind"] != "deploy-key-added" || m["store"] != "github-china-train" || m["sensitive"] != false || m["title"] != "jarvis2 github-china-train" {
		t.Fatalf("answer: %v", m)
	}
	ks := g.keys["DE0CH/china-train"]
	if len(ks) != 1 || ks[0].Title != "jarvis2 github-china-train" || !strings.HasPrefix(ks[0].Key, "ssh-ed25519 ") {
		t.Fatalf("GitHub keys: %+v", ks)
	}
	if _, open := c.unlocked[DeployKeyTokenStore]; open {
		t.Fatal("the token store stayed unlocked after the call")
	}
	if !c.notSensitive["github-china-train"] {
		t.Fatal("the repo's store came out sensitive")
	}
	v := storeValues(t, c, p, "github-china-train")
	if v["GITHUB_DEPLOY_REPO_DE0CH_CHINA_TRAIN"] != "DE0CH/china-train" || len(v) != 2 {
		t.Fatalf("store keys: %v", keysOf(v))
	}
	pem, err := b64.DecodeString(v["GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN"])
	if err != nil || !strings.HasPrefix(string(pem), "-----BEGIN OPENSSH PRIVATE KEY-----\n") {
		t.Fatal("the store doesn't hold an OpenSSH private key")
	}
	if strings.Contains(logs.String(), g.token) {
		t.Fatal("the token reached the log")
	}
	// the private half is the public key GitHub got (an independent implementation: ssh-keygen)
	if kg, err := exec.LookPath("ssh-keygen"); err == nil {
		f := filepath.Join(t.TempDir(), "k")
		os.WriteFile(f, pem, 0o600)
		out, err := exec.Command(kg, "-y", "-f", f).Output()
		if err != nil {
			t.Fatalf("ssh-keygen can't read the key: %v", err)
		}
		if strings.Fields(string(out))[1] != strings.Fields(ks[0].Key)[1] {
			t.Fatal("the stored private key isn't the deploy key on GitHub")
		}
	} else {
		t.Log("no ssh-keygen: skipped the independent check of the key format")
	}
}

func keysOf(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDeployKeyReAddRotatesAndRemoveDeletesBoth(t *testing.T) {
	c, g, p := deployKeyCore(t)
	g.keys["DE0CH/claude-env"] = []DeployKey{{ID: 100, Title: "someone else's key"}}
	if _, err := deployKey(t, c, p, "add", "DE0CH/claude-env", false); err != nil {
		t.Fatal(err)
	}
	first := g.keys["DE0CH/claude-env"][1].Key
	m, err := deployKey(t, c, p, "add", "DE0CH/claude-env", false)
	if err != nil {
		t.Fatal(err)
	}
	ks := g.keys["DE0CH/claude-env"]
	if len(ks) != 2 || ks[0].ID != 100 || ks[1].Key == first {
		t.Fatalf("a re-add didn't rotate the one key (and only it): %+v", ks)
	}
	if m["kind"] != "deploy-key-added" {
		t.Fatal(m)
	}
	m, err = deployKey(t, c, p, "remove", "DE0CH/claude-env", false)
	if err != nil || m["kind"] != "deploy-key-removed" || m["deleted"] != float64(1) {
		t.Fatal(m, err)
	}
	if len(g.keys["DE0CH/claude-env"]) != 1 || g.keys["DE0CH/claude-env"][0].ID != 100 {
		t.Fatal("remove touched another key or left ours")
	}
	if _, ok := c.stores["github-claude-env"]; ok {
		t.Fatal("remove left the store")
	}
}

// sensitivity is what the app asks for (the app insists on it for DE0CH/jarvis2: Checks.deployKeyBegin); the core
// only keeps an existing sensitive store sensitive
func TestDeployKeySensitivity(t *testing.T) {
	c, _, p := deployKeyCore(t)
	// asked for: sensitive
	if m, _ := deployKey(t, c, p, "add", "DE0CH/private-thing", true); m["sensitive"] != true {
		t.Fatal(m)
	}
	// an existing sensitive store stays sensitive on a re-add that doesn't ask for it
	if m, _ := deployKey(t, c, p, "add", "DE0CH/private-thing", false); m["sensitive"] != true || c.notSensitive["github-private-thing"] {
		t.Fatal("a re-add downgraded a sensitive store")
	}
	// the begin document says so before the phone signs
	b, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/private-thing", false))
	var bd deployKeyBegin
	json.Unmarshal([]byte(b.Payload), &bd)
	if !bd.Sensitive || !bd.Replaces || bd.Store != "github-private-thing" || bd.TokenStore != DeployKeyTokenStore {
		t.Fatalf("begin: %+v", bd)
	}
}

func TestDeployKeyNeedsThePhone(t *testing.T) {
	c, g, p := deployKeyCore(t)
	other := newPhone()
	// another key's signature
	b, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false))
	id, s, _ := p.answerDeployKey(t, b)
	if _, err := c.DeployKeyFinish(id, s, other.sign(b.Payload)); err == nil {
		t.Fatal("another key's signature was accepted")
	}
	if _, err := c.DeployKeyFinish(id, s, p.sign(b.Payload)); err == nil {
		t.Fatal("a pending was usable twice")
	}
	// the phone's signature over ANOTHER begin document (the router swapping requests)
	b1, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false))
	b2, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/y", false))
	id2, s2 := p.share(b2)
	if _, err := c.DeployKeyFinish(id2, s2, p.sign(b1.Payload)); err == nil {
		t.Fatal("a signature over another request was accepted")
	}
	// another phone's share
	b3, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false))
	id3, s3 := other.share(b3)
	if _, err := c.DeployKeyFinish(id3, s3, p.sign(b3.Payload)); err == nil {
		t.Fatal("another phone's share opened the token store")
	}
	if len(g.seen) != 0 || len(g.keys) != 0 {
		t.Fatal("GitHub was called without the phone's approval")
	}
}

func TestDeployKeyRefusals(t *testing.T) {
	c, _, p := setup(t)
	c.github = newTestGitHub()
	if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false)); err == nil || !strings.Contains(err.Error(), DeployKeyTokenStore) {
		t.Fatal("began without the token store:", err)
	}
	pl(t)(c.WriteStore(writeStore(t, c, p, DeployKeyTokenStore, map[string]string{"OTHER": "x"})))
	if _, err := deployKey(t, c, p, "add", "DE0CH/x", false); err == nil || !strings.Contains(err.Error(), DeployKeyTokenKey) {
		t.Fatal("a token store without the token:", err)
	}
	for _, bad := range []string{"", "x", "DE0CH/", "/x", "DE0CH/a/b", "DE0CH/..", "DE0CH/deploy-keys", "-x/y", "DE0CH/a b", "DE0CH/."} {
		if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", bad, false)); err == nil {
			t.Fatalf("repo %q accepted", bad)
		}
	}
	if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "rotate", "DE0CH/x", false)); err == nil {
		t.Fatal("an unknown action")
	}
	empty, _, _ := newCore(t)
	if _, err := empty.DeployKeyBegin(keyRequest(t, empty, p, "add", "DE0CH/x", false)); err == nil {
		t.Fatal("an empty core began")
	}
}

func TestDeployKeyTokenWithoutAdministration(t *testing.T) {
	c, g, p := deployKeyCore(t)
	g.refuse["DE0CH/x"] = true
	_, err := deployKey(t, c, p, "add", "DE0CH/x", false)
	if err == nil || !strings.Contains(err.Error(), "github: HTTP 403") {
		t.Fatal("no GitHub status:", err)
	}
	if _, ok := c.stores["github-x"]; ok {
		t.Fatal("a store was made though GitHub refused")
	}
}

func TestRepoStoreAndEnvSlug(t *testing.T) {
	for in, want := range map[string]string{"DE0CH/claude-env": "github-claude-env", "DE0CH/china_train": "github-china-train",
		"de0ch/Jarvis2": "github-jarvis2", "someone/Thing.js": "github-someone-thing-js"} {
		if got := RepoStore(in); got != want {
			t.Errorf("RepoStore(%s) = %s, want %s", in, got, want)
		}
	}
	if EnvSlug("DE0CH/claude-env") != "DE0CH_CLAUDE_ENV" {
		t.Fatal(EnvSlug("DE0CH/claude-env"))
	}
}

func TestOpenSSHKeyFormat(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pem := OpenSSHPrivateKey(priv, "c")
	body := strings.Join(strings.Split(strings.TrimSpace(string(pem)), "\n")[1:len(strings.Split(strings.TrimSpace(string(pem)), "\n"))-1], "")
	raw, err := b64.DecodeString(body)
	if err != nil || !strings.HasPrefix(string(raw), "openssh-key-v1\x00") {
		t.Fatal("not an openssh-key-v1 file")
	}
	if !strings.Contains(string(raw), string(pub)) {
		t.Fatal("the public key isn't in the file")
	}
}

// colliding repos share a store name: the second repo's add (or remove) is refused with 409 naming the owner, and
// GitHub is never called for it; the owning repo still re-adds and removes, after which the name is free
func TestDeployKeyStoreClashRefused(t *testing.T) {
	c, g, p := deployKeyCore(t)
	if RepoStore("DE0CH/foo-bar") != RepoStore("foo/bar") || RepoStore("DE0CH/my.repo") != RepoStore("DE0CH/My-Repo") {
		t.Fatal("the test's repos don't collide")
	}
	if _, err := deployKey(t, c, p, "add", "DE0CH/foo-bar", false); err != nil {
		t.Fatal(err)
	}
	calls := len(g.seen)
	for _, action := range []string{"add", "remove"} {
		_, err := c.DeployKeyBegin(keyRequest(t, c, p, action, "foo/bar", false))
		if e, ok := err.(*Err); !ok || e.Status != 409 || !strings.Contains(err.Error(), "store github-foo-bar belongs to DE0CH/foo-bar") {
			t.Fatalf("%s for a colliding repo: %v", action, err)
		}
	}
	// a begin taken before the store was owned is refused at finish, before GitHub
	c2, g2, p2 := deployKeyCore(t)
	early, _ := c2.DeployKeyBegin(keyRequest(t, c2, p2, "add", "DE0CH/My-Repo", false))
	if _, err := deployKey(t, c2, p2, "add", "DE0CH/my.repo", false); err != nil {
		t.Fatal(err)
	}
	n2 := len(g2.seen)
	id, s, sig := p2.answerDeployKey(t, early)
	if _, err := c2.DeployKeyFinish(id, s, sig); err == nil || !strings.Contains(err.Error(), "belongs to DE0CH/my.repo") {
		t.Fatal("a pending add for a colliding repo finished:", err)
	}
	if len(g.seen) != calls || len(g2.seen) != n2 || len(g2.keys["DE0CH/My-Repo"]) != 0 {
		t.Fatal("GitHub was called for a refused repo")
	}
	if v := storeValues(t, c2, p2, "github-my-repo"); v["GITHUB_DEPLOY_REPO_DE0CH_MY_REPO"] != "DE0CH/my.repo" {
		t.Fatal("the owner's store was replaced:", keysOf(v))
	}
	// the owner re-adds (any case) and removes; then the name is free for the other repo
	if _, err := deployKey(t, c, p, "add", "de0ch/FOO-BAR", false); err != nil {
		t.Fatal("the owner's re-add:", err)
	}
	if m, err := deployKey(t, c, p, "remove", "DE0CH/foo-bar", false); err != nil || m["kind"] != "deploy-key-removed" {
		t.Fatal("the owner's remove:", m, err)
	}
	if _, err := deployKey(t, c, p, "add", "foo/bar", false); err != nil {
		t.Fatal("the freed name:", err)
	}
	if c.repoOwner["github-foo-bar"] != "foo/bar" {
		t.Fatal(c.repoOwner)
	}
}

// the same repo re-added keeps working, and keeps its owner
func TestDeployKeySameRepoReAdd(t *testing.T) {
	c, g, p := deployKeyCore(t)
	for i := 0; i < 3; i++ {
		if _, err := deployKey(t, c, p, "add", "DE0CH/china-train", false); err != nil {
			t.Fatal(i, err)
		}
	}
	if len(g.keys["DE0CH/china-train"]) != 1 || c.repoOwner["github-china-train"] != "DE0CH/china-train" {
		t.Fatal(g.keys, c.repoOwner)
	}
	if b, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/china-train", false)); err != nil || !strings.Contains(b.Payload, `"replaces":true`) {
		t.Fatal(err)
	}
}

// a Recover keeps each deploy-key store's owner: the bundle's owners (the app reads them from the stores), for
// stores the bundle holds and repos that are repos
func TestDeployKeyRecoverKeepsTheOwner(t *testing.T) {
	c, _, master := newCore(t)
	p := newPhone()
	rb := recoverBundle(t, c, p, "fly-secret")
	rb.Blobs = append(rb.Blobs,
		appWrap(t, c, p, "github-foo-bar", map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_FOO_BAR": "DE0CH/foo-bar", "GITHUB_DEPLOY_KEY_DE0CH_FOO_BAR": "x"}),
		appWrap(t, c, p, "github-odd", map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_OTHER": "DE0CH/other"}),
		appWrap(t, c, p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: "gh-admin-token"}))
	rb.Owners = map[string]string{"github-foo-bar": "DE0CH/foo-bar", "github-odd": "not a repo", "github-gone": "DE0CH/gone"}
	s, sig, b := claimFor(c, master, p, rb)
	pl(t)(c.Claim(s, sig, b))
	c.github = newTestGitHub()
	if len(c.repoOwner) != 1 || c.repoOwner["github-foo-bar"] != "DE0CH/foo-bar" {
		t.Fatalf("owners after Recover: %v", c.repoOwner)
	}
	if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", "foo/bar", false)); err == nil || !strings.Contains(err.Error(), "belongs to DE0CH/foo-bar") {
		t.Fatal("a Recover lost the owner:", err)
	}
	if _, err := deployKey(t, c, p, "add", "DE0CH/foo-bar", false); err != nil {
		t.Fatal("the owner's re-add after Recover:", err)
	}
}

// a GitHub that runs a hook inside AddDeployKey (another add finishing while this one talks to GitHub)
type racingGitHub struct {
	*testGitHub
	onAdd func()
}

func (g racingGitHub) AddDeployKey(token, repo, title, pub string) (DeployKey, error) {
	k, err := g.testGitHub.AddDeployKey(token, repo, title, pub)
	if g.onAdd != nil {
		g.onAdd()
	}
	return k, err
}

// two colliding adds in flight: the one that loses takes its new key back off GitHub and is refused
func TestDeployKeyClashRaceTakesTheKeyBack(t *testing.T) {
	c, g, p := deployKeyCore(t)
	c.github = racingGitHub{g, func() {
		c.mu.Lock()
		c.repoOwner["github-foo-bar"] = "foo/bar"
		c.mu.Unlock()
	}}
	if _, err := deployKey(t, c, p, "add", "DE0CH/foo-bar", false); err == nil || !strings.Contains(err.Error(), "belongs to foo/bar") {
		t.Fatal("the losing add went through:", err)
	}
	if len(g.keys["DE0CH/foo-bar"]) != 0 {
		t.Fatal("the losing add left its key on GitHub")
	}
	if _, ok := c.stores["github-foo-bar"]; ok {
		t.Fatal("the losing add wrote the store")
	}
}

// ---- the app's form (R2): the app makes the key pair and wraps the store to the core's store key -------------------

// appKey: what the app does before Face ID — an ed25519 pair, the store's values (the same format as the core's), the
// data key wrapped to the store key the core signed (store_key)
func appKey(t *testing.T, c *Core, p *phone, repo, store string) (string, *StoreBlob, ed25519.PrivateKey) {
	t.Helper()
	sk := pl(t)(c.StoreKey(p.agreementKey()))
	if sk["phone"] != p.agreementKey() {
		t.Fatal("the store key names another phone")
	}
	C, _ := b64.DecodeString(sk["storeKey"].(string))
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dk := make([]byte, 32)
	rand.Read(dk)
	w, err := WrapToPoint(C, dk)
	if err != nil {
		t.Fatal(err)
	}
	vals, _ := json.Marshal(map[string]string{DeployRepoPrefix + EnvSlug(repo): repo,
		DeployKeyPrefix + EnvSlug(repo): b64.EncodeToString(OpenSSHPrivateKey(priv, "jarvis2 "+store))})
	return "ssh-ed25519 " + b64.EncodeToString(sshPublicWire(pub)), &StoreBlob{Name: store, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, vals, []byte(store)))}, priv
}

func TestDeployKeyFromTheAppsKeyPair(t *testing.T) {
	c, g, p := deployKeyCore(t)
	pub, blob, priv := appKey(t, c, p, "DE0CH/china-train", "github-china-train")
	req := DeployKeyRequest{Action: "add", Repo: "DE0CH/china-train", Store: "github-china-train", Title: "jarvis2 github-china-train", PublicKey: pub, Blob: blob}
	for name, bad := range map[string]func(*DeployKeyRequest){
		"no public key":      func(r *DeployKeyRequest) { r.PublicKey = "" },
		"not ed25519":        func(r *DeployKeyRequest) { r.PublicKey = "ssh-rsa AAAA" },
		"no blob":            func(r *DeployKeyRequest) { r.Blob = nil },
		"a blob for another": func(r *DeployKeyRequest) { x := *blob; x.Name = "github-other"; r.Blob = &x },
		"the token store": func(r *DeployKeyRequest) {
			r.Store = DeployKeyTokenStore
			x := *blob
			x.Name = DeployKeyTokenStore
			r.Blob = &x
		},
		"a title with a line":                               func(r *DeployKeyRequest) { r.Title = "x\ny" },
		"no store or title (the core named them before R2)": func(r *DeployKeyRequest) { r.Store, r.Title = "", "" },
	} {
		in := req
		bad(&in)
		if _, err := c.DeployKeyBegin(in); err == nil {
			t.Fatalf("%s: began", name)
		}
	}
	b := pl(t)(c.DeployKeyBegin(req))
	if b["publicKey"] != pub || b["blobE"] != blob.Wrapped.E || b["blobSha256"] != sha256Hex(blob.Data) {
		t.Fatalf("the begin document doesn't name the key pair: %v", b)
	}
	d, _ := c.DeployKeyBegin(req)
	id, s, sig := p.answerDeployKey(t, d)
	a := pl(t)(c.DeployKeyFinish(id, s, sig))
	if a["kind"] != "deploy-key-added" || a["publicKey"] != pub || a["fingerprint"] != nil {
		t.Fatalf("answer %v", a)
	}
	if ks := g.keys["DE0CH/china-train"]; len(ks) != 1 || ks[0].Key != pub {
		t.Fatalf("GitHub got %v", ks)
	}
	if got := c.stores["github-china-train"]; got.Data != blob.Data || got.Writer != "core" {
		t.Fatal("the store isn't the app's blob, vouched by the core")
	}
	// the phone and the core open it as any store: the private half GitHub's key belongs to
	v := storeValues(t, c, p, "github-china-train")
	k, _ := b64.DecodeString(v["GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN"])
	if !strings.Contains(string(k), "OPENSSH PRIVATE KEY") || priv == nil {
		t.Fatal("the store doesn't hold the app's private key")
	}
	if _, err := c.StoreKey("not a key"); err == nil {
		t.Fatal("a store key for nothing")
	}
}

// ---- the app's OpenSSH key (ios OpenSSH.ed25519), as a Go stand-in for the tests ----------------------------------

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
