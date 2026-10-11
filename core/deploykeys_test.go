package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
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

func deployKey(t *testing.T, c *Core, p *phone, action, repo string, sensitive bool) (map[string]any, error) {
	t.Helper()
	b, err := c.DeployKeyBegin(action, repo, sensitive)
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

func TestDeployKeySensitivity(t *testing.T) {
	c, _, p := deployKeyCore(t)
	// Jarvis 2's own repo is sensitive whatever the request says
	m, err := deployKey(t, c, p, "add", "DE0CH/jarvis2", false)
	if err != nil || m["sensitive"] != true || c.notSensitive["github-jarvis2"] {
		t.Fatal("github-jarvis2 came out not sensitive", m, err)
	}
	// asked for: sensitive
	if m, _ := deployKey(t, c, p, "add", "DE0CH/private-thing", true); m["sensitive"] != true {
		t.Fatal(m)
	}
	// an existing sensitive store stays sensitive on a re-add that doesn't ask for it
	if m, _ := deployKey(t, c, p, "add", "DE0CH/private-thing", false); m["sensitive"] != true || c.notSensitive["github-private-thing"] {
		t.Fatal("a re-add downgraded a sensitive store")
	}
	// the begin document says so before the phone signs
	b, _ := c.DeployKeyBegin("add", "DE0CH/jarvis2", false)
	var bd deployKeyBegin
	json.Unmarshal([]byte(b.Payload), &bd)
	if !bd.Sensitive || !bd.Replaces || bd.Store != "github-jarvis2" || bd.TokenStore != DeployKeyTokenStore {
		t.Fatalf("begin: %+v", bd)
	}
}

func TestDeployKeyNeedsThePhone(t *testing.T) {
	c, g, p := deployKeyCore(t)
	other := newPhone()
	// another key's signature
	b, _ := c.DeployKeyBegin("add", "DE0CH/x", false)
	id, s, _ := p.answerDeployKey(t, b)
	if _, err := c.DeployKeyFinish(id, s, other.sign(b.Payload)); err == nil {
		t.Fatal("another key's signature was accepted")
	}
	if _, err := c.DeployKeyFinish(id, s, p.sign(b.Payload)); err == nil {
		t.Fatal("a pending was usable twice")
	}
	// the phone's signature over ANOTHER begin document (the router swapping requests)
	b1, _ := c.DeployKeyBegin("add", "DE0CH/x", false)
	b2, _ := c.DeployKeyBegin("add", "DE0CH/y", false)
	id2, s2 := p.share(b2)
	if _, err := c.DeployKeyFinish(id2, s2, p.sign(b1.Payload)); err == nil {
		t.Fatal("a signature over another request was accepted")
	}
	// another phone's share
	b3, _ := c.DeployKeyBegin("add", "DE0CH/x", false)
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
	if _, err := c.DeployKeyBegin("add", "DE0CH/x", false); err == nil || !strings.Contains(err.Error(), DeployKeyTokenStore) {
		t.Fatal("began without the token store:", err)
	}
	pl(t)(c.WriteStore(writeStore(t, c, p, DeployKeyTokenStore, map[string]string{"OTHER": "x"})))
	if _, err := deployKey(t, c, p, "add", "DE0CH/x", false); err == nil || !strings.Contains(err.Error(), DeployKeyTokenKey) {
		t.Fatal("a token store without the token:", err)
	}
	for _, bad := range []string{"", "x", "DE0CH/", "/x", "DE0CH/a/b", "DE0CH/..", "DE0CH/deploy-keys", "-x/y", "DE0CH/a b", "DE0CH/."} {
		if _, err := c.DeployKeyBegin("add", bad, false); err == nil {
			t.Fatalf("repo %q accepted", bad)
		}
	}
	if _, err := c.DeployKeyBegin("rotate", "DE0CH/x", false); err == nil {
		t.Fatal("an unknown action")
	}
	empty, _, _ := newCore(t)
	if _, err := empty.DeployKeyBegin("add", "DE0CH/x", false); err == nil {
		t.Fatal("an empty core began")
	}
}

func TestDeployKeyTokenWithoutAdministration(t *testing.T) {
	c, g, p := deployKeyCore(t)
	g.refuse["DE0CH/x"] = true
	_, err := deployKey(t, c, p, "add", "DE0CH/x", false)
	if err == nil || !strings.Contains(err.Error(), `"Administration: read and write"`) {
		t.Fatal("no permission message:", err)
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
	_ = ecdh.P256
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
		_, err := c.DeployKeyBegin(action, "foo/bar", false)
		if e, ok := err.(*Err); !ok || e.Status != 409 || !strings.Contains(err.Error(), "store github-foo-bar belongs to DE0CH/foo-bar") {
			t.Fatalf("%s for a colliding repo: %v", action, err)
		}
	}
	// a begin taken before the store was owned is refused at finish, before GitHub
	c2, g2, p2 := deployKeyCore(t)
	early, _ := c2.DeployKeyBegin("add", "DE0CH/My-Repo", false)
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
	if b, err := c.DeployKeyBegin("add", "DE0CH/china-train", false); err != nil || !strings.Contains(b.Payload, `"replaces":true`) {
		t.Fatal(err)
	}
}

// a Recover keeps each deploy-key store's owner: derived from the store's own GITHUB_DEPLOY_REPO_* value
func TestDeployKeyRecoverKeepsTheOwner(t *testing.T) {
	c, _, master := newCore(t)
	p := newPhone()
	rb := recoverBundle("fly-secret")
	rb.Stores = append(rb.Stores,
		storeData{Name: "github-foo-bar", Values: map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_FOO_BAR": "DE0CH/foo-bar", "GITHUB_DEPLOY_KEY_DE0CH_FOO_BAR": "x"}},
		// a value that doesn't name this store's repo, or two repos, make no owner
		storeData{Name: "github-odd", Values: map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_OTHER": "DE0CH/other"}},
		storeData{Name: "github-two", Values: map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_TWO": "DE0CH/two", "GITHUB_DEPLOY_REPO_TWO_X": "two/x"}},
		storeData{Name: DeployKeyTokenStore, Values: map[string]string{DeployKeyTokenKey: "gh-admin-token"}})
	s, sig, b := claimFor(c, master, p, rb)
	pl(t)(c.Claim(s, sig, b))
	c.github = newTestGitHub()
	if len(c.repoOwner) != 1 || c.repoOwner["github-foo-bar"] != "DE0CH/foo-bar" {
		t.Fatalf("owners after Recover: %v", c.repoOwner)
	}
	if _, err := c.DeployKeyBegin("add", "foo/bar", false); err == nil || !strings.Contains(err.Error(), "belongs to DE0CH/foo-bar") {
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
