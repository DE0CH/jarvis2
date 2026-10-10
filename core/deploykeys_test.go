package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
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
	if strings.Contains(strings.Join(c.log, "\n"), g.token) {
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
