package main

// Against real GitHub, only when asked: JARVIS2_LIVE_GITHUB_TOKEN_FILE (a token with Administration on the
// repo) and JARVIS2_LIVE_REPO (a throwaway repo it may write). The core makes the key through the phone flow,
// git clones and pushes over SSH with exactly that key, another repo refuses it, and remove takes it away.
//
//	JARVIS2_LIVE_GITHUB_TOKEN_FILE=~/.jarvis2/gh-deploy-keys.token JARVIS2_LIVE_REPO=DE0CH/jarvis2-deploykey-test \
//	JARVIS2_LIVE_OTHER_REPO=DE0CH/claude-env go test -run Live -v

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveDeployKeyOnGitHub(t *testing.T) {
	tf, repo := os.Getenv("JARVIS2_LIVE_GITHUB_TOKEN_FILE"), os.Getenv("JARVIS2_LIVE_REPO")
	if tf == "" || repo == "" {
		t.Skip("set JARVIS2_LIVE_GITHUB_TOKEN_FILE and JARVIS2_LIVE_REPO to run against GitHub")
	}
	if strings.HasPrefix(tf, "~/") {
		home, _ := os.UserHomeDir()
		tf = filepath.Join(home, tf[2:])
	}
	tok, err := os.ReadFile(tf)
	if err != nil {
		t.Fatal(err)
	}
	c, _, p := setup(t)
	c.github = newGitHubAPI()
	pl(t)(c.WriteStore(writeStore(t, c, p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: strings.TrimSpace(string(tok))})))
	m, err := deployKey(t, c, p, "add", repo, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("added: %v", m["fingerprint"])
	store := RepoStore(repo)
	v := storeValues(t, c, p, store)
	pem, _ := b64.DecodeString(v[DeployKeyPrefix+EnvSlug(repo)])
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	os.WriteFile(key, pem, 0o600)
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, []byte("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"), 0o644)
	sshCmd := "ssh -i " + key + " -o IdentitiesOnly=yes -o UserKnownHostsFile=" + kh + " -o StrictHostKeyChecking=yes"
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+sshCmd, "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	wt := filepath.Join(dir, "wt")
	if out, err := git("clone", "-q", "git@github.com:"+repo+".git", wt); err != nil {
		t.Fatal("clone with the deploy key:", out)
	}
	os.WriteFile(filepath.Join(wt, "probe.txt"), []byte(m["fingerprint"].(string)+"\n"), 0o644)
	git("-C", wt, "add", "probe.txt")
	git("-C", wt, "-c", "user.name=jarvis2-test", "-c", "user.email=test@jarvis2.invalid", "commit", "-qm", "deploy key probe")
	if out, err := git("-C", wt, "push", "-q", "origin", "HEAD"); err != nil {
		t.Fatal("push with the deploy key:", out)
	}
	if other := os.Getenv("JARVIS2_LIVE_OTHER_REPO"); other != "" {
		if out, err := git("ls-remote", "git@github.com:"+other+".git"); err == nil {
			t.Fatal("the key reached another repo:", out)
		}
	}
	if m, err := deployKey(t, c, p, "remove", repo, false); err != nil || m["deleted"] != float64(1) {
		t.Fatal(m, err)
	}
	if out, err := git("ls-remote", "git@github.com:"+repo+".git"); err == nil {
		t.Fatal("the removed key still works:", out)
	}
}
