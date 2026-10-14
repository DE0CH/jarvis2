package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func pairJSON(exp int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"a%d","refreshToken":"r%d","expiresAt":%d}}`, exp, exp, exp)
}

const acctRecord = `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"x"}}`

const acct2Record = `{"oauthAccount":{"accountUuid":"acct-2","emailAddress":"y"},"userID":"u2"}`

func home(t *testing.T) string {
	h, _ := os.UserHomeDir()
	return h
}

// the Claude login comes from the claude store with the pull: at boot it is written, whatever its account
func TestClaudeLoginFromTheStore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var l loginState
	l.apply(map[string]string{"A": "1"}, true)
	if _, err := os.Stat(credsPath()); err == nil {
		t.Fatal("no claude store: nothing written")
	}
	l.apply(map[string]string{"CLAUDE_CREDENTIALS": pairJSON(2000), "CLAUDE_ACCOUNT": acctRecord}, true)
	b, err := os.ReadFile(credsPath())
	if err != nil || expiresAt(b) != 2000 {
		t.Fatalf("credentials file: %v %s", err, b)
	}
	if fi, _ := os.Stat(credsPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if localAccount() != "acct-1" {
		t.Fatal("~/.claude.json didn't take the account")
	}
	// a pair of the same account here that expires later is kept
	os.WriteFile(credsPath(), []byte(pairJSON(3000)), 0o600)
	l.apply(map[string]string{"CLAUDE_CREDENTIALS": pairJSON(2000), "CLAUDE_ACCOUNT": acctRecord}, true)
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 3000 {
		t.Fatalf("a later pair was replaced: %s", b)
	}
	// a resume after a Re-login to another account: the restored ~/.claude.json takes the new account, other keys kept
	os.WriteFile(home(t)+"/.claude.json", []byte(`{"oauthAccount":{"accountUuid":"acct-1"},"projects":{"x":1}}`), 0o600)
	l.apply(map[string]string{"CLAUDE_CREDENTIALS": pairJSON(2500), "CLAUDE_ACCOUNT": acct2Record}, true)
	j, _ := os.ReadFile(home(t) + "/.claude.json")
	if localAccount() != "acct-2" || !strings.Contains(string(j), `"projects"`) || !strings.Contains(string(j), `"u2"`) {
		t.Fatalf("~/.claude.json: %s", j)
	}
}

// a Re-login to another account reaches a running machine with the next pull: the store's pair wins even though the
// pair here expires later, and the switch is left for the supervisor (the host restarts once idle)
func TestClaudeLoginAccountSwitchWhileRunning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(home(t)+"/.claude.json", []byte(acctRecord), 0o600)
	os.WriteFile(credsPath(), []byte(pairJSON(9000)), 0o600)
	oldKill, oldPoll := killHost, hostIdlePoll
	defer func() { killHost, hostIdlePoll = oldKill, oldPoll }()
	hostIdlePoll = 10 * time.Millisecond
	killHost = func() error { return nil }
	var l loginState
	l.apply(map[string]string{"CLAUDE_CREDENTIALS": pairJSON(4000), "CLAUDE_ACCOUNT": acct2Record}, false)
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 4000 {
		t.Fatalf("the other account's pair wasn't taken: %s", b)
	}
	if b, err := os.ReadFile(switchPath()); err != nil || recordAccount(string(b)) != "acct-2" {
		t.Fatalf("switch file: %v %s", err, b)
	}
	if localAccount() != "acct-2" {
		t.Fatal("the pending switch is this machine's account now")
	}
}

// lessons/74 on the machine: "claude-prepare:<gen>" takes the CLI's lock and acknowledges; the new pair (with the next
// pull) is written, then the lock released; a lock held past lockHoldMax is released; the CLI's own lock is left alone
func TestClaudeRefreshLockProtocol(t *testing.T) {
	x := newWorld(t)
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(credsPath(), []byte(pairJSON(1000)), 0o600)
	acks := []string{}
	inner := x.srv.Config.Handler
	var mu sync.Mutex
	pushes := []string{}
	x.srv.Config.Handler = httpFunc(func(path string, body []byte) bool {
		mu.Lock()
		defer mu.Unlock()
		var m map[string]string
		json.Unmarshal(body, &m)
		switch path {
		case "/m/claude-ack":
			acks = append(acks, m["gen"])
			return true
		case "/m/claude-push":
			pushes = append(pushes, m["credentials"])
			return true
		}
		return false
	}, inner)
	old := lockHoldMax
	lockHoldMax = 50 * time.Millisecond
	defer func() { lockHoldMax = old }()
	l := &x.g.login
	l.known = pairJSON(1000)
	done := make(chan struct{})
	go func() { l.prepare(x.g, "7"); close(done) }()
	time.Sleep(10 * time.Millisecond)
	if _, err := os.Stat(lockDir()); err != nil {
		t.Fatal("the CLI's lock dir isn't there")
	}
	l.apply(map[string]string{"CLAUDE_CREDENTIALS": pairJSON(5000)}, false)
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 5000 {
		t.Fatal("the new pair wasn't written")
	}
	if _, err := os.Stat(lockDir()); err == nil {
		t.Fatal("the lock wasn't released after the write")
	}
	<-done
	if len(acks) != 1 || acks[0] != "7" {
		t.Fatalf("acks %v", acks)
	}
	// a refresh that never brings a pair: released after lockHoldMax
	l.prepare(x.g, "8")
	if _, err := os.Stat(lockDir()); err == nil {
		t.Fatal("a stale lock stayed")
	}
	// the CLI's own lock (it is refreshing itself) is never removed
	os.Mkdir(lockDir(), 0o700)
	l.prepare(x.g, "9")
	if _, err := os.Stat(lockDir()); err != nil {
		t.Fatal("the CLI's own lock was removed")
	}
	os.Remove(lockDir())
	// a malformed generation is refused (no lock, no ack)
	l.prepare(x.g, "9; rm -rf ~")
	if len(acks) != 3 {
		t.Fatalf("acks %v", acks)
	}
	// the session's claude refreshed by itself: its newer pair goes out, once
	os.WriteFile(credsPath(), []byte(pairJSON(9000)), 0o600)
	l.pushOnce(x.g)
	l.pushOnce(x.g)
	if len(pushes) != 1 || expiresAt([]byte(pushes[0])) != 9000 {
		t.Fatal("the session's own refresh wasn't pushed once", pushes)
	}
}

// the host is restarted only once idle, then the supervisor's start merges the switch
func TestRestartHostWhenIdle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	os.MkdirAll(home(t)+"/.claude/sessions", 0o700)
	reg := func(status string) {
		b, _ := json.Marshal(map[string]any{"status": status, "pid": os.Getpid(), "bridgeSessionId": "b1"})
		os.WriteFile(home(t)+"/.claude/sessions/1.json", b, 0o600)
	}
	oldKill, oldPoll := killHost, hostIdlePoll
	defer func() { killHost, hostIdlePoll = oldKill, oldPoll }()
	hostIdlePoll = 10 * time.Millisecond
	var mu sync.Mutex
	kills := 0
	killHost = func() error {
		mu.Lock()
		kills++
		mu.Unlock()
		os.Remove(home(t) + "/.claude/sessions/1.json")
		os.Remove(switchPath()) // the relaunched host's start() merges it
		return nil
	}
	if err := os.WriteFile(switchPath(), []byte(acct2Record), 0o600); err != nil {
		t.Fatal(err)
	}
	reg("busy")
	done := make(chan struct{})
	go func() { restartHostWhenIdle(); close(done) }()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if kills != 0 {
		t.Fatal("a busy host was restarted")
	}
	mu.Unlock()
	reg("shell")
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if kills != 0 {
		t.Fatal("a host with background shells was restarted")
	}
	mu.Unlock()
	reg("idle")
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("never restarted")
	}
	if kills != 1 {
		t.Fatal("kills", kills)
	}
	// no host at all: nothing to do, the next start merges it
	os.WriteFile(switchPath(), []byte(acct2Record), 0o600)
	restartHostWhenIdle()
	if kills != 1 {
		t.Fatal("killed with no host")
	}
}

func TestTakeIfLater(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if took, err := takeIfLater([]byte(`{}`)); took || err == nil {
		t.Fatal("a pair without expiresAt is refused")
	}
	if took, _ := takeIfLater([]byte(pairJSON(10))); !took {
		t.Fatal("no file: taken")
	}
	if took, _ := takeIfLater([]byte(pairJSON(10))); took {
		t.Fatal("same expiry: kept")
	}
	if took, _ := takeIfLater([]byte(pairJSON(11))); !took {
		t.Fatal("later: taken")
	}
}
