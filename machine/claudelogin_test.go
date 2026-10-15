package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func pairJSON(exp int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"a%d","refreshToken":"r%d","expiresAt":%d}}`, exp, exp, exp)
}

// fakeLoginRouter: the router's /m/claude-login
type fakeLoginRouter struct {
	mu      sync.Mutex
	srv     *httptest.Server
	answers []routerLogin // served in turn, the last one repeated
	polls   []string      // the query of each poll
	pushes  []string
	none    bool // the session has no Claude account (404 noAccount)
}

func newFakeLoginRouter(t *testing.T) (*fakeLoginRouter, *client) {
	f := &fakeLoginRouter{}
	key := newKey()
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.HasPrefix(req.URL.Path, "/m/") { // signed as the router checks it (router/http.go requireMachine)
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			sum := sha256.Sum256(body)
			msg := req.Method + " " + req.URL.Path + " " + req.Header.Get("X-Time") + " " + hex.EncodeToString(sum[:])
			if !verify(key.pub(), []byte(msg), req.Header.Get("X-Sig")) {
				w.WriteHeader(401)
				return
			}
		}
		switch {
		case req.URL.Path == "/m/claude-login" && req.Method == "GET" && f.none:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"this session has no Claude account","noAccount":true}`))
		case req.URL.Path == "/m/claude-login" && req.Method == "GET":
			f.polls = append(f.polls, req.URL.RawQuery)
			a := f.answers[0]
			if len(f.answers) > 1 {
				f.answers = f.answers[1:]
			}
			json.NewEncoder(w).Encode(a)
		case req.URL.Path == "/m/claude-login" && req.Method == "POST":
			var b map[string]string
			json.NewDecoder(req.Body).Decode(&b)
			f.pushes = append(f.pushes, b["credentials"])
			w.Write([]byte(`{"stored":false}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f, &client{base: f.srv.URL, me: "m1", sig: key.k, http: f.srv.Client()}
}

const acctRecord = `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"x"}}`

const acct2Record = `{"oauthAccount":{"accountUuid":"acct-2","emailAddress":"y"},"userID":"u2"}`

// a new session's Claude login comes from the router at boot (its Claude account's), whatever the account: no grant,
// no store key; a session the router names no account for gets none
func TestSessionClaudeLoginAtBoot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	f.answers = []routerLogin{{Credentials: pairJSON(2000), Account: acctRecord, ExpiresAt: 2000}}
	oldStart := startCredsSync
	defer func() { startCredsSync = oldStart }()
	started := 0
	startCredsSync = func() { started++ }

	f.none = true
	if acct := sessionClaudeLogin(c); acct != "" || started != 0 {
		t.Fatal("no Claude account for the session: nothing to do")
	}
	if _, err := os.Stat(credsPath()); err == nil {
		t.Fatal("a session with no account got a credentials file")
	}
	f.none = false
	acct := sessionClaudeLogin(c)
	if started != 1 || !strings.Contains(acct, "acct-1") {
		t.Fatalf("started %d account %q", started, acct)
	}
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
	// a resumed pair of the same account that expires later is kept
	os.WriteFile(credsPath(), []byte(pairJSON(3000)), 0o600)
	sessionClaudeLogin(c)
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 3000 {
		t.Fatalf("a later pair was replaced: %s", b)
	}
	// a resume after a Re-login to another account: the restored ~/.claude.json takes the new account, other keys kept
	os.WriteFile(home(t)+"/.claude.json", []byte(`{"oauthAccount":{"accountUuid":"acct-1"},"projects":{"x":1}}`), 0o600)
	f.answers = []routerLogin{{Credentials: pairJSON(2500), Account: acct2Record, ExpiresAt: 2500}}
	sessionClaudeLogin(c)
	j, _ := os.ReadFile(home(t) + "/.claude.json")
	if localAccount() != "acct-2" || !strings.Contains(string(j), `"projects"`) || !strings.Contains(string(j), `"u2"`) {
		t.Fatalf("~/.claude.json: %s", j)
	}
}

// a Re-login to another account reaches a running machine: the router's pair wins even though the pair here (the old
// account's, refreshed by its own claude) expires later, and the switch is left for the supervisor
func TestCredsSyncAccountSwitch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(home(t)+"/.claude.json", []byte(acctRecord), 0o600)
	os.WriteFile(credsPath(), []byte(pairJSON(9000)), 0o600)
	oldKill, oldPoll := killHost, hostIdlePoll
	defer func() { killHost, hostIdlePoll = oldKill, oldPoll }()
	hostIdlePoll = 10 * time.Millisecond
	killHost = func() error { return nil } // no host registry here: nothing is killed
	s := &syncer{c: c, pushed: []byte(pairJSON(9000))}

	// the first answer only tells the router's account (its pair expires sooner than ours)
	f.answers = []routerLogin{{Account: acct2Record, ExpiresAt: 4000}, {Credentials: pairJSON(4000), Account: acct2Record, ExpiresAt: 4000}}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.polls[0], "have=9000") || !strings.Contains(f.polls[1], "have=0") {
		t.Fatalf("polls %v", f.polls)
	}
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 4000 {
		t.Fatalf("the other account's pair wasn't taken: %s", b)
	}
	if b, err := os.ReadFile(switchPath()); err != nil || recordAccount(string(b)) != "acct-2" {
		t.Fatalf("switch file: %v %s", err, b)
	}
	if localAccount() != "acct-2" {
		t.Fatal("the pending switch is this machine's account now")
	}
	// in step again: the usual expiry rule
	f.answers = []routerLogin{{Account: acct2Record, ExpiresAt: 4000}}
	s.step()
	if !strings.Contains(f.polls[2], "have=4000") {
		t.Fatalf("polls %v", f.polls)
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

// lessons/74 on the machine: a refresh notice takes the CLI's lock and acknowledges; the new pair is written, then the
// lock released; a failed refresh releases it
func TestCredsSyncLockProtocol(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(credsPath(), []byte(pairJSON(1000)), 0o600)
	s := &syncer{c: c, pushed: []byte(pairJSON(1000))}

	f.answers = []routerLogin{{ExpiresAt: 1000, Gen: 1, Preparing: true}}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if s.lockGen != 1 {
		t.Fatal("no lock taken")
	}
	if _, err := os.Stat(lockDir()); err != nil {
		t.Fatal("the CLI's lock dir isn't there")
	}
	f.answers = []routerLogin{{Credentials: pairJSON(5000), ExpiresAt: 5000, Gen: 1}}
	if err := s.step(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.polls[1], "ack=1") || !strings.Contains(f.polls[1], "have=1000") {
		t.Fatalf("the second poll must acknowledge: %v", f.polls)
	}
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 5000 {
		t.Fatal("the new pair wasn't written")
	}
	if _, err := os.Stat(lockDir()); err == nil || s.lockGen != 0 {
		t.Fatal("the lock wasn't released after the write")
	}
	if len(f.pushes) != 0 {
		t.Fatal("the router's own pair was pushed back", f.pushes)
	}
	// a failed refresh: preparing, then not preparing with no newer pair → released
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 2, Preparing: true}}
	s.step()
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 2}}
	s.step()
	if _, err := os.Stat(lockDir()); err == nil || s.lockGen != 0 {
		t.Fatal("a failed refresh left the lock")
	}
	// a lock the CLI holds (it is refreshing itself) is never removed by us
	os.Mkdir(lockDir(), 0o700)
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 3, Preparing: true}}
	s.step()
	f.answers = []routerLogin{{ExpiresAt: 5000, Gen: 3}}
	s.step()
	if _, err := os.Stat(lockDir()); err != nil {
		t.Fatal("the CLI's own lock was removed")
	}
	os.Remove(lockDir())
	// the session's claude refreshed by itself: its newer pair is pushed
	os.WriteFile(credsPath(), []byte(pairJSON(9000)), 0o600)
	f.answers = []routerLogin{{ExpiresAt: 5000}}
	s.step()
	if len(f.pushes) != 1 || expiresAt([]byte(f.pushes[0])) != 9000 {
		t.Fatal("the session's own refresh wasn't pushed", f.pushes)
	}
	// a lock held past lockHoldMax is released before the next poll (which then acknowledges nothing)
	f.answers = []routerLogin{{ExpiresAt: 9000, Gen: 4, Preparing: true}}
	s.step()
	if s.lockGen != 4 {
		t.Fatal("no lock for gen 4")
	}
	old := lockHoldMax
	lockHoldMax = 0
	defer func() { lockHoldMax = old }()
	f.answers = []routerLogin{{ExpiresAt: 9000}}
	s.step()
	if !strings.Contains(f.polls[len(f.polls)-1], "ack=0") || s.lockGen != 0 {
		t.Fatal("a stale lock wasn't released before the poll", f.polls[len(f.polls)-1])
	}
	if _, err := os.Stat(lockDir()); err == nil {
		t.Fatal("the stale lock is still there")
	}
}

func home(t *testing.T) string {
	h, _ := os.UserHomeDir()
	return h
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
