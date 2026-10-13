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
	"strconv"
	"strings"
	"sync"
	"testing"
)

func pairJSON(exp int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"a%d","refreshToken":"r%d","expiresAt":%d}}`, exp, exp, exp)
}

// fakeLoginRouter: the router's /m/claude-login and Anthropic's profile endpoint (each access token "a<exp>"
// belongs to acct-1 unless other[exp])
type fakeLoginRouter struct {
	mu      sync.Mutex
	srv     *httptest.Server
	answers []routerLogin // served in turn, the last one repeated
	polls   []string      // the query of each poll
	pushes  []string
	other   map[int64]bool
}

func newFakeLoginRouter(t *testing.T) (*fakeLoginRouter, *client) {
	f := &fakeLoginRouter{other: map[int64]bool{}}
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
		case req.URL.Path == "/profile":
			exp, _ := strconv.ParseInt(strings.TrimPrefix(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), "a"), 10, 64)
			acct := "acct-1"
			if f.other[exp] {
				acct = "acct-evil"
			}
			json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"uuid": acct}})
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
	old := profileURL
	profileURL = f.srv.URL + "/profile"
	t.Cleanup(func() { profileURL = old })
	return f, &client{base: f.srv.URL, me: "m1", sig: key.k, http: f.srv.Client()}
}

const acctRecord = `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"x"}}`

// a new session's Claude login comes from the router at boot, checked against the store's account: no grant
func TestSessionClaudeLoginAtBoot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	f.answers = []routerLogin{{Credentials: pairJSON(2000), Account: acctRecord, ExpiresAt: 2000}}
	oldStart := startCredsSync
	defer func() { startCredsSync = oldStart }()
	started := ""
	startCredsSync = func(want string) { started = want }

	if acct := sessionClaudeLogin(c, map[string]string{"CLAUDE_ACCOUNT_UUID": "acct-1"}, []string{"default"}); acct != "" || started != "" {
		t.Fatal("no claude store in the cert: nothing to do")
	}
	if acct := sessionClaudeLogin(c, map[string]string{}, []string{"claude"}); acct != "" || started != "" {
		t.Fatal("no account to check against: no login")
	}
	acct := sessionClaudeLogin(c, map[string]string{"CLAUDE_ACCOUNT_UUID": "acct-1"}, []string{"claude"})
	if started != "acct-1" || !strings.Contains(acct, "acct-1") {
		t.Fatalf("started %q account %q", started, acct)
	}
	b, err := os.ReadFile(credsPath())
	if err != nil || expiresAt(b) != 2000 {
		t.Fatalf("credentials file: %v %s", err, b)
	}
	if fi, _ := os.Stat(credsPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// a resumed pair that expires later is kept
	os.WriteFile(credsPath(), []byte(pairJSON(3000)), 0o600)
	sessionClaudeLogin(c, map[string]string{"CLAUDE_ACCOUNT_UUID": "acct-1"}, []string{"claude"})
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 3000 {
		t.Fatalf("a later pair was replaced: %s", b)
	}
	// a resume whose carried store predates CLAUDE_ACCOUNT_UUID: the account in the restored ~/.claude.json
	home, _ := os.UserHomeDir()
	os.WriteFile(home+"/.claude.json", []byte(acctRecord), 0o600)
	started = ""
	sessionClaudeLogin(c, map[string]string{"JARVIS1_CREDENTIALS_ID": "old"}, []string{"claude"})
	if started != "acct-1" {
		t.Fatal("the snapshot's account wasn't used", started)
	}
}

// the router hands another account's pair: refused, nothing written
func TestSessionClaudeLoginRefusesOtherAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	f.other[2000] = true
	f.answers = []routerLogin{{Credentials: pairJSON(2000), Account: `{"oauthAccount":{"accountUuid":"acct-evil"}}`, ExpiresAt: 2000}}
	oldStart := startCredsSync
	defer func() { startCredsSync = oldStart }()
	startCredsSync = func(string) {}
	if acct := sessionClaudeLogin(c, map[string]string{"CLAUDE_ACCOUNT_UUID": "acct-1"}, []string{"claude"}); acct != "" {
		t.Fatal("another account's record was passed on")
	}
	if _, err := os.Stat(credsPath()); err == nil {
		t.Fatal("another account's pair was written")
	}
	s := &syncer{c: c, want: "acct-1"}
	if err := s.step(); err == nil || s.refused != 2000 {
		t.Fatal("credsSync must refuse it too", err)
	}
	if _, err := os.Stat(credsPath()); err == nil {
		t.Fatal("written by credsSync")
	}
	f.answers = []routerLogin{{ExpiresAt: 2000}}
	s.step()
	if !strings.Contains(f.polls[len(f.polls)-1], "have=2000") {
		t.Fatal("the refused pair is asked for again", f.polls)
	}
}

// lessons/74 on the machine: a refresh notice takes the CLI's lock and acknowledges; the new pair is written, then the
// lock released; a failed refresh releases it
func TestCredsSyncLockProtocol(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f, c := newFakeLoginRouter(t)
	os.MkdirAll(home(t)+"/.claude", 0o700)
	os.WriteFile(credsPath(), []byte(pairJSON(1000)), 0o600)
	s := &syncer{c: c, want: "acct-1", pushed: []byte(pairJSON(1000))}

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
