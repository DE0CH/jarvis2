package main

// The Claude login: one OAuth pair shared by every Claude session, kept and refreshed by the router
// (router/claudelogin.go; Jarvis 1 reads it from there too). A session whose cert names the store `claude` takes
// the pair at boot over the signed /m channel and keeps in step for the machine's life (credsSync, its own
// process): a long poll that answers with a newer pair, or with "a refresh is coming" — then credsSync takes
// the CLI's own refresh lock (~/.claude/.oauth_refresh.lock, lessons/74) until the new pair is written, so a
// claude process that gets a 401 in between waits and adopts it instead of burning its refresh token.
//
// The router is not trusted to pick the account (DESIGN "Inputs to a machine": the login decides whose Claude
// app reaches this session through Remote Control). So every pair is checked before it is written: Anthropic's
// profile endpoint (a trusted provider over TLS) must name the account the store vouches for
// (CLAUDE_ACCOUNT_UUID, written by the setup session; else the account in the ~/.claude.json the predecessor's
// signed snapshot restored). A pair for any other account is refused; the router can only withhold the login.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

var (
	profileURL    = "https://api.anthropic.com/api/oauth/profile" // the store may name a stand-in (the end-to-end test)
	credsPollWait = 50 * time.Second
	credsRetry    = 10 * time.Second
	lockHoldMax   = 45 * time.Second // a lock held for a refresh that never answered is released (the CLI's own stale limit is 60 s)
)

type routerLogin struct {
	Credentials string `json:"credentials"`
	Account     string `json:"account"`
	ExpiresAt   int64  `json:"expiresAt"`
	Gen         int64  `json:"gen"`
	Preparing   bool   `json:"preparing"`
}

func credsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", ".credentials.json")
}

func expiresAt(raw []byte) int64 {
	var d struct {
		O struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	json.Unmarshal(raw, &d)
	return d.O.ExpiresAt
}

func accessToken(raw []byte) string {
	var d struct {
		O struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	json.Unmarshal(raw, &d)
	return d.O.AccessToken
}

func recordAccount(account string) string {
	var d struct {
		O struct {
			UUID string `json:"accountUuid"`
		} `json:"oauthAccount"`
	}
	json.Unmarshal([]byte(account), &d)
	return d.O.UUID
}

// expectedAccount: the Claude account this machine accepts a login for — the store's CLAUDE_ACCOUNT_UUID, else the
// account recorded in ~/.claude.json (restored from the predecessor's signed snapshot); "" = none, no login
func expectedAccount(secrets map[string]string) string {
	if a := strings.TrimSpace(secrets["CLAUDE_ACCOUNT_UUID"]); a != "" {
		return a
	}
	home, _ := os.UserHomeDir()
	b, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	return recordAccount(string(b))
}

// pairAccount: the account Anthropic says the pair's access token belongs to
func pairAccount(creds []byte) (string, error) {
	tok := accessToken(creds)
	if tok == "" {
		return "", errors.New("the pair has no access token")
	}
	req, _ := http.NewRequest("GET", profileURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("User-Agent", "jarvis2-machine/1")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("profile: HTTP %d", resp.StatusCode)
	}
	var p struct {
		Account struct {
			UUID string `json:"uuid"`
		} `json:"account"`
	}
	if json.Unmarshal(b, &p) != nil || p.Account.UUID == "" {
		return "", errors.New("profile: no account")
	}
	return p.Account.UUID, nil
}

func checkPair(creds []byte, want string) error {
	got, err := pairAccount(creds)
	if err != nil {
		return fmt.Errorf("checking the pair's account: %w", err)
	}
	if got != want {
		return errors.New("the router's pair belongs to another Claude account than this session's store vouches for: refused")
	}
	return nil
}

// fetchLogin: one poll; the path is signed as every /m call, the query (numbers only) travels beside it as on the
// session API proxy (apiproxy.go), and what comes back is checked against Anthropic before it is used
func fetchLogin(c *client, have, ack int64, wait time.Duration) (routerLogin, error) {
	var l routerLogin
	status, _, b, err := c.signedDo("GET", "/m/claude-login", "/m/claude-login", fmt.Sprintf("have=%d&ack=%d&wait=%d", have, ack, int(wait.Seconds())), nil, "")
	if err != nil {
		return l, err
	}
	if status != 200 {
		return l, fmt.Errorf("GET /m/claude-login: HTTP %d", status)
	}
	return l, json.Unmarshal(b, &l)
}

// sessionClaudeLogin: a session's first Claude login, at boot, before the harness starts (Deyao, 2026-10-11: a new
// session logs in by itself, no grant, no Face ID). Returns the account record (~/.claude.json oauthAccount) for
// CLAUDE_ACCOUNT, "" when there is none.
func sessionClaudeLogin(c *client, secrets map[string]string, stores []string) string {
	if !slices.Contains(stores, "claude") {
		return ""
	}
	if u := secrets["CLAUDE_PROFILE_URL"]; strings.HasPrefix(u, "https://") {
		profileURL = u // a stand-in named by the store itself (vouched like the rest of it): the end-to-end test's
	}
	want := expectedAccount(secrets)
	if want == "" {
		log.Printf("claude login: no account to check the router's pair against (the store claude has no CLAUDE_ACCOUNT_UUID): no login")
		return ""
	}
	var account string
	var err error
	for i := 0; i < 3; i++ { // a short retry: the harness starts right after, logged in or not (credsSync catches up)
		var l routerLogin
		if l, err = fetchLogin(c, 0, 0, 0); err == nil && l.Credentials == "" {
			err = errors.New("the router holds no Claude login")
		}
		if err == nil {
			if err = checkPair([]byte(l.Credentials), want); err == nil {
				if recordAccount(l.Account) == want {
					account = l.Account
				}
				switch took, werr := takeIfLater([]byte(l.Credentials)); {
				case werr != nil:
					log.Printf("claude login: writing the credentials file: %v", werr)
				case took:
					log.Printf("claude login: took the router's pair at boot")
				default:
					log.Printf("claude login: the pair here expires as late or later; kept")
				}
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Printf("claude login: at boot: %v (credsSync keeps trying)", err)
	}
	startCredsSync(want)
	return account
}

// startCredsSync: credsSync in its own process (`jarvis2-machine creds-sync`) for the machine's life; a var so
// tests don't start one
var startCredsSync = func(want string) {
	cmd := exec.Command("/proc/self/exe", "creds-sync")
	home, _ := os.UserHomeDir()
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "CLAUDE_ACCOUNT_UUID=" + want, "CLAUDE_PROFILE_URL=" + profileURL}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // outlives the exec into Jarvis 1's entrypoint
	if err := cmd.Start(); err != nil {
		log.Printf("claude login: credsSync: %v", err)
		return
	}
	log.Printf("claude login: credsSync running (long poll on the router)")
}

// takeIfLater: write the pair unless the file here already expires as late or later; atomic, 0600
func takeIfLater(creds []byte) (bool, error) {
	ne := expiresAt(creds)
	if ne == 0 {
		return false, errors.New("the pair has no expiresAt")
	}
	if cur, err := os.ReadFile(credsPath()); err == nil && expiresAt(cur) >= ne {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(credsPath()), 0o700); err != nil {
		return false, err
	}
	tmp := credsPath() + ".new"
	if err := os.WriteFile(tmp, creds, 0o600); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, credsPath())
}

// ---- the CLI's refresh lock (Jarvis 1's LOCK_PY / UNLOCK_PY, lib/claudelogin.js) ----------------------------------

func lockDir() string { return filepath.Join(filepath.Dir(credsPath()), ".oauth_refresh.lock") }
func lockMark() string {
	return filepath.Join(filepath.Dir(credsPath()), ".jarvis-refresh-lock")
}

type lockMarker struct {
	Ino   uint64 `json:"ino"`
	Mtime int64  `json:"mtime"`
}

func lockID(fi os.FileInfo) lockMarker {
	m := lockMarker{Mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		m.Ino = st.Ino
	}
	return m
}

// releaseLock: removes the lock only while it is still the one this machine made (a lock the CLI re-took after
// ours went stale has another inode or mtime)
func releaseLock() {
	b, err := os.ReadFile(lockMark())
	if err != nil {
		return
	}
	var m lockMarker
	json.Unmarshal(b, &m)
	if fi, err := os.Stat(lockDir()); err == nil && lockID(fi) == m {
		os.Remove(lockDir())
	}
	os.Remove(lockMark())
}

// takeLock: "locked", or "busy" (a claude process is refreshing right now)
func takeLock() string {
	releaseLock() // one left from an earlier run that never got its pair
	os.MkdirAll(filepath.Dir(lockDir()), 0o700)
	if err := os.Mkdir(lockDir(), 0o700); err != nil {
		return "busy"
	}
	fi, err := os.Stat(lockDir())
	if err != nil {
		return "busy"
	}
	b, _ := json.Marshal(lockID(fi))
	os.WriteFile(lockMark(), b, 0o600)
	return "locked"
}

// ---- credsSync ------------------------------------------------------------------------------------------------------

// credsSync: the machine's side of the router's login protocol, for the machine's life
func credsSync() {
	want := os.Getenv("CLAUDE_ACCOUNT_UUID")
	if u := os.Getenv("CLAUDE_PROFILE_URL"); strings.HasPrefix(u, "https://") {
		profileURL = u
	}
	c, err := newClient()
	if err != nil || want == "" {
		log.Printf("claude login: credsSync can't run (%v, account %q)", err, want)
		return
	}
	s := &syncer{c: c, want: want}
	for {
		if err := s.step(); err != nil {
			log.Printf("claude login: %v", err)
			time.Sleep(credsRetry)
		}
	}
}

type syncer struct {
	c        *client
	want     string
	pushed   []byte    // the content last pushed or taken
	refused  int64     // expiry of a pair refused by the account check: not asked for again
	lockGen  int64     // the router's refresh this machine holds the CLI lock for (0: none)
	lockedAt time.Time // when it took it
}

func (s *syncer) release() {
	if s.lockGen != 0 {
		releaseLock()
		s.lockGen = 0
	}
}

// step: push this machine's own newer pair (its claude refreshed by itself), then one long poll and its answer
func (s *syncer) step() error {
	local, _ := os.ReadFile(credsPath())
	if s.lockGen != 0 && time.Since(s.lockedAt) > lockHoldMax {
		log.Printf("claude login: no pair %s after the refresh notice: lock released", lockHoldMax)
		s.release()
	}
	if len(local) > 0 && !bytes.Equal(local, s.pushed) && s.lockGen == 0 {
		var out map[string]any
		if err := s.c.json("POST", "/m/claude-login", map[string]string{"credentials": string(local)}, &out); err != nil {
			log.Printf("claude login: push: %v", err)
		}
		s.pushed = local
	}
	have := max(expiresAt(local), s.refused)
	l, err := fetchLogin(s.c, have, s.lockGen, credsPollWait)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}
	switch {
	case l.Credentials != "" && l.ExpiresAt > have:
		if err := checkPair([]byte(l.Credentials), s.want); err != nil {
			s.release()
			s.refused = l.ExpiresAt
			return err
		}
		took, err := takeIfLater([]byte(l.Credentials))
		s.release() // after the write: a claude process waiting on the lock re-reads the file and adopts the pair
		if err != nil {
			return fmt.Errorf("writing the credentials file: %w", err)
		}
		if took {
			s.pushed = []byte(l.Credentials)
			log.Printf("claude login: took the router's newer pair")
		}
	case l.Preparing && l.Gen != s.lockGen:
		s.release()
		if took := takeLock(); took == "locked" {
			s.lockGen, s.lockedAt = l.Gen, time.Now()
		} else {
			// a claude process is refreshing right now (no marker of ours: release() leaves its lock alone);
			// acknowledge anyway so the router doesn't wait for us
			s.lockGen, s.lockedAt = l.Gen, time.Now()
		}
	case !l.Preparing && s.lockGen != 0:
		s.release() // the refresh is over (failed): the pair here stays
	}
	return nil
}
