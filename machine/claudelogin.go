package main

// The Claude login: one OAuth pair shared by every Claude session, kept and refreshed by the router
// (router/claudelogin.go; Jarvis 1 reads it from there too). A session whose cert names the store `claude` takes
// the pair at boot over the signed /m channel and keeps in step for the machine's life (credsSync, its own
// process): a long poll that answers with a newer pair, or with "a refresh is coming" — then credsSync takes
// the CLI's own refresh lock (~/.claude/.oauth_refresh.lock, lessons/74) until the new pair is written, so a
// claude process that gets a 401 in between waits and adopts it instead of burning its refresh token.
//
// The router's pair is taken whatever its account (DECISIONS 116, Deyao 2026-10-14): a Re-login to another Claude
// account reaches every running and new session within a minute, with no store write and no grant. When the pair
// on disk belongs to another account than the router's, the router's wins even if it expires sooner, the account
// record (~/.claude.json oauthAccount) is handed to the supervisor (~/.claude/.account-switch.json, merged at the
// host's next start), and the claude host is restarted as soon as it is idle, so its Remote Control comes up under
// the new account (a running host keeps the account it connected with).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

var (
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

// localAccount: the account of the login on this machine: a switch the host hasn't started under yet, else
// ~/.claude.json's; "" = not known
func localAccount() string {
	if b, err := os.ReadFile(switchPath()); err == nil {
		return recordAccount(string(b))
	}
	home, _ := os.UserHomeDir()
	b, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	return recordAccount(string(b))
}

func switchPath() string { return filepath.Join(filepath.Dir(credsPath()), ".account-switch.json") }

// takeRouterPair: write the router's pair; one for another account than this machine's always wins, and returns
// switched (its account record is then left for the supervisor: ~/.claude/.account-switch.json)
func takeRouterPair(l routerLogin) (took, switched bool, err error) {
	ra, la := recordAccount(l.Account), localAccount()
	if ra == "" || la == "" || ra == la {
		took, err = takeIfLater([]byte(l.Credentials))
		return took, false, err
	}
	if err = writeAtomic(switchPath(), []byte(l.Account)); err != nil {
		return false, false, err
	}
	return true, true, writeAtomic(credsPath(), []byte(l.Credentials))
}

// fetchLogin: one poll; the path is signed as every /m call, the query (numbers only) travels beside it as on the
// session API proxy (apiproxy.go)
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
func sessionClaudeLogin(c *client, stores []string) string {
	if !slices.Contains(stores, "claude") {
		return ""
	}
	var l routerLogin
	var err error
	for i := 0; i < 3; i++ { // a short retry: the harness starts right after, logged in or not (credsSync catches up)
		if l, err = fetchLogin(c, 0, 0, 0); err == nil && l.Credentials == "" {
			err = errors.New("the router holds no Claude login")
		}
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Printf("claude login: at boot: %v (credsSync keeps trying)", err)
		startCredsSync()
		return ""
	}
	// the host hasn't started: its ~/.claude.json takes the account now (the entrypoint merges CLAUDE_ACCOUNT too)
	if recordAccount(l.Account) != "" && recordAccount(l.Account) != localAccount() {
		if err := mergeAccount(l.Account); err != nil {
			log.Printf("claude login: ~/.claude.json: %v", err)
		}
	}
	switch took, werr := takeIfLater([]byte(l.Credentials)); {
	case werr != nil:
		log.Printf("claude login: writing the credentials file: %v", werr)
	case took:
		log.Printf("claude login: took the router's pair at boot")
	default:
		log.Printf("claude login: the pair here expires as late or later; kept")
	}
	startCredsSync()
	return l.Account
}

// mergeAccount: the account record's keys (oauthAccount, userID) into ~/.claude.json, the rest kept
func mergeAccount(account string) error {
	var rec map[string]any
	if err := json.Unmarshal([]byte(account), &rec); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, ".claude.json")
	cur := map[string]any{}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &cur)
	}
	for k, v := range rec {
		cur[k] = v
	}
	b, _ := json.Marshal(cur)
	return writeAtomic(p, b)
}

// startCredsSync: credsSync in its own process (`jarvis2-machine creds-sync`) for the machine's life; a var so
// tests don't start one
var startCredsSync = func() {
	cmd := exec.Command("/proc/self/exe", "creds-sync")
	home, _ := os.UserHomeDir()
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // outlives the exec into Jarvis 1's entrypoint
	if err := cmd.Start(); err != nil {
		log.Printf("claude login: credsSync: %v", err)
		return
	}
	log.Printf("claude login: credsSync running (long poll on the router)")
}

// writeAtomic: 0600, through a rename
func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	return true, writeAtomic(credsPath(), creds)
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
	c, err := newClient()
	if err != nil {
		log.Printf("claude login: credsSync can't run: %v", err)
		return
	}
	s := &syncer{c: c}
	if _, err := os.Stat(switchPath()); err == nil {
		go restartHostWhenIdle() // a switch left by an earlier credsSync whose host never got restarted
	}
	for {
		if err := s.step(); err != nil {
			log.Printf("claude login: %v", err)
			time.Sleep(credsRetry)
		}
	}
}

type syncer struct {
	c         *client
	pushed    []byte    // the content last pushed or taken
	routerAcc string    // the account of the router's login, from its last answer
	restarter bool      // restartHostWhenIdle is running
	lockGen   int64     // the router's refresh this machine holds the CLI lock for (0: none)
	lockedAt  time.Time // when it took it
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
	have := expiresAt(local)
	if la := localAccount(); s.routerAcc != "" && la != "" && s.routerAcc != la {
		have = 0 // the router holds another account's login: asked for whatever its expiry
	}
	l, err := fetchLogin(s.c, have, s.lockGen, credsPollWait)
	if err != nil {
		return fmt.Errorf("poll: %w", err)
	}
	s.routerAcc = recordAccount(l.Account)
	switch {
	case l.Credentials != "" && l.ExpiresAt > have:
		took, switched, err := takeRouterPair(l)
		s.release() // after the write: a claude process waiting on the lock re-reads the file and adopts the pair
		if err != nil {
			return fmt.Errorf("writing the credentials file: %w", err)
		}
		if took {
			s.pushed = []byte(l.Credentials)
			log.Printf("claude login: took the router's newer pair")
		}
		if switched {
			log.Printf("claude login: the router's login is another Claude account: the host restarts under it once idle")
			if !s.restarter {
				s.restarter = true
				go func() { restartHostWhenIdle(); s.restarter = false }()
			}
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

// ---- an account switch: restart the host -------------------------------------------------------------------------

var (
	hostIdlePoll = 5 * time.Second
	killHost     = func() error { return exec.Command("tmux", "kill-session", "-t", "claude").Run() }
)

// hostState: the Remote Control host's status and pid from claude's own session registry (~/.claude/sessions/*.json,
// what the supervisor and the dashboard read); "" = no host
func hostState() (status string, pid int) {
	home, _ := os.UserHomeDir()
	files, _ := filepath.Glob(filepath.Join(home, ".claude", "sessions", "*.json"))
	for _, f := range files {
		var e struct {
			Status          string `json:"status"`
			Pid             int    `json:"pid"`
			BridgeSessionID string `json:"bridgeSessionId"`
		}
		b, err := os.ReadFile(f)
		if err != nil || json.Unmarshal(b, &e) != nil || e.BridgeSessionID == "" || e.Pid == 0 {
			continue
		}
		if syscall.Kill(e.Pid, 0) != nil {
			continue // a dead host's leftover entry
		}
		return e.Status, e.Pid
	}
	return "", 0
}

// restartHostWhenIdle: once the host is idle (no turn, no background shell: "shell" means some are running) on two
// polls in a row, kill its tmux session; the supervisor's watchdog relaunches it (--resume, the same conversation)
// and its start() merges the switch file into ~/.claude.json. Returns when the switch is merged or there is no host
// to restart (the next start merges it).
func restartHostWhenIdle() {
	idle := 0
	killed := 0
	for {
		if _, err := os.Stat(switchPath()); err != nil {
			return // merged by the supervisor's start()
		}
		status, pid := hostState()
		switch {
		case pid == 0:
			if killed == 0 {
				return
			}
		case pid == killed:
			// still exiting
		case status == "idle":
			if idle++; idle >= 2 {
				log.Printf("claude login: restarting the idle host (pid %d) under the new Claude account", pid)
				if err := killHost(); err != nil {
					log.Printf("claude login: restarting the host: %v", err)
				}
				killed, idle = pid, 0
			}
		default:
			idle = 0
		}
		time.Sleep(hostIdlePoll)
	}
}
