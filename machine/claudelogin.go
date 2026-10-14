package main

// The Claude login (docs/DESIGN.md "Secrets": the Claude login is the `claude` store). One OAuth pair is shared by every
// Claude session; the router keeps and refreshes it and writes it into the store `claude` as two keys:
//
//	CLAUDE_CREDENTIALS  the exact contents of ~/.claude/.credentials.json ({"claudeAiOauth":{…,"expiresAt":…}})
//	CLAUDE_ACCOUNT      the account record (~/.claude.json's {"oauthAccount":{…},"userID":…})
//
// then sends "pull" to every running machine whose grant names the store. After each pull the guard takes the pair
// (apply): one for the same account only when it expires later than the file here; one for another account always,
// with the account record handed to the supervisor (~/.claude/.account-switch.json, merged at the host's next start)
// and the claude host restarted as soon as it is idle, so its Remote Control comes up under the new account.
//
// The refresh handshake is content-free: the router sends "claude-prepare:<gen>"; the guard takes the CLI's own
// refresh lock (~/.claude/.oauth_refresh.lock, lessons/74) and answers POST /m/claude-ack {gen}; the router refreshes,
// writes the store and sends "pull"; the pull's apply writes the new pair and releases the lock (a lock held
// lockHoldMax without a pair is released). A pair the CLI here refreshed by itself goes out (POST /m/claude-push):
// output only, the router decides whether to write it to the store.

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"
)

var (
	lockHoldMax   = 45 * time.Second // a lock held for a refresh that never answered is released (the CLI's own stale limit is 60 s)
	loginPushPoll = 30 * time.Second
	genRE         = regexp.MustCompile(`^[0-9]{1,19}$`)
)

// loginState: the guard's side of the shared login
type loginState struct {
	mu        sync.Mutex
	known     string // the pair last taken from the store or pushed
	lockGen   string // the router's refresh this machine holds the CLI lock for ("": none)
	lockedAt  time.Time
	restarter bool
}

// apply: after a pull, the `claude` store's pair (when the grant served it). atBoot: the host hasn't started, so
// another account's record goes straight into ~/.claude.json.
func (l *loginState) apply(secrets map[string]string, atBoot bool) {
	creds, account := secrets["CLAUDE_CREDENTIALS"], secrets["CLAUDE_ACCOUNT"]
	l.mu.Lock()
	defer l.mu.Unlock()
	if creds == "" {
		return
	}
	if atBoot && recordAccount(account) != "" && recordAccount(account) != localAccount() {
		if err := mergeAccount(account); err != nil {
			log.Printf("claude login: ~/.claude.json: %v", err)
		}
	}
	took, switched, err := takeStorePair(creds, account)
	if err != nil {
		log.Printf("claude login: writing the credentials file: %v", err)
		return
	}
	if took {
		l.known = creds
		l.releaseLocked() // after the write: a claude process waiting on the lock re-reads the file and adopts the pair
		log.Printf("claude login: took the store's pair")
	} else if l.known == "" {
		l.known = creds
	}
	if switched && !atBoot && !l.restarter {
		log.Printf("claude login: the store's login is another Claude account: the host restarts under it once idle")
		l.restarter = true
		go func() {
			restartHostWhenIdle()
			l.mu.Lock()
			l.restarter = false
			l.mu.Unlock()
		}()
	}
}

// releaseLocked: the CLI lock, if this machine holds one for a refresh (l.mu held)
func (l *loginState) releaseLocked() {
	if l.lockGen != "" {
		releaseLock()
		l.lockGen = ""
	}
}

// prepare: "claude-prepare:<gen>" — take the CLI's refresh lock, acknowledge, and release it after lockHoldMax if no
// pair came (a claude process refreshing right now holds it: acknowledged anyway, its lock left alone)
func (l *loginState) prepare(g *guard, gen string) {
	if !genRE.MatchString(gen) {
		log.Printf("claude login: refused prepare %q: not a generation number", gen)
		return
	}
	l.mu.Lock()
	l.releaseLocked()
	if takeLock() == "locked" {
		l.lockGen = gen
	} else {
		l.lockGen = ""
	}
	l.lockedAt = time.Now()
	l.mu.Unlock()
	if err := g.c.json("POST", "/m/claude-ack", map[string]string{"gen": gen}, nil); err != nil {
		log.Printf("claude login: ack %s: %v", gen, err)
	}
	time.Sleep(lockHoldMax)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lockGen == gen && time.Since(l.lockedAt) >= lockHoldMax {
		log.Printf("claude login: no pair %s after the refresh notice: lock released", lockHoldMax)
		l.releaseLocked()
	}
}

// pushLoop: a pair the CLI here refreshed by itself goes to the router (output), for the machine's life
func (l *loginState) pushLoop(g *guard) {
	for ; ; time.Sleep(loginPushPoll) {
		l.pushOnce(g)
	}
}

func (l *loginState) pushOnce(g *guard) {
	local, err := os.ReadFile(credsPath())
	l.mu.Lock()
	if err != nil || len(local) == 0 || l.known == "" || string(local) == l.known || l.lockGen != "" {
		l.mu.Unlock()
		return
	}
	l.known = string(local)
	l.mu.Unlock()
	if err := g.c.json("POST", "/m/claude-push", map[string]string{"credentials": string(local)}, nil); err != nil {
		log.Printf("claude login: push: %v", err)
	}
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

// takeStorePair: write the store's pair; one for another account than this machine's always wins, and returns
// switched (its account record is then left for the supervisor: ~/.claude/.account-switch.json)
func takeStorePair(creds, account string) (took, switched bool, err error) {
	ra, la := recordAccount(account), localAccount()
	if ra == "" || la == "" || ra == la {
		took, err = takeIfLater([]byte(creds))
		return took, false, err
	}
	if err = writeAtomic(switchPath(), []byte(account)); err != nil {
		return false, false, err
	}
	return true, true, writeAtomic(credsPath(), []byte(creds))
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
