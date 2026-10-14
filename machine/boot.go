package main

// The guard (docs/DESIGN.md "Target design", "The guard"): the session machine's entry point and its one long-lived
// process. At boot it checks the chain the router presents, restores only the snapshot the source names, reads the
// start settings from the source, takes its grant and pulls the secrets with it, then starts the harness as its child
// and serves, for the machine's life, everything that comes in over the signed /m channel (commandLoop): the grant
// (one at a time), shell commands under it, content-free "pull", "snapshot", "free" and "claude-prepare" commands, and
// content-free "X is due" signals for the session's own wakeups, crons and watches. Screen, status, memory, repo
// changes, live transcripts and the snapshot only go out.
//
// What it trusts: the roster and the spawner's key from the machine's Fly config (only the spawner's Fly token creates
// machines in the app, and it sets them), the kernel's signatures checked against that roster, its own keys, and its
// clock. The router only carries.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

type guard struct {
	c      *client
	roster kernel.Roster
	me     kernel.Object // this machine with its keys
	now    func() time.Time

	// fixed at boot
	source    kernel.Object // the source the spawner started this machine from
	fromPhone bool          // the source was made by the phone out of the sink (a new session, or a phone-approved restart)
	st        Settings
	ex        FormatExceptions

	rec       *records
	grantPath string

	mu  sync.Mutex
	cur *current // the one grant held

	secretsMu   sync.Mutex
	lastSecrets map[string]string // the flat env of the last pull

	login loginState // claudelogin.go

	harnessPid atomic.Int64
	ready      atomic.Bool // the chain, the settings and the snapshot are done: grants and commands may be judged
}

// BootChain: GET /m/boot (docs/API-grants.md)
type BootChain struct {
	Spawn  kernel.NotarizedCert `json:"spawn"`  // (source, this machine, ⊤) by the spawner
	Source kernel.NotarizedCert `json:"source"` // the cert the source came out of: (sink, source) by the phone, or (M, source) by the spawner
}

// checkBoot: the chain, checked against the roster. The spawn cert is the spawner's, notarized, from a source to this
// machine with its keys; the source cert is notarized and ends in exactly that source (image, settings and snapshot
// hash compared whole) and came out of the sink (signed by the phone or root) or out of a killed machine (signed by
// the spawner or root); the image this machine runs is the source's. → the source, and whether the phone made it.
func checkBoot(r kernel.Roster, me kernel.Object, chain BootChain, imageRef string) (kernel.Object, bool, error) {
	s, err := kernel.OpenNotarized(r, chain.Spawn)
	if err != nil {
		return kernel.Object{}, false, fmt.Errorf("the spawn cert: %v", err)
	}
	if s.Signer != kernel.RoleSpawner || s.Predecessor.Kind() != kernel.KindSource {
		return kernel.Object{}, false, errors.New("the spawn cert isn't the spawner's, from a source")
	}
	if s.Successor != me {
		return kernel.Object{}, false, fmt.Errorf("the spawn cert is for %s, not this machine with its keys", s.Successor.ID)
	}
	src := s.Predecessor
	o, err := kernel.OpenNotarized(r, chain.Source)
	if err != nil {
		return kernel.Object{}, false, fmt.Errorf("the source's cert: %v", err)
	}
	if o.Successor != src {
		return kernel.Object{}, false, errors.New("the source's cert ends in another source (or other image, settings or snapshot)")
	}
	fromPhone := false
	switch o.Predecessor.Kind() {
	case kernel.KindSink:
		if o.Signer != kernel.RolePhone && o.Signer != kernel.RoleRoot {
			return kernel.Object{}, false, errors.New("a source out of the sink is the phone's (or root's)")
		}
		fromPhone = true
	case kernel.KindMachine:
		if o.Signer != kernel.RoleSpawner && o.Signer != kernel.RoleRoot {
			return kernel.Object{}, false, errors.New("a source out of a machine is the spawner's kill (or root's)")
		}
	default:
		return kernel.Object{}, false, errors.New("the source came out of neither the sink nor a machine")
	}
	if imageRef != "" {
		if d := digestOf(imageRef); d == "" || d != digestOf(src.Image) {
			return kernel.Object{}, false, fmt.Errorf("this machine runs %s, the source names %s", imageRef, src.Image)
		}
	}
	return src, fromPhone, nil
}

// digestOf: the sha256:… digest at the end of an image reference ("" when there is none)
func digestOf(ref string) string {
	i := strings.LastIndex(ref, "@sha256:")
	if i < 0 || !sha256RE.MatchString(ref[i+len("@sha256:"):]) {
		return ""
	}
	return ref[i+1:]
}

// ---- boot ---------------------------------------------------------------------------------------------

// runGuard: after init asked boot to go on. Returns only on a failed check (the machine then starts nothing).
func runGuard() error {
	r, err := parseRoster(os.Getenv(rosterEnv), strings.TrimSpace(os.Getenv(spawnerKeyEnv)))
	if err != nil {
		return err
	}
	rb, _ := json.Marshal(r)
	if err := os.WriteFile(rosterPath, rb, 0o644); err != nil {
		return err
	}
	keys, err := ownKeys()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	g := &guard{c: c, roster: r, now: time.Now, rec: newRecords(home), grantPath: grantPath,
		me: kernel.Object{ID: os.Getenv("FLY_MACHINE_ID"), SigningKey: keys["signingKey"], EncryptionKey: keys["encryptionKey"]}}
	os.Remove(bootedPath)
	os.Remove(grantPath)
	// the command loop first: a pause or destroy never waits on a machine still booting (until bootedPath exists a
	// snapshot command gets "nothing to snapshot")
	go g.commandLoop()
	return g.boot()
}

func (g *guard) boot() error {
	if err := bootUntilHarness(g); err != nil {
		return err
	}
	return g.startHarness()
}

// bootUntilHarness: the checks and what they let in — the chain, the settings, the snapshot, the grant, the secrets
func bootUntilHarness(g *guard) error {
	// 1. the chain: the spawn cert and the source's own cert
	var chain BootChain
	for i := 0; ; i++ {
		err := g.c.json("GET", "/m/boot", nil, &chain)
		if err == nil {
			break
		}
		if i > 300 {
			return fmt.Errorf("no boot chain: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	src, fromPhone, err := checkBoot(g.roster, g.me, chain, os.Getenv("FLY_IMAGE_REF"))
	if err != nil {
		return err
	}
	st, err := parseSettings(src.Settings)
	if err != nil {
		return err
	}
	g.source, g.fromPhone, g.st = src, fromPhone, st
	g.ex = fetchExceptions(g.c)
	writeRunInfo(g)
	log.Printf("boot chain ok: source %s (made by the %s), session %s, harness %s, mode %s", src.ID,
		map[bool]string{true: "phone", false: "spawner's kill"}[fromPhone], st.Session, st.Harness, st.PermissionMode)

	// 2. the snapshot the source names: exactly that one, or nothing starts
	if src.Snapshot != "" {
		if err := restoreSnapshot(g, src.Snapshot); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if fromPhone {
			if st.Rollback != "" { // rollback.go: only one the phone approved, on the verified snapshot
				applyRollback(st.Rollback)
			}
			if st.Prompt != "" { // the supervisor types the approved prompt into the restored conversation
				os.Remove(filepath.Join(homeDir(), ".claude", ".first-prompt-sent"))
			}
		}
	} else if fromPhone {
		os.Remove(g.rec.path) // a new session starts with no records
	}
	g.ready.Store(true)

	// 3. the grant, then the secrets pulled with it (a store still locked: retried for 10 minutes, the router shows
	// which; once unlocked later, the router's "pull" brings it)
	for g.grant() == nil {
		var out struct {
			Grant *kernel.SignedDoc `json:"grant"`
		}
		if err := g.c.json("GET", "/m/grant", nil, &out); err == nil && out.Grant != nil {
			if err := g.acceptGrant(*out.Grant); err != nil {
				log.Printf("grant refused: %v", err)
			}
		}
		if g.grant() == nil {
			time.Sleep(2 * time.Second)
		}
	}
	for i := 0; ; i++ {
		ans, err := g.pullAndApply(true)
		if err == nil && len(ans.Locked) == 0 {
			break
		}
		if i >= 120 {
			log.Printf("secrets: starting with what was served (%v)", err)
			break
		}
		if i%12 == 0 {
			log.Printf("secrets: waiting (locked %v, error %v)", ans.Locked, err)
		}
		time.Sleep(5 * time.Second)
	}
	return nil
}

// startHarness: the repos, the booted marker, the reporters, then the harness (or the task) as the guard's child
func (g *guard) startHarness() error {
	st, src, fromPhone := g.st, g.source, g.fromPhone
	secrets := g.secrets()
	sj, _ := json.Marshal(secrets)

	// 4. repos: the settings' (or the deploy-key stores'), over SSH with their deploy keys
	cloneRepos(reposToClone(st, secrets))
	placeImportedTranscripts() // jarvis1import.go
	rearmJarvis1(g)            // jarvis1import.go

	// 5. booted: snapshots are real from now on; the reporters, the local API and the live sync start
	if err := os.WriteFile(bootedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644); err != nil {
		return fmt.Errorf("booted marker: %w", err)
	}
	go statusReporter(g.c)
	go memoryReporter(g.c)
	go screenReporter(g.c)
	go serveAPIProxy(g)
	go liveSync(g)
	go g.login.pushLoop(g)

	clean := os.Environ() // already the clean env (ensureCleanEnv)
	if t, ok := strings.CutPrefix(st.Harness, taskHarnessPrefix); ok {
		for _, kv := range taskEnv(st, g.ex) { // task.go reads these from the process env
			k, val, _ := strings.Cut(kv, "=")
			os.Setenv(k, val)
		}
		runTask(g.c, t, secrets, st.PermissionMode) // never returns
	}
	env := harnessEnv(clean, st, g.ex, fromPhone, string(sj), secrets)
	if b, err := os.ReadFile(filepath.Join(homeDir(), ".session-secret-conflicts.json")); err == nil {
		env = append(env, "SESSION_SECRET_CONFLICTS="+string(b)) // the entrypoint writes it back (it clears the file first)
	}
	if fromPhone && src.Snapshot == "" && len(st.Attachments) > 0 {
		env = append(env, fetchAttachments(g.c, st.Attachments)...) // attachments.go: hash-checked against the settings
	}
	waitAPIProxy(15 * time.Second)
	return g.runHarness(env)
}

// runHarness: Jarvis 1's entrypoint as the guard's child, for the machine's life
func (g *guard) runHarness(env []string) error {
	log.Printf("starting the harness")
	cmd := exec.Command(baseEntry)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("harness: %w", err)
	}
	g.harnessPid.Store(int64(cmd.Process.Pid))
	err := cmd.Wait()
	log.Printf("the harness exited (%v); the guard keeps serving", err)
	select {}
}

// secrets: the flat env of the last pull
func (g *guard) secrets() map[string]string {
	g.secretsMu.Lock()
	defer g.secretsMu.Unlock()
	return maps.Clone(g.lastSecrets)
}

// ---- the command loop ---------------------------------------------------------------------------------------

// Commands: GET /m/commands (docs/API-grants.md), decoded strictly: an unknown field refuses the whole answer, so a
// router that sends two grants (a list) or anything the guard doesn't know has nothing taken from it
type Commands struct {
	Commands []string          `json:"commands"`
	Grant    *kernel.SignedDoc `json:"grant"`
	Shell    []ShellRequest    `json:"shell"`
	Due      []Due             `json:"due"`
	Notices  []Notice          `json:"notices"`
}

func decodeCommands(b []byte) (Commands, error) {
	var out Commands
	if err := strictUnmarshal(b, &out); err != nil {
		return out, fmt.Errorf("the router's commands: %w", err)
	}
	return out, nil
}

// commandLoop: the machine's one reader of the router's commands, for its whole life
func (g *guard) commandLoop() {
	for {
		b, _, status, err := g.c.raw("GET", "/m/commands", nil)
		if err != nil || status != 200 {
			time.Sleep(5 * time.Second)
			continue
		}
		cmds, err := decodeCommands(b)
		if err != nil {
			log.Printf("%v: nothing taken", err)
			time.Sleep(time.Second)
			continue
		}
		g.handle(cmds)
	}
}

// handle: one answer of /m/commands. The grant first (the commands after it run under it). Before the chain and the
// settings are checked only content-free commands are taken (a snapshot asked while booting).
func (g *guard) handle(cmds Commands) {
	if !g.ready.Load() {
		if cmds.Grant != nil || len(cmds.Shell)+len(cmds.Due)+len(cmds.Notices) > 0 {
			log.Printf("commands: still booting; the grant, shell, due and notices are not taken yet")
		}
		for _, cmd := range cmds.Commands {
			if cmd == "snapshot" {
				g.command(cmd)
			}
		}
		return
	}
	if cmds.Grant != nil {
		if changed, err := g.takeGrant(*cmds.Grant); err != nil {
			log.Printf("grant refused: %v", err)
		} else if changed && booted() {
			go g.pullQuiet()
		}
	}
	for _, r := range cmds.Shell {
		go g.runShell(r)
	}
	for _, d := range cmds.Due {
		go g.runDue(d)
	}
	for _, n := range cmds.Notices {
		go g.runNotice(n)
	}
	for _, cmd := range cmds.Commands {
		g.command(cmd)
	}
}

// command: a content-free word with fixed behaviour; anything else is refused (false)
func (g *guard) command(cmd string) bool {
	switch {
	case cmd == "snapshot":
		if !booted() {
			if err := noSnapshot(g.c); err != nil {
				log.Printf("answering the snapshot while booting: %v", err)
			}
		} else if err := uploadSnapshot(g.c); err != nil {
			log.Printf("snapshot failed: %v", err)
		}
	case cmd == "free":
		if booted() && !frozen.Load() { // memory.go: an Upgrade, before its snapshot
			freeMemory(int(g.harnessPid.Load()))
		}
	case cmd == "pull":
		if booted() {
			go g.pullQuiet()
		}
	case strings.HasPrefix(cmd, "claude-prepare:"):
		go g.login.prepare(g, strings.TrimPrefix(cmd, "claude-prepare:"))
	default:
		log.Printf("command %q refused: not one this guard knows", cmd)
		return false
	}
	return true
}

func booted() bool { _, err := os.Stat(bootedPath); return err == nil }

// writeRunInfo: what the CLI subcommands (stores, put-key) read about this session
func writeRunInfo(g *guard) {
	b, _ := json.Marshal(map[string]any{"session": g.st.Session, "liveSyncSeconds": g.ex.LiveSyncSeconds})
	os.WriteFile(runInfoPath, b, 0o644)
}

func homeDir() string { h, _ := os.UserHomeDir(); return h }
