// jarvis2-machine: the session machine's side of Jarvis 2 (docs/DESIGN.md,
// "Machine side"). It is the image's entry point and its fixed init entry point:
//
//	jarvis2-machine boot       ENTRYPOINT: make the machine's key pairs, wait for init, then check the
//	                           succession cert, restore the predecessor's snapshot, pull the secrets and
//	                           hand over to Jarvis 1's entrypoint (the harness). Any failed check → start
//	                           nothing.
//	jarvis2-machine init       what the core runs through Fly exec (no arguments): asks boot to go on.
//	jarvis2-machine stores [--json]
//	                           every store and the key NAMES it holds (never a value), to know which store to
//	                           ask for (stores.go).
//	jarvis2-machine add-store <name>
//	                           asks Deyao to add one store to this session; on approval re-pulls the
//	                           secrets into ~/.secrets.
//
// It trusts only what it can check: the core's public key arrives through Fly exec (written by the core at
// start), the cert and the secrets are core-signed, and the predecessor's snapshot is signed by the
// predecessor's own key, taken from the predecessor's core-signed cert. The router only relays.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	dir         = "/run/jarvis2"
	keysPath    = dir + "/keys.json"    // public halves, printed by init for the core (through Fly exec)
	privPath    = dir + "/private.json" // private halves, never leave the machine
	coreKeyPath = dir + "/core-key"     // the core's key, from the machine's Fly config (the core set it)
	coreKeyEnv  = "JARVIS2_CORE_KEY"    // the core that created this machine puts its signing key here
	goPath      = dir + "/init-requested"
	certPath    = dir + "/cert.json"
	bootedPath  = dir + "/booted"      // written once the boot is done (cert, snapshot, secrets, repos): the harness starts next
	clientPath  = dir + "/client.json" // the router URL + this machine's id, for later commands
	baseEntry   = "/usr/local/bin/entrypoint.sh"
)

var b64 = base64.StdEncoding

type SignedDoc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

type Machine struct {
	ID            string `json:"id"`
	Image         string `json:"image"`
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
}

type Cert struct {
	Kind    string   `json:"kind"`
	PredID  string   `json:"predecessorId"`
	Machine *Machine `json:"machine"`
	Stores  []string `json:"stores"`
	Options struct {
		Harness        string `json:"harness"`
		PermissionMode string `json:"permissionMode"`
		Config         string `json:"config"` // the session's settings (vouch.go)
		Once           string `json:"once"`   // this machine's one-time inputs
	} `json:"options"`
	Phone     string `json:"phone"`
	Sensitive bool   `json:"sensitive"`
	Line      string `json:"line"`
	Snapshot  string `json:"snapshot"` // sha256 of the predecessor's snapshot, from the core's kill record
}

type private struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[jarvis2] ")
	if len(os.Args) < 2 {
		log.Fatal("usage: jarvis2-machine boot | init | stores [--json] | add-store <name> | await-store <name> | downgrade <store>… | --none | allow [<holder> <duration> | --remove <holder>]")
	}
	var err error
	switch os.Args[1] {
	case "boot":
		err = boot()
	case "init":
		err = initCmd()
	case "add-store":
		if len(os.Args) != 3 {
			log.Fatal("usage: jarvis2-machine add-store <name>")
		}
		err = addStore(os.Args[2])
	case "await-store": // after `jarvis2-request add-store`: no second ask, only the wait and the pull
		if len(os.Args) != 3 {
			log.Fatal("usage: jarvis2-machine await-store <name>")
		}
		err = awaitStore(os.Args[2])
	case "stores":
		err = storesCmd(os.Args[2:]) // stores.go
	case "downgrade":
		var keep []string
		if keep, err = downgradeArgs(os.Args[2:]); err == nil {
			err = downgrade(keep)
		}
	case "agent":
		err = agent()
	case "creds-sync":
		credsSync() // claudelogin.go: started by boot for a session with the `claude` store; never returns
	case "allow":
		err = allowCmd(os.Args[2:])
	case "allow-at-least":
		err = allowAtLeastCmd(os.Args[2:]) // apiproxy.go
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ---- boot -----------------------------------------------------------------------------------------

func boot() error {
	// first: the env this machine was started with is thrown away, except what the image, Fly and the core set
	// (vouch.go). Re-execs once.
	if err := ensureCleanEnv(); err != nil {
		log.Printf("REFUSING TO START: %v", err)
		select {}
	}
	if err := keygen(); err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	log.Printf("keys ready; waiting for init")
	for {
		if _, err := os.Stat(goPath); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err := prepare(); err != nil {
		// any failed check → start nothing; keep the machine up so the failure is visible in its log
		log.Printf("REFUSING TO START: %v", err)
		select {}
	}
	return nil // prepare execs the harness
}

// initCmd: the one command the core runs through Fly (no arguments). It prints this machine's public keys
// (the core binds them into the cert) and lets boot go on.
func initCmd() error {
	var b []byte
	var err error
	for i := 0; i < 60; i++ { // boot makes the keys first
		if b, err = os.ReadFile(keysPath); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("no keys yet: %w", err)
	}
	if err := os.WriteFile(goPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644); err != nil {
		return err
	}
	_, err = os.Stdout.Write(b)
	return err
}

func keygen() error {
	if err := sudo("install", "-d", "-o", "claude", "-m", "755", dir); err != nil {
		return err
	}
	enc, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sig, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	p, _ := json.Marshal(private{b64.EncodeToString(enc.Bytes()), b64.EncodeToString(sig.Bytes())})
	if err := os.WriteFile(privPath, p, 0o600); err != nil {
		return err
	}
	pub, _ := json.Marshal(map[string]string{"encryptionKey": b64.EncodeToString(enc.PublicKey().Bytes()), "signingKey": b64.EncodeToString(sig.PublicKey().Bytes())})
	return os.WriteFile(keysPath, pub, 0o644)
}

func sudo(args ...string) error {
	if os.Geteuid() == 0 {
		return exec.Command(args[0], args[1:]...).Run()
	}
	return exec.Command("sudo", append([]string{"-n"}, args...)...).Run()
}

func prepare() error {
	me := os.Getenv("FLY_MACHINE_ID")
	// the core: the one that created this machine. It sets its signing key in the machine's Fly config, and only
	// the core's Fly token (besides the setup session's org token) can create or change machines in this app —
	// the router's is read-only — so the key comes from the core through Fly, never from the router.
	coreKey := strings.TrimSpace(os.Getenv(coreKeyEnv))
	if coreKey == "" {
		return errors.New("no core key in the machine's config (" + coreKeyEnv + ")")
	}
	keys, err := ownKeys()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	// 0. the agent, first: it answers the router's commands at every stage of this machine's life, so a pause or
	// destroy never waits on a machine still booting (e.g. looping on a locked store): until bootedPath exists a
	// snapshot command gets "nothing to snapshot" (agent())
	os.Remove(bootedPath)
	agentCmd := exec.Command("/proc/self/exe", "agent")
	agentCmd.Stdout, agentCmd.Stderr = os.Stdout, os.Stderr
	agentCmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := agentCmd.Start(); err != nil {
		return fmt.Errorf("agent: %w", err)
	}

	// 1. this machine's succession cert: core-signed, naming this machine and its own keys
	var certs struct {
		Cert            *SignedDoc `json:"cert"`
		PredecessorCert *SignedDoc `json:"predecessorCert"`
	}
	for i := 0; ; i++ {
		err = c.json("GET", "/m/cert", nil, &certs)
		if err == nil && certs.Cert != nil {
			break
		}
		if i > 300 {
			return fmt.Errorf("no cert: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	if err := os.WriteFile(coreKeyPath, []byte(coreKey), 0o644); err != nil {
		return err
	}
	var cert Cert
	if err := verifyDoc(coreKey, certs.Cert, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil {
		return fmt.Errorf("the cert isn't a succession cert signed by the core (%v)", err)
	}
	if cert.Machine.ID != me || cert.Machine.EncryptionKey != keys["encryptionKey"] || cert.Machine.SigningKey != keys["signingKey"] {
		return errors.New("the cert names another machine or other keys")
	}
	raw, _ := json.Marshal(certs.Cert)
	os.WriteFile(certPath, raw, 0o644)
	log.Printf("cert ok: stores %v, harness %s, predecessor %q", cert.Stores, cert.Options.Harness, cert.PredID)

	v, err := vouch(cert) // vouch.go: what the cert vouches for
	if err != nil {
		return err
	}
	v.Ex = fetchExceptions(c) // the few router values whose format can't carry an instruction
	writeVouched(v)
	firstMachine := cert.PredID == ""

	// 2. the predecessor's snapshot: the one whose hash the cert names, signed by the predecessor
	if !firstMachine && cert.PredID != me {
		var pc Cert
		if err := verifyDoc(coreKey, certs.PredecessorCert, &pc); err != nil || pc.Kind != "succession-cert" || pc.Machine == nil || pc.Machine.ID != cert.PredID {
			return fmt.Errorf("the predecessor's cert isn't core-signed for %s (%v)", cert.PredID, err)
		}
		if cert.Snapshot != "" {
			predecessorKey = pc.Machine.SigningKey
			if err := restore(c, pc.Machine.SigningKey, v); err != nil {
				return fmt.Errorf("snapshot: %w", err)
			}
		} else if v.Config.Restore != nil {
			// a line whose machines never left a snapshot (an import stopped mid-way): the import its signed config
			// names again, Jarvis 1 imports only (restore.go reimportJarvis1)
			predecessorKey = pc.Machine.SigningKey
			if err := reimportJarvis1(c, v); err != nil {
				return fmt.Errorf("re-import: %w", err)
			}
		} else {
			log.Printf("the cert names no snapshot of %s: starting with no predecessor state", cert.PredID)
		}
		if v.Once.Rollback != "" { // rollback.go: only a rollback the phone approved, on the verified snapshot
			applyRollback(v.Once.Rollback)
		}
	}
	// 2b. a new line restoring a destroyed session's archived snapshot (restore.go): only the one the cert names
	if err := restoreArchived(c, coreKey, me, &cert, v); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	trustLineKeys(cert) // deliver.go: this line's signing keys, for what it asked to be delivered later

	// 3. the secrets, sealed to this machine's encryption key
	secrets, err := pullSecrets(c, coreKey, me)
	if err != nil {
		return err
	}
	sj, _ := json.Marshal(secrets)
	log.Printf("secrets ok: %d keys", len(secrets))

	// 4. repos: each repo's deploy key from its store (SSH, that repo only), then the clones the cert names
	if err := setupDeployKeys(secrets); err != nil {
		log.Printf("deploy keys: %v", err)
	}
	cloneRepos(reposToClone(v, secrets))
	placeImportedTranscripts()     // jarvis1import.go: an import's transcripts, under the working dir's project
	rearmJarvis1(c, sessionID(me)) // jarvis1import.go: its wakeups and crons, as this line's own requests

	// 5. booted: from now on a snapshot command gets a real snapshot; then Jarvis 1's entrypoint runs the harness
	if err := os.WriteFile(bootedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644); err != nil {
		return fmt.Errorf("booted marker: %w", err)
	}
	clean := os.Environ() // already the clean env (ensureCleanEnv)
	if t, ok := strings.CutPrefix(cert.Options.Harness, taskHarnessPrefix); ok {
		for _, kv := range taskVouchedEnv(v) { // task.go reads these from the process env
			k, val, _ := strings.Cut(kv, "=")
			os.Setenv(k, val)
		}
		runTask(c, t, secrets, certMode(cert)) // task.go: the template instead of a harness; never returns
	}
	// 6. the Claude login (claudelogin.go): the router's shared pair, checked against the store's account, kept in step
	if account := sessionClaudeLogin(c, secrets, cert.Stores); account != "" && secrets["CLAUDE_ACCOUNT"] == "" {
		secrets = maps.Clone(secrets)
		secrets["CLAUDE_ACCOUNT"] = account // Jarvis 1's entrypoint merges it into ~/.claude.json
	}
	env := harnessEnv(clean, v, me, firstMachine, string(sj), secrets)
	if !firstMachine && v.Once.Prompt != "" {
		home, _ := os.UserHomeDir()
		os.Remove(filepath.Join(home, ".claude", ".first-prompt-sent")) // the supervisor types the approved resume prompt
	}
	if firstMachine && len(v.Config.Attachments) > 0 {
		env = append(env, fetchAttachments(c, coreKey, v.Config.Attachments)...) // attachments.go: hash-checked against the cert
	}
	waitAPIProxy(15 * time.Second) // the entrypoint's first calls ($JARVIS_URL: content-sync pull) need it up
	log.Printf("starting the harness")
	return syscall.Exec(baseEntry, []string{baseEntry}, env)
}

// waitAPIProxy: the agent starts the local Jarvis API once bootedPath exists (agent(), polled every second); the
// harness's entrypoint calls it at once (content-sync pull), so wait until it accepts connections (at most d)
func waitAPIProxy(d time.Duration) {
	addr := os.Getenv("JARVIS2_API_ADDR")
	if addr == "" {
		addr = apiProxyAddr
	}
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			return
		}
	}
	log.Printf("the local Jarvis API on %s isn't up after %s: starting the harness anyway", addr, d)
}

func ownKeys() (map[string]string, error) {
	b, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	return m, json.Unmarshal(b, &m)
}

func readTrim(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", p)
	}
	return s, nil
}

// pullSecrets: the core seals the answer to this machine's encryption key, so it needs no other proof
func pullSecrets(c *client, coreKey, me string) (map[string]string, error) {
	var doc SignedDoc
	var lastErr error
	// a store may still be locked: the app shows which (the router notes the core's 423) and Deyao unlocks it on the
	// phone; the pull is retried every 2 s for 10 minutes, so the machine carries on within seconds of the unlock
	for i := 0; i < 300; i++ {
		if lastErr = c.json("POST", "/m/pull-secrets", map[string]string{}, &doc); lastErr == nil {
			break
		}
		if i%30 == 0 {
			log.Printf("pull secrets: %v (retrying)", lastErr)
		}
		time.Sleep(2 * time.Second)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("pull secrets: %w", lastErr)
	}
	var out struct {
		Kind    string `json:"kind"`
		Machine string `json:"machine"`
		Sealed  struct {
			E    string `json:"e"`
			Data string `json:"data"`
		} `json:"sealed"`
	}
	if err := verifyDoc(coreKey, &doc, &out); err != nil || out.Kind != "secrets" || out.Machine != me {
		return nil, fmt.Errorf("the secrets answer isn't core-signed for this machine (%v)", err)
	}
	priv, err := loadPrivate()
	if err != nil {
		return nil, err
	}
	plain, err := openSealed(priv.enc, out.Sealed.E, out.Sealed.Data, "jarvis2/secrets")
	if err != nil {
		return nil, fmt.Errorf("the secrets don't decrypt with this machine's key: %w", err)
	}
	m := map[string]string{}
	return m, json.Unmarshal(plain, &m)
}

// cloneRepos: the repos the cert names (reposToClone) into ~/workspace. A repo whose deploy key is in the session's
// stores goes over SSH with that key (setupDeployKeys has already written git's rewrites for its https URL); any
// other is cloned anonymously over HTTPS from GitHub (public repos only).
func cloneRepos(repos []string) {
	home, _ := os.UserHomeDir()
	for _, url := range repos {
		url = cloneURL(url)
		if url == "" {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(url), ".git")
		dst := filepath.Join(home, "workspace", name)
		if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
			continue // restored from the snapshot
		}
		cmd := exec.Command("git", "clone", "-q", "--", url, dst)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("clone %s failed: %s", name, strings.TrimSpace(string(out)))
			continue
		}
		log.Printf("cloned %s", name)
	}
}

// ---- snapshots ------------------------------------------------------------------------------------

// what a snapshot holds (relative to $HOME): the conversation, the work, the artefacts, and the OpenCode/Paseo and
// OpenClaw harnesses' own state (Paseo's daemon identity and pairings, OpenCode's sessions, the OpenClaw gateway's
// state and device pairings), so their apps stay paired across a pause, as in Jarvis 1 (its lib/archive.js)
var snapshotPaths = []string{".claude/projects", ".claude.json", ".claude/.first-prompt-sent", "workspace", "artifacts",
	".paseo", ".claude/.paseo-agent", ".local/share/opencode", ".openclaw",
	allowFile, changesFile, lineKeysFile, deliveredFile}

// snapshotSkip: what the snapshot leaves out under those roots (filepath.Match against the path relative to $HOME):
// the harnesses' logs, pid files, caches and downloaded binaries, which a successor rebuilds (Jarvis 1's excludes)
var snapshotSkip = []string{
	".paseo/models", ".paseo/runtime", ".paseo/paseo.pid", ".paseo/*.log", ".paseo/*.out", ".paseo/*.err",
	".local/share/opencode/log", ".local/share/opencode/bin",
	".openclaw/logs", ".openclaw/tmp", ".openclaw/*.out", ".openclaw/*.err", ".openclaw/.hold", ".openclaw/gateway.pid",
}

func skipInSnapshot(rel string) bool {
	for _, pat := range snapshotSkip {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
	}
	return false
}

// makeSnapshot: the snapshot as a tar.gz written to path (streamed: a workspace can be several GB) → its sha256
func makeSnapshot(path string) (string, int64, error) {
	home, _ := os.UserHomeDir()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	gz := gzip.NewWriter(cw)
	tw := tar.NewWriter(gz)
	for _, rel := range snapshotPaths {
		root := filepath.Join(home, rel)
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			name, _ := filepath.Rel(home, p)
			if skipInSnapshot(name) {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			link := ""
			if fi.Mode()&os.ModeSymlink != 0 {
				link, _ = os.Readlink(p)
			}
			h, err := tar.FileInfoHeader(fi, link)
			if err != nil {
				return nil
			}
			h.Name = name
			if fi.Mode().IsRegular() {
				f, err := os.Open(p)
				if err != nil {
					return nil
				}
				defer f.Close()
				if err := tw.WriteHeader(h); err != nil {
					return err
				}
				// a file that shrank while being read would break the archive: pad to the header's size
				n, err := io.Copy(tw, io.LimitReader(f, h.Size))
				if err == nil && n < h.Size {
					_, err = io.Copy(tw, io.LimitReader(zeros{}, h.Size-n))
				}
				return err
			}
			return tw.WriteHeader(h)
		})
		if err != nil {
			return "", 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return "", 0, err
	}
	if err := gz.Close(); err != nil {
		return "", 0, err
	}
	if err := f.Sync(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), cw.n, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// restore: the predecessor's snapshot. The cert names its hash (the core took it from the predecessor's signed
// kill): exactly that one, or nothing starts.
// predecessorTmp: where the predecessor's snapshot lands while it is checked (a var: tests move it)
var predecessorTmp = dir + "/predecessor.tar.gz"

func restore(c *client, predSigningKey string, v Vouched) error {
	tmp := predecessorTmp
	defer os.Remove(tmp)
	sum, hdr, err := c.download("/m/snapshot", tmp) // streamed to disk, hashed on the way
	if err != nil {
		return err
	}
	if sum != v.Cert.Snapshot {
		return errors.New("the snapshot isn't the one the cert names")
	}
	if !verify(predSigningKey, []byte(sum), hdr.Get("X-Snapshot-Sig")) {
		return errors.New("the snapshot isn't signed by the predecessor")
	}
	n, err := unpackFile(tmp)
	if err != nil {
		return err
	}
	log.Printf("restored the predecessor's snapshot (%d files)", n)
	return nil
}

// unpack: a snapshot (tar.gz relative to $HOME) into $HOME
func unpack(body []byte) (int, error) { return unpackReader(bytes.NewReader(body)) }

func unpackFile(p string) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return unpackReader(f)
}

func unpackReader(r io.Reader) (int, error) {
	home, _ := os.UserHomeDir()
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(gz)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		name := filepath.Clean(h.Name)
		if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			return n, fmt.Errorf("bad path in snapshot: %s", h.Name)
		}
		dst := filepath.Join(home, name)
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(dst, os.FileMode(h.Mode)|0o700)
		case tar.TypeSymlink:
			os.MkdirAll(filepath.Dir(dst), 0o755)
			os.Remove(dst)
			os.Symlink(h.Linkname, dst)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(dst), 0o755)
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode)&0o777)
			if err != nil {
				return n, err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return n, err
			}
			os.Chtimes(dst, h.ModTime, h.ModTime) // git's index keeps trusting unchanged files
			n++
		}
	}
	return n, nil
}

// ---- agent: the router's commands (pause = snapshot) -----------------------------------------------

// agent: started first thing at boot (prepare), it is the machine's one reader of the router's commands for its
// whole life. While the machine boots it answers a snapshot with "nothing to snapshot" (no workspace of its own yet:
// a resumed line's files are the predecessor's snapshot, which the router already holds); once booted it uploads
// real snapshots and starts the status reports (the router's sign that the machine got past boot), the local
// Jarvis API and the live transcript sync.
func agent() error {
	c, err := newClient()
	if err != nil {
		return err
	}
	go func() {
		for !booted() {
			time.Sleep(time.Second)
		}
		go statusReporter(c)
		go memoryReporter(c) // memory.go: RAM for the router's starvation watch
		go screenReporter(c) // screen.go: the pane for the read-only terminal
		go serveAPIProxy(c)  // apiproxy.go: $JARVIS_URL for Jarvis 1's session scripts
		go liveSync(c)       // livesync.go: the transcripts to the Storage Box (through the router) for search
	}()
	for {
		var out struct {
			Commands   []string   `json:"commands"`
			Execs      []Exec     `json:"execs"`
			Deliveries []Delivery `json:"deliveries"` // deliver.go: vouched, core-attested inputs
		}
		if err := c.json("GET", "/m/commands", nil, &out); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		for _, e := range out.Execs {
			go runExec(c, e)
		}
		for _, d := range out.Deliveries {
			go runDelivery(c, d)
		}
		for _, cmd := range out.Commands {
			if cmd == "free" && booted() && !frozen.Load() { // memory.go: an Upgrade, before its snapshot
				freeMemory()
				continue
			}
			if cmd == "snapshot" {
				if !booted() {
					if err := noSnapshot(c); err != nil {
						log.Printf("answering the snapshot while booting: %v", err)
					}
				} else if err := uploadSnapshot(c); err != nil {
					log.Printf("snapshot failed: %v", err)
				}
			}
		}
	}
}

func booted() bool { _, err := os.Stat(bootedPath); return err == nil }

// noSnapshot: the answer to a snapshot command while booting — nothing to snapshot, so the router kills at once
func noSnapshot(c *client) error {
	_, _, status, err := c.raw("POST", "/m/snapshot", nil, "X-Snapshot-None", "booting")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("HTTP %d", status)
	}
	log.Printf("snapshot asked while booting: answered nothing to snapshot")
	return nil
}

// The snapshot is this machine's LAST state (R1 audit, 2026-10-11): the router asks for one only to pause or destroy
// the machine, and the core fixes the snapshot its kill names as what the successor restores. So the machine signs
// exactly one in its life: before taking it, it stops every process of the session (SIGSTOP), so nothing changes
// after it, and a later snapshot command gets that same one again. A router that keeps an earlier signed snapshot
// therefore has none to keep, and can't roll a successor back to a state from before the session's last work.
var (
	finalSnapshot    = dir + "/final-snapshot.tar.gz"
	finalSnapshotSig = dir + "/final-snapshot.sig"
	// snapshotKey: the machine's current signing key (re-read: a downgrade changes it under the agent)
	snapshotKey = func() (*ecdh.PrivateKey, error) { p, err := loadPrivate(); return p.sig, err }
)

var frozen atomic.Bool // the session is stopped for its final snapshot: no execs, no deliveries

func notFrozen() error {
	if frozen.Load() {
		return errors.New("the session is stopped for its final snapshot")
	}
	return nil
}

// freezeSession: SIGSTOP to every process this user may signal except this one (kill(-1)); only on a Fly machine
var freezeSession = func() {
	if os.Getenv("FLY_MACHINE_ID") == "" {
		return
	}
	if err := syscall.Kill(-1, syscall.SIGSTOP); err != nil {
		log.Printf("freezing the session: %v", err)
	}
}

// finalSnapshotSum: the kept final snapshot's sha256 and signature ("" when there is none yet)
func finalSnapshotSum() (string, string, error) {
	sig, err := readTrim(finalSnapshotSig)
	if err != nil {
		return "", "", err
	}
	sum, err := readTrim(finalSnapshotSig + ".sha256")
	if err != nil {
		return "", "", err
	}
	return sum, sig, nil
}

func uploadSnapshot(c *client) error {
	sum, sig, err := finalSnapshotSum()
	if err != nil { // the first: freeze, take, sign, keep
		frozen.Store(true)
		freezeSession()
		writeChanges() // restore.go: the repos' state, for the router's uncommitted-work check
		if sum, _, err = makeSnapshot(finalSnapshot); err != nil {
			return err
		}
		key, err := snapshotKey()
		if err != nil {
			return err
		}
		if sig, err = sign(key, []byte(sum)); err != nil {
			return err
		}
		if err := os.WriteFile(finalSnapshotSig+".sha256", []byte(sum), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(finalSnapshotSig, []byte(sig), 0o600); err != nil {
			return err
		}
	}
	status, n, err := c.upload("/m/snapshot", finalSnapshot, sum, "X-Snapshot-Sig", sig)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("HTTP %d", status)
	}
	log.Printf("snapshot uploaded (%d bytes)", n)
	return nil
}

// ---- add a store ----------------------------------------------------------------------------------

func addStore(name string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.json("POST", "/m/add-store", map[string]string{"store": name}, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asked Deyao to add %s to this session (approval in the Jarvis 2 app)\n", name)
	return awaitStore(name)
}

// awaitStore: wait (up to 1 h) for a cert of this machine that holds the store, then pull the secrets. Also what
// `jarvis2-request add-store` runs after its request, which asks by itself (with a reason) and so must not ask again.
func awaitStore(name string) error {
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "waiting up to 1 h for %s (Deyao's approval in the Jarvis 2 app)\n", name)
	me := c.me
	deadline := time.Now().Add(time.Hour)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		if !hasStore(certStores(c, coreKey, me), name) {
			continue
		}
		n, err := refreshSecrets(func() error {
			doc, ok := newestCert(c, coreKey, me)
			if !ok {
				return errors.New("the router has no cert for this machine")
			}
			raw, _ := json.Marshal(doc)
			return os.WriteFile(certPath, raw, 0o644)
		}, func() (map[string]string, error) { return pullSecrets(c, coreKey, me) })
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "added %s: ~/.secrets rewritten (%d keys); run `set -a; . ~/.secrets; set +a` in a shell to load them\n", name, n)
		return nil
	}
	return errors.New("no approval within 1 h")
}

// newestCert: the router's cert for this machine, when it is core-signed for this machine and its current keys (read
// per call: a downgrade replaces them)
func newestCert(c *client, coreKey, me string) (*SignedDoc, bool) {
	var certs struct {
		Cert *SignedDoc `json:"cert"`
	}
	if c.json("GET", "/m/cert", nil, &certs) != nil || certs.Cert == nil {
		return nil, false
	}
	keys, _ := ownKeys()
	var cert Cert
	if verifyDoc(coreKey, certs.Cert, &cert) != nil || cert.Kind != "succession-cert" || cert.Machine == nil ||
		cert.Machine.ID != me || cert.Machine.SigningKey != keys["signingKey"] {
		return nil, false
	}
	return certs.Cert, true
}

func certStores(c *client, coreKey, me string) []string {
	doc, ok := newestCert(c, coreKey, me)
	if !ok {
		return nil
	}
	var cert Cert
	json.Unmarshal([]byte(doc.Payload), &cert)
	return cert.Stores
}

func hasStore(stores []string, name string) bool {
	for _, s := range stores {
		if s == name {
			return true
		}
	}
	return false
}

// secretsLockPath: one writer of ~/.secrets at a time (with the cert file and the deploy keys it implies)
func secretsLockPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".jarvis2-secrets.lock")
}

// withSecretsLock: run fn holding the machine-wide lock on ~/.secrets
func withSecretsLock(fn func() error) error {
	lock, err := os.OpenFile(secretsLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// refreshSecrets: under the lock, take the newest cert (prepare) and pull with it, then write ~/.secrets and the deploy
// keys. Two waiters (two add-stores approved together) used to pull and write side by side, and the slower one could
// write an older pull over a newer file; under the lock each pull happens after the previous write, from the router's
// newest cert at that moment, so the last file written is always the newest.
func refreshSecrets(prepare func() error, pull func() (map[string]string, error)) (int, error) {
	n := 0
	err := withSecretsLock(func() error {
		if err := prepare(); err != nil {
			return err
		}
		secrets, err := pull()
		if err != nil {
			return err
		}
		if err := writeSecrets(secrets); err != nil {
			return err
		}
		if err := setupDeployKeys(secrets); err != nil { // a repo's store: its key and rewrites now
			return err
		}
		n = len(secrets)
		return nil
	})
	return n, err
}

// downgradeArgs: the stores to keep. No names is refused rather than read as "keep none": a session that
// meant to drop one store once dropped all of them that way; dropping everything takes --none.
func downgradeArgs(args []string) ([]string, error) {
	if len(args) == 1 && args[0] == "--none" {
		return []string{}, nil
	}
	if len(args) == 0 {
		return nil, errors.New("name every store to KEEP (e.g. downgrade default github-claude-env); --none drops them all")
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return nil, fmt.Errorf("unknown option %s (store names only, or --none alone)", a)
		}
	}
	return args, nil
}

// downgrade: keep only the named stores, in place. A new key pair; the core's challenge signed with the old
// key; the new cert checked; only then the old keys and the secrets of the dropped stores are shredded (the
// old cert still pulls, but sealed to a key that no longer exists). Under the ~/.secrets lock, so an add-store's
// waiter neither pulls with the keys being replaced nor writes over the downgraded file; an add-store answered
// between the challenge and its answer makes the challenge stale (the core takes only the newest cert), and the
// downgrade starts again from the new cert, with a new key pair (nothing was kept from the stale try).
func downgrade(keep []string) error {
	return withSecretsLock(func() error {
		var err error
		for try := 0; try < 3; try++ {
			if err = downgradeOnce(keep); err == nil || !strings.Contains(err.Error(), "newest") {
				return err
			}
			log.Printf("downgrade: the cert changed meanwhile (%v); again from the newest", err)
		}
		return err
	})
}

func downgradeOnce(keep []string) error {
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	enc, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sig, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	encPub, sigPub := b64.EncodeToString(enc.PublicKey().Bytes()), b64.EncodeToString(sig.PublicKey().Bytes())
	sort.Strings(keep)
	if keep == nil {
		keep = []string{}
	}
	var begin struct {
		Challenge *SignedDoc `json:"challenge"`
	}
	if err := c.json("POST", "/m/downgrade", map[string]any{"stores": keep, "newEncryptionKey": encPub, "newSigningKey": sigPub}, &begin); err != nil {
		return err
	}
	if err := checkDowngradeChallenge(coreKey, begin.Challenge, c.me, encPub, sigPub, keep); err != nil {
		return err
	}
	signature, err := sign(c.sig, []byte(begin.Challenge.Payload))
	if err != nil {
		return err
	}
	var fin struct {
		Cert *SignedDoc `json:"cert"`
	}
	if err := c.json("POST", "/m/downgrade/finish", map[string]any{"challenge": begin.Challenge, "signature": signature}, &fin); err != nil {
		return err
	}
	cert, err := checkDowngradeCert(coreKey, fin.Cert, c.me, encPub, sigPub, keep)
	if err != nil {
		return err
	}
	// the new cert is in hand: switch to the new keys, shred the old ones, re-pull the remaining secrets
	p, _ := json.Marshal(private{b64.EncodeToString(enc.Bytes()), b64.EncodeToString(sig.Bytes())})
	if err := shredWrite(privPath, p, 0o600); err != nil {
		return err
	}
	addLineKey(sigPub) // deliver.go: what this machine asks for from now on is signed with the new key
	pub, _ := json.Marshal(map[string]string{"encryptionKey": encPub, "signingKey": sigPub})
	os.WriteFile(keysPath, pub, 0o644)
	raw, _ := json.Marshal(fin.Cert)
	os.WriteFile(certPath, raw, 0o644)
	c2, err := newClient()
	if err != nil {
		return err
	}
	secrets, err := pullSecrets(c2, coreKey, c.me)
	if err != nil {
		secrets = map[string]string{} // locked or empty: nothing kept
	}
	if err := writeSecrets(secrets); err != nil {
		return err
	}
	if err := setupDeployKeys(secrets); err != nil { // a dropped repo store's key and rewrites go
		return err
	}
	fmt.Fprintf(os.Stderr, "downgraded to %v: old keys shredded, ~/.secrets rewritten (%d keys). Values already loaded in running processes stay there until they exit.\n", cert.Stores, len(secrets))
	return nil
}

// checkDowngradeChallenge: what the old key signs is a core-signed downgrade of this machine to its new keys,
// keeping exactly the stores asked for (the router chooses the challenge's list: R1 audit)
func checkDowngradeChallenge(coreKey string, d *SignedDoc, me, encPub, sigPub string, keep []string) error {
	var ch struct {
		Kind    string `json:"kind"`
		Request struct {
			Downgrade bool     `json:"downgrade"`
			Machine   *Machine `json:"machine"`
			Stores    []string `json:"stores"`
		} `json:"request"`
	}
	if err := verifyDoc(coreKey, d, &ch); err != nil || ch.Kind != "challenge" || !ch.Request.Downgrade ||
		ch.Request.Machine == nil || ch.Request.Machine.ID != me || ch.Request.Machine.SigningKey != sigPub || ch.Request.Machine.EncryptionKey != encPub {
		return fmt.Errorf("the challenge isn't a core-signed downgrade of this machine to the new keys (%v)", err)
	}
	if !sameStores(ch.Request.Stores, keep) {
		return fmt.Errorf("the challenge keeps %v, not the %v asked for: not signed", ch.Request.Stores, keep)
	}
	return nil
}

// checkDowngradeCert: the new cert names this machine, its new keys and exactly the kept stores
func checkDowngradeCert(coreKey string, d *SignedDoc, me, encPub, sigPub string, keep []string) (Cert, error) {
	var cert Cert
	if err := verifyDoc(coreKey, d, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil ||
		cert.Machine.ID != me || cert.Machine.SigningKey != sigPub || cert.Machine.EncryptionKey != encPub {
		return cert, fmt.Errorf("the new cert isn't core-signed for the new keys (%v)", err)
	}
	if !sameStores(cert.Stores, keep) {
		return cert, fmt.Errorf("the new cert names %v, not the %v asked for", cert.Stores, keep)
	}
	return cert, nil
}

// shredWrite: overwrite the file's old bytes before replacing its contents
func shredWrite(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		z := make([]byte, fi.Size())
		rand.Read(z)
		os.WriteFile(path, z, mode)
	}
	return os.WriteFile(path, data, mode)
}

// sameStores: the same set of store names
func sameStores(a, b []string) bool {
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

// writeSecrets: ~/.secrets in the format Jarvis 1's entrypoint writes (shell-quoted export lines). A key that isn't
// an env name is left out (a store's writer isn't vouched for by this machine; the file is sourced by shells).
func writeSecrets(m map[string]string) error {
	home, _ := os.UserHomeDir()
	keys := make([]string, 0, len(m))
	for k := range m {
		if !envNameRE.MatchString(k) {
			log.Printf("~/.secrets: left out a key that isn't an env name (%d bytes)", len(k))
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "='" + strings.ReplaceAll(m[k], "'", `'\''`) + "'\n")
	}
	return shredWrite(filepath.Join(home, ".secrets"), []byte(b.String()), 0o600)
}

// ---- the router client (over Fly's private network; every request signed by this machine) -----------

type client struct {
	base, me string
	sig      *ecdh.PrivateKey
	http     *http.Client
}

type clientConf struct{ URL, Machine string }

// newClient: from the machine's env at boot (saved to clientPath, mode 600), from that file later
func newClient() (*client, error) {
	priv, err := loadPrivate()
	if err != nil {
		return nil, err
	}
	conf := clientConf{os.Getenv("JARVIS2_URL"), os.Getenv("FLY_MACHINE_ID")}
	if conf.URL != "" && conf.Machine != "" {
		b, _ := json.Marshal(conf)
		os.WriteFile(clientPath, b, 0o600)
	} else if b, err := os.ReadFile(clientPath); err == nil {
		json.Unmarshal(b, &conf)
	}
	if conf.URL == "" {
		return nil, errors.New("no router URL (JARVIS2_URL)")
	}
	return &client{base: strings.TrimSuffix(conf.URL, "/"), me: conf.Machine, sig: priv.sig, http: &http.Client{Timeout: 10 * time.Minute}}, nil
}

func (c *client) raw(method, path string, body []byte, hdr ...string) ([]byte, http.Header, int, error) {
	// the keys can change under a running process (a downgrade): sign with the current ones
	if k, err := loadPrivate(); err == nil {
		c.sig = k.sig
	}
	t := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(body)
	sig, err := sign(c.sig, []byte(method+" "+path+" "+t+" "+hex.EncodeToString(sum[:])))
	if err != nil {
		return nil, nil, 0, err
	}
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	req.Header.Set("X-Machine", c.me)
	req.Header.Set("X-Time", t)
	req.Header.Set("X-Sig", sig)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.Header, resp.StatusCode, err
}

// streamHTTP: for the multi-GB transfers (snapshots, an import's tarballs): no overall time limit
var streamHTTP = &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 5 * time.Minute}}

func (c *client) signed(method, path, bodySum string) (map[string]string, error) {
	if k, err := loadPrivate(); err == nil {
		c.sig = k.sig
	}
	t := strconv.FormatInt(time.Now().Unix(), 10)
	sig, err := sign(c.sig, []byte(method+" "+path+" "+t+" "+bodySum))
	if err != nil {
		return nil, err
	}
	return map[string]string{"X-Machine": c.me, "X-Time": t, "X-Sig": sig}, nil
}

// download: a signed GET streamed into a file → the body's sha256 and the response headers (non-200 is an error)
func (c *client) download(path, dst string) (string, http.Header, error) {
	sum, hdr, _, err := c.downloadTo(path, func(r io.Reader) error {
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, r)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	})
	return sum, hdr, err
}

// downloadTo: a signed GET whose body fn consumes as a stream → the sha256 and size of everything fn read (fn must
// read to the end; what it leaves is read here too, so the hash always covers the whole body)
func (c *client) downloadTo(path string, fn func(io.Reader) error) (string, http.Header, int64, error) {
	empty := sha256.Sum256(nil)
	h, err := c.signed("GET", path, hex.EncodeToString(empty[:]))
	if err != nil {
		return "", nil, 0, err
	}
	req, _ := http.NewRequest("GET", c.base+path, nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	hc := c.http
	if c.http == nil || c.http.Timeout != 0 {
		hc = streamHTTP
		if c.http != nil && c.http.Transport != nil {
			hc = &http.Client{Transport: c.http.Transport} // tests: the fake router's own transport
		}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return "", resp.Header, 0, fmt.Errorf("GET %s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	sh := sha256.New()
	cw := &countWriter{w: sh}
	tee := io.TeeReader(resp.Body, cw)
	if err := fn(tee); err != nil {
		return "", resp.Header, cw.n, err
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return "", resp.Header, cw.n, err
	}
	return hex.EncodeToString(sh.Sum(nil)), resp.Header, cw.n, nil
}

// upload: a file as a signed POST body, streamed (sum = the file's sha256, which the signature covers)
func (c *client) upload(path, file, sum string, hdr ...string) (int, int64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	h, err := c.signed("POST", path, sum)
	if err != nil {
		return 0, 0, err
	}
	req, _ := http.NewRequest("POST", c.base+path, f)
	req.ContentLength = fi.Size()
	for k, v := range h {
		req.Header.Set(k, v)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	hc := streamHTTP
	if c.http != nil && c.http.Transport != nil {
		hc = &http.Client{Transport: c.http.Transport}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, fi.Size(), nil
}

func (c *client) json(method, path string, in, out any) error {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	b, _, status, err := c.raw(method, path, body)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, status, strings.TrimSpace(string(b))[:min(200, len(strings.TrimSpace(string(b))))])
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// ---- crypto (the core's formats, core/crypto.go) -----------------------------------------------------

type keys struct{ enc, sig *ecdh.PrivateKey }

func loadPrivate() (keys, error) {
	b, err := os.ReadFile(privPath)
	if err != nil {
		return keys{}, err
	}
	var p private
	if err := json.Unmarshal(b, &p); err != nil {
		return keys{}, err
	}
	eb, _ := b64.DecodeString(p.Enc)
	sb, _ := b64.DecodeString(p.Sig)
	enc, err := ecdh.P256().NewPrivateKey(eb)
	if err != nil {
		return keys{}, err
	}
	sig, err := ecdh.P256().NewPrivateKey(sb)
	if err != nil {
		return keys{}, err
	}
	return keys{enc, sig}, nil
}

func ecdsaPriv(k *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), k.Bytes())
}

func sign(k *ecdh.PrivateKey, payload []byte) (string, error) {
	e, err := ecdsaPriv(k)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(payload)
	s, err := ecdsa.SignASN1(rand.Reader, e, h[:])
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(s), nil
}

func verify(pubRaw string, payload []byte, sigB64 string) bool {
	b, err := b64.DecodeString(pubRaw)
	if err != nil {
		return false
	}
	pk, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return false
	}
	der, _ := x509.MarshalPKIXPublicKey(pk)
	anyKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	k, ok := anyKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(k, h[:], sig)
}

func verifyDoc(pub string, d *SignedDoc, out any) error {
	if d == nil || !verify(pub, []byte(d.Payload), d.Sig) {
		return errors.New("bad signature")
	}
	return json.Unmarshal([]byte(d.Payload), out)
}

// openSealed: ephemeral ECDH + HKDF-SHA256 + AES-256-GCM (nonce ‖ ciphertext ‖ tag), as core.SealTo
func openSealed(priv *ecdh.PrivateKey, eB64, dataB64, info string) ([]byte, error) {
	eb, err := b64.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e, err := ecdh.P256().NewPublicKey(eb)
	if err != nil {
		return nil, err
	}
	x, err := priv.ECDH(e)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, x, nil, info, 32)
	if err != nil {
		return nil, err
	}
	d, err := b64.DecodeString(dataB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(d) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("sealed data too short")
	}
	return g.Open(nil, d[:g.NonceSize()], d[g.NonceSize():], nil)
}

// certMode: the signed permission mode (it replaces the router's env value);
// a running session raised in place keeps bypass until its next cert, which then signs it
func certMode(c Cert) string {
	if c.Options.PermissionMode == "bypass" {
		return "bypass"
	}
	return "auto"
}

func withoutEnv(env []string, names ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		drop := false
		for _, n := range names {
			drop = drop || strings.HasPrefix(kv, n+"=")
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}
