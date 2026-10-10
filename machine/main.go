// jarvis2-machine: the session machine's side of Jarvis 2 (docs/DESIGN.md,
// "Machine side"). It is the image's entry point and its fixed init entry point:
//
//	jarvis2-machine boot       ENTRYPOINT: make the machine's key pairs, wait for init, then check the
//	                           succession cert, restore the predecessor's snapshot, pull the secrets and
//	                           hand over to Jarvis 1's entrypoint (the harness). Any failed check → start
//	                           nothing.
//	jarvis2-machine init       what the core runs through Fly exec (no arguments): asks boot to go on.
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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	dir         = "/run/jarvis2"
	keysPath    = dir + "/keys.json"        // public halves, printed by init for the core (through Fly exec)
	privPath    = dir + "/private.json"     // private halves, never leave the machine
	coreKeyPath = dir + "/core-key"         // the core's key, from the machine's Fly config (the core set it)
	coreKeyEnv  = "JARVIS2_CORE_KEY"        // the core that created this machine puts its signing key here
	goPath      = dir + "/init-requested"
	certPath    = dir + "/cert.json"
	bootedPath  = dir + "/booted" // written once the boot is done (cert, snapshot, secrets, repos): the harness starts next
	clientPath  = dir + "/client.json" // the router URL + this machine's id, for later commands
	jarvis1     = "/usr/local/bin/entrypoint.sh"
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
	} `json:"options"`
	Phone     string `json:"phone"`
	Sensitive bool   `json:"sensitive"`
	Line      string `json:"line"`
}

type private struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[jarvis2] ")
	if len(os.Args) < 2 {
		log.Fatal("usage: jarvis2-machine boot | init | add-store <name> | downgrade [<store>…] | allow [<holder> <duration> | --remove <holder>]")
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
	case "downgrade":
		err = downgrade(os.Args[2:])
	case "agent":
		err = agent()
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

	// 2. the predecessor's snapshot, checked against the predecessor's own signing key
	if cert.PredID != "" && cert.PredID != me {
		var pc Cert
		if err := verifyDoc(coreKey, certs.PredecessorCert, &pc); err != nil || pc.Kind != "succession-cert" || pc.Machine == nil || pc.Machine.ID != cert.PredID {
			return fmt.Errorf("the predecessor's cert isn't core-signed for %s (%v)", cert.PredID, err)
		}
		if err := restore(c, pc.Machine.SigningKey); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		applyRollback(cert.PredID) // rollback.go: a restart's transcript rollback, on the verified snapshot
	}
	// 2b. a new line restoring a destroyed session's archived snapshot (restore.go)
	if err := restoreArchived(c, coreKey, me, &cert); err != nil {
		return fmt.Errorf("restore: %w", err)
	}

	// 3. the secrets, sealed to this machine's encryption key
	secrets, err := pullSecrets(c, coreKey, me)
	if err != nil {
		return err
	}
	sj, _ := json.Marshal(secrets)
	log.Printf("secrets ok: %d keys", len(secrets))

	// 4. repos: each repo's deploy key from its store (SSH, that repo only), then the clones
	if err := setupDeployKeys(secrets); err != nil {
		log.Printf("deploy keys: %v", err)
	}
	cloneRepos()

	// 5. booted: from now on a snapshot command gets a real snapshot; then Jarvis 1's entrypoint runs the harness
	if err := os.WriteFile(bootedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644); err != nil {
		return fmt.Errorf("booted marker: %w", err)
	}
	if t, ok := strings.CutPrefix(cert.Options.Harness, taskHarnessPrefix); ok {
		runTask(c, t, secrets, certMode(cert)) // task.go: the template instead of a harness; never returns
	}
	env := os.Environ()
	env = withoutEnv(env, "SESSION_HARNESS", "SESSION_PERMISSION_MODE") // the signed values below replace the router's
	env = append(env, "SESSION_SECRETS_JSON="+string(sj), "SESSION_HARNESS="+cert.Options.Harness, "SESSION_PERMISSION_MODE="+certMode(cert), "SESSION_ID="+sessionID(me))
	if p := tunnelProof(c); p != "" { // tunnelproof.go
		env = append(env, "TUNNEL_AGENT_SECRET="+p)
	}
	if v := secrets["CLAUDE_CREDENTIALS"]; v != "" {
		env = append(env, "CLAUDE_CREDENTIALS="+v)
	}
	if v := secrets["CLAUDE_ACCOUNT"]; v != "" {
		env = append(env, "CLAUDE_ACCOUNT="+v)
	}
	env = append(env, fetchAttachments(c)...) // attachments.go: first-prompt attachments, before the harness
	log.Printf("starting the harness")
	return syscall.Exec(jarvis1, []string{jarvis1}, env)
}

func sessionID(me string) string {
	if s := os.Getenv("JARVIS2_SESSION_ID"); s != "" {
		return s
	}
	return me
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
	for i := 0; i < 150; i++ { // a store may still be locked; Deyao unlocks it in the app
		if lastErr = c.json("POST", "/m/pull-secrets", map[string]string{}, &doc); lastErr == nil {
			break
		}
		if i%15 == 0 {
			log.Printf("pull secrets: %v (retrying)", lastErr)
		}
		time.Sleep(4 * time.Second)
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

// cloneRepos: JARVIS2_REPOS into ~/workspace. A repo whose deploy key is in the session's stores goes over SSH
// with that key (setupDeployKeys has already written git's rewrites for its https URL); any other is cloned
// anonymously over HTTPS (public repos only).
func cloneRepos() {
	home, _ := os.UserHomeDir()
	repos := strings.TrimSpace(os.Getenv("JARVIS2_REPOS"))
	if repos == "" {
		return
	}
	for _, url := range strings.Split(repos, ",") {
		url = cloneURL(url)
		if url == "" {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(url), ".git")
		dst := filepath.Join(home, "workspace", name)
		if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
			continue // restored from the snapshot
		}
		cmd := exec.Command("git", "clone", "-q", url, dst)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("clone %s failed: %s", name, strings.TrimSpace(string(out)))
			continue
		}
		log.Printf("cloned %s", name)
	}
}

// ---- snapshots ------------------------------------------------------------------------------------

// what a snapshot holds (relative to $HOME): the conversation, the work, the artefacts
var snapshotPaths = []string{".claude/projects", ".claude.json", ".claude/.first-prompt-sent", "workspace", "artifacts", allowFile, changesFile}

func makeSnapshot() ([]byte, error) {
	home, _ := os.UserHomeDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
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
			link := ""
			if fi.Mode()&os.ModeSymlink != 0 {
				link, _ = os.Readlink(p)
			}
			h, err := tar.FileInfoHeader(fi, link)
			if err != nil {
				return nil
			}
			h.Name = name
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if fi.Mode().IsRegular() {
				f, err := os.Open(p)
				if err != nil {
					return nil
				}
				defer f.Close()
				_, err = io.Copy(tw, f)
				return err
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes(), nil
}

func restore(c *client, predSigningKey string) error {
	body, hdr, status, err := c.raw("GET", "/m/snapshot", nil)
	if err != nil {
		return err
	}
	if status == 404 {
		log.Printf("the predecessor left no snapshot: starting fresh")
		return nil
	}
	if status != 200 {
		return fmt.Errorf("HTTP %d", status)
	}
	sum := sha256.Sum256(body)
	if !verify(predSigningKey, []byte(hex.EncodeToString(sum[:])), hdr.Get("X-Snapshot-Sig")) {
		return errors.New("the snapshot isn't signed by the predecessor")
	}
	n, err := unpack(body)
	if err != nil {
		return err
	}
	log.Printf("restored the predecessor's snapshot (%d files)", n)
	return nil
}

// unpack: a snapshot (tar.gz relative to $HOME) into $HOME
func unpack(body []byte) (int, error) {
	home, _ := os.UserHomeDir()
	gz, err := gzip.NewReader(bytes.NewReader(body))
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
		go serveAPIProxy(c) // apiproxy.go: $JARVIS_URL for Jarvis 1's session scripts
		go liveSync(c)      // livesync.go: the transcripts to the Storage Box (through the router) for search
	}()
	for {
		var out struct {
			Commands []string `json:"commands"`
			Execs    []Exec   `json:"execs"`
		}
		if err := c.json("GET", "/m/commands", nil, &out); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		for _, e := range out.Execs {
			go runExec(c, e)
		}
		for _, cmd := range out.Commands {
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

func uploadSnapshot(c *client) error {
	writeChanges() // restore.go: the repos' state, for the router's uncommitted-work check
	body, err := makeSnapshot()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	priv, err := loadPrivate()
	if err != nil {
		return err
	}
	sig, err := sign(priv.sig, []byte(hex.EncodeToString(sum[:])))
	if err != nil {
		return err
	}
	_, _, status, err := c.raw("POST", "/m/snapshot", body, "X-Snapshot-Sig", sig)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("HTTP %d", status)
	}
	log.Printf("snapshot uploaded (%d bytes)", len(body))
	return nil
}

// ---- add a store ----------------------------------------------------------------------------------

func addStore(name string) error {
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.json("POST", "/m/add-store", map[string]string{"store": name}, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asked Deyao to add %s to this session (approval in the Jarvis 2 app); waiting up to 1 h\n", name)
	me := c.me
	keys, _ := ownKeys()
	deadline := time.Now().Add(time.Hour)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		var certs struct {
			Cert *SignedDoc `json:"cert"`
		}
		if c.json("GET", "/m/cert", nil, &certs) != nil || certs.Cert == nil {
			continue
		}
		var cert Cert
		if verifyDoc(coreKey, certs.Cert, &cert) != nil || cert.Kind != "succession-cert" || cert.Machine == nil ||
			cert.Machine.ID != me || cert.Machine.SigningKey != keys["signingKey"] {
			continue
		}
		if i := sort.SearchStrings(cert.Stores, name); i >= len(cert.Stores) || cert.Stores[i] != name {
			continue
		}
		raw, _ := json.Marshal(certs.Cert)
		os.WriteFile(certPath, raw, 0o644)
		secrets, err := pullSecrets(c, coreKey, me)
		if err != nil {
			return err
		}
		if err := writeSecrets(secrets); err != nil {
			return err
		}
		if err := setupDeployKeys(secrets); err != nil { // a repo's store: its key and rewrites now
			return err
		}
		fmt.Fprintf(os.Stderr, "added %s: ~/.secrets rewritten (%d keys); run `set -a; . ~/.secrets; set +a` in a shell to load them\n", name, len(secrets))
		return nil
	}
	return errors.New("no approval within 1 h")
}

// downgrade: keep only the named stores, in place. A new key pair; the core's challenge signed with the old
// key; the new cert checked; only then the old keys and the secrets of the dropped stores are shredded (the
// old cert still pulls, but sealed to a key that no longer exists).
func downgrade(keep []string) error {
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
	var ch struct {
		Kind    string `json:"kind"`
		Request struct {
			Downgrade bool     `json:"downgrade"`
			Machine   *Machine `json:"machine"`
			Stores    []string `json:"stores"`
		} `json:"request"`
	}
	if err := verifyDoc(coreKey, begin.Challenge, &ch); err != nil || ch.Kind != "challenge" || !ch.Request.Downgrade ||
		ch.Request.Machine == nil || ch.Request.Machine.ID != c.me || ch.Request.Machine.SigningKey != sigPub || ch.Request.Machine.EncryptionKey != encPub {
		return fmt.Errorf("the challenge isn't a core-signed downgrade of this machine to the new keys (%v)", err)
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
	var cert Cert
	if err := verifyDoc(coreKey, fin.Cert, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil ||
		cert.Machine.ID != c.me || cert.Machine.SigningKey != sigPub || cert.Machine.EncryptionKey != encPub {
		return fmt.Errorf("the new cert isn't core-signed for the new keys (%v)", err)
	}
	// the new cert is in hand: switch to the new keys, shred the old ones, re-pull the remaining secrets
	p, _ := json.Marshal(private{b64.EncodeToString(enc.Bytes()), b64.EncodeToString(sig.Bytes())})
	if err := shredWrite(privPath, p, 0o600); err != nil {
		return err
	}
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

// shredWrite: overwrite the file's old bytes before replacing its contents
func shredWrite(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		z := make([]byte, fi.Size())
		rand.Read(z)
		os.WriteFile(path, z, mode)
	}
	return os.WriteFile(path, data, mode)
}

// writeSecrets: ~/.secrets in the format Jarvis 1's entrypoint writes (shell-quoted export lines)
func writeSecrets(m map[string]string) error {
	home, _ := os.UserHomeDir()
	keys := make([]string, 0, len(m))
	for k := range m {
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
