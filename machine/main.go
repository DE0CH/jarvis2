// jarvis2-machine: the session machine's guard (docs/DESIGN.md "Target design", "The guard"; docs/API-grants.md). It
// is the image's entry point, its fixed init entry point, and a few session-side tools:
//
//	jarvis2-machine boot       ENTRYPOINT: make the machine's key pairs, wait for init, then run the guard (boot.go): check
//	                           the chain, restore the snapshot the source names, read the source's start settings, take
//	                           the grant and pull the secrets with it, start the harness as a child, and serve the router's
//	                           commands for the machine's life. Any failed check → start nothing.
//	jarvis2-machine init       what the spawner runs through Fly exec (no arguments): prints the public keys and lets
//	                           boot go on.
//	jarvis2-machine stores [--keys | --json]
//	                           every store and the key NAMES it holds (never a value) (stores.go).
//	jarvis2-machine put-key STORE KEY [--explain TEXT] < value | delete-key STORE KEY
//	                           write one store key (putkey.go).
//
// It trusts only what it can check: the kernel roster and the spawner's key arrive in the machine's Fly config (set by
// the spawner, the only holder of a Fly token that creates machines), every kernel document is checked against that
// roster, and the rest is its own keys and clock. The router only carries.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const dir = "/run/jarvis2"

// the machine's files (vars: tests move them)
var (
	keysPath    = dir + "/keys.json"    // public halves, printed by init for the spawner (through Fly exec)
	privPath    = dir + "/private.json" // private halves, never leave the machine
	goPath      = dir + "/init-requested"
	rosterPath  = dir + "/roster.json"  // the kernel roster from the Fly config, for the CLI subcommands
	grantPath   = dir + "/grant.json"   // the grant the guard holds, for the CLI subcommands (not a source of trust)
	runInfoPath = dir + "/session.json" // the session id and the like, for the CLI subcommands
	bootedPath  = dir + "/booted"       // written once the boot is done (chain, snapshot, grant, secrets, repos): the harness starts next
	clientPath  = dir + "/client.json"  // the router URL + this machine's id, for later commands
	baseEntry   = "/usr/local/bin/entrypoint.sh"
)

var b64 = base64.StdEncoding

type private struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[jarvis2] ")
	if len(os.Args) < 2 {
		log.Fatal("usage: jarvis2-machine boot | init | stores [--keys | --json] | put-key <store> <key> [--explain <text>] < value | delete-key <store> <key>")
	}
	var err error
	switch os.Args[1] {
	case "boot":
		err = boot()
	case "init":
		err = initCmd()
	case "stores":
		err = storesCmd(os.Args[2:]) // stores.go
	case "put-key":
		err = putKeyCmd(os.Args[2:], false) // putkey.go
	case "delete-key":
		err = putKeyCmd(os.Args[2:], true)
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ---- boot -----------------------------------------------------------------------------------------

func boot() error {
	// first: the env this machine was started with is thrown away, except what the image, Fly and the spawner set
	// (settings.go). Re-execs once.
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
	if err := runGuard(); err != nil {
		// any failed check → start nothing; keep the machine up so the failure is visible in its log
		log.Printf("REFUSING TO START: %v", err)
		select {}
	}
	return nil
}

// strictUnmarshal: one JSON value, no unknown fields, nothing after it
func strictUnmarshal(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// initCmd: the one command the spawner runs through Fly (no arguments). It prints this machine's public keys
// (the spawner binds them into the spawn cert) and lets boot go on.
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

// cloneRepos: the repos the settings name (reposToClone) into ~/workspace. A repo whose deploy key is in the session's
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
	changesFile, recordsFile}

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
// the machine, and the spawner's kill fixes the hash of this snapshot in the source the successor restores. So the machine signs
// exactly one in its life: before taking it, it stops every process of the session (SIGSTOP), so nothing changes
// after it, and a later snapshot command gets that same one again. A router that keeps an earlier signed snapshot
// therefore has none to keep, and can't roll a successor back to a state from before the session's last work.
var (
	finalSnapshot    = dir + "/final-snapshot.tar.gz"
	finalSnapshotSig = dir + "/final-snapshot.sig"
	// snapshotKey: the machine's signing key
	snapshotKey = func() (*ecdh.PrivateKey, error) { p, err := loadPrivate(); return p.sig, err }
)

var frozen atomic.Bool // the session is stopped for its final snapshot: no commands, nothing delivered

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

// shredWrite: overwrite the file's old bytes before replacing its contents
func shredWrite(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		z := make([]byte, fi.Size())
		rand.Read(z)
		os.WriteFile(path, z, mode)
	}
	return os.WriteFile(path, data, mode)
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
