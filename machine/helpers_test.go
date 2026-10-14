package main

// Test helpers: a kernel world (ktest: a key for every role, documents signed directly), this machine's keys in a temp
// run dir, and an in-repo fake router that checks the machine signature as the router does and plays the kernel parts
// behind it (the notary's challenges, the secrets component's pulls) with the world's keys.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

type tkey struct{ k *ecdh.PrivateKey }

func newKey() tkey {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	return tkey{k}
}

func (k tkey) pub() string { return b64.EncodeToString(k.k.PublicKey().Bytes()) }

// useRunDir: the machine's run files in a temp dir (never /run/jarvis2), and HOME in another
func useRunDir(t *testing.T) string {
	t.Helper()
	run := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	old := []string{keysPath, privPath, goPath, rosterPath, grantPath, runInfoPath, bootedPath, clientPath, restoreTmp, finalSnapshot, finalSnapshotSig}
	keysPath, privPath, goPath = filepath.Join(run, "keys.json"), filepath.Join(run, "private.json"), filepath.Join(run, "go")
	rosterPath, grantPath, runInfoPath = filepath.Join(run, "roster.json"), filepath.Join(run, "grant.json"), filepath.Join(run, "session.json")
	bootedPath, clientPath, restoreTmp = filepath.Join(run, "booted"), filepath.Join(run, "client.json"), filepath.Join(run, "restore.tar.gz")
	finalSnapshot, finalSnapshotSig = filepath.Join(run, "f.tar.gz"), filepath.Join(run, "f.sig")
	t.Cleanup(func() {
		keysPath, privPath, goPath, rosterPath, grantPath, runInfoPath, bootedPath, clientPath, restoreTmp, finalSnapshot, finalSnapshotSig =
			old[0], old[1], old[2], old[3], old[4], old[5], old[6], old[7], old[8], old[9], old[10]
		frozen.Store(false)
	})
	return run
}

const settingsJSON = `{"v":1,"session":"s1","harness":"claude","permissionMode":"auto","title":"t","prompt":"hello"}`

// world: the kernel's keys, this machine, a fake router, and a guard wired to it
type world struct {
	t     *testing.T
	w     *ktest.World
	me    kernel.Object
	enc   *ecdh.PrivateKey
	sig   *ecdh.PrivateKey
	g     *guard
	clock time.Time

	mu         sync.Mutex
	srv        *httptest.Server
	chain      BootChain
	grant      *kernel.SignedDoc
	stores     map[string]map[string]string // the secrets component's unlocked stores
	snapshot   []byte
	shellRes   []ShellResult
	dueRes     []DueResult
	noticeRes  []NoticeResult
	forwarded  map[string][]byte // path → body the router got on /m/api/…
	headers    map[string]http.Header
	challenges int
	// tampering: the fake kernel answers wrong
	challengeKey   string // "" = the notary
	challengeShift time.Duration
	challengeSubj  string
	secretsKey     string // "" = secrets
	secretsGrant   string // "" = the grant pulled with
	apiAnswer      func(path string, body []byte) (int, string)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	useRunDir(t)
	x := &world{t: t, w: ktest.New(t), stores: map[string]map[string]string{}, forwarded: map[string][]byte{}, headers: map[string]http.Header{},
		clock: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	x.enc, _ = ecdh.P256().GenerateKey(rand.Reader)
	x.sig, _ = ecdh.P256().GenerateKey(rand.Reader)
	x.me = kernel.Object{ID: "m1", SigningKey: b64.EncodeToString(x.sig.PublicKey().Bytes()), EncryptionKey: b64.EncodeToString(x.enc.PublicKey().Bytes())}
	p, _ := json.Marshal(private{b64.EncodeToString(x.enc.Bytes()), b64.EncodeToString(x.sig.Bytes())})
	os.WriteFile(privPath, p, 0o600)
	pub, _ := json.Marshal(map[string]string{"encryptionKey": x.me.EncryptionKey, "signingKey": x.me.SigningKey})
	os.WriteFile(keysPath, pub, 0o644)
	x.srv = httptest.NewServer(http.HandlerFunc(x.serve))
	t.Cleanup(x.srv.Close)
	c := &client{base: x.srv.URL, me: "m1", sig: x.sig, http: x.srv.Client()}
	home, _ := os.UserHomeDir()
	x.g = &guard{c: c, roster: x.w.Roster, me: x.me, now: func() time.Time { return x.clock }, rec: newRecords(home), grantPath: grantPath}
	st, err := parseSettings(settingsJSON)
	if err != nil {
		t.Fatal(err)
	}
	x.g.st = st
	x.g.ready.Store(true)
	rb, _ := json.Marshal(x.w.Roster)
	os.WriteFile(rosterPath, rb, 0o644)
	return x
}

// chainFor: a phone-made source with these settings (and snapshot), notarized, and the spawner's (source, me) cert
func (x *world) chainFor(settings, snapshot string) (BootChain, kernel.Object) {
	src := ktest.Source(ktest.Image, settings)
	src.Snapshot = snapshot
	origin := x.w.Notarize(x.t, x.w.Cert(x.t, "phone", "phone", ktest.SinkObj(), src, ktest.P([]string{"shell"})))
	spawn := x.w.Notarize(x.t, x.w.Cert(x.t, "spawner", "spawner", src, x.me, kernel.Top()))
	return BootChain{Spawn: spawn, Source: origin}, src
}

// grantFor: a grant on this machine made by the mover
func (x *world) grantFor(allowed []string, conds ...string) kernel.SignedDoc {
	return x.w.Grant(x.t, "mover", "mover", x.me, ktest.P(allowed, conds...))
}

func (x *world) serve(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	sum := sha256.Sum256(body)
	msg := req.Method + " " + req.URL.Path + " " + req.Header.Get("X-Time") + " " + hex.EncodeToString(sum[:])
	if req.Header.Get("X-Machine") != "m1" || !verify(x.me.SigningKey, []byte(msg), req.Header.Get("X-Sig")) {
		w.WriteHeader(401)
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	js := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
	switch p := req.URL.Path; {
	case p == "/m/boot":
		js(x.chain)
	case p == "/m/grant":
		js(map[string]any{"grant": x.grant})
	case p == "/m/config":
		js(map[string]any{"discordChannel": "123", "permissionMode": "bypass", "sessionId": "sX"})
	case p == "/m/tunnel-proof":
		js(map[string]string{"proof": "p"})
	case p == "/m/challenge":
		var in struct{ Subject, About string }
		json.Unmarshal(body, &in)
		x.challenges++
		if x.challengeSubj != "" {
			in.Subject = x.challengeSubj
		}
		key := x.w.Keys["notary"]
		if x.challengeKey != "" {
			key = x.w.Keys[x.challengeKey]
		}
		d, _ := kernel.Sign(key, kernel.Challenge{Kind: "challenge", Seq: int64(x.challenges), At: x.clock.Add(x.challengeShift).Format(time.RFC3339Nano),
			Subject: in.Subject, About: in.About, Nonce: "00112233445566778899aabbccddeeff"})
		js(d)
	case p == "/m/secrets/pull":
		var in struct {
			Grant kernel.SignedDoc `json:"grant"`
		}
		json.Unmarshal(body, &in)
		gr, err := kernel.OpenGrant(x.w.Roster, in.Grant, kernel.RoleMover, kernel.RoleMerger)
		if err != nil {
			w.WriteHeader(403)
			return
		}
		served, plain := []string{}, map[string]map[string]string{}
		for n, v := range x.stores {
			if gr.Allowed.Contains(storePrefix + n) {
				served, plain[n] = append(served, n), v
			}
		}
		b, _ := json.Marshal(plain)
		sealed, _ := kernel.SealTo(gr.Machine.EncryptionKeyOf(), b, infoSecrets)
		gid := in.Grant.ID()
		if x.secretsGrant != "" {
			gid = x.secretsGrant
		}
		key := x.w.Keys["secrets"]
		if x.secretsKey != "" {
			key = x.w.Keys[x.secretsKey]
		}
		d, _ := kernel.Sign(key, map[string]any{"kind": "secrets", "grant": gid, "machine": gr.Machine, "conditions": gr.Conditions,
			"stores": served, "versions": map[string]string{}, "locked": []string{}, "missing": []string{}, "withheld": []string{}, "sealed": sealed})
		js(d)
	case p == "/m/snapshot" && req.Method == "GET":
		w.Write(x.snapshot)
	case p == "/m/shell-result":
		var r ShellResult
		json.Unmarshal(body, &r)
		x.shellRes = append(x.shellRes, r)
		js(map[string]bool{"ok": true})
	case p == "/m/due-result":
		var r DueResult
		json.Unmarshal(body, &r)
		x.dueRes = append(x.dueRes, r)
		js(map[string]bool{"ok": true})
	case p == "/m/notice-result":
		var r NoticeResult
		json.Unmarshal(body, &r)
		x.noticeRes = append(x.noticeRes, r)
		js(map[string]bool{"ok": true})
	case strings.HasPrefix(p, "/m/api/"):
		x.forwarded[p] = body
		x.headers[p] = req.Header.Clone()
		if x.apiAnswer != nil {
			st, out := x.apiAnswer(p, body)
			w.WriteHeader(st)
			w.Write([]byte(out))
			return
		}
		js(map[string]any{"ok": true, "id": "r1"})
	default:
		w.WriteHeader(404)
	}
}

// sent: what the guard typed into the harness (sendToHarness replaced)
func captureHarness(t *testing.T) *[]string {
	var mu sync.Mutex
	got := []string{}
	old := sendToHarness
	sendToHarness = func(harness, mode, from, text string) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, text)
		return nil
	}
	t.Cleanup(func() { sendToHarness = old })
	return &got
}

func markBooted(t *testing.T) {
	if err := os.WriteFile(bootedPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func jsonBytes(v any) []byte {
	var b bytes.Buffer
	json.NewEncoder(&b).Encode(v)
	return b.Bytes()
}

// httpFunc: a handler taking some paths itself (fn returns true: answered {"ok":true}), the rest to next
func httpFunc(fn func(path string, body []byte) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if fn(r.URL.Path, body) {
			w.Write([]byte(`{"ok":true}`))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}
