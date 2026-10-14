package main

// The test rig: the kernel's real parts in-process (each its own HTTP server with its own key, core/kernel), the
// spawner on the fake Fly, secrets set up the way the phone sets it up (claim, a store written and unlocked), a router
// pointed at them, the phone's and the root key's signatures made with the world's keys, and machines that sign their
// /m requests with the keys the fake Fly made for them.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/gullible"
	"github.com/DE0CH/jarvis2/core/kernel/identitysigner"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
	"github.com/DE0CH/jarvis2/core/kernel/merger"
	"github.com/DE0CH/jarvis2/core/kernel/mover"
	"github.com/DE0CH/jarvis2/core/kernel/notarizer"
	"github.com/DE0CH/jarvis2/core/kernel/notary"
	"github.com/DE0CH/jarvis2/core/kernel/secrets"
	"github.com/DE0CH/jarvis2/core/kernel/spawner"
)

func TestMain(m *testing.M) {
	if os.Getenv("ROUTER_TEST_LOG") == "" {
		log.SetOutput(io.Discard)
	}
	initStep, killStep, scheduleWaitStep = 10*time.Millisecond, 10*time.Millisecond, 20*time.Millisecond
	grantTick = time.Hour
	os.Exit(m.Run())
}

const testImage = ktest.Image

type krig struct {
	t        *testing.T
	w        *ktest.World
	fly      *spawner.FakeFly
	sec      *secrets.Secrets
	r        *Router
	app, mch http.Handler
	phoneAgr *ecdh.PrivateKey
	backups  *kBucket
}

type kBucket struct {
	mu   sync.Mutex
	puts map[string][]byte
}

func newKRig(t *testing.T) *krig {
	t.Helper()
	w := ktest.New(t)
	g := &krig{t: t, w: w, fly: spawner.NewFakeFly()}
	serve := func(s *kernel.Signer, routes map[string]kernel.Route) string {
		srv := httptest.NewServer(kernel.Handler(s, routes))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	nz, _ := notarizer.New(w.Keys["notarizer"], w.Roster, "")
	sp, _ := spawner.New(w.Keys["spawner"], w.Roster, g.fly, "http://router.internal:8081")
	g.sec, _ = secrets.New(w.Keys["secrets"], w.Roster, secrets.NewFakeGitHub())
	// secrets' /identity (kernel.Serve adds it in production)
	secRoutes := g.sec.Routes()
	id := kernel.MakeIdentity("secrets", w.Keys["secrets"], g.sec.AgreementKey(), nil)
	secRoutes["GET /identity"] = func([]byte) (any, error) { return id, nil }
	k := &Kernel{HTTP: &http.Client{Timeout: time.Minute}, URLs: map[string]string{
		"notary":    serve(w.Keys["notary"], notary.New(w.Keys["notary"], nil).Routes()),
		"notarizer": serve(w.Keys["notarizer"], nz.Routes()),
		"mover":     serve(w.Keys["mover"], mover.New(w.Keys["mover"], w.Roster).Routes()),
		"merger":    serve(w.Keys["merger"], merger.New(w.Keys["merger"], w.Roster).Routes()),
		"identity":  serve(w.Keys["identity"], identitysigner.New(w.Keys["identity"]).Routes()),
		"gullible":  serve(w.Keys["gullible"], gullible.New(w.Keys["gullible"]).Routes()),
		"spawner":   serve(w.Keys["spawner"], sp.Routes()),
		"secrets":   serve(w.Keys["secrets"], secRoutes),
	}}
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pol := Policy{Harnesses: map[string]struct {
		Stores []string `json:"stores"`
	}{"claude": {Stores: []string{"claude"}}}}
	g.r = NewRouter(Config{NoAccess: true, DataDir: st.dir, WebDir: t.TempDir(), SessionImage: testImage, Region: "lhr",
		SnapshotWait: 2 * time.Second}, st, k, pol)
	g.app, g.mch = g.r.Handler(), g.r.MachineHandler()
	if err := g.r.setRootGrant(w.RootGrant(t)); err != nil {
		t.Fatal(err)
	}
	// the backup bucket: a stand-in that keeps every PUT
	g.backups = &kBucket{puts: map[string][]byte{}}
	bsrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		g.backups.mu.Lock()
		g.backups.puts[req.URL.Path] = b
		g.backups.mu.Unlock()
	}))
	t.Cleanup(bsrv.Close)
	t.Setenv("BACKUP_READ_ACCESS_KEY", "a")
	t.Setenv("BACKUP_READ_SECRET_KEY", "b")
	t.Setenv("BACKUP_ENDPOINT", bsrv.URL)
	t.Setenv("RECORDS_OFF", "1")
	return g
}

// setUpSecrets: Reset-style claim, the store "claude" written by the router and unlocked by the phone
func (g *krig) setUpSecrets() {
	t := g.t
	id := kernel.MakeIdentity("secrets", g.w.Keys["secrets"], g.sec.AgreementKey(), nil)
	master, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g.phoneAgr, _ = ecdh.P256().GenerateKey(rand.Reader)
	me, _ := master.PublicKey.ECDH()
	bundle := []byte(`{"format":"keys"}`)
	sum := sha256.Sum256(bundle)
	st, _ := json.Marshal(map[string]any{"kind": "claim", "master": kernel.B64.EncodeToString(me.Bytes()),
		"core":         map[string]string{"signingKey": id.SigningKey, "agreementKey": id.AgreementKey},
		"phone":        map[string]string{"signingKey": g.w.Roster.Phone, "agreementKey": kernel.B64.EncodeToString(g.phoneAgr.PublicKey().Bytes())},
		"bundleSha256": hex.EncodeToString(sum[:])})
	h := sha256.Sum256(st)
	sig, _ := ecdsa.SignASN1(rand.Reader, master, h[:])
	sealed, _ := kernel.SealTo(id.AgreementKey, bundle, "jarvis2/claim")
	code, out := g.do(g.app, "POST", "/api/secrets/claim", map[string]any{"statement": string(st), "masterSig": kernel.B64.EncodeToString(sig), "bundle": sealed})
	if code != 200 {
		t.Fatalf("claim: %d %s", code, out)
	}
}

// writeKey: the router writes a key of a store (writer router), as publishLogin does
func (g *krig) writeKey(store, key, value string) {
	g.t.Helper()
	tg, err := g.r.sealTargets()
	if err != nil {
		g.t.Fatal(err)
	}
	in, err := sealKeyWrite(tg, store, key, []byte(value), "a test key")
	if err != nil {
		g.t.Fatal(err)
	}
	if _, err := g.r.WriteKey("router", "", store, key, in); err != nil {
		g.t.Fatal(err)
	}
}

// unlock: the phone's unlock of a store, through the router
func (g *krig) unlock(store string) {
	t := g.t
	t.Helper()
	code, out := g.do(g.app, "POST", "/api/secrets/unlock/begin", map[string]string{"store": store})
	if code != 200 {
		t.Fatalf("unlock begin: %d %s", code, out)
	}
	var begin kernel.SignedDoc
	json.Unmarshal(out, &begin)
	var b struct {
		Pending, T string
		Keys       []struct{ Key, E string }
	}
	json.Unmarshal([]byte(begin.Payload), &b)
	shares := map[string]kernel.Sealed{}
	for _, k := range b.Keys {
		eb, _ := kernel.B64.DecodeString(k.E)
		E, _ := ecdh.P256().NewPublicKey(eb)
		x, _ := g.phoneAgr.ECDH(E)
		shares[k.Key], _ = kernel.SealTo(b.T, x, "jarvis2/unlock-share")
	}
	if code, out := g.do(g.app, "POST", "/api/secrets/unlock/finish", map[string]any{"pending": b.Pending, "shares": shares}); code != 200 {
		t.Fatalf("unlock finish: %d %s", code, out)
	}
}

// do: one request to a handler with a JSON body → status, body
func (g *krig) do(h http.Handler, method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// sign: the phone's (or root's) signature over an approval's drafts
func (g *krig) sign(role string, a *Approval) []string {
	out := []string{}
	for _, d := range a.Drafts {
		sig, err := g.w.Keys[role].Sign([]byte(d.Payload))
		if err != nil {
			g.t.Fatal(err)
		}
		out = append(out, sig)
	}
	return out
}

// approval: the session's pending approval of a kind
func (g *krig) approval(sid, kind string) *Approval {
	var a *Approval
	g.r.st.Do(func(d *persisted) {
		for _, x := range d.Approvals {
			if x.Session == sid && x.Kind == kind {
				c := *x
				a = &c
			}
		}
	})
	if a == nil {
		g.t.Fatalf("no %s approval for %s", kind, sid)
	}
	return a
}

func (g *krig) session(sid string) Session {
	var s Session
	g.r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
			if x.Chain != nil {
				c := x.Chain.clone()
				s.Chain = &c
			}
		}
	})
	return s
}

func (g *krig) waitState(sid, want string) Session {
	g.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s := g.session(sid)
		if s.State == want {
			return s
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("session %s is %q (%s), not %q", sid, s.State, s.Error, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// newSession: a session created, the phone's approval answered, its machine spawned and given its grant
func (g *krig) newSession(stores ...string) (string, *vmach) {
	g.t.Helper()
	sid, err := g.r.CreateSession(NewSession{Label: "t", Prompt: "hello", Stores: stores})
	if err != nil {
		g.t.Fatal(err)
	}
	a := g.approval(sid, "new-session")
	if _, err := g.r.Respond(a.ID, g.sign("phone", a)); err != nil {
		g.t.Fatal(err)
	}
	s := g.waitState(sid, "initialising")
	return sid, g.vm(s.MachineID)
}

// ---- a machine, as the guard calls the router ----------------------------------------------------------------------

type vmach struct {
	g   *krig
	id  string
	sig *ecdsa.PrivateKey
	enc *ecdh.PrivateKey
}

func (g *krig) vm(id string) *vmach {
	fm := g.fly.Machines[id]
	if fm == nil {
		g.t.Fatalf("no fake machine %s", id)
	}
	priv, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), fm.Sig.Bytes())
	return &vmach{g: g, id: id, sig: priv, enc: fm.Enc}
}

// call: a signed request to the machine listener
func (m *vmach) call(method, path string, body []byte, hdr ...string) (int, []byte, http.Header) {
	t := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(body)
	h := sha256.Sum256([]byte(method + " " + path + " " + t + " " + hex.EncodeToString(sum[:])))
	sig, _ := ecdsa.SignASN1(rand.Reader, m.sig, h[:])
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("X-Machine", m.id)
	req.Header.Set("X-Time", t)
	req.Header.Set("X-Sig", kernel.B64.EncodeToString(sig))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	m.g.mch.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), rec.Header()
}

func (m *vmach) json(method, path string, in any, out any) int {
	var b []byte
	if in != nil {
		b, _ = json.Marshal(in)
	}
	code, body, _ := m.call(method, path, b)
	if out != nil {
		json.Unmarshal(body, out)
	}
	return code
}

// grant: the grant the router holds for this machine (GET /m/grant)
func (m *vmach) grant() kernel.Grant {
	var out struct {
		Grant *kernel.SignedDoc `json:"grant"`
	}
	if code := m.json("GET", "/m/grant", nil, &out); code != 200 || out.Grant == nil {
		m.g.t.Fatalf("no grant for %s (%d)", m.id, code)
	}
	gr, err := kernel.OpenGrant(m.g.w.Roster, *out.Grant, kernel.RoleMover, kernel.RoleMerger)
	if err != nil {
		m.g.t.Fatal(err)
	}
	return gr
}

func (m *vmach) grantDoc() kernel.SignedDoc {
	var out struct {
		Grant *kernel.SignedDoc `json:"grant"`
	}
	m.json("GET", "/m/grant", nil, &out)
	if out.Grant == nil {
		m.g.t.Fatal("no grant")
	}
	return *out.Grant
}

// pull: the secrets answer for the grant the machine holds, opened with its key
func (m *vmach) pull() (map[string]map[string]string, map[string]any) {
	var d kernel.SignedDoc
	if code := m.json("POST", "/m/secrets/pull", map[string]any{"grant": m.grantDoc()}, &d); code != 200 {
		m.g.t.Fatalf("pull: %d", code)
	}
	var a map[string]any
	if err := kernel.Open(m.g.w.Roster.Secrets, d, &a); err != nil {
		var loose map[string]any
		json.Unmarshal([]byte(d.Payload), &loose)
		a = loose
	}
	sb, _ := json.Marshal(a["sealed"])
	var s kernel.Sealed
	json.Unmarshal(sb, &s)
	plain, err := kernel.OpenSealed(m.enc, s, "jarvis2/secrets")
	if err != nil {
		m.g.t.Fatal(err)
	}
	vals := map[string]map[string]string{}
	json.Unmarshal(plain, &vals)
	return vals, a
}

// commands: one poll of the command channel (short wait; the outbox GET /m/commands serves)
func (m *vmach) commands() commandsAnswer { return m.g.r.out(m.id).next(50*time.Millisecond, nil) }

// hasWord: the answer carries the word
func hasWord(a commandsAnswer, w string) bool {
	for _, x := range a.Commands {
		if x == w {
			return true
		}
	}
	return false
}

// boot: what the guard does to boot (the chain checked against the roster, the status report that marks it booted)
func (m *vmach) boot() {
	t := m.g.t
	var chain struct {
		Spawn  kernel.NotarizedCert `json:"spawn"`
		Source kernel.NotarizedCert `json:"source"`
	}
	if code := m.json("GET", "/m/boot", nil, &chain); code != 200 {
		t.Fatalf("boot chain: %d", code)
	}
	s, err := kernel.OpenNotarized(m.g.w.Roster, chain.Spawn)
	if err != nil || s.Successor.ID != m.id {
		t.Fatalf("spawn cert: %v %+v", err, s)
	}
	if _, err := kernel.OpenNotarized(m.g.w.Roster, chain.Source); err != nil {
		t.Fatal(err)
	}
	m.pull()
	m.json("POST", "/m/status", map[string]string{"raw": "", "appTitle": ""}, nil)
}

// snapshot: the machine uploads a signed final snapshot
func (m *vmach) snapshot(data []byte) string {
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])
	h := sha256.Sum256([]byte(hexsum))
	ssig, _ := ecdsa.SignASN1(rand.Reader, m.sig, h[:])
	code, out, _ := m.call("POST", "/m/snapshot", data, "X-Snapshot-Sig", kernel.B64.EncodeToString(ssig))
	if code != 200 {
		m.g.t.Fatalf("snapshot: %d %s", code, out)
	}
	return hexsum
}

func newECDSA() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
