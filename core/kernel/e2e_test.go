package kernel_test

// One session's whole life through every kernel part, over HTTP (each part its own server holding only its own key):
// new session, spawn, pull, adding a terminal to the running machine (identity edge + merge), pause (kill), resume
// (spawn from the kill's source), end (burn), and the refusals along the way.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

type part struct {
	t   *testing.T
	url string
}

// call: POST path with body; out gets the answer; the error carries the status of a refusal
func (p part) call(path string, body any, out any) error {
	p.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(p.url+path, "application/json", bytes.NewReader(b))
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d %s", path, resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		p.t.Fatalf("%s: %v", path, err)
	}
	return nil
}

func (p part) must(path string, body any, out any) {
	p.t.Helper()
	if err := p.call(path, body, out); err != nil {
		p.t.Fatal(err)
	}
}

func serve(t *testing.T, s *kernel.Signer, routes map[string]kernel.Route) part {
	srv := httptest.NewServer(kernel.Handler(s, routes))
	t.Cleanup(srv.Close)
	return part{t, srv.URL}
}

type kernelParts struct {
	w                                                                      *ktest.World
	fly                                                                    *spawner.FakeFly
	sec                                                                    *secrets.Secrets
	notary, notarizer, mover, merger, identity, gullible, spawner, secrets part
}

func startKernel(t *testing.T) kernelParts {
	w := ktest.New(t)
	k := kernelParts{w: w, fly: spawner.NewFakeFly()}
	nz, _ := notarizer.New(w.Keys["notarizer"], w.Roster, "")
	sp, _ := spawner.New(w.Keys["spawner"], w.Roster, k.fly, "http://router.internal:8081")
	k.sec, _ = secrets.New(w.Keys["secrets"], w.Roster, secrets.NewFakeGitHub())
	k.notary = serve(t, w.Keys["notary"], notary.New(w.Keys["notary"], nil).Routes())
	k.notarizer = serve(t, w.Keys["notarizer"], nz.Routes())
	k.mover = serve(t, w.Keys["mover"], mover.New(w.Keys["mover"], w.Roster).Routes())
	k.merger = serve(t, w.Keys["merger"], merger.New(w.Keys["merger"], w.Roster).Routes())
	k.identity = serve(t, w.Keys["identity"], identitysigner.New(w.Keys["identity"]).Routes())
	k.gullible = serve(t, w.Keys["gullible"], gullible.New(w.Keys["gullible"]).Routes())
	k.spawner = serve(t, w.Keys["spawner"], sp.Routes())
	k.secrets = serve(t, w.Keys["secrets"], k.sec.Routes())
	return k
}

// notarize: the router's two calls — a challenge from the log notary, then the notarizer
func (k kernelParts) notarize(cert kernel.SignedDoc) (kernel.NotarizedCert, error) {
	var ch kernel.SignedDoc
	k.notary.must("/challenge", map[string]string{"subject": cert.ID(), "about": "succession"}, &ch)
	var nc kernel.NotarizedCert
	err := k.notarizer.call("/notarize", map[string]any{"cert": cert, "challenge": ch}, &nc)
	return nc, err
}

func (k kernelParts) mustNotarize(t *testing.T, cert kernel.SignedDoc) kernel.NotarizedCert {
	t.Helper()
	nc, err := k.notarize(cert)
	if err != nil {
		t.Fatal(err)
	}
	return nc
}

func (k kernelParts) move(t *testing.T, g kernel.SignedDoc, nc kernel.NotarizedCert) kernel.SignedDoc {
	t.Helper()
	var out kernel.SignedDoc
	k.mover.must("/move", map[string]any{"grant": g, "cert": nc}, &out)
	return out
}

func (k kernelParts) spawn(t *testing.T, nc kernel.NotarizedCert) (kernel.NotarizedCert, kernel.Object) {
	t.Helper()
	var created kernel.SignedDoc
	k.spawner.must("/spawn", map[string]any{"cert": nc, "region": "lhr", "size": "small"}, &created)
	var c struct{ Machine string }
	json.Unmarshal([]byte(created.Payload), &c)
	var cert kernel.SignedDoc
	k.spawner.must("/init", map[string]string{"machine": c.Machine}, &cert)
	var s kernel.Succession
	ktest.Payload(t, cert, &s)
	return k.mustNotarize(t, cert), s.Successor
}

// pull: the secrets answer for a grant, opened with the key given (nil: only the answer)
func (k kernelParts) pull(t *testing.T, g kernel.SignedDoc, enc *ecdh.PrivateKey) (map[string]any, map[string]map[string]string, error) {
	t.Helper()
	var d kernel.SignedDoc
	k.secrets.must("/pull", map[string]any{"grant": g}, &d)
	var a map[string]any
	json.Unmarshal([]byte(d.Payload), &a)
	if enc == nil {
		return a, nil, nil
	}
	sb, _ := json.Marshal(a["sealed"])
	var s kernel.Sealed
	json.Unmarshal(sb, &s)
	plain, err := kernel.OpenSealed(enc, s, "jarvis2/secrets")
	if err != nil {
		return a, nil, err
	}
	vals := map[string]map[string]string{}
	json.Unmarshal(plain, &vals)
	return a, vals, nil
}

// setUpSecrets: Reset-style claim with one store written and unlocked (the phone's side in software)
func setUpSecrets(t *testing.T, k kernelParts) {
	id := kernel.MakeIdentity("secrets", k.w.Keys["secrets"], k.sec.AgreementKey(), nil)
	master, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	phoneAgr, _ := ecdh.P256().GenerateKey(rand.Reader)
	pub := func(k *ecdsa.PrivateKey) string {
		e, _ := k.PublicKey.ECDH()
		return kernel.B64.EncodeToString(e.Bytes())
	}
	sign := func(k *ecdsa.PrivateKey, s string) string {
		h := sha256.Sum256([]byte(s))
		sig, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
		return kernel.B64.EncodeToString(sig)
	}
	bundle := []byte(`{"format":"keys"}`)
	sum := sha256.Sum256(bundle)
	st, _ := json.Marshal(map[string]any{"kind": "claim", "master": pub(master),
		"core":         map[string]string{"signingKey": id.SigningKey, "agreementKey": id.AgreementKey},
		"phone":        map[string]string{"signingKey": k.w.Roster.Phone, "agreementKey": kernel.B64.EncodeToString(phoneAgr.PublicKey().Bytes())},
		"bundleSha256": hex.EncodeToString(sum[:])})
	sealed, _ := kernel.SealTo(id.AgreementKey, bundle, "jarvis2/claim")
	var out kernel.SignedDoc
	k.secrets.must("/claim", map[string]any{"statement": string(st), "masterSig": sign(master, string(st)), "bundle": sealed}, &out)
	// the setup session writes CLAUDE_CREDENTIALS into "claude": wrapped to P + K (store_key), live copy to secrets
	var skDoc kernel.SignedDoc
	k.secrets.must("/store-key", map[string]string{"phone": kernel.B64.EncodeToString(phoneAgr.PublicKey().Bytes())}, &skDoc)
	var sk struct{ StoreKey string }
	json.Unmarshal([]byte(skDoc.Payload), &sk)
	C, _ := kernel.B64.DecodeString(sk.StoreKey)
	dk := make([]byte, 32)
	rand.Read(dk)
	wrapped, _ := secrets.WrapToPoint(C, dk)
	live, _ := kernel.SealTo(id.AgreementKey, []byte("login-1"), secrets.LiveInfo("claude", "CLAUDE_CREDENTIALS"))
	k.secrets.must("/stores/write-key", map[string]any{"store": "claude", "key": "CLAUDE_CREDENTIALS", "wrapped": wrapped,
		"data": kernel.B64.EncodeToString(kernel.GCMSeal(dk, []byte("login-1"), secrets.KeyAAD("claude", "CLAUDE_CREDENTIALS"))),
		"live": live, "writer": "router"}, &out)
	// the phone unlocks it
	var begin kernel.SignedDoc
	k.secrets.must("/unlock/begin", map[string]string{"store": "claude"}, &begin)
	var b struct {
		Pending, T string
		Keys       []struct{ Key, E string }
	}
	json.Unmarshal([]byte(begin.Payload), &b)
	shares := map[string]kernel.Sealed{}
	for _, key := range b.Keys {
		eb, _ := kernel.B64.DecodeString(key.E)
		E, _ := ecdh.P256().NewPublicKey(eb)
		x, _ := phoneAgr.ECDH(E)
		shares[key.Key], _ = kernel.SealTo(b.T, x, "jarvis2/unlock-share")
	}
	k.secrets.must("/unlock/finish", map[string]any{"pending": b.Pending, "shares": shares}, &out)
}

func TestASessionsWholeLife(t *testing.T) {
	k := startKernel(t)
	w := k.w
	setUpSecrets(t, k)
	top := w.RootGrant(t) // ⊤ on the sink, the root key's one grant

	// new session: the phone signs (sink, source-x, P); notarized; ⊤ moved along it
	src := ktest.Source(ktest.Image, `{"harness":"claude","permissionMode":"auto","title":"t"}`)
	P := ktest.P([]string{"store:claude"}, "session:s1")
	nc1 := k.mustNotarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), src, P))
	g1 := k.move(t, top, nc1)

	// spawn from it; the grant follows to the machine
	nc2, M := k.spawn(t, nc1)
	g2 := k.move(t, g1, nc2)
	fm := k.fly.Machines[M.ID]
	if _, vals, err := k.pull(t, g2, fm.Enc); err != nil || vals["claude"]["CLAUDE_CREDENTIALS"] != "login-1" {
		t.Fatalf("pull on the machine: %v %v", vals, err)
	}
	// a second spawn of source-x: the spawner refuses, and the phone's (source-x, M') isn't notarized
	if err := k.spawner.call("/spawn", map[string]any{"cert": nc1, "region": "lhr", "size": "small"}, &kernel.SignedDoc{}); err == nil {
		t.Fatal("source-x spawned twice")
	}
	if _, err := k.notarize(w.Cert(t, "phone", "phone", src, ktest.NewMachine(t, "other").Obj, kernel.Top())); err == nil {
		t.Fatal("a second successor of source-x notarized")
	}

	// adding a terminal: (sink, source-a, P_add) and (source-a, M, ⊤) by the phone; M's main grant moved along
	// (M, M, (everything, {until:T})) so the conditions match; merged
	add := ktest.Source("", "")
	Padd := ktest.P([]string{"shell"}, "session:s1", "until:2026-10-14T12:10Z")
	ga := k.move(t, top, k.mustNotarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), add, Padd)))
	ga = k.move(t, ga, k.mustNotarize(t, w.Cert(t, "phone", "phone", add, M, kernel.Top())))
	var idCert kernel.SignedDoc
	k.identity.must("/sign", map[string]any{"machine": M, "allowed": kernel.Everything(), "conditions": kernel.CanonConditions("until:2026-10-14T12:10Z")}, &idCert)
	gNarrow := k.move(t, g2, k.mustNotarize(t, idCert))
	var merged kernel.SignedDoc
	if err := k.merger.call("/merge", map[string]any{"a": g2, "b": ga}, &merged); err == nil {
		t.Fatal("merged grants with different conditions")
	}
	k.merger.must("/merge", map[string]any{"a": gNarrow, "b": ga}, &merged)
	mg, err := kernel.OpenGrant(w.Roster, merged, "merger")
	if err != nil || !mg.Allowed.Equal(kernel.Only("shell", "store:claude")) || mg.Machine != M {
		t.Fatalf("%v %+v", err, mg)
	}
	// the gullible signer can't hand a source a machine
	var gcert kernel.SignedDoc
	k.gullible.must("/sign", map[string]any{"predecessor": ktest.Source("", ""), "successor": M, "allowed": kernel.Everything(), "conditions": []string{}}, &gcert)
	if _, err := k.notarize(gcert); err == nil {
		t.Fatal("a gullible (source, M) notarized")
	}

	// pause: kill M with its snapshot; the main grant moves to the fresh source, where it seals to nobody
	sum := strings.Repeat("ab", 32)
	h := sha256.Sum256([]byte(sum))
	priv, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), fm.Sig.Bytes())
	ssig, _ := ecdsa.SignASN1(rand.Reader, priv, h[:])
	var killCert kernel.SignedDoc
	k.spawner.must("/kill", map[string]any{"cert": nc2, "snapshot": map[string]string{"sha256": sum, "sig": kernel.B64.EncodeToString(ssig)}}, &killCert)
	nc3 := k.mustNotarize(t, killCert)
	gy := k.move(t, g2, nc3)
	var ks kernel.Succession
	ktest.Payload(t, killCert, &ks)
	if ks.Successor.Snapshot != sum || ks.Successor.Settings != src.Settings {
		t.Fatalf("%+v", ks.Successor)
	}
	if _, _, err := k.pull(t, gy, fm.Enc); err == nil {
		t.Fatal("a grant on a source opened with the old machine's key")
	}
	// the terminal grant on the dead machine stays on it (a machine stays whatever is signed about it), and pulls
	// nothing new for anyone alive: it is sealed to M's key

	// resume: spawn from the kill's source
	nc4, M2 := k.spawn(t, nc3)
	g4 := k.move(t, gy, nc4)
	if _, vals, err := k.pull(t, g4, k.fly.Machines[M2.ID].Enc); err != nil || vals["claude"]["CLAUDE_CREDENTIALS"] != "login-1" {
		t.Fatalf("pull after resume: %v %v", vals, err)
	}
	// the grant is never wider than the phone's P
	if g, _ := kernel.OpenGrant(w.Roster, g4, "mover"); !g.Pair().Leq(P) {
		t.Fatal("wider than P")
	}

	// end: kill M2, burn the source; it is never continued
	var kill2 kernel.SignedDoc
	k.spawner.must("/kill", map[string]any{"cert": nc4}, &kill2)
	nc5 := k.mustNotarize(t, kill2)
	var ks2 kernel.Succession
	ktest.Payload(t, kill2, &ks2)
	var burn kernel.SignedDoc
	k.gullible.must("/sign", map[string]any{"predecessor": ks2.Successor, "successor": ktest.SinkObj(), "allowed": kernel.Everything(), "conditions": []string{}}, &burn)
	k.mustNotarize(t, burn)
	var created kernel.SignedDoc
	k.spawner.must("/spawn", map[string]any{"cert": nc5, "region": "lhr", "size": "small"}, &created) // the spawner doesn't know about burns…
	var c struct{ Machine string }
	json.Unmarshal([]byte(created.Payload), &c)
	var late kernel.SignedDoc
	k.spawner.must("/init", map[string]string{"machine": c.Machine}, &late)
	if _, err := k.notarize(late); err == nil { // …the notarizer does: that machine never gets a grant
		t.Fatal("a burned source continued")
	}
	// (machine, sink) burns nothing: no row takes it except root's
	var mburn kernel.SignedDoc
	k.gullible.must("/sign", map[string]any{"predecessor": M2, "successor": ktest.SinkObj(), "allowed": kernel.Everything(), "conditions": []string{}}, &mburn)
	if _, err := k.notarize(mburn); err == nil {
		t.Fatal("a machine burned")
	}
}

// Every part has exactly its own routes (GET /identity is added by kernel.Serve)
func TestEachPartHasOnlyItsOwnRoutes(t *testing.T) {
	w := ktest.New(t)
	nz, _ := notarizer.New(w.Keys["notarizer"], w.Roster, "")
	sp, _ := spawner.New(w.Keys["spawner"], w.Roster, spawner.NewFakeFly(), "")
	sec, _ := secrets.New(w.Keys["secrets"], w.Roster, secrets.NewFakeGitHub())
	want := map[string][]string{
		"notary":    {"POST /challenge"},
		"notarizer": {"POST /notarize", "GET /table"},
		"mover":     {"POST /move"},
		"merger":    {"POST /merge"},
		"identity":  {"POST /sign"},
		"gullible":  {"POST /sign"},
		"spawner":   {"POST /fly-token", "POST /spawn", "POST /init", "POST /kill"},
	}
	got := map[string]map[string]kernel.Route{
		"notary": notary.New(w.Keys["notary"], nil).Routes(), "notarizer": nz.Routes(), "mover": mover.New(w.Keys["mover"], w.Roster).Routes(),
		"merger": merger.New(w.Keys["merger"], w.Roster).Routes(), "identity": identitysigner.New(w.Keys["identity"]).Routes(),
		"gullible": gullible.New(w.Keys["gullible"]).Routes(), "spawner": sp.Routes(),
	}
	for name, routes := range want {
		if len(got[name]) != len(routes) {
			t.Fatalf("%s: %d routes", name, len(got[name]))
		}
		for _, r := range routes {
			if got[name][r] == nil {
				t.Fatalf("%s: no %s", name, r)
			}
		}
	}
	// secrets has no route that takes a cert, a carry blob or an unlock "for" a session
	for r := range sec.Routes() {
		for _, gone := range []string{"carry", "certify", "succession", "approve", "pull-secrets", "fly-token"} {
			if strings.Contains(r, gone) {
				t.Fatalf("secrets has %s", r)
			}
		}
	}
}
