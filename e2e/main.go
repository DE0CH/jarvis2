// e2e: drives a real Jarvis 2 (core + router + Fly machines running the session image) through every
// flow with a SOFTWARE phone standing in for the iPhone. It sets the phone key on the core, which a core
// accepts only once — so run it against a fresh core and restart the core afterwards (a restart = a new
// controller) before pairing the real iPhone.
//
//	E2E_ROUTER=http://127.0.0.1:28080 E2E_CORE=http://127.0.0.1:28090 E2E_MASTER_KEY_FILE=testdata/master-test.pem E2E_BOX_PUB=… \
//	E2E_FLY_TOKEN=… E2E_FLY_APP=jarvis2-sessions go run .
//
// It plays the iPhone, recovery included, with the public TEST master key (e2e/testdata): run a core
// (MASTER_KEY = its public half, BOX_KEY_FILE = a throwaway box key) and a router (NO_ACCESS=1, WG_CONFIG = a
// WireGuard peer of the Fly org, the jarvis2-session-test image) locally, so the machines reach this router over
// Fly's private network as in production. infra/e2e.sh does all that.
package main

import (
	"bytes"
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
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var b64 = base64.StdEncoding

type Doc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

type phone struct {
	sig *ecdsa.PrivateKey
	agr *ecdh.PrivateKey
}

func (p *phone) signingKey() string {
	k, _ := p.sig.PublicKey.ECDH()
	return b64.EncodeToString(k.Bytes())
}

func (p *phone) sign(payload string) string {
	h := sha256.Sum256([]byte(payload))
	s, _ := ecdsa.SignASN1(rand.Reader, p.sig, h[:])
	return b64.EncodeToString(s)
}

var router, core string
var coreKey string

func call(base, method, path string, in any, out any, hdr ...string) (int, []byte) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, body)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == 200 {
		json.Unmarshal(b, out)
	}
	return resp.StatusCode, b
}

func must(status int, b []byte, what string) {
	if status != 200 {
		log.Fatalf("%s: HTTP %d %s", what, status, string(b))
	}
}

func verify(d Doc, out any) {
	kb, _ := b64.DecodeString(coreKey)
	pk, err := ecdh.P256().NewPublicKey(kb)
	if err != nil {
		log.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pk.Bytes())
	sig, _ := b64.DecodeString(d.Sig)
	h := sha256.Sum256([]byte(d.Payload))
	if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], sig) {
		log.Fatalf("a document isn't signed by the core: %.120s", d.Payload)
	}
	if out != nil {
		json.Unmarshal([]byte(d.Payload), out)
	}
}

func step(f string, a ...any) { log.Printf("== "+f, a...) }

func main() {
	log.SetFlags(log.Ltime)
	router, core = os.Getenv("E2E_ROUTER"), os.Getenv("E2E_CORE")
	pemb, err := os.ReadFile(os.Getenv("E2E_MASTER_KEY_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	master := parseKey(pemb)
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ak, _ := ecdh.P256().GenerateKey(rand.Reader)
	p := &phone{sk, ak}

	step("the core's identity, checked against the box key")
	var id0 map[string]string
	must2(call(router, "GET", "/api/core/identity", nil, &id0))
	if !verifyRaw(os.Getenv("E2E_BOX_PUB"), "jarvis2-core-identity "+id0["signingKey"]+" "+id0["agreementKey"], id0["boxSig"]) {
		log.Fatal("the core's identity isn't signed by the box key")
	}
	coreKey = id0["signingKey"]

	step("recovery: the master key vouches for the core and the phone; every store comes in")
	secret := hex.EncodeToString(randBytes(8))
	bundle, _ := json.Marshal(map[string]any{
		"stores": []map[string]any{
			{"name": "core", "values": map[string]string{"FLY_API_TOKEN": os.Getenv("E2E_FLY_TOKEN"), "FLY_APP": os.Getenv("E2E_FLY_APP")}},
			{"name": "e2e", "values": map[string]string{"E2E_SECRET": secret}},
			{"name": "e2e-extra", "values": map[string]string{"E2E_EXTRA": "extra-" + secret}},
		},
		"notSensitive": []string{"e2e"},
	})
	sum := sha256.Sum256(bundle)
	stmt, _ := json.Marshal(map[string]any{"kind": "recovery",
		"core":         map[string]string{"signingKey": id0["signingKey"], "agreementKey": id0["agreementKey"]},
		"phone":        map[string]string{"signingKey": p.signingKey(), "agreementKey": b64.EncodeToString(ak.PublicKey().Bytes())},
		"bundleSha256": hex.EncodeToString(sum[:])})
	h := sha256.Sum256(stmt)
	msig, _ := ecdsa.SignASN1(rand.Reader, master, h[:])
	var rec Doc
	must2(call(router, "POST", "/api/core/recover", map[string]any{"statement": string(stmt), "masterSig": b64.EncodeToString(msig),
		"bundle": sealTo(id0["agreementKey"], bundle, "jarvis2/recover")}, &rec))
	verify(rec, nil)

	step("stores: e2e not sensitive, e2e-extra sensitive; a created store is not; the upgrade is one-way")
	stores := func() map[string]bool {
		var d Doc
		must2(call(router, "POST", "/api/core/stores", map[string]string{"nonce": "n"}, &d))
		var l struct {
			Stores []struct {
				Name      string
				Sensitive bool
			}
		}
		verify(d, &l)
		m := map[string]bool{}
		for _, x := range l.Stores {
			m[x.Name] = x.Sensitive
		}
		return m
	}
	must2(call(router, "POST", "/api/core/stores/create", map[string]string{"name": "e2e-notes"}, nil))
	if st := stores(); st["e2e"] || !st["e2e-extra"] || st["e2e-notes"] {
		log.Fatalf("sensitivity: %v", st)
	}
	if _, ok := stores()["core"]; ok {
		log.Fatal("the Fly store is a session store")
	}
	must2(call(router, "POST", "/api/core/stores/mark-sensitive", map[string]string{"name": "e2e-notes"}, nil))
	if s, _ := call(router, "POST", "/api/core/stores/create", map[string]string{"name": "e2e-notes"}, nil); s == 200 {
		log.Fatal("re-created a sensitive store")
	}

	step("unlock e2e and e2e-extra (split key, through the router)")
	unlock(p, "e2e")
	unlock(p, "e2e-extra")

	step("new session (stores [e2e])")
	s, b := call(router, "POST", "/api/sessions", map[string]any{"label": "e2e test", "stores": []string{"e2e"}, "size": "small", "harness": "claude"}, nil)
	must(s, b, "create")
	a := waitApproval("new-session", "")
	checkChallenge(a, []string{"e2e"}, "")
	id := approve(p, a)
	waitState(id, "started", 6*time.Minute)
	m1 := machineOf(id)
	expectOnMachine(m1, "grep -c E2E_SECRET /home/claude/.secrets", "1")
	expectOnMachine(m1, "echo marker-"+secret+" > /home/claude/artifacts/e2e-marker && chown claude /home/claude/artifacts/e2e-marker && echo ok", "ok")

	step("grants: no shell without one; a phone grant opens it; the session's own allow list too")
	s, b = call(router, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": "echo hi"}, nil)
	if s == 200 {
		log.Fatalf("a shell without any grant: %s", b)
	}
	var draft struct{ Text string }
	must2(call(router, "POST", "/api/sessions/"+id+"/grants/draft", map[string]any{"holder": "terminal", "kind": "grant", "minutes": 10}, &draft))
	var grant struct{ ID string }
	must2(call(router, "POST", "/api/sessions/"+id+"/grants", map[string]string{"payload": draft.Text, "sig": p.sign(draft.Text)}, &grant))
	expectExec(id, "echo hi from $(whoami)", "hi from claude")
	must2(call(router, "DELETE", "/api/grants/"+grant.ID, nil, nil))
	expectOnMachine(m1, "su - claude -c 'jarvis2 allow terminal 1h' && echo ok", "ok")
	expectExec(id, "echo allowed", "allowed")
	expectOnMachine(m1, "su - claude -c 'jarvis2 allow --remove terminal' && echo ok", "ok")
	must2(call(router, "POST", "/api/sessions/"+id+"/grants/draft", map[string]any{"holder": "terminal", "kind": "rule", "until": time.Now().Add(24 * time.Hour)}, &draft))
	must2(call(router, "POST", "/api/sessions/"+id+"/grants", map[string]string{"payload": draft.Text, "sig": p.sign(draft.Text)}, &grant))

	step("add a store from the machine (e2e-extra)")
	go flyExec(m1, []string{"su", "-", "claude", "-c", "jarvis2 add-store e2e-extra"})
	a = waitApproval("add-store", id)
	checkChallenge(a, []string{"e2e", "e2e-extra"}, "e2e-extra")
	approve(p, a)
	expectOnMachine(m1, "for i in $(seq 1 30); do grep -q E2E_EXTRA /home/claude/.secrets && break; sleep 2; done; grep -c E2E_EXTRA /home/claude/.secrets", "1")

	step("downgrade in place: back to [e2e], new keys, the extra secret shredded")
	expectOnMachine(m1, "su - claude -c 'jarvis2 downgrade e2e' >/dev/null 2>&1 && grep -c E2E_SECRET /home/claude/.secrets && grep -c E2E_EXTRA /home/claude/.secrets || true", "1\n0")

	step("pause → paused (snapshot uploaded, machine killed)")
	s, b = call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil)
	must(s, b, "pause")
	waitState(id, "paused", 12*time.Minute)

	step("resume, same image → no approval (dead-machine responder), snapshot restored")
	s, b = call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil)
	must(s, b, "resume")
	waitState(id, "started", 8*time.Minute)
	m2 := machineOf(id)
	if m2 == m1 {
		log.Fatal("resume reused the old machine")
	}
	expectOnMachine(m2, "cat /home/claude/artifacts/e2e-marker", "marker-"+secret)
	expectOnMachine(m2, "grep -c E2E_EXTRA /home/claude/.secrets || true", "0")
	expectExec(id, "echo the rule still holds", "the rule still holds") // grants name the line, not the machine

	step("pause, then resume with the latest image → the iPhone approves first, then the machine starts")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": true}, nil))
	a = waitApproval("resume-upgrade", id)
	approve(p, a)
	waitState(id, "started", 8*time.Minute)
	m3 := machineOf(id)
	expectOnMachine(m3, "cat /home/claude/artifacts/e2e-marker", "marker-"+secret)

	step("destroy → killed + burned (a succession to the null image), moved to records")
	must2(call(router, "POST", "/api/sessions/"+id+"/destroy", nil, nil))
	deadline := time.Now().Add(5 * time.Minute)
	for {
		var recs struct {
			Records []map[string]any `json:"records"`
		}
		call(router, "GET", "/api/records", nil, &recs)
		if len(recs.Records) > 0 && recs.Records[0]["id"] == id {
			break
		}
		if time.Now().After(deadline) {
			log.Fatal("destroy didn't finish")
		}
		time.Sleep(3 * time.Second)
	}

	step("lock both stores; the unlocked list is signed and empty")
	var ul struct {
		Kind     string           `json:"kind"`
		Nonce    string           `json:"nonce"`
		Unlocked []map[string]any `json:"unlocked"`
	}
	for _, uid := range unlockIDs {
		var d Doc
		must2(call(router, "POST", "/api/core/lock", map[string]string{"id": uid}, &d))
	}
	var d Doc
	must2(call(router, "POST", "/api/core/unlocked", map[string]string{"nonce": "n-123"}, &d))
	verify(d, &ul)
	if ul.Nonce != "n-123" || len(ul.Unlocked) != 0 {
		log.Fatalf("unlocked list: %+v", ul)
	}
	log.Printf("E2E PASSED (machines %s → %s → %s)", m1, m2, m3)
}

func must2(s int, b []byte) { must(s, b, "request") }

// verifyRaw: an ECDSA P-256 signature (base64 DER) by a base64 x963 public key
func verifyRaw(pubB64, payload, sigB64 string) bool {
	kb, err := b64.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), kb)
	if x == nil {
		return false
	}
	sig, _ := b64.DecodeString(sigB64)
	h := sha256.Sum256([]byte(payload))
	return ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], sig)
}

func parseKey(pemBytes []byte) *ecdsa.PrivateKey {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		log.Fatal("E2E_SETUP_KEY_FILE: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatal("E2E_SETUP_KEY_FILE: not an EC key")
	}
	return ek
}

// sealTo: Sealed{e, data} to a P-256 public key (HKDF-SHA256 empty salt, AES-256-GCM nonce||ct||tag)
func sealTo(recipient string, plain []byte, info string) map[string]string {
	rb, _ := b64.DecodeString(recipient)
	R, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		log.Fatal(err)
	}
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	x, _ := e.ECDH(R)
	k, _ := hkdf.Key(sha256.New, x, nil, info, 32)
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	nonce := randBytes(g.NonceSize())
	return map[string]string{"e": b64.EncodeToString(e.PublicKey().Bytes()), "data": b64.EncodeToString(append(nonce, g.Seal(nil, nonce, plain, nil)...))}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

var unlockIDs []string

func unlock(p *phone, store string) {
	var d Doc
	must2(call(router, "POST", "/api/core/unlock/begin", map[string]string{"store": store}, &d))
	var ub struct{ Kind, Pending, Store, E, T string }
	verify(d, &ub)
	if ub.Kind != "unlock-begin" || ub.Store != store {
		log.Fatalf("unlock-begin: %+v", ub)
	}
	eb, _ := b64.DecodeString(ub.E)
	E, _ := ecdh.P256().NewPublicKey(eb)
	x, _ := p.agr.ECDH(E) // the Enclave returns x(p·E)
	tb, _ := b64.DecodeString(ub.T)
	T, _ := ecdh.P256().NewPublicKey(tb)
	r, _ := ecdh.P256().GenerateKey(rand.Reader)
	x2, _ := r.ECDH(T)
	k, _ := hkdf.Key(sha256.New, x2, nil, "jarvis2/unlock-share", 32)
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	nonce := randBytes(g.NonceSize())
	share := map[string]string{"e": b64.EncodeToString(r.PublicKey().Bytes()), "data": b64.EncodeToString(append(nonce, g.Seal(nil, nonce, x, nil)...))}
	must2(call(router, "POST", "/api/core/unlock/finish", map[string]any{"pending": ub.Pending, "share": share}, &d))
	var uf struct{ Kind, ID, Store string }
	verify(d, &uf)
	if uf.Kind != "unlocked" {
		log.Fatalf("unlock-finish: %+v", uf)
	}
	unlockIDs = append(unlockIDs, uf.ID)
}

type approval struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Session   string `json:"session"`
	Challenge *Doc   `json:"challenge"`
}

func waitApproval(kind, session string) approval {
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		var out struct {
			Approvals []approval `json:"approvals"`
		}
		call(router, "GET", "/api/approvals", nil, &out)
		for _, a := range out.Approvals {
			if a.Kind == kind && (session == "" || a.Session == session) {
				return a
			}
		}
		time.Sleep(3 * time.Second)
	}
	dumpState()
	log.Fatalf("no %s approval", kind)
	return approval{}
}

// the checks the iPhone makes before signing (docs/API.md)
func checkChallenge(a approval, stores []string, added string) {
	var ch struct {
		Kind    string `json:"kind"`
		Request struct {
			Machine    *map[string]any `json:"machine"`
			Stores     []string        `json:"stores"`
			AddedStore string          `json:"addedStore"`
			Options    struct{ Harness string }
		} `json:"request"`
	}
	verify(*a.Challenge, &ch)
	if ch.Kind != "challenge" || (added != "") != (ch.Request.Machine != nil) || strings.Join(ch.Request.Stores, ",") != strings.Join(stores, ",") ||
		ch.Request.AddedStore != added || ch.Request.Options.Harness != "claude" {
		log.Fatalf("challenge doesn't match: %s", a.Challenge.Payload)
	}
}

func approve(p *phone, a approval) string {
	var out struct {
		Answer  Doc    `json:"answer"`
		Session string `json:"session"`
	}
	s, b := call(router, "POST", "/api/approvals/"+a.ID+"/respond", map[string]string{"signature": p.sign(a.Challenge.Payload)}, &out)
	must(s, b, "respond")
	var c struct{ Kind string }
	verify(out.Answer, &c)
	if c.Kind != "approval" && c.Kind != "succession-cert" { // a new line: an approval; adding a store: the cert at once
		log.Fatalf("answer kind %s", c.Kind)
	}
	return out.Session
}

func session(id string) map[string]any {
	var st struct {
		Sessions []map[string]any `json:"sessions"`
	}
	call(router, "GET", "/api/state", nil, &st)
	for _, s := range st.Sessions {
		if s["id"] == id {
			return s
		}
	}
	return nil
}

func waitState(id, want string, d time.Duration) {
	deadline := time.Now().Add(d)
	last := ""
	for time.Now().Before(deadline) {
		s := session(id)
		if s != nil {
			cur := fmt.Sprint(s["state"])
			if cur != last {
				log.Printf("   %s: %s %v", id, cur, s["error"])
				last = cur
			}
			if cur == want {
				return
			}
			if cur == "failed" {
				log.Fatalf("session failed: %v", s["error"])
			}
		}
		time.Sleep(3 * time.Second)
	}
	dumpState()
	log.Fatalf("%s never reached %s", id, want)
}

func machineOf(id string) string { return fmt.Sprint(session(id)["machineId"]) }

func dumpState() {
	_, b := call(router, "GET", "/api/state", nil, nil)
	log.Printf("state: %.2000s", string(b))
}

// flyExec: a command on a machine through the Machines API → its stdout and exit code
func flyExec(m string, cmd []string) (string, int, error) {
	body, _ := json.Marshal(map[string]any{"command": cmd, "timeout": 60})
	req, _ := http.NewRequest("POST", "https://api.machines.dev/v1/apps/"+os.Getenv("E2E_FLY_APP")+"/machines/"+m+"/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("E2E_FLY_TOKEN"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", -1, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", -1, fmt.Errorf("HTTP %d %s", resp.StatusCode, b)
	}
	var out struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	json.Unmarshal(b, &out)
	return out.Stdout, out.ExitCode, nil
}

// expectOnMachine: exit 0 and stdout (trimmed) exactly `want`
func expectOnMachine(m, cmd, want string) {
	var out string
	var code int
	var err error
	for i := 0; i < 10; i++ {
		out, code, err = flyExec(m, []string{"sh", "-c", cmd})
		if err == nil && code == 0 && strings.TrimSpace(out) == want {
			log.Printf("   on %s: %q → %q ok", m, cmd, want)
			return
		}
		time.Sleep(5 * time.Second)
	}
	log.Fatalf("on %s, %q gave %q (exit %d, %v), want %q", m, cmd, out, code, err, want)
}

// expectExec: a command through the router's grant relay (holder "terminal")
func expectExec(id, cmd, want string) {
	var res struct {
		Stdout string
		Code   int
	}
	s, b := call(router, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": cmd, "timeout": 30}, &res)
	must(s, b, "exec "+cmd)
	if strings.TrimSpace(res.Stdout) != want || res.Code != 0 {
		log.Fatalf("exec %q: got %q (code %d), want %q", cmd, res.Stdout, res.Code, want)
	}
}
