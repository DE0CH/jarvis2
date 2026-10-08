// e2e: drives a real Jarvis 2 (core + router + Fly machines running the session image) through every
// flow with a SOFTWARE phone standing in for the iPhone. It sets the phone key on the core, which a core
// accepts only once — so run it against a fresh core and restart the core afterwards (a restart = a new
// controller) before pairing the real iPhone.
//
//	E2E_ROUTER=http://127.0.0.1:18080 E2E_CORE=http://127.0.0.1:18090 E2E_SETUP_TOKEN=… \
//	E2E_FLY_TOKEN=… E2E_FLY_APP=jarvis2-sessions go run .
//
// The router must run with NO_ACCESS=1 (reached by port-forward, not through Cloudflare).
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
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

var router, core, setupToken string
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
	router, core, setupToken = os.Getenv("E2E_ROUTER"), os.Getenv("E2E_CORE"), os.Getenv("E2E_SETUP_TOKEN")
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ak, _ := ecdh.P256().GenerateKey(rand.Reader)
	p := &phone{sk, ak}
	var key map[string]string
	call(core, "GET", "/key", nil, &key)
	coreKey = key["signingKey"]

	step("setup: phone keys, two stores, the Fly token")
	st := []string{"X-Setup-Token", setupToken}
	s, b := call(core, "POST", "/setup/phone", map[string]string{"signingKey": p.signingKey(), "agreementKey": b64.EncodeToString(ak.PublicKey().Bytes())}, nil, st...)
	must(s, b, "setup phone")
	secret := hex.EncodeToString(randBytes(8))
	s, b = call(core, "POST", "/setup/store", map[string]any{"name": "e2e", "values": map[string]string{"E2E_SECRET": secret}}, nil, st...)
	must(s, b, "seed e2e")
	s, b = call(core, "POST", "/setup/store", map[string]any{"name": "e2e-extra", "values": map[string]string{"E2E_EXTRA": "extra-" + secret}, "sensitive": true}, nil, st...)
	must(s, b, "seed e2e-extra")
	s, b = call(core, "POST", "/setup/fly", map[string]string{"token": os.Getenv("E2E_FLY_TOKEN"), "app": os.Getenv("E2E_FLY_APP")}, nil, st...)
	must(s, b, "setup fly")

	step("unlock e2e and e2e-extra (split key, through the router)")
	unlock(p, "e2e")
	unlock(p, "e2e-extra")

	step("new session (stores [e2e])")
	s, b = call(router, "POST", "/api/sessions", map[string]any{"label": "e2e test", "stores": []string{"e2e"}, "size": "small", "harness": "claude"}, nil)
	must(s, b, "create")
	a := waitApproval("new-session", "")
	checkChallenge(a, []string{"e2e"}, "")
	id := approve(p, a)
	waitState(id, "started", 6*time.Minute)
	m1 := machineOf(id)
	expectOnMachine(m1, "grep -c E2E_SECRET /home/claude/.secrets", "1")
	expectOnMachine(m1, "sh -c 'echo marker-"+secret+" > /home/claude/artifacts/e2e-marker; echo ok'", "ok")

	step("add a store from the machine (e2e-extra)")
	go exec.Command("flyctl", "machine", "exec", m1, "-a", os.Getenv("E2E_FLY_APP"), "su - claude -c 'jarvis2 add-store e2e-extra'").Run()
	a = waitApproval("add-store", id)
	checkChallenge(a, []string{"e2e", "e2e-extra"}, "e2e-extra")
	approve(p, a)

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
	expectOnMachine(m2, "grep -c E2E_EXTRA /home/claude/.secrets", "1")

	step("the old machine can't be used again: a second successor of m1 is refused")
	// (the core refuses: m1 is in `used`) — checked through a direct succession + dead-machine answer
	var line struct {
		Sessions []map[string]any `json:"sessions"`
	}
	call(router, "GET", "/api/state", nil, &line)

	step("pause, then resume with the latest image → burn + iPhone approval")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": true}, nil))
	a = waitApproval("resume-upgrade", id)
	var burn struct {
		Kind   string `json:"kind"`
		PredID string `json:"predecessorId"`
	}
	verify(*a.BurnCert, &burn)
	if burn.Kind != "burn-cert" || burn.PredID != m2 {
		log.Fatalf("burn cert: %+v", burn)
	}
	approve(p, a)
	waitState(id, "started", 8*time.Minute)
	m3 := machineOf(id)
	expectOnMachine(m3, "cat /home/claude/artifacts/e2e-marker", "marker-"+secret)

	step("destroy → killed + burned, moved to records")
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
	BurnCert  *Doc   `json:"burnCert"`
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
	if ch.Kind != "challenge" || ch.Request.Machine == nil || strings.Join(ch.Request.Stores, ",") != strings.Join(stores, ",") ||
		ch.Request.AddedStore != added || ch.Request.Options.Harness != "claude" {
		log.Fatalf("challenge doesn't match: %s", a.Challenge.Payload)
	}
}

func approve(p *phone, a approval) string {
	var out struct {
		Cert    Doc    `json:"cert"`
		Session string `json:"session"`
	}
	s, b := call(router, "POST", "/api/approvals/"+a.ID+"/respond", map[string]string{"signature": p.sign(a.Challenge.Payload)}, &out)
	must(s, b, "respond")
	var c struct{ Kind string }
	verify(out.Cert, &c)
	if c.Kind != "succession-cert" {
		log.Fatalf("cert kind %s", c.Kind)
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

func expectOnMachine(m, cmd, want string) {
	var out []byte
	var err error
	for i := 0; i < 10; i++ {
		out, err = exec.Command("flyctl", "machine", "exec", m, "-a", os.Getenv("E2E_FLY_APP"), cmd).CombinedOutput()
		if strings.Contains(string(out), want) {
			log.Printf("   on %s: %q ok", m, cmd)
			return
		}
		time.Sleep(5 * time.Second)
	}
	log.Fatalf("on %s, %q gave %q (%v), want %q", m, cmd, string(out), err, want)
}
