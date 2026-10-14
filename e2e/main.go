// e2e: drives a real Jarvis 2 (the eight kernel parts + the router + Fly machines running the session image) through
// every flow with a SOFTWARE phone standing in for the iPhone. It sets secrets up (a Recover with test stores), which an
// empty secrets accepts once — so run it against kernel parts of its own, never production's.
//
//	E2E_ROUTER=http://127.0.0.1:28080 E2E_ROSTER_FILE=… E2E_PHONE_KEY_FILE=… E2E_ROOT_KEY_FILE=… \
//	E2E_MASTER_KEY_FILE=testdata/master-test.pem E2E_BOX_PUB=… E2E_FLY_TOKEN=… go run .
//
// It plays the iPhone (its signing key is the roster's `phone`), the root key (the roster's `root`: it signs ⊤ on the
// sink once) and the Recover, with the public TEST master key (e2e/testdata). infra/e2e.sh runs the kernel parts (each
// with its own throwaway key, one throwaway box key, a roster naming them and the test phone and root keys) and a
// router (NO_ACCESS=1, WG_CONFIG = a WireGuard peer of the Fly org, the session image) locally, so the machines reach
// this router over Fly's private network as in production.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

var b64 = base64.StdEncoding

// Doc: every signed document (core/kernel SignedDoc)
type Doc = kernel.SignedDoc

// phone: the software iPhone — its signing key (the roster's phone) and its agreement key (named in the claim)
type phone struct {
	sig *kernel.Signer
	agr *ecdh.PrivateKey
}

func (p *phone) signingKey() string { return p.sig.PublicKey() }

func (p *phone) sign(payload string) string {
	s, err := p.sig.Sign([]byte(payload))
	if err != nil {
		log.Fatal(err)
	}
	return s
}

var router string
var roster kernel.Roster

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

func must2(s int, b []byte) { must(s, b, "request") }

// verifyBy: d is signed by the key pub (a part's, from the roster); its payload into out
func verifyBy(pub, what string, d Doc, out any) {
	if !kernel.Verify(pub, []byte(d.Payload), d.Sig) {
		log.Fatalf("a document isn't signed by %s: %.160s", what, d.Payload)
	}
	if out != nil {
		json.Unmarshal([]byte(d.Payload), out)
	}
}

// verify: signed by secrets (most documents the test reads)
func verify(d Doc, out any) { verifyBy(roster.Secrets, "secrets", d, out) }

func step(f string, a ...any) { log.Printf("== "+f, a...) }

func readFile(env string) []byte {
	b, err := os.ReadFile(os.Getenv(env))
	if err != nil {
		log.Fatalf("%s: %v", env, err)
	}
	return b
}

func signerFrom(env string) *kernel.Signer {
	s, err := kernel.SignerFromPEM(readFile(env))
	if err != nil {
		log.Fatalf("%s: %v", env, err)
	}
	return s
}

// partRoles: the eight parts, by roster role, with what each must hold
var partRoles = []string{"notary", "notarizer", "mover", "merger", "identity", "gullible", "spawner", "secrets"}

func rosterKey(role string) string {
	return map[string]string{"notary": roster.Notary, "notarizer": roster.Notarizer, "mover": roster.Mover, "merger": roster.Merger,
		"identity": roster.Identity, "gullible": roster.Gullible, "spawner": roster.Spawner, "secrets": roster.Secrets}[role]
}

func main() {
	log.SetFlags(log.Ltime)
	router = os.Getenv("E2E_ROUTER")
	if err := json.Unmarshal(readFile("E2E_ROSTER_FILE"), &roster); err != nil {
		log.Fatalf("E2E_ROSTER_FILE: %v", err)
	}
	master := parseKey(readFile("E2E_MASTER_KEY_FILE"))
	root := signerFrom("E2E_ROOT_KEY_FILE")
	ak, _ := ecdh.P256().GenerateKey(rand.Reader)
	p := &phone{signerFrom("E2E_PHONE_KEY_FILE"), ak}
	if p.signingKey() != roster.Phone || root.PublicKey() != roster.Root {
		log.Fatal("the test's phone and root keys aren't the roster's")
	}
	serveStandIns()        // nojarvis1.go: search, the watch runner and the Storage Box, stood in for
	go blackholeMachines() // nojarvis1.go: Jarvis 1 out of every session machine's reach

	step("the kernel's identities: every part answers with the roster's key, vouched for by the box key; secrets is empty")
	ids := map[string]*kernel.Identity{}
	must2(call(router, "GET", "/api/kernel/identities", nil, &ids))
	for _, role := range partRoles {
		id := ids[role]
		if id == nil || id.SigningKey != rosterKey(role) {
			log.Fatalf("part %s: %+v isn't the roster's", role, id)
		}
		if !verifyRaw(os.Getenv("E2E_BOX_PUB"), kernel.IdentityText(role, id.SigningKey, id.AgreementKey), id.BoxSig) {
			log.Fatalf("part %s's identity isn't signed by the box key", role)
		}
	}
	secretsID, spawnerID := ids["secrets"], ids["spawner"]
	var sd Doc
	must2(call(router, "POST", "/api/secrets/state", map[string]any{}, &sd))
	var state struct{ Kind, Master string }
	verify(sd, &state)
	if state.Kind != "secrets-state" || state.Master != "" {
		log.Fatalf("not an empty secrets: %+v", state)
	}

	step("the root key's ⊤ on the sink, kept by the router (the app makes it once, behind the root-key warning)")
	rg, err := kernel.Sign(root, kernel.RootGrant())
	if err != nil {
		log.Fatal(err)
	}
	must2(call(router, "PUT", "/api/kernel/root-grant", rg, nil))
	var rgBack Doc
	must2(call(router, "GET", "/api/kernel/root-grant", nil, &rgBack))
	if rgBack.Payload != rg.Payload {
		log.Fatal("the router serves another root grant")
	}

	step("the spawner's Fly token, sealed to the spawner's agreement key (the setup session's /setup/fly-token)")
	tok, _ := json.Marshal(map[string]string{"FLY_API_TOKEN": os.Getenv("E2E_FLY_TOKEN")})
	var ft Doc
	must2(call(router, "POST", "/setup/fly-token", map[string]any{"sealed": sealTo(spawnerID.AgreementKey, tok, "jarvis2/fly-token")}, &ft))
	var ftk struct{ Kind string }
	verifyBy(roster.Spawner, "the spawner", ft, &ftk)
	if ftk.Kind != "fly-token-set" {
		log.Fatalf("fly-token: %s", ft.Payload)
	}

	step("Recover: the master key claims secrets, naming secrets and the phone; every store comes in, wrapped by the app")
	phoneAgreement := b64.EncodeToString(ak.PublicKey().Bytes())
	var skd Doc
	must2(call(router, "POST", "/api/secrets/store-key", map[string]string{"phone": phoneAgreement}, &skd))
	var skey struct{ Kind, Phone, StoreKey string }
	verify(skd, &skey)
	if skey.Kind != "store-key" || skey.Phone != phoneAgreement {
		log.Fatalf("not this phone's store key: %+v", skey)
	}
	secret := hex.EncodeToString(randBytes(8))
	recovered := map[string]map[string]string{
		"e2e":       {"E2E_SECRET": secret},
		"e2e-extra": {"E2E_EXTRA": "extra-" + secret},
		"e2e-more":  {"E2E_MORE": "more-" + secret},
		// the Claude login store: no keys yet; the router writes the pair into it (the one-shot step below)
		"claude": {},
	}
	names, keys := []string{}, []map[string]any{}
	for _, n := range []string{"claude", "e2e", "e2e-extra", "e2e-more"} {
		names = append(names, n)
		for k, v := range recovered[n] {
			keys = append(keys, wrapKey(skey.StoreKey, n, k, v))
		}
	}
	bundle, _ := json.Marshal(map[string]any{"format": "keys", "stores": names, "keys": keys,
		"notSensitive": []string{"e2e", "claude"}, "owners": map[string]string{}})
	sum := sha256.Sum256(bundle)
	mpub, _ := master.PublicKey.ECDH()
	stmt, _ := json.Marshal(map[string]any{"kind": "claim", "master": b64.EncodeToString(mpub.Bytes()),
		"core":         map[string]string{"signingKey": secretsID.SigningKey, "agreementKey": secretsID.AgreementKey},
		"phone":        map[string]string{"signingKey": p.signingKey(), "agreementKey": phoneAgreement},
		"bundleSha256": hex.EncodeToString(sum[:])})
	h := sha256.Sum256(stmt)
	msig, _ := ecdsa.SignASN1(rand.Reader, master, h[:])
	claim := map[string]any{"statement": string(stmt), "masterSig": b64.EncodeToString(msig),
		"bundle": sealTo(secretsID.AgreementKey, bundle, "jarvis2/claim")}
	var rec Doc
	must2(call(router, "POST", "/api/secrets/claim", claim, &rec))
	var claimed struct{ Kind string }
	verify(rec, &claimed)
	if claimed.Kind != "claimed" {
		log.Fatalf("claim: %s", rec.Payload)
	}
	if s, _ := call(router, "POST", "/api/secrets/claim", claim, nil); s == 200 {
		log.Fatal("a set-up secrets was claimed again")
	}

	step("stores: e2e not sensitive, e2e-extra sensitive; a created store is not; the upgrade is one-way")
	stores := func() map[string]bool {
		var d Doc
		must2(call(router, "POST", "/api/secrets/stores", map[string]string{"nonce": "n"}, &d))
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
	must2(call(router, "POST", "/api/secrets/stores/create", map[string]string{"name": "e2e-notes"}, nil))
	if st := stores(); st["e2e"] || !st["e2e-extra"] || st["e2e-notes"] {
		log.Fatalf("sensitivity: %v", st)
	}
	if _, ok := stores()["core"]; ok {
		log.Fatal("the reserved store is a session store")
	}
	must2(call(router, "POST", "/api/secrets/stores/mark-sensitive", map[string]string{"name": "e2e-notes"}, nil))
	if s, _ := call(router, "POST", "/api/secrets/stores/create", map[string]string{"name": "e2e-notes"}, nil); s == 200 {
		log.Fatal("re-created a sensitive store")
	}

	step("an unlock is per store and never ends by itself: open until locked")
	unlock(p, "e2e-extra")
	if !storeOpen("e2e-extra") {
		log.Fatal("an unlock doesn't show as unlocked")
	}
	lockAll()
	if storeOpen("e2e-extra") {
		log.Fatal("still unlocked after lock")
	}

	if os.Getenv("E2E_ONLY") == "restore" { // the restore of a store alone, on secrets set up as above (no machines)
		restoreStep(p, master, skey.StoreKey, secretsID.AgreementKey)
		lockAll()
		expectNoUnlocks("at the end")
		log.Printf("E2E PASSED (the restore of a store only)")
		return
	}
	if os.Getenv("E2E_ONLY") == "jarvis1-import" { // the import alone, on secrets set up as above
		jarvis1ImportStep(p)
		lockAll()
		expectNoUnlocks("at the end")
		log.Printf("E2E PASSED (the Jarvis 1 import only)")
		return
	}

	step("new session (stores [e2e]): the phone signs (sink, source-x, ({store:e2e}, {session:<id>})); e2e unlocked, the first pull serves it")
	newBody := map[string]any{"label": "e2e test", "stores": []string{"e2e"}, "size": "small", "harness": "claude"}
	if os.Getenv("E2E_ONLY") != "drain" {
		contentSetupStep(secret) // nojarvis1.go
		newBody["content"] = []string{"e2e-content"}
	}
	s, b := call(router, "POST", "/api/sessions", newBody, nil)
	must(s, b, "create")
	a := waitApproval("new-session", "")
	checkDrafts(a, 1, []string{"store:e2e"}, "")
	unlock(p, "e2e")
	id := approve(p, a)
	waitState(id, "started", 6*time.Minute)
	m1 := machineOf(id)
	expectOnMachine(m1, "grep -c E2E_SECRET /home/claude/.secrets", "1")
	checkChain(id, "after the start")
	expectOnMachine(m1, "echo marker-"+secret+" > /home/claude/artifacts/e2e-marker && chown claude /home/claude/artifacts/e2e-marker && echo ok", "ok")
	// the OpenCode/Paseo and OpenClaw harnesses' state travels in the snapshot too (their pairings), their pid files don't
	expectOnMachine(m1, "cd /home/claude && mkdir -p .paseo .openclaw/devices .local/share/opencode/storage && echo paseo > .paseo/e2e-state && "+
		"echo openclaw > .openclaw/devices/e2e-state && echo opencode > .local/share/opencode/storage/e2e-state && echo 1 > .openclaw/gateway.pid && "+
		"chown -R claude .paseo .openclaw .local && echo ok", "ok")

	if os.Getenv("E2E_ONLY") == "drain" {
		drainStep(id)
		return
	}

	servicesStep(id, m1, secret) // nojarvis1.go

	step("a terminal: no shell without one; the phone signs (sink, source-a, ({shell}, {session, until})) and (source-a, M, ⊤); merged onto the main grant")
	if s, b := call(router, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": "echo hi"}, nil); s == 200 {
		log.Fatalf("a shell without a terminal: %s", b)
	}
	var filed struct{ ID string }
	must2(call(router, "POST", "/api/requests/terminal", map[string]any{"session": id, "minutes": 10, "explanation": "e2e terminal"}, &filed))
	a = waitApproval("terminal", id)
	checkDrafts(a, 2, []string{"shell"}, "until:")
	approve(p, a)
	expectExec(id, "echo hi from $(whoami)", "hi from claude")

	step("a command: the phone signs one command by its hash, run once; the result kept on the session")
	must2(call(router, "POST", "/api/requests/command", map[string]any{"session": id, "cmd": "echo cmd-" + secret[:6], "explanation": "e2e command"}, nil))
	a = waitApproval("command", id)
	checkDrafts(a, 2, []string{"shell"}, "cmd:")
	approve(p, a)
	waitCommand(id, "cmd-"+secret[:6])

	step("inputs: the machine's Fly config carries only what the spawner set (its key, the roster, the router's address)")
	env := flyMachineEnv(m1)
	if len(env) != 3 || env["JARVIS2_SPAWNER_KEY"] != roster.Spawner || env["JARVIS2_ROSTER"] == "" || env["JARVIS2_URL"] == "" {
		log.Fatalf("the machine's Fly config env is %v, want only JARVIS2_SPAWNER_KEY, JARVIS2_ROSTER and JARVIS2_URL", env)
	}
	if strings.Contains(env["JARVIS2_URL"], "jarvis2-box") {
		log.Fatalf("an e2e machine points at production's router (%s)", env["JARVIS2_URL"])
	}
	var mr kernel.Roster
	if json.Unmarshal([]byte(env["JARVIS2_ROSTER"]), &mr) != nil || mr != roster {
		log.Fatalf("the machine's roster isn't the kernel's: %s", env["JARVIS2_ROSTER"])
	}

	step("status: the machine reports itself; the session's local Jarvis API arms a wakeup (its text kept by the guard, only \"due\" from the router)")
	for i := 0; ; i++ {
		if lr, _ := session(id)["lastReport"].(string); lr != "" && !strings.HasPrefix(lr, "0001") {
			break
		}
		if i > 45 {
			log.Fatal("no status report from the machine in 90 s")
		}
		time.Sleep(2 * time.Second)
	}
	expectOnMachine(m1, "su - claude -c \"curl -s -X POST -H 'Content-Type: application/json' -d '{\\\"prompt\\\":\\\"e2e wake\\\",\\\"delaySeconds\\\":3600,\\\"name\\\":\\\"e2e\\\"}' http://127.0.0.1:7171/api/sessions/"+id+"/wakeups\" | grep -c '\"ok\":true'", "1")
	expectOnMachine(m1, "su - claude -c 'curl -s -o /dev/null -w %{http_code} -X POST -d {} http://127.0.0.1:7171/api/sessions/s0000000000000000/wakeups'", "403")
	var wk struct{ Wakeups []map[string]any }
	must2(call(router, "GET", "/api/sessions/"+id+"/wakeups", nil, &wk))
	if len(wk.Wakeups) != 1 || wk.Wakeups[0]["name"] != "e2e" {
		log.Fatalf("the router doesn't list the wakeup: %v", wk.Wakeups)
	}
	if strings.Contains(fmt.Sprint(wk.Wakeups), "e2e wake") {
		log.Fatal("the router holds the wakeup's text (it lives in the guard's records)")
	}
	must2(call(router, "DELETE", "/api/sessions/"+id+"/wakeups/e2e", nil, nil))

	step("live transcript sync: the machine sends a changed conversation to the router (no Storage Box in the test: received, not stored)")
	tname := "0e2e0000-1111-4222-8333-" + secret[:12] + ".jsonl"
	expectOnMachine(m1, "mkdir -p /home/claude/.claude/projects/-e2e && echo '{\"type\":\"user\",\"message\":{\"content\":\"e2e live\"}}' > /home/claude/.claude/projects/-e2e/"+tname+
		" && chown -R claude /home/claude/.claude/projects && echo ok", "ok")
	waitLiveSync(id, tname, 3*time.Minute)

	step("store key names: secrets', listed to the session for every store (not only its own)")
	expectOnMachine(m1, "su - claude -c 'jarvis2 stores' | grep -c '^e2e-extra \\[sensitive, locked\\]: E2E_EXTRA$'", "1")
	expectOnMachine(m1, "su - claude -c 'jarvis2 stores' | grep -c '^e2e \\[in this session\\]: E2E_SECRET$'", "1")

	step("two add-stores pending at once (e2e-extra, e2e-more), filed by the session itself, approved in the order they weren't filed: " +
		"each merges into the main grant, and the session ends with both")
	expectOnMachine(m1, sessionAPI("POST", "/api/requests/add-store", `{"store":"e2e-extra","explanation":"e2e add-store"}`)+" | grep -c '\"approval\":true'", "1")
	expectOnMachine(m1, sessionAPI("POST", "/api/requests/add-store", `{"store":"e2e-more","explanation":"e2e add-store"}`)+" | grep -c '\"approval\":true'", "1")
	pending := waitApprovals("add-store", id, 2)
	byStore := map[string]approval{}
	for _, a := range pending {
		byStore[a.Store] = a
	}
	checkDrafts(byStore["e2e-extra"], 2, []string{"store:e2e-extra"}, "")
	checkDrafts(byStore["e2e-more"], 2, []string{"store:e2e-more"}, "")
	unlock(p, "e2e-more")
	unlock(p, "e2e-extra")
	approve(p, byStore["e2e-more"])
	approve(p, byStore["e2e-extra"])
	expectSessionStores(id, "[e2e e2e-extra e2e-more]")
	expectOnMachine(m1, "for i in $(seq 1 30); do grep -q E2E_EXTRA /home/claude/.secrets && grep -q E2E_MORE /home/claude/.secrets && break; sleep 2; done; "+
		"sleep 6; grep -c E2E_EXTRA /home/claude/.secrets; grep -c E2E_MORE /home/claude/.secrets; grep -c E2E_SECRET /home/claude/.secrets", "1\n1\n1")

	step("a session writes one key into a store it doesn't hold, with no approval: backed up first (the bucket stand-in), " +
		"the explanation listed, the phone shown which session wrote it")
	expectOnMachine(m1, "su - claude -c \"printf note-"+secret+" | jarvis2 put-key e2e-notes E2E_NOTE --explain 'the e2e note'\" 2>&1 | grep -c 'E2E_NOTE written in e2e-notes'", "1")
	if _, err := os.Stat(filepath.Join(os.Getenv("E2E_S3_DIR"), "keys", "e2e-notes", "E2E_NOTE.json")); err != nil {
		log.Fatalf("no backup of the written key in the bucket: %v", err)
	}
	expectOnMachine(m1, "su - claude -c 'jarvis2 stores --keys' | grep -c '^  E2E_NOTE: the e2e note \\[written by session '", "1")
	uid := unlock(p, "e2e-notes")
	if lastUnlockWriters["e2e-notes/E2E_NOTE"] != "machine "+m1 {
		log.Fatalf("the phone isn't shown the session's machine as the writer: %v", lastUnlockWriters)
	}
	lockID(uid)

	step("a key written into a store the session holds (unlocked): served with the next pull at once, no phone; the other keys untouched")
	expectOnMachine(m1, "su - claude -c \"printf more2-"+secret+" | jarvis2 put-key e2e-more E2E_MORE --explain 'the e2e more key'\" >/dev/null 2>&1; "+
		"for i in $(seq 1 30); do grep -q more2- /home/claude/.secrets && break; sleep 2; done; "+
		"grep -c more2- /home/claude/.secrets; grep -c E2E_EXTRA /home/claude/.secrets; grep -c E2E_SECRET /home/claude/.secrets", "1\n1\n1")

	step("delete a key: gone from secrets' list")
	expectOnMachine(m1, "su - claude -c 'jarvis2 delete-key e2e-notes E2E_NOTE' >/dev/null 2>&1; su - claude -c 'jarvis2 stores' | grep -c '^e2e-notes \\[.*\\]: $'", "1")

	step("narrow in place: back to [e2e] along M's identity edge; the extra stores go from the machine's secrets")
	must2(call(router, "POST", "/api/sessions/"+id+"/narrow", map[string]any{"stores": []string{"e2e"}}, nil))
	expectSessionStores(id, "[e2e]")
	expectOnMachine(m1, "for i in $(seq 1 30); do grep -q E2E_EXTRA /home/claude/.secrets || break; sleep 2; done; "+
		"grep -c E2E_SECRET /home/claude/.secrets; grep -c E2E_EXTRA /home/claude/.secrets || true", "1\n0")

	step("a key written into e2e before the pause: served at once (e2e is unlocked) and carried by the resumed session's pull")
	expectOnMachine(m1, "su - claude -c \"printf late-"+secret+" | jarvis2 put-key e2e E2E_LATE --explain 'written before the pause'\" >/dev/null 2>&1; "+
		"for i in $(seq 1 30); do grep -q late- /home/claude/.secrets && break; sleep 2; done; grep -c late- /home/claude/.secrets", "1")

	step("pause → paused (snapshot signed and uploaded, the spawner's kill into a fresh source)")
	s, b = call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil)
	must(s, b, "pause")
	waitState(id, "paused", 12*time.Minute)
	checkChain(id, "after the pause")

	step("resume, same source contents → no phone (a spawn from the paused source), snapshot restored (harness state too), e2e served")
	s, b = call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil)
	must(s, b, "resume")
	waitState(id, "started", 8*time.Minute)
	m2 := machineOf(id)
	if m2 == m1 {
		log.Fatal("resume reused the old machine")
	}
	expectOnMachine(m2, "cat /home/claude/artifacts/e2e-marker", "marker-"+secret)
	expectOnMachine(m2, "cd /home/claude && cat .paseo/e2e-state .openclaw/devices/e2e-state .local/share/opencode/storage/e2e-state && "+
		"{ test -e .openclaw/gateway.pid && echo pid || echo no-pid; }", "paseo\nopenclaw\nopencode\nno-pid")
	expectOnMachine(m2, "grep -c E2E_SECRET /home/claude/.secrets; grep -c late- /home/claude/.secrets; grep -c E2E_EXTRA /home/claude/.secrets || true", "1\n1\n0")
	if s, _ := call(router, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": "echo hi"}, nil); s == 200 {
		log.Fatal("the terminal outlived the machine it was granted on")
	}

	step("a locked store: the resumed session's pull lists e2e as locked; an unlock serves it with no other step")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	lockAll()
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil))
	deadline := time.Now().Add(8 * time.Minute)
	for session(id)["lockedStore"] != "e2e" {
		if time.Now().After(deadline) {
			dumpState()
			log.Fatal("the session doesn't say it waits on store e2e")
		}
		time.Sleep(3 * time.Second)
	}
	unlock(p, "e2e")
	waitState(id, "started", 12*time.Minute)
	expectOnMachine(machineOf(id), "for i in $(seq 1 30); do grep -q E2E_SECRET /home/claude/.secrets && break; sleep 2; done; grep -c E2E_SECRET /home/claude/.secrets", "1")

	step("the permission mode is fixed for the session's life: no route changes it")
	if s, _ := call(router, "POST", "/api/sessions/"+id+"/permission-mode", map[string]string{"mode": "bypass"}, nil); s == 200 {
		log.Fatal("the permission mode changed on a running session")
	}

	step("pause, then resume with the latest image → a new phone-made source naming the snapshot; the paused source is burned")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": true}, nil))
	a = waitApproval("resume-upgrade", id)
	checkDrafts(a, 1, []string{"store:e2e"}, "")
	if a.Source == nil || a.Source.Snapshot == "" {
		log.Fatalf("the resume-upgrade source names no snapshot: %+v", a.Source)
	}
	approve(p, a)
	waitState(id, "started", 8*time.Minute)
	m3 := machineOf(id)
	expectOnMachine(m3, "cat /home/claude/artifacts/e2e-marker", "marker-"+secret)

	step("destroy → paused (final snapshot), archived (off in the test), burned: (source, sink) by the gullible signer; moved to records")
	must2(call(router, "POST", "/api/sessions/"+id+"/destroy", nil, nil))
	waitRecord(id, 12*time.Minute) // destroy waits for the final snapshot
	checkBurned(id)

	step("one-shot (stores [claude]): the router writes the Claude login into the store claude; once unlocked the machine pulls it at boot")
	must2(call(router, "POST", "/peer/claude-login", map[string]any{"credentials": fakePair,
		"account": `{"oauthAccount":{"accountUuid":"e2e-account","emailAddress":"e2e@example.com"}}`, "relogin": true}, nil))
	waitStoreKey("claude", "CLAUDE_CREDENTIALS", time.Minute)
	unlock(p, "claude")
	s, b = call(router, "POST", "/api/sessions", map[string]any{"label": "e2e one-shot", "stores": []string{"claude"}, "size": "small", "harness": "claude",
		"oneShot": true, "prompt": "e2e: nothing to do"}, nil)
	must(s, b, "create one-shot")
	a = waitApproval("new-session", "")
	checkDrafts(a, 1, []string{"store:claude"}, "")
	os1 := approve(p, a)
	waitState(os1, "started", 6*time.Minute)
	om := machineOf(os1)
	expectOnMachine(om, "grep -c e2e-fake-refresh /home/claude/.claude/.credentials.json; stat -c %a /home/claude/.claude/.credentials.json", "1\n600")
	loginRefreshStep(om) // nojarvis1.go
	// a repo with an uncommitted file and no upstream, then the supervisor's marker (no real Claude login here, so
	// claude never finishes a prompt by itself)
	expectOnMachine(om, "su - claude -c 'mkdir -p ~/workspace/lost && cd ~/workspace/lost && git init -q && echo x > f && echo ok'", "ok")
	expectOnMachine(om, "su - claude -c 'echo \"done e2e\" > ~/.claude/.one-shot-done && echo ok'", "ok")
	waitRecord(os1, 12*time.Minute)
	if lf := os.Getenv("E2E_ROUTER_LOG"); lf != "" {
		var logb []byte
		for i := 0; i < 10; i++ {
			logb, _ = os.ReadFile(lf)
			if bytes.Contains(logb, []byte("one-shot session “e2e one-shot” was destroyed with work lost")) {
				break
			}
			time.Sleep(time.Second)
		}
		if !bytes.Contains(logb, []byte("one-shot session “e2e one-shot” was destroyed with work lost")) || !bytes.Contains(logb, []byte("lost: 1 uncommitted file(s), branch has no upstream")) {
			log.Fatal("no lost-work DM for the one-shot session in the router's log")
		}
	}

	step("a task: the iPhone approves its line once; a run resumes it with no phone, runs the script, pauses it")
	var inst map[string]any
	must2(call(router, "POST", "/api/tasks/instances", map[string]any{"template": "hello", "name": "e2e hello", "params": map[string]any{"message": "hi from e2e"}}, &inst))
	iid := fmt.Sprint(inst["id"])
	approve(p, waitApproval("new-session", fmt.Sprint(inst["session"])))
	waitTask(iid, "ready", 10*time.Minute)
	var run struct{ Name string }
	must2(call(router, "POST", "/api/tasks/instances/"+iid+"/run", map[string]any{}, &run))
	deadline = time.Now().Add(10 * time.Minute)
	for {
		var rr struct {
			Run    map[string]any
			Output string
		}
		call(router, "GET", "/api/tasks/runs/"+run.Name, nil, &rr)
		ph := fmt.Sprint(rr.Run["phase"])
		if ph == "succeeded" {
			if !strings.Contains(rr.Output, "hi from e2e") {
				log.Fatalf("the run's output: %q", rr.Output)
			}
			break
		}
		if ph == "failed" || ph == "timedout" || ph == "lost" || time.Now().After(deadline) {
			log.Fatalf("the task run ended %s: %v", ph, rr.Run)
		}
		time.Sleep(5 * time.Second)
	}
	waitTask(iid, "ready", 5*time.Minute) // paused again for the next run
	must2(call(router, "DELETE", "/api/tasks/instances/"+iid, nil, nil))

	jarvis1ImportStep(p)                                          // jarvis1import.go
	restoreStep(p, master, skey.StoreKey, secretsID.AgreementKey) // storerestore.go

	step("every unlock this test opened, locked; secrets' signed unlocked list is empty")
	lockAll()
	expectNoUnlocks("at the end")
	checkNoJarvis1("at the end") // nojarvis1.go
	log.Printf("E2E PASSED with Jarvis 1 unreachable (machines %s → %s → %s)", m1, m2, m3)
}

// verifyRaw: an ECDSA P-256 signature (base64 DER) by a base64 x963 public key
func verifyRaw(pubB64, payload, sigB64 string) bool {
	return kernel.Verify(strings.TrimSpace(pubB64), []byte(payload), sigB64)
}

func parseKey(pemBytes []byte) *ecdsa.PrivateKey {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		log.Fatal("E2E_MASTER_KEY_FILE: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatal("E2E_MASTER_KEY_FILE: not an EC key")
	}
	return ek
}

// sealTo: Sealed{e, data} to a P-256 public key (HKDF-SHA256 empty salt, AES-256-GCM nonce||ct||tag)
func sealTo(recipient string, plain []byte, info string) map[string]string {
	return sealToAAD(recipient, plain, info, nil)
}

func sealToAAD(recipient string, plain []byte, info string, aad []byte) map[string]string {
	rb, _ := b64.DecodeString(recipient)
	R, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		log.Fatal(err)
	}
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	x, _ := e.ECDH(R)
	k, _ := hkdf.Key(sha256.New, x, nil, info, 32)
	return map[string]string{"e": b64.EncodeToString(e.PublicKey().Bytes()), "data": b64.EncodeToString(gcm(k, plain, aad))}
}

// wrapKey: one key as the app wraps it for a Recover — the value under its own data key (AAD store\nkey), that key
// wrapped to the store key P + K
func wrapKey(storeKey, store, key, value string) map[string]any {
	dk := randBytes(32)
	w := sealTo(storeKey, dk, "jarvis2/store-data-key")
	return map[string]any{"store": store, "key": key, "wrapped": map[string]string{"e": w["e"], "wrapped": w["data"]},
		"data": b64.EncodeToString(gcm(dk, []byte(value), []byte(store+"\n"+key)))}
}

// gcm: AES-256-GCM, nonce || ciphertext || tag
func gcm(key, plain, aad []byte) []byte {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	nonce := randBytes(g.NonceSize())
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

var unlockIDs []string

// lastUnlockWriters: store/key → who secrets said wrote it ("machine <id>", "setup ", "router ", "core "), from the last unlock
var lastUnlockWriters = map[string]string{}

// fakePair: the Claude login the test router holds (a fake pair, public; never refreshed: it expires in 2100)
const fakePair = `{"claudeAiOauth": {"accessToken": "e2e-fake-access", "refreshToken": "e2e-fake-refresh", "expiresAt": 4102444800000, "scopes": ["user:inference"], "subscriptionType": "max"}}`

// unlock: a store opened by the phone (one share per key), until locked → the unlock's id
func unlock(p *phone, store string) string {
	var d Doc
	must2(call(router, "POST", "/api/secrets/unlock/begin", map[string]string{"store": store}, &d))
	var ub struct {
		Kind, Pending, Store, T string
		Keys                    []struct {
			Key, E string
			Writer struct{ By, Machine string }
		}
	}
	verify(d, &ub)
	if ub.Kind != "unlock-begin" || ub.Store != store {
		log.Fatalf("unlock-begin: %+v", ub)
	}
	// the phone's share x(p·E) of each key's E (the Enclave returns only x), sealed to secrets' one-off T
	shares := map[string]map[string]string{}
	for _, k := range ub.Keys {
		eb, _ := b64.DecodeString(k.E)
		E, _ := ecdh.P256().NewPublicKey(eb)
		x, _ := p.agr.ECDH(E)
		shares[k.Key] = sealTo(ub.T, x, "jarvis2/unlock-share")
		lastUnlockWriters[store+"/"+k.Key] = k.Writer.By + " " + k.Writer.Machine
	}
	must2(call(router, "POST", "/api/secrets/unlock/finish", map[string]any{"pending": ub.Pending, "shares": shares}, &d))
	var uf struct{ Kind, ID, Store string }
	verify(d, &uf)
	if uf.Kind != "unlocked" {
		log.Fatalf("unlock-finish: %+v", uf)
	}
	unlockIDs = append(unlockIDs, uf.ID)
	return uf.ID
}

// storeOpen: secrets' signed store list says the store is unlocked
func storeOpen(name string) bool {
	var d Doc
	must2(call(router, "POST", "/api/secrets/stores", map[string]string{"nonce": "n-open"}, &d))
	var l struct {
		Stores []struct {
			Name     string
			Unlocked bool
		}
	}
	verify(d, &l)
	for _, x := range l.Stores {
		if x.Name == name {
			return x.Unlocked
		}
	}
	return false
}

func lockID(uid string) {
	must2(call(router, "POST", "/api/secrets/lock", map[string]string{"id": uid}, nil))
	for i, x := range unlockIDs {
		if x == uid {
			unlockIDs = append(unlockIDs[:i], unlockIDs[i+1:]...)
			break
		}
	}
}

// lockAll: lock every unlock this test opened that is still open
func lockAll() {
	for _, uid := range unlockIDs {
		call(router, "POST", "/api/secrets/lock", map[string]string{"id": uid}, nil)
	}
	unlockIDs = nil
}

// expectNoUnlocks: secrets' signed unlocked list is empty (unlocks end only with a lock)
func expectNoUnlocks(when string) {
	var ul struct {
		Kind     string           `json:"kind"`
		Nonce    string           `json:"nonce"`
		Unlocked []map[string]any `json:"unlocked"`
	}
	var d Doc
	must2(call(router, "POST", "/api/secrets/unlocked", map[string]string{"nonce": "n-123"}, &d))
	verify(d, &ul)
	if ul.Nonce != "n-123" || len(ul.Unlocked) != 0 {
		log.Fatalf("a store is still unlocked %s: %+v", when, ul)
	}
}

// waitStoreKey: secrets' list (through the router) names the key in the store
func waitStoreKey(store, key string, d time.Duration) {
	for deadline := time.Now().Add(d); ; time.Sleep(2 * time.Second) {
		for _, k := range keyNamesOf(store) {
			if k == key {
				return
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("store %s never got %s", store, key)
		}
	}
}

type approval struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Session string         `json:"session"`
	Machine string         `json:"machine"`
	Store   string         `json:"store"`
	Drafts  []draft        `json:"drafts"`
	Source  *kernel.Object `json:"source"`
}

type draft struct {
	Payload   string `json:"payload"`
	Challenge Doc    `json:"challenge"`
}

func waitApproval(kind, session string) approval {
	deadline := time.Now().Add(12 * time.Minute) // destroy waits for the final snapshot
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

// waitApprovals: n approvals of that kind for the session, all pending at once
func waitApprovals(kind, session string, n int) []approval {
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		var out struct {
			Approvals []approval `json:"approvals"`
		}
		call(router, "GET", "/api/approvals", nil, &out)
		var got []approval
		for _, a := range out.Approvals {
			if a.Kind == kind && a.Session == session {
				got = append(got, a)
			}
		}
		if len(got) == n {
			return got
		}
		time.Sleep(3 * time.Second)
	}
	dumpState()
	log.Fatalf("not %d %s approvals", n, kind)
	return nil
}

// checkDrafts: the checks the iPhone makes before signing (docs/API.md "Approvals"): n drafts, each a phone succession
// cert with the log notary's challenge over exactly its payload; the first out of the sink into a source, allowing
// exactly `allowed`, on the session's condition (and, when cond is set, a condition starting with it); a second
// (an add-on's) from that source into the running machine with ⊤
func checkDrafts(a approval, n int, allowed []string, cond string) {
	if len(a.Drafts) != n {
		log.Fatalf("%s approval: %d drafts, want %d", a.Kind, len(a.Drafts), n)
	}
	var certs []kernel.Succession
	for _, d := range a.Drafts {
		var ch kernel.Challenge
		verifyBy(roster.Notary, "the log notary", d.Challenge, &ch)
		if ch.Subject != kernel.SHA256Hex(d.Payload) || ch.About != kernel.AboutSuccession {
			log.Fatalf("a draft's challenge is over something else: %s", d.Challenge.Payload)
		}
		var c kernel.Succession
		if err := json.Unmarshal([]byte(d.Payload), &c); err != nil || c.Kind != "succession" || c.Signer != "phone" {
			log.Fatalf("not a phone succession cert: %s", d.Payload)
		}
		certs = append(certs, c)
	}
	c := certs[0]
	if c.Predecessor.ID != kernel.Sink || !strings.HasPrefix(c.Successor.ID, "source-") || !c.Allowed.Equal(kernel.Only(allowed...)) {
		log.Fatalf("the first draft isn't (sink, source, %v): %s", allowed, a.Drafts[0].Payload)
	}
	hasSession, hasCond := false, cond == ""
	for _, x := range c.Conditions {
		hasSession = hasSession || x == "session:"+a.Session
		hasCond = hasCond || strings.HasPrefix(x, cond)
	}
	if a.Session != "" && !hasSession || !hasCond {
		log.Fatalf("the first draft's conditions %v lack session:%s or %s…", c.Conditions, a.Session, cond)
	}
	if a.Kind == "new-session" || a.Kind == "resume-upgrade" {
		var st struct{ Session, Harness, PermissionMode string }
		if json.Unmarshal([]byte(c.Successor.Settings), &st) != nil || st.Harness == "" || st.PermissionMode == "" ||
			(a.Session != "" && st.Session != a.Session) {
			log.Fatalf("the source's settings: %s", c.Successor.Settings)
		}
	}
	if n == 2 {
		m := certs[1]
		if m.Predecessor != c.Successor || m.Successor.ID != a.Machine || !m.Allowed.Equal(kernel.Everything()) || len(m.Conditions) != 0 {
			log.Fatalf("the second draft isn't (source-a, M, ⊤): %s", a.Drafts[1].Payload)
		}
	}
}

// approve: one Face ID → the phone's signature over each draft, in order
func approve(p *phone, a approval) string {
	sigs := []string{}
	for _, d := range a.Drafts {
		sigs = append(sigs, p.sign(d.Payload))
	}
	var out struct {
		OK      bool   `json:"ok"`
		Session string `json:"session"`
	}
	s, b := call(router, "POST", "/api/approvals/"+a.ID+"/respond", map[string]any{"signatures": sigs}, &out)
	must(s, b, "respond")
	if out.Session == "" {
		out.Session = a.Session
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

func expectSessionStores(id, want string) {
	for i := 0; ; i++ {
		st, _ := session(id)["stores"].([]any)
		got := make([]string, 0, len(st))
		for _, x := range st {
			got = append(got, fmt.Sprint(x))
		}
		sort.Strings(got)
		if fmt.Sprint(got) == want {
			return
		}
		if i > 30 {
			log.Fatalf("the session's stores: %v, want %s", got, want)
		}
		time.Sleep(2 * time.Second)
	}
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

func waitRecord(id string, d time.Duration) {
	deadline := time.Now().Add(d)
	for {
		var recs struct {
			Records []map[string]any `json:"records"`
		}
		call(router, "GET", "/api/records", nil, &recs)
		if len(recs.Records) > 0 && recs.Records[0]["id"] == id {
			return
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatalf("%s wasn't destroyed", id)
		}
		time.Sleep(3 * time.Second)
	}
}

// waitCommand: the approved command's result is on the session
func waitCommand(id, want string) {
	for i := 0; ; i++ {
		cmds, _ := session(id)["commands"].([]any)
		if len(cmds) > 0 {
			last, _ := cmds[len(cmds)-1].(map[string]any)
			if strings.TrimSpace(fmt.Sprint(last["stdout"])) == want && fmt.Sprint(last["code"]) == "0" {
				return
			}
			if e, _ := last["error"].(string); e != "" {
				log.Fatalf("the command failed: %v", last)
			}
		}
		if i > 60 {
			dumpState()
			log.Fatalf("no result %q for the approved command", want)
		}
		time.Sleep(2 * time.Second)
	}
}

// chainView: GET /api/sessions/:id/chain, what the test checks of it
type chainView struct {
	Steps []struct {
		Kind      string                `json:"kind"`
		ID        string                `json:"id"`
		Notarized *kernel.NotarizedCert `json:"notarized"`
		Grant     *Doc                  `json:"grant"`
	} `json:"steps"`
	Main *Doc `json:"main"`
}

func chainOf(id string) chainView {
	var c chainView
	must2(call(router, "GET", "/api/sessions/"+id+"/chain", nil, &c))
	return c
}

// checkChain: every cert step is notarized (checked against the roster, the notarizer's table included) and the main
// grant is the mover's or the merger's
func checkChain(id, when string) {
	c := chainOf(id)
	if len(c.Steps) == 0 || c.Main == nil {
		log.Fatalf("%s: no chain for %s", when, id)
	}
	for _, s := range c.Steps {
		if s.Kind == "cert" {
			if s.Notarized == nil {
				log.Fatalf("%s: cert step %s without its notarization", when, s.ID)
			}
			if _, err := kernel.OpenNotarized(roster, *s.Notarized); err != nil {
				log.Fatalf("%s: cert step %s: %v", when, s.ID, err)
			}
		}
	}
	if _, err := kernel.OpenGrant(roster, *c.Main, kernel.RoleMover, kernel.RoleMerger); err != nil {
		log.Fatalf("%s: the main grant: %v", when, err)
	}
}

// checkBurned: a destroyed session's chain ends in the sink, by the gullible signer
func checkBurned(id string) {
	c := chainOf(id)
	for i := len(c.Steps) - 1; i >= 0; i-- {
		s := c.Steps[i]
		if s.Kind != "cert" || s.Notarized == nil {
			continue
		}
		cert, err := kernel.OpenNotarized(roster, *s.Notarized)
		if err != nil || cert.Successor.ID != kernel.Sink || cert.Signer != kernel.RoleGullible {
			log.Fatalf("the destroyed session's last cert isn't a burn (source, sink) by the gullible signer: %+v %v", cert, err)
		}
		return
	}
	log.Fatal("the destroyed session has no chain")
}

func machineOf(id string) string { return fmt.Sprint(session(id)["machineId"]) }

func dumpState() {
	_, b := call(router, "GET", "/api/state", nil, nil)
	log.Printf("state: %.2000s", string(b))
}

// flyMachineEnv: the env in a machine's Fly config
func flyMachineEnv(m string) map[string]string {
	req, _ := http.NewRequest("GET", "https://api.machines.dev/v1/apps/jarvis2-sessions/machines/"+m, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("E2E_FLY_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("fly get %s: %v", m, err)
	}
	defer resp.Body.Close()
	var out struct {
		Config struct {
			Env map[string]string `json:"env"`
		} `json:"config"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.Config.Env
}

// flyExec: a command on a machine through the Machines API (the test's own org token, an observer the router never
// is) → its stdout and exit code
func flyExec(m string, cmd []string) (string, int, error) {
	body, _ := json.Marshal(map[string]any{"command": cmd, "timeout": 60})
	req, _ := http.NewRequest("POST", "https://api.machines.dev/v1/apps/jarvis2-sessions/machines/"+m+"/exec", bytes.NewReader(body))
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

// expectExec: a command through the router's exec (only while a terminal is open)
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

// waitLiveSync: the router lists the file in the session's liveSync
func waitLiveSync(id, name string, d time.Duration) {
	deadline := time.Now().Add(d)
	for {
		if ls, ok := session(id)["liveSync"].(map[string]any); ok {
			if files, ok := ls["files"].(map[string]any); ok && files[name] != nil {
				log.Printf("   live sync: %s received (stored %v)", name, ls["stored"])
				return
			}
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatalf("live sync: %s never reached the router", name)
		}
		time.Sleep(5 * time.Second)
	}
}

func waitTask(id, want string, d time.Duration) {
	deadline := time.Now().Add(d)
	for {
		var t struct{ Instances []map[string]any }
		call(router, "GET", "/api/tasks", nil, &t)
		for _, i := range t.Instances {
			if i["id"] == id && i["state"] == want {
				return
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("task %s never %s: %v", id, want, t.Instances)
		}
		time.Sleep(5 * time.Second)
	}
}

// drainStep (E2E_ONLY=drain): a router rollout while a pause is in flight. SIGTERM reaches the router right after the
// pause began: it goes on serving reads and the machine's snapshot (over Fly's private network), refuses a new action
// with 503 "router updating, try again shortly", lets the pause finish, then exits on its own.
func drainStep(id string) {
	step("drain: SIGTERM with a pause in flight → reads served, new actions 503, the pause finishes, then the router exits")
	pid, err := strconv.Atoi(os.Getenv("E2E_ROUTER_PID"))
	if err != nil {
		log.Fatal("E2E_ONLY=drain needs E2E_ROUTER_PID (infra/e2e.sh sets it)")
	}
	proc, _ := os.FindProcess(pid)
	s, b := call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil)
	must(s, b, "pause")
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		log.Fatalf("SIGTERM: %v", err)
	}
	time.Sleep(time.Second)
	if s, b := call(router, "GET", "/api/state", nil, nil); s != 200 {
		log.Fatalf("GET /api/state during the drain: %d %s", s, b)
	}
	s, b = call(router, "POST", "/api/sessions/"+id+"/destroy", nil, nil)
	if s != 503 || !strings.Contains(string(b), "router updating, try again shortly") {
		log.Fatalf("a new action during the drain: %d %s", s, b)
	}
	// the router exits once the pause is done (it may be gone before a poll sees "paused"): its volume says how it ended
	for i := 0; proc.Signal(syscall.Signal(0)) == nil; i++ {
		if i > 12*60*2 {
			log.Fatal("the router didn't exit within 12 min of the drain")
		}
		time.Sleep(500 * time.Millisecond)
	}
	var st struct {
		Sessions map[string]struct{ State, Error string }
	}
	sb, err := os.ReadFile(filepath.Join(os.Getenv("E2E_DATA_DIR"), "state.json"))
	if err != nil || json.Unmarshal(sb, &st) != nil {
		log.Fatalf("the router's state.json: %v", err)
	}
	if x := st.Sessions[id]; x.State != "paused" {
		log.Fatalf("the in-flight pause ended %q (%s)", x.State, x.Error)
	}
	lb, _ := os.ReadFile(os.Getenv("E2E_ROUTER_LOG"))
	if strings.Contains(string(lb), "not waiting for a snapshot") || strings.Contains(string(lb), "never got past boot") {
		log.Fatal("the pause didn't wait for the machine's snapshot: the drain wasn't tested with one in flight")
	}
	if !strings.Contains(string(lb), "drained") {
		log.Fatal("the router's log has no \"drained\"")
	}
	log.Printf("E2E PASSED (the drain only)")
}
