package main

// Inputs Jarvis 2 delivers into a running session after it started (docs/DESIGN.md "Inputs to a machine"): a
// wakeup's or cron's prompt, the router's watchdog nudge, a "continue" after a re-login. Each arrives in
// /m/commands as a delivery and is taken only when it is
//
//   - vouched for: a wakeup or cron is the session's OWN request (the machine-signed POST the session made to
//     /m/api/sessions/<id>/wakeup or /crons, which the router keeps as it was), checked against this line's signing
//     keys (lineKeysFile: every machine of the line adds its key; the file travels in the signed snapshot); the
//     nudge and "continue" are texts built into this image, so the router chooses only when, never what;
//   - and logged: it carries the core's attestation over (this machine, the kind, the sha256 of the input), so
//     every input is in the core's hash-chained input log (core/audit.go).
//
// A delivery missing either is refused. The machine sends the text into the harness itself (the Claude host's
// inbox socket, or harness-send for OpenCode/OpenClaw); the router never runs a command for it. Older routers
// keep the grant-checked exec path ("scheduler"), which a machine whose cert vouches (Vouch 2) refuses.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// lineKeysFile: this line's machines' signing keys (relative to $HOME; in snapshotPaths)
const lineKeysFile = ".jarvis2-line-keys.json"

var lineKeysMu sync.Mutex

func readLineKeys() []string {
	home, _ := os.UserHomeDir()
	var keys []string
	if b, err := os.ReadFile(filepath.Join(home, lineKeysFile)); err == nil {
		json.Unmarshal(b, &keys)
	}
	return keys
}

func addLineKey(k string) {
	if k == "" {
		return
	}
	lineKeysMu.Lock()
	defer lineKeysMu.Unlock()
	keys := readLineKeys()
	for _, x := range keys {
		if x == k {
			return
		}
	}
	keys = append(keys, k)
	home, _ := os.UserHomeDir()
	b, _ := json.Marshal(keys)
	os.WriteFile(filepath.Join(home, lineKeysFile), b, 0o600)
}

// trustLineKeys: at boot, after the predecessor's verified snapshot (which carried the file) is restored. A new
// line's first machine starts the file (an archived restore brings the old line's keys: the phone approved that
// snapshot). Also the predecessor's own key, from its core-signed cert.
func trustLineKeys(cert Cert) {
	if cert.PredID == "" && !restoredArchive {
		home, _ := os.UserHomeDir()
		os.Remove(filepath.Join(home, lineKeysFile))
	}
	if predecessorKey != "" {
		addLineKey(predecessorKey)
	}
	if cert.Machine != nil {
		addLineKey(cert.Machine.SigningKey)
	}
}

var (
	predecessorKey  string // set by prepare from the predecessor's core-signed cert
	restoredArchive bool   // set by restoreArchived
)

// deliveredFile: what this line's own requests have already delivered (relative to $HOME; in snapshotPaths, so a
// successor knows too): a one-time wakeup's request once, a cron's request once per run, in order and no faster
// than half its period (R1 audit: the router kept a signed request and could deliver it again and again)
const deliveredFile = ".jarvis2-delivered.json"

type delivered struct {
	Run int   `json:"run"`
	At  int64 `json:"at"` // unix seconds
}

var deliveredMu sync.Mutex

// notReplayed: records the delivery, or refuses a repeat of one already made (wakeup, cron); other kinds pass
func notReplayed(d Delivery, now time.Time) error {
	if (d.Kind != "wakeup" && d.Kind != "cron") || d.Request == nil {
		return nil
	}
	deliveredMu.Lock()
	defer deliveredMu.Unlock()
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, deliveredFile)
	seen := map[string]delivered{}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &seen)
	}
	key := d.Kind + " " + d.Request.Sig
	last, ok := seen[key]
	if d.Kind == "wakeup" && ok {
		return errors.New("this wakeup was already delivered")
	}
	if d.Kind == "cron" && ok {
		every := int64(24 * 60 * 60)
		if body, err := base64.StdEncoding.DecodeString(d.Request.Body); err == nil {
			var b struct {
				Every int64 `json:"everySeconds"`
			}
			if json.Unmarshal(body, &b) == nil && b.Every > 0 {
				every = max(b.Every, 15*60)
			}
		}
		if d.Run <= last.Run {
			return fmt.Errorf("cron run %d was already delivered (last %d)", d.Run, last.Run)
		}
		if now.Unix()-last.At < every/2 {
			return errors.New("this cron ran less than half its period ago")
		}
	}
	seen[key] = delivered{Run: d.Run, At: now.Unix()}
	if len(seen) > 2000 { // keep the newest
		type kv struct {
			k string
			v delivered
		}
		all := make([]kv, 0, len(seen))
		for k, v := range seen {
			all = append(all, kv{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v.At > all[j].v.At })
		seen = map[string]delivered{}
		for _, x := range all[:2000] {
			seen[x.k] = x.v
		}
	}
	b, _ := json.Marshal(seen)
	return os.WriteFile(p, b, 0o600)
}

// SignedRequest: a request this line's machine made to the router, exactly as signed (client.raw)
type SignedRequest struct {
	Machine string `json:"machine"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	At      string `json:"at"`
	Body    string `json:"body"` // base64
	Sig     string `json:"sig"`
}

type Delivery struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"` // wakeup | cron | nudge | continue
	Request *SignedRequest `json:"request,omitempty"`
	Run     int            `json:"run,omitempty"`     // a cron's run number (a number)
	Minutes int            `json:"minutes,omitempty"` // nudge: idle minutes (a number)
	Jobs    int            `json:"jobs,omitempty"`    // nudge: background jobs (a number)
	Attest  *SignedDoc     `json:"attest"`
}

// ownRequestBody: the body of a request one of this line's machines signed (a wakeup or cron it asked for)
func ownRequestBody(r *SignedRequest, keys []string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("no request")
	}
	body, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		return nil, errors.New("bad body")
	}
	sum := sha256.Sum256(body)
	payload := []byte(r.Method + " " + r.Path + " " + r.At + " " + hex.EncodeToString(sum[:]))
	for _, k := range keys {
		if verify(k, payload, r.Sig) {
			return body, nil
		}
	}
	return nil, errors.New("not signed by a machine of this line")
}

// deliveryText: the text a delivery puts into the harness, and the bytes the core attested
func deliveryText(d Delivery, keys []string) (text string, attested []byte, err error) {
	switch d.Kind {
	case "wakeup", "cron":
		body, err := ownRequestBody(d.Request, keys)
		if err != nil {
			return "", nil, err
		}
		want := map[string]string{"wakeup": "/wakeup", "cron": "/crons"}[d.Kind]
		if d.Request.Method != "POST" || !strings.HasPrefix(d.Request.Path, "/m/api/sessions/") ||
			!(strings.HasSuffix(d.Request.Path, want) || (d.Kind == "wakeup" && strings.HasSuffix(d.Request.Path, "/wakeups"))) {
			return "", nil, fmt.Errorf("the signed request isn't a %s", d.Kind)
		}
		var b struct {
			Name   any    `json:"name"`
			Prompt string `json:"prompt"`
		}
		if json.Unmarshal(body, &b) != nil || strings.TrimSpace(b.Prompt) == "" {
			return "", nil, errors.New("the signed request has no prompt")
		}
		name := strings.TrimSpace(fmt.Sprint(b.Name))
		if b.Name == nil || name == "" {
			name = "default"
		}
		prompt := strings.Join(strings.Fields(b.Prompt), " ")
		if d.Kind == "wakeup" {
			if name == "default" {
				return prompt, body, nil
			}
			return fmt.Sprintf("[scheduled wakeup %q] %s", name, prompt), body, nil
		}
		return fmt.Sprintf("[recurring wakeup %q — run %d] %s", name, max(1, d.Run), prompt), body, nil
	case "continue":
		return "continue", []byte("continue"), nil
	case "nudge":
		jobs := fmt.Sprintf("%d background jobs have", d.Jobs)
		if d.Jobs == 1 {
			jobs = "1 background job has"
		}
		t := fmt.Sprintf("Jarvis watchdog: this session has been idle for %d min while %s been running, and none has finished or woken you. ", d.Minutes, jobs) +
			"Check on them now: read their output, and if a job is hung or no longer needed, stop it and continue the task another way. " +
			"If a job is legitimately still running, make sure it will end on its own (a timeout or deadline), then end your turn — this check repeats while the state lasts. " +
			"This is an automated message from Jarvis, not from Deyao, and not an answer to any open question."
		return t, []byte(t), nil
	}
	return "", nil, fmt.Errorf("unknown delivery kind %q", d.Kind)
}

// checkAttest: the core's input-log entry for exactly this input on this machine
func checkAttest(coreKey, me, kind string, attested []byte, d *SignedDoc) error {
	var e struct {
		Kind    string `json:"kind"`
		Machine string `json:"machine"`
		Input   string `json:"input"`
		Sha256  string `json:"sha256"`
	}
	if err := verifyDoc(coreKey, d, &e); err != nil || e.Kind != "input" {
		return errors.New("no core attestation (the input isn't in the core's log)")
	}
	sum := sha256.Sum256(attested)
	if e.Machine != me || e.Input != kind || e.Sha256 != hex.EncodeToString(sum[:]) {
		return errors.New("the core's attestation is for another input or machine")
	}
	return nil
}

type DeliveryResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func runDelivery(c *client, d Delivery) {
	res := DeliveryResult{ID: d.ID}
	err := deliver(c, d)
	if err != nil {
		res.Error = err.Error()
		log.Printf("delivery %s (%s) refused: %v", d.ID, d.Kind, err)
	} else {
		res.OK = true
		log.Printf("delivery %s (%s) delivered", d.ID, d.Kind)
	}
	if err := c.json("POST", "/m/delivery-result", res, nil); err != nil {
		log.Printf("delivery result not sent: %v", err)
	}
}

func deliver(c *client, d Delivery) error {
	cert, err := currentCert()
	if err != nil {
		return err
	}
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return err
	}
	text, attested, err := deliveryText(d, readLineKeys())
	if err != nil {
		return err
	}
	if err := checkAttest(coreKey, c.me, d.Kind, attested, d.Attest); err != nil {
		return err
	}
	if err := notFrozen(); err != nil {
		return err
	}
	if err := notReplayed(d, time.Now()); err != nil {
		return err
	}
	return sendToHarness(cert.Options.Harness, certMode(cert), "jarvis", text)
}

// sendToHarness: the text into the harness (the same as the router's old exec path, run here)
func sendToHarness(harness, mode, from, text string) error {
	var cmd *exec.Cmd
	if harness == "opencode" || harness == "openclaw" {
		cmd = exec.Command("/usr/local/bin/harness-send", "--queue")
		cmd.Stdin = strings.NewReader(text)
	} else {
		fm := "prompting"
		if mode == "bypass" {
			fm = "bypass"
		}
		cmd = exec.Command("python3", "-I", "-c", peerPy, base64.StdEncoding.EncodeToString([]byte(text)), "", fm, from)
	}
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return errors.New("the harness didn't take the message within 30 s")
	}
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// the in-machine sender (router/peer.go's, the same program). argv: base64 text, target name ("" = the one live
// session), from-mode, from-name.
const peerPy = `
import base64, glob, hashlib, json, os, socket, sys, uuid
text = base64.b64decode(sys.argv[1]).decode("utf-8", "replace")
name, mode, sender = sys.argv[2], sys.argv[3], sys.argv[4]
sess = os.path.expanduser("~/.claude/sessions")
def done(ok, message, **kw):
    print(json.dumps({"success": ok, "message": message, **kw})); sys.exit(0 if ok else 1)
def alive(pid):
    try: os.kill(int(pid), 0); return True
    except Exception: return False
live = []
for f in sorted(glob.glob(os.path.join(sess, "*.json"))):
    try: d = json.load(open(f))
    except Exception: continue
    p = d.get("messagingSocketPath")
    if not p or not os.path.exists(p) or not alive(d.get("pid")): continue
    if d.get("kind", "interactive") != "interactive": continue
    live.append(d)
named = [d for d in live if name and d.get("name") == name]
if len(named) == 1: t = named[0]
elif not named and len(live) == 1: t = live[0]
else:
    done(False, "target session not found: %s (live interactive sessions: %s)" % (name or "(unnamed)", ", ".join(str(d.get("name") or d.get("pid")) for d in live) or "none"))
if t.get("peerProtocol") != 1:
    done(False, "host %s speaks peerProtocol %r, this sender speaks 1" % (t.get("name"), t.get("peerProtocol")))
sock_path = t["messagingSocketPath"]
token = None
for f in glob.glob(os.path.join(sess, "*.%s.key" % hashlib.sha256(sock_path.lower().encode()).hexdigest())):
    try: token = json.load(open(f)).get("peerToken"); break
    except Exception: pass
body = '<cross-session-message from="uds:%s" from-name="%s" from-mode="%s">\n%s\n</cross-session-message>' % (sender, sender, mode, text)
frames = ([json.dumps({"type": "auth", "token": token})] if token else []) + [json.dumps({
    "msgV": 1, "msg_id": str(uuid.uuid4()), "type": "user",
    "message": {"role": "user", "content": body}, "priority": "next", "from": "uds:" + sender})]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sock_path)
    s.sendall(("\n".join(frames) + "\n").encode())
except Exception as e:
    done(False, "inbox socket %s: %s" % (sock_path, e))
s.settimeout(2)
try: ack = s.recv(65536).decode("utf-8", "replace")
except Exception: ack = ""
s.close()
done(True, "delivered to %s (pid %s)" % (t.get("name") or "?", t.get("pid")), target=t.get("name") or "", ack=ack[:500])
`
