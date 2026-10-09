package main

// Message delivery into a session's harness (Jarvis 1's lib/peer.js, lessons/52 in claude-env): a peer message
// written straight to the host's inbox socket, never keystrokes (typing + Enter answers whatever dialog is open)
// and never through a model. The sender is a small stdlib Python program run inside the machine as the session
// user, through a grant (holder "scheduler", grants.go); the machine decides whether it runs.
//
// The text is untrusted data: it travels base64-encoded as an argv item (base64's alphabet is safe inside single
// quotes), never inside the shell string or the heredoc. An OpenCode/OpenClaw session takes it through the
// image's harness-send instead (spooled; the session's supervisor delivers it).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	peerMaxText  = 16000
	peerExecWait = 30 * time.Second
)

// the in-machine sender. argv: base64 text, target name ("" = the one live session), from-mode, from-name.
// Prints ONE JSON line {success, message, target?, ack?}; exit 1 on failure.
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

// harnesses that take prompts through /usr/local/bin/harness-send rather than a claude host
var harnessSend = map[string]bool{"opencode": true, "openclaw": true}

var senderRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// peerFromMode: the class the CLI itself puts on the wire, so the message is in the host's permission class
func peerFromMode(permissionMode string) string {
	if permissionMode == "bypass" {
		return "bypass"
	}
	return "prompting"
}

// cleanPeerText: CRLF → LF, trimmed, capped
func cleanPeerText(text string) string {
	text = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"))
	if len(text) > peerMaxText {
		text = text[:peerMaxText]
	}
	return text
}

// peerCommand: the shell command that delivers text. Every variable part is base64 or from a fixed set; the
// heredoc carries only the constant program, under a delimiter with a random part.
func peerCommand(harness, permissionMode, from, text, after string) string {
	b := base64.StdEncoding.EncodeToString([]byte(text))
	var cmd string
	if harnessSend[harness] {
		cmd = fmt.Sprintf("printf %%s '%s' | base64 -d | /usr/local/bin/harness-send --queue", b)
	} else {
		if !senderRE.MatchString(from) {
			from = "jarvis"
		}
		delim := "__JARVIS2_PEER_" + randID() + "__"
		cmd = fmt.Sprintf("cd \"$HOME\"; python3 - '%s' '' '%s' '%s' <<'%s'\n%s\n%s", b, peerFromMode(permissionMode), from, delim, peerPy, delim)
	}
	if after != "" {
		// run whatever follows (the cron's allow-list renewal) without changing the delivery's exit status
		cmd = "{ " + cmd + "\n}; rc=$?; { " + after + "; } >/dev/null 2>&1; exit $rc"
	}
	return cmd
}

type peerAnswer struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Target  string `json:"target"`
	Ack     string `json:"ack"`
}

// parsePeerAnswer: the sender's last JSON line
func parsePeerAnswer(stdout string) *peerAnswer {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "{") {
			var a peerAnswer
			if json.Unmarshal([]byte(l), &a) == nil {
				return &a
			}
			return nil
		}
	}
	return nil
}

var heldRE = regexp.MustCompile(`(?i)held for|not accepting|refus`)

// errNotUp: the harness isn't listening yet (booting); worth retrying in a few seconds
var errNotUp = errors.New("no live harness to deliver to yet")

// checkPeerResult: what the exec's output means
func checkPeerResult(harness string, res ExecResult) error {
	if harnessSend[harness] {
		if res.Code != 0 {
			return fmt.Errorf("harness-send exited %d: %s", res.Code, trimTo(res.Stderr+res.Stdout, 300))
		}
		return nil
	}
	a := parsePeerAnswer(res.Stdout)
	if a == nil || !a.Success {
		why := strings.TrimSpace(res.Stderr + res.Stdout)
		if a != nil {
			why = a.Message
		}
		if why == "" {
			why = fmt.Sprintf("sender exited %d", res.Code)
		}
		if strings.Contains(why, "target session not found") {
			return fmt.Errorf("%w: %s", errNotUp, trimTo(why, 300))
		}
		return errors.New("peer message not delivered: " + trimTo(why, 300))
	}
	if heldRE.MatchString(a.Ack) {
		return errors.New("peer message held/refused by the host: " + trimTo(a.Ack, 300))
	}
	return nil
}

func trimTo(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// deliverPeer: deliverHook (features.go). Fails when the machine refuses the scheduler (see isGrantRefusal).
func deliverPeer(r *Router, session, from, text string) error {
	return r.deliverPeer(session, from, text, "")
}

func (r *Router) deliverPeer(session, from, text, after string) error {
	text = cleanPeerText(text)
	if text == "" {
		return errors.New("empty message")
	}
	var harness, mode string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[session]; s != nil {
			harness, mode = s.Harness, s.PermissionMode
		}
	})
	res, err := r.Exec(session, "scheduler", peerCommand(harness, mode, from, text, after), peerExecWait)
	if err != nil {
		return err
	}
	return checkPeerResult(harness, res)
}

// isGrantRefusal: the machine refused the scheduler's shell (no grant, not on the allow list, a sensitive store).
// Retrying won't help until Deyao grants it from the phone.
func isGrantRefusal(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	if !strings.Contains(m, "the machine refused or failed") {
		return false
	}
	for _, k := range []string{"allow list", "sensitive store", "phone grant", "grant is", "standing rule", "not signed by the phone"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}
