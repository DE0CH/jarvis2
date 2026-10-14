package main

// What goes into the harness after it started (docs/DESIGN.md "The guard": wakeups, crons and watches; docs/API-grants.md):
//
//   - the session's own wakeups, crons and watches: the session arms them through the local API (apiproxy.go), which
//     keeps their texts in the guard's records (records.go, in the snapshot) and gives the router only what it needs to
//     schedule them, with no text: an id, a time, a period, the watch's check script (the router's runner runs it). When
//     one is due or fired, the router sends a content-free Due {kind, id, run, outcome}; the guard looks the text up,
//     applies its own replay rules (a wakeup once, a watch once, a cron run at most once per half period, never after
//     its end) and types it into the harness;
//   - notices: texts built into this image, which the router only triggers, naming nothing but strictly formatted
//     values (numbers, sizes, a device name, an Inbox id, an outcome word): the watchdog nudge, "upgraded", the lease
//     notices (the granted lease's note is the session's own, from the records) and Inbox outcomes (outcomes.go).
//
// Messages from other sessions are out of scope: nothing here delivers them.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Due: "X is due" / "X fired" (no text)
type Due struct {
	Kind    string `json:"kind"`              // wakeup | cron | watch
	ID      string `json:"id"`                // the id the guard gave it when the session armed it
	Run     int    `json:"run,omitempty"`     // a cron's run number
	Outcome string `json:"outcome,omitempty"` // a watch: met | gave-up
}

var textIDRE = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// dueText: the text for a due signal, with the records updated (or an error: refused, nothing recorded)
func (g *guard) dueText(d Due, now time.Time) (string, *watchText, error) {
	if !textIDRE.MatchString(d.ID) {
		return "", nil, errors.New("not an id")
	}
	var text string
	var w *watchText
	err := g.rec.update(func(r *recordsData) error {
		switch d.Kind {
		case "wakeup":
			x, ok := r.Wakeups[d.ID]
			if !ok {
				return errors.New("no wakeup this session armed has that id")
			}
			if x.Delivered != "" {
				return errors.New("this wakeup was already delivered")
			}
			x.Delivered = now.UTC().Format(time.RFC3339)
			r.Wakeups[d.ID] = x
			text = x.Prompt
			if x.Name != "" && x.Name != "default" {
				text = fmt.Sprintf("[scheduled wakeup %q] %s", x.Name, x.Prompt)
			}
		case "cron":
			x, ok := r.Crons[d.ID]
			if !ok {
				return errors.New("no cron this session armed has that id")
			}
			if x.Until > 0 && now.UnixMilli() > x.Until {
				return errors.New("this cron has ended")
			}
			every := max(x.EverySeconds, 15*60)
			if d.Run <= x.LastRun {
				return fmt.Errorf("cron run %d was already delivered (last %d)", d.Run, x.LastRun)
			}
			if x.LastAt > 0 && now.Unix()-x.LastAt < every/2 {
				return errors.New("this cron ran less than half its period ago")
			}
			x.LastRun, x.LastAt = d.Run, now.Unix()
			r.Crons[d.ID] = x
			text = fmt.Sprintf("[recurring wakeup %q — run %d] %s", x.Name, max(1, d.Run), x.Prompt)
		case "watch":
			x, ok := r.Watches[d.ID]
			if !ok {
				return errors.New("no watch this session armed has that id")
			}
			if x.Delivered != "" {
				return errors.New("this watch was already delivered")
			}
			switch d.Outcome {
			case "met":
				text = fmt.Sprintf("[watch %q met] %s", x.Name, x.Prompt)
			case "gave-up":
				text = fmt.Sprintf("[watch %q gave up] Conditional wakeup %q gave up (its check said to give up, or its time ran out without the condition being met). Decide what to do next.", x.Name, x.Name)
				if x.FailPrompt != "" {
					text = fmt.Sprintf("[watch %q gave up] %s", x.Name, x.FailPrompt)
				}
			default:
				return errors.New("a watch's outcome is met or gave-up")
			}
			x.Delivered = now.UTC().Format(time.RFC3339)
			r.Watches[d.ID] = x
			w = &x
		default:
			return fmt.Errorf("unknown kind %q", d.Kind)
		}
		return nil
	})
	return text, w, err
}

// DueResult: POST /m/due-result
type DueResult struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (g *guard) runDue(d Due) {
	res := DueResult{Kind: d.Kind, ID: d.ID}
	err := g.deliverDue(d)
	if err != nil {
		res.Error = err.Error()
		log.Printf("due %s %s refused: %v", d.Kind, d.ID, err)
	} else {
		res.OK = true
	}
	if err := g.c.json("POST", "/m/due-result", res, nil); err != nil {
		log.Printf("due result not sent: %v", err)
	}
}

func (g *guard) deliverDue(d Due) error {
	if !booted() {
		return errors.New("still booting")
	}
	if err := notFrozen(); err != nil {
		return err
	}
	text, w, err := g.dueText(d, g.now())
	if err != nil {
		return err
	}
	if w != nil { // the check once more, here, with the session's own env: its output is the context
		text += rerunCheck(w)
	}
	return sendToHarness(g.st.Harness, g.st.PermissionMode, "jarvis", text)
}

// ---- notices ------------------------------------------------------------------------------------------------

// Notice: a text built into this image; the router names only these strictly formatted values
type Notice struct {
	Kind        string        `json:"kind"`                  // nudge | upgraded | lease-granted | lease-taken | lease-back | request-outcome | continue
	Minutes     int           `json:"minutes,omitempty"`     // nudge: idle minutes; lease-granted: the lease's length
	Jobs        int           `json:"jobs,omitempty"`        // nudge: background jobs
	From        string        `json:"from,omitempty"`        // upgraded: small | medium | large
	To          string        `json:"to,omitempty"`          // upgraded
	Device      string        `json:"device,omitempty"`      // a lease name
	Handover    bool          `json:"handover,omitempty"`    // lease-granted: Deyao had taken it over
	Interrupted bool          `json:"interrupted,omitempty"` // lease-granted: and interrupted this session
	Filing      string        `json:"filing,omitempty"`      // request-outcome: the filing id the guard gave the request
	Items       []OutcomeItem `json:"items,omitempty"`       // request-outcome: the decided items
}

func (g *guard) noticeText(n Notice) (string, error) {
	switch n.Kind {
	case "nudge":
		if n.Minutes < 1 || n.Minutes > 100000 || n.Jobs < 0 || n.Jobs > 10000 {
			return "", errors.New("nudge: not a number of minutes and jobs")
		}
		jobs := fmt.Sprintf("%d background jobs have", n.Jobs)
		if n.Jobs == 1 {
			jobs = "1 background job has"
		}
		return fmt.Sprintf("Jarvis watchdog: this session has been idle for %d min while %s been running, and none has finished or woken you. ", n.Minutes, jobs) +
			"Check on them now: read their output, and if a job is hung or no longer needed, stop it and continue the task another way. " +
			"If a job is legitimately still running, make sure it will end on its own (a timeout or deadline), then end your turn — this check repeats while the state lasts. " +
			"This is an automated message from Jarvis, not from Deyao, and not an answer to any open question.", nil
	case "upgraded":
		return upgradedText(n.From, n.To)
	case "lease-granted", "lease-taken", "lease-back":
		return leaseText(n, g.rec.read().Leases[n.Device])
	case "request-outcome":
		return g.outcomeText(n)
	case "continue":
		return "continue", nil
	}
	return "", fmt.Errorf("unknown notice %q", n.Kind)
}

// NoticeResult: POST /m/notice-result
type NoticeResult struct {
	Kind  string `json:"kind"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (g *guard) runNotice(n Notice) {
	res := NoticeResult{Kind: n.Kind}
	err := func() error {
		if !booted() {
			return errors.New("still booting")
		}
		if err := notFrozen(); err != nil {
			return err
		}
		t, err := g.noticeText(n)
		if err != nil {
			return err
		}
		return sendToHarness(g.st.Harness, g.st.PermissionMode, "jarvis", t)
	}()
	if err != nil {
		res.Error = err.Error()
		log.Printf("notice %s refused: %v", n.Kind, err)
	} else {
		res.OK = true
	}
	if err := g.c.json("POST", "/m/notice-result", res, nil); err != nil {
		log.Printf("notice result not sent: %v", err)
	}
}

var sizeGB = map[string]int{"small": 2, "medium": 4, "large": 8}

// upgradedText: after an Upgrade, the first message on the bigger machine (router/memory.go builds the same text)
func upgradedText(from, to string) (string, error) {
	if sizeGB[from] == 0 || sizeGB[to] == 0 {
		return "", errors.New("upgraded: not a machine size")
	}
	return fmt.Sprintf("Jarvis: this session ran out of memory and was moved from a %s (%d GB) to a %s (%d GB) machine. ", from, sizeGB[from], to, sizeGB[to]) +
		"To free memory for the move, every process of the old machine was stopped: Claude itself, background jobs, builds, dev servers, browsers. " +
		"Their list is in ~/artifacts/jarvis2-upgrade-freed.txt. Check which of them the task still needs, restart only those (and keep an eye on memory: run fewer heavy things at once), then carry on with the task. " +
		"This is an automated message from Jarvis, not from Deyao, and not an answer to any open question.", nil
}

var leaseNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// leaseText: the device is a lease name, note the session's own (records)
func leaseText(n Notice, note string) (string, error) {
	if !leaseNameRE.MatchString(n.Device) {
		return "", errors.New("lease: not a device name")
	}
	dev := n.Device
	switch n.Kind {
	case "lease-taken":
		return fmt.Sprintf("[lease %q taken over] Deyao has taken the shared device %q himself. Stop using it now: every device action is refused while he has it. ", dev, dev) +
			"You are first in the queue; when he hands it back you'll be woken. Then look at the device first: it will be in whatever state he left it. " +
			"This is an automated message from Jarvis, not an answer to any open question.", nil
	case "lease-back":
		return fmt.Sprintf("[lease %q handed back] Deyao has handed the shared device %q back. Earlier this session found it taken over: that no longer applies. ", dev, dev) +
			fmt.Sprintf("Run scripts/lease.py status %s to see whether it is free or who holds it now, and acquire it if this session still needs it (scripts/lease.py acquire %s --purpose \"…\"). ", dev, dev) +
			"If you told Deyao or planned around it being unavailable, reconsider now. It is in whatever state he left it: look at it first. " +
			"This is an automated message from Jarvis, not an answer to any open question.", nil
	}
	if n.Minutes < 1 || n.Minutes > 6*60 {
		return "", errors.New("lease: not a lease length")
	}
	t := fmt.Sprintf("[lease %q granted] This session now holds the shared device %q (you were queued for it). ", dev, dev) +
		fmt.Sprintf("It is yours for %d min, renewed automatically by the device helpers on every action; return it when done (scripts/lease.py return %s). ", n.Minutes, dev)
	if n.Handover {
		t += fmt.Sprintf("Deyao had taken %q over himself", dev)
		if n.Interrupted {
			t += " (interrupting you: your earlier steps may no longer apply)"
		}
		t += fmt.Sprintf(" and has handed it back; his notes are in scripts/lease.py status %s. The device is in whatever state he left it: look at it first (screenshot / UI tree) and continue from there.", dev)
	} else {
		t += "The previous holder may have left it in any state: inspect it first."
	}
	if note = strings.TrimSpace(strings.Join(strings.Fields(note), " ")); note != "" {
		if r := []rune(note); len(r) > 2000 {
			note = string(r[:2000])
		}
		t += " Your note: " + note
	}
	return t, nil
}

// ---- into the harness ---------------------------------------------------------------------------------------

// sendToHarness: the text into the harness (the Claude host's inbox socket, or harness-send for OpenCode/OpenClaw)
var sendToHarness = func(harness, mode, from, text string) error {
	var cmd *exec.Cmd
	if harness == "opencode" || harness == "openclaw" {
		cmd = exec.Command("/usr/local/bin/harness-send", "--queue")
		cmd.Stdin = strings.NewReader(text)
	} else {
		fm := "prompting"
		if mode == "bypass" {
			fm = "bypass"
		}
		cmd = exec.Command("python3", "-I", "-c", inboxPy, base64.StdEncoding.EncodeToString([]byte(text)), "", fm, from)
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

// inboxPy: the in-machine sender into the claude host's inbox socket. argv: base64 text, target name ("" = the one
// live session), from-mode, from-name.
const inboxPy = `
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

// ---- watches: the check, run again here ----------------------------------------------------------------------

var rerunTimeout = 40 * time.Second

// rerunCheck: the watch's check run here (a login shell: the session's env and secrets) in a throwaway directory,
// within rerunTimeout; its stdout, capped, as the prompt's context
func rerunCheck(w *watchText) string {
	dir, err := os.MkdirTemp("", "watch-")
	if err != nil {
		return ""
	}
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "check.sh")
	if os.WriteFile(f, []byte(w.Script), 0o700) != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), rerunTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-l", f)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "WATCH_NAME="+w.Name)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: 6000}
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		code = -1
	}
	s := strings.TrimSpace(out.String())
	if ctx.Err() != nil {
		return fmt.Sprintf("\n\n[watch %q check output] (the check, run again on this machine, didn't finish within %s) %s", w.Name, rerunTimeout, s)
	}
	if s == "" {
		return ""
	}
	return fmt.Sprintf("\n\n[watch %q check output] (run again on this machine just now, exit %d)\n%s", w.Name, code, s)
}

type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}
