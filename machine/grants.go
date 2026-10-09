package main

// Grants (docs/DESIGN.md "Grants"): a router feature (terminal, scheduler, archive, …) has its own key pair,
// the holder. It asks this machine to run a shell command. The machine runs it when one of these allows it:
//   - a phone grant: the phone's signature over {kind "grant", holder, session, scope "shell", expires}, at most
//     10 minutes long. The phone's key comes from this machine's core-signed cert.
//   - a standing rule: the phone's signature over {kind "rule", holder, session, scope "shell", until}.
//   - this session's own allow list (~/.jarvis2-allow.json, written by `jarvis2-machine allow`): the machine
//     approving for itself. It travels in the snapshot, so it survives a pause.
// A session holding a sensitive store accepts only a phone grant. The core takes no part.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	allowFile     = ".jarvis2-allow.json"
	maxGrant      = 10*time.Minute + 30*time.Second // 10 minutes, plus clock slack
	maxExecOutput = 1 << 20
)

// ExecRequest: what the holder signs
type ExecRequest struct {
	ID      string `json:"id"`
	Session string `json:"session"`
	Holder  string `json:"holder"` // the holder's public key (base64 x963)
	Cmd     string `json:"cmd"`
	Timeout int    `json:"timeout"` // seconds
	At      int64  `json:"at"`      // unix seconds
	// PhoneOnly: only a phone grant may allow this request (raising the session to bypass)
	PhoneOnly bool `json:"phoneOnly,omitempty"`
}

// Session in requests and grants is the line id from the core-signed cert (the line's first machine), not the
// router's session id.

// Exec: one item of /m/commands — the holder-signed request and what authorises it
type Exec struct {
	Request string     `json:"request"`
	Sig     string     `json:"sig"`
	Grant   *SignedDoc `json:"grant,omitempty"` // phone-signed grant or rule; nil = the allow list
}

type Grant struct {
	Kind    string `json:"kind"` // grant | rule
	Holder  string `json:"holder"`
	Session string `json:"session"`
	Scope   string `json:"scope"`
	Issued  string `json:"issued"`
	Expires string `json:"expires"` // grant
	Until   string `json:"until"`   // rule
}

type allowEntry struct {
	Holder string `json:"holder"`
	Name   string `json:"name"`
	Until  string `json:"until"`
}

type ExecResult struct {
	ID     string `json:"id"`
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Error  string `json:"error,omitempty"`
}

var (
	seenMu sync.Mutex
	seen   = map[string]time.Time{}
)

var currentCert = readCert // a var so tests can supply a cert

func readCert() (Cert, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return Cert{}, err
	}
	var d SignedDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Cert{}, err
	}
	key, err := readTrim(coreKeyPath)
	if err != nil {
		return Cert{}, err
	}
	var c Cert
	return c, verifyDoc(key, &d, &c)
}

func readAllow() []allowEntry {
	home, _ := os.UserHomeDir()
	var out []allowEntry
	if b, err := os.ReadFile(filepath.Join(home, allowFile)); err == nil {
		json.Unmarshal(b, &out)
	}
	return out
}

// authorise: nil when the request may run
func authorise(e Exec, now time.Time) (ExecRequest, error) {
	var r ExecRequest
	if err := json.Unmarshal([]byte(e.Request), &r); err != nil {
		return r, errors.New("bad request")
	}
	if !verify(r.Holder, []byte(e.Request), e.Sig) {
		return r, errors.New("not signed by the holder it names")
	}
	if at := time.Unix(r.At, 0); now.Sub(at) > 2*time.Minute || at.Sub(now) > 2*time.Minute {
		return r, errors.New("request too old or from the future")
	}
	seenMu.Lock()
	for id, t := range seen {
		if now.Sub(t) > 5*time.Minute {
			delete(seen, id)
		}
	}
	dup := seen[r.ID] != time.Time{}
	seen[r.ID] = now
	seenMu.Unlock()
	if r.ID == "" || dup {
		return r, errors.New("request id missing or already used")
	}
	cert, err := currentCert()
	if err != nil {
		return r, fmt.Errorf("no valid cert: %v", err)
	}
	me := cert.Line // core-signed, so the router can't relabel a machine to reuse another line's grant
	if me == "" || r.Session != me {
		return r, fmt.Errorf("request is for line %s, this is %s", r.Session, me)
	}
	if r.PhoneOnly && e.Grant == nil {
		return r, errors.New("this request needs a phone grant")
	}
	if e.Grant == nil {
		if cert.Sensitive {
			return r, errors.New("this session holds a sensitive store: only a phone grant opens a shell")
		}
		for _, a := range readAllow() {
			if u, err := time.Parse(time.RFC3339, a.Until); err == nil && a.Holder == r.Holder && now.Before(u) {
				return r, nil
			}
		}
		return r, errors.New("no grant, and the holder isn't on this session's allow list")
	}
	var g Grant
	if cert.Phone == "" || verifyDoc(cert.Phone, e.Grant, &g) != nil {
		return r, errors.New("the grant isn't signed by the phone named in this machine's cert")
	}
	if g.Holder != r.Holder || g.Session != me || g.Scope != "shell" {
		return r, errors.New("the grant is for another holder, session or scope")
	}
	switch g.Kind {
	case "grant":
		iss, err1 := time.Parse(time.RFC3339, g.Issued)
		exp, err2 := time.Parse(time.RFC3339, g.Expires)
		if err1 != nil || err2 != nil || exp.Sub(iss) > maxGrant || !now.Before(exp) || now.Before(iss.Add(-2*time.Minute)) {
			return r, errors.New("the grant is expired, or longer than 10 minutes")
		}
	case "rule":
		if r.PhoneOnly {
			return r, errors.New("this request needs a phone grant, not a standing rule")
		}
		if cert.Sensitive {
			return r, errors.New("this session holds a sensitive store: standing rules don't apply")
		}
		u, err := time.Parse(time.RFC3339, g.Until)
		if err != nil || !now.Before(u) {
			return r, errors.New("the standing rule has expired")
		}
	default:
		return r, errors.New("unknown grant kind")
	}
	return r, nil
}

type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := maxExecOutput - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func runExec(c *client, e Exec) {
	r, err := authorise(e, time.Now())
	res := ExecResult{ID: r.ID}
	if err != nil {
		res.Code, res.Error = -1, err.Error()
		log.Printf("exec refused: %v", err)
	} else {
		t := time.Duration(max(1, min(r.Timeout, 600))) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), t)
		cmd := exec.CommandContext(ctx, "bash", "-lc", r.Cmd)
		var out, errb capped
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		cancel()
		res.Stdout, res.Stderr = out.String(), errb.String()
		if cmd.ProcessState != nil {
			res.Code = cmd.ProcessState.ExitCode()
		}
		if err != nil && cmd.ProcessState == nil {
			res.Code, res.Error = -1, err.Error()
		}
	}
	if err := c.json("POST", "/m/exec-result", res, nil); err != nil {
		log.Printf("exec result not delivered: %v", err)
	}
}

// allowCmd: `jarvis2-machine allow <holder name> <duration>` (e.g. scheduler 720h) or `allow --remove <name>`;
// the holder's key comes from the router's list of feature keys
func allowCmd(args []string) error {
	home, _ := os.UserHomeDir()
	list := readAllow()
	if len(args) == 2 && args[0] == "--remove" {
		out := list[:0]
		for _, a := range list {
			if a.Name != args[1] {
				out = append(out, a)
			}
		}
		b, _ := json.MarshalIndent(out, "", " ")
		return os.WriteFile(filepath.Join(home, allowFile), b, 0o600)
	}
	if len(args) == 0 {
		b, _ := json.MarshalIndent(list, "", " ")
		fmt.Println(string(b))
		return nil
	}
	if len(args) != 2 {
		return errors.New("usage: jarvis2-machine allow [<holder> <duration> | --remove <holder>]")
	}
	d, err := time.ParseDuration(args[1])
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var holders map[string]string
	if err := c.json("GET", "/m/holders", nil, &holders); err != nil {
		return err
	}
	key := holders[args[0]]
	if key == "" {
		names := []string{}
		for n := range holders {
			names = append(names, n)
		}
		return fmt.Errorf("no holder %q (known: %s)", args[0], strings.Join(names, ", "))
	}
	out := []allowEntry{}
	for _, a := range list {
		if a.Name != args[0] {
			out = append(out, a)
		}
	}
	out = append(out, allowEntry{Holder: key, Name: args[0], Until: time.Now().Add(d).UTC().Format(time.RFC3339)})
	b, _ := json.MarshalIndent(out, "", " ")
	return os.WriteFile(filepath.Join(home, allowFile), b, 0o600)
}
