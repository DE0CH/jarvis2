package main

// The guard's judgement of grants (docs/DESIGN.md "Target design", "The guard"; docs/API-grants.md). A grant is
// (machine, allowed, conditions), made only by the kernel's grant mover or grant merger. The guard:
//
//   - holds exactly one grant at a time: a new one (from /m/commands) replaces the old one whole; the guard never
//     unions two grants itself (that is the merger's job);
//   - takes a grant only when the mover's or the merger's key (from the roster in the machine's Fly config) signed it,
//     and it names this machine with its own keys (the whole object);
//   - gives the conditions their meaning, and refuses a grant with a condition it doesn't know (fail closed):
//     until:<RFC 3339 time>  holds while the clock is before it (several: the earliest);
//     cmd:<sha256 hex>       the grant covers only a command whose sha256 is that (several: only one that is all);
//     once:<id>              the grant covers one command, once in the session's life (records in the snapshot);
//     session:<id>           holds only on this session (the session id in the source's start settings);
//   - reads two allowed strings: `shell` (run any command the router delivers while the grant holds, after a
//     log-notary challenge over the command's sha256) and `store:<name>` (the secrets component serves that store;
//     the guard only pulls with the grant). Any other allowed string grants nothing here.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

const (
	allowShell     = "shell"
	storePrefix    = "store:"
	maxExecOutput  = 1 << 20
	maxExecTimeout = 600 // seconds
	// challengeSkew: how far a log-notary challenge's time may be from this machine's clock
	challengeSkew = 5 * time.Minute
	aboutShell    = "shell"
)

var (
	sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	onceIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// untilLayouts: an until condition's time: RFC 3339 (seconds optional, as in DESIGN's `until:2026-10-14T12:10Z`)
var untilLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00"}

// conds: a grant's conditions, read
type conds struct {
	until    *time.Time
	cmds     []string
	once     []string
	sessions []string
}

// parseConditions: every condition read, or an error naming the first one the guard doesn't know (the grant is then
// refused whole)
func parseConditions(cs kernel.Conditions) (conds, error) {
	var c conds
	for _, x := range cs {
		kind, val, ok := strings.Cut(x, ":")
		if !ok {
			return c, fmt.Errorf("unknown condition %q", x)
		}
		switch kind {
		case "until":
			var t time.Time
			var err error
			for _, l := range untilLayouts {
				if t, err = time.Parse(l, val); err == nil {
					break
				}
			}
			if err != nil {
				return c, fmt.Errorf("condition %q: not a time", x)
			}
			if c.until == nil || t.Before(*c.until) {
				c.until = &t
			}
		case "cmd":
			if !sha256RE.MatchString(val) {
				return c, fmt.Errorf("condition %q: not a sha256", x)
			}
			c.cmds = append(c.cmds, val)
		case "once":
			if !onceIDRE.MatchString(val) {
				return c, fmt.Errorf("condition %q: not an id", x)
			}
			c.once = append(c.once, val)
		case "session":
			if !sessionIDRE.MatchString(val) {
				return c, fmt.Errorf("condition %q: not a session id", x)
			}
			c.sessions = append(c.sessions, val)
		default:
			return c, fmt.Errorf("unknown condition %q", x)
		}
	}
	return c, nil
}

// holds: the conditions that don't depend on a command, now, on this session, with these once records
func (c conds) holds(now time.Time, session string, used func(string) bool) error {
	if c.until != nil && !now.Before(*c.until) {
		return fmt.Errorf("the grant ran out at %s", c.until.UTC().Format(time.RFC3339))
	}
	for _, s := range c.sessions {
		if s != session {
			return fmt.Errorf("the grant is for session %s, this is %s", s, session)
		}
	}
	for _, id := range c.once {
		if used(id) {
			return fmt.Errorf("the grant's once:%s was already used", id)
		}
	}
	return nil
}

// coversCmd: a command whose sha256 is sum, under the grant's cmd: conditions (none: any command)
func (c conds) coversCmd(sum string) bool {
	for _, h := range c.cmds {
		if h != sum {
			return false
		}
	}
	return true
}

// current: the grant the guard holds
type current struct {
	doc   kernel.SignedDoc
	g     kernel.Grant
	conds conds
}

// checkGrant: a grant the guard may take: by the mover or the merger, for this machine with its keys, every condition
// known, and holding right now (a grant already run out, for another session, or whose once was used is refused)
func (g *guard) checkGrant(doc kernel.SignedDoc) (*current, error) {
	gr, err := kernel.OpenGrant(g.roster, doc, kernel.RoleMover, kernel.RoleMerger)
	if err != nil {
		return nil, err
	}
	if gr.Machine != g.me {
		return nil, fmt.Errorf("the grant is for %s, not this machine with its keys", gr.Machine.ID)
	}
	cs, err := parseConditions(gr.Conditions)
	if err != nil {
		return nil, err
	}
	if err := cs.holds(g.now(), g.st.Session, g.rec.onceUsed); err != nil {
		return nil, err
	}
	return &current{doc: doc, g: gr, conds: cs}, nil
}

// acceptGrant: the grant replaces the one the guard holds (one at a time); the caller pulls the stores it names
func (g *guard) acceptGrant(doc kernel.SignedDoc) error {
	_, err := g.takeGrant(doc)
	return err
}

// takeGrant: acceptGrant, and whether it changed the grant held (the same grant sent again changes nothing)
func (g *guard) takeGrant(doc kernel.SignedDoc) (bool, error) {
	cur, err := g.checkGrant(doc)
	if err != nil {
		return false, err
	}
	g.mu.Lock()
	same := g.cur != nil && g.cur.doc.ID() == doc.ID()
	g.cur = cur
	g.mu.Unlock()
	if same {
		return false, nil
	}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(g.grantPath, b, 0o600); err != nil {
		log.Printf("grant: keeping a copy for the CLI: %v", err)
	}
	log.Printf("grant %s taken (by %s): allowed %s, conditions %v", doc.ID()[:12], cur.g.By, setString(cur.g.Allowed), []string(cur.g.Conditions))
	return true, nil
}

// grant: the grant the guard holds (nil: none yet)
func (g *guard) grant() *current {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cur
}

func setString(s kernel.Set) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ---- shell -----------------------------------------------------------------------------------------------

// ShellRequest: a command the router delivers (docs/API-grants.md /m/commands "shell")
type ShellRequest struct {
	ID             string `json:"id"`
	Cmd            string `json:"cmd"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// ShellResult: POST /m/shell-result
type ShellResult struct {
	ID        string `json:"id"`
	Code      int    `json:"code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Error     string `json:"error,omitempty"`
	Grant     string `json:"grant,omitempty"`     // ID of the grant it ran under
	Challenge string `json:"challenge,omitempty"` // ID of the log notary's challenge over the command
}

var shellIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// authoriseShell: the grant the command may run under, or why not
func (g *guard) authoriseShell(sum string) (*current, error) {
	cur := g.grant()
	if cur == nil {
		return nil, errors.New("no grant")
	}
	if !cur.g.Allowed.Contains(allowShell) {
		return nil, errors.New("the grant doesn't allow shell")
	}
	if err := cur.conds.holds(g.now(), g.st.Session, g.rec.onceUsed); err != nil {
		return nil, err
	}
	if !cur.conds.coversCmd(sum) {
		return nil, errors.New("the grant covers another command (cmd: condition)")
	}
	return cur, nil
}

// challenge: the log notary's challenge over subject (through the router), checked: the notary's key, this subject
// and word, and a time near this machine's clock
func (g *guard) challenge(subject, about string) (kernel.SignedDoc, error) {
	var doc kernel.SignedDoc
	if err := g.c.json("POST", "/m/challenge", map[string]string{"subject": subject, "about": about}, &doc); err != nil {
		return doc, fmt.Errorf("challenge: %w", err)
	}
	return doc, g.checkChallenge(doc, subject, about)
}

func (g *guard) checkChallenge(doc kernel.SignedDoc, subject, about string) error {
	ch, err := kernel.OpenChallenge(g.roster, doc)
	if err != nil {
		return err
	}
	if ch.Subject != subject || ch.About != about {
		return errors.New("the challenge is about something else")
	}
	at, err := time.Parse(time.RFC3339Nano, ch.At)
	if err != nil {
		return errors.New("the challenge has no time")
	}
	if d := g.now().Sub(at); d > challengeSkew || d < -challengeSkew {
		return fmt.Errorf("the challenge's time %s is too far from this machine's clock", ch.At)
	}
	return nil
}

// shell: one delivered command — authorised by the grant, logged by the notary, once conditions recorded before it
// runs — and its result
func (g *guard) shell(r ShellRequest) ShellResult {
	res := ShellResult{ID: r.ID}
	fail := func(err error) ShellResult {
		res.Code, res.Error = -1, err.Error()
		log.Printf("shell %s refused: %v", r.ID, err)
		return res
	}
	if !shellIDRE.MatchString(r.ID) || r.Cmd == "" {
		return fail(errors.New("a command has an id and a command line"))
	}
	if err := notFrozen(); err != nil {
		return fail(err)
	}
	h := sha256.Sum256([]byte(r.Cmd))
	sum := hex.EncodeToString(h[:])
	if _, err := g.authoriseShell(sum); err != nil {
		return fail(err)
	}
	ch, err := g.challenge(sum, aboutShell)
	if err != nil {
		return fail(err)
	}
	res.Challenge = ch.ID()
	cur, err := g.authoriseShell(sum) // the grant may have changed while the notary answered: judge again
	if err != nil {
		return fail(err)
	}
	res.Grant = cur.doc.ID()
	if err := g.rec.useOnce(cur.conds.once, g.now()); err != nil {
		return fail(err)
	}
	t := time.Duration(max(1, min(r.TimeoutSeconds, maxExecTimeout))) * time.Second
	if r.TimeoutSeconds <= 0 {
		t = maxExecTimeout * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-lc", r.Cmd)
	var out, errb capped
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	res.Stdout, res.Stderr = out.String(), errb.String()
	if cmd.ProcessState != nil {
		res.Code = cmd.ProcessState.ExitCode()
	}
	if err != nil && cmd.ProcessState == nil {
		res.Code, res.Error = -1, err.Error()
	}
	log.Printf("shell %s ran under grant %s (challenge %s): exit %d", r.ID, res.Grant[:12], res.Challenge[:12], res.Code)
	return res
}

type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := maxExecOutput - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (g *guard) runShell(r ShellRequest) {
	res := g.shell(r)
	if err := g.c.json("POST", "/m/shell-result", res, nil); err != nil {
		log.Printf("shell result not sent: %v", err)
	}
}
