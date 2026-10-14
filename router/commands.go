package main

// The command channel to a machine (docs/API-grants.md "The command channel"): GET /m/commands is a long poll that
// answers one object with any of content-free words, ONE grant (the newest the router holds for the machine), shell
// commands under the held grant, due signals and notices. The guard decides every one of them.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// ShellCmd: one command under the held grant
type ShellCmd struct {
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
	Grant     string `json:"grant"`
	Challenge string `json:"challenge"`
}

// Due: "X is due" / "X fired" (no text)
type Due struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Run     int    `json:"run,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

// DueResult: POST /m/due-result
type DueResult struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Notice: a text built into the image, named by strictly formatted values only
type Notice struct {
	Kind        string        `json:"kind"`
	Minutes     int           `json:"minutes,omitempty"`
	Jobs        int           `json:"jobs,omitempty"`
	From        string        `json:"from,omitempty"`
	To          string        `json:"to,omitempty"`
	Device      string        `json:"device,omitempty"`
	Handover    bool          `json:"handover,omitempty"`
	Interrupted bool          `json:"interrupted,omitempty"`
	Filing      string        `json:"filing,omitempty"`
	Items       []OutcomeItem `json:"items,omitempty"`
}

// NoticeResult: POST /m/notice-result
type NoticeResult struct {
	Kind  string `json:"kind"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// commandsAnswer: one answer of GET /m/commands (every field optional)
type commandsAnswer struct {
	Commands []string          `json:"commands,omitempty"`
	Grant    *kernel.SignedDoc `json:"grant,omitempty"`
	Shell    []ShellCmd        `json:"shell,omitempty"`
	Due      []Due             `json:"due,omitempty"`
	Notices  []Notice          `json:"notices,omitempty"`
}

func (a commandsAnswer) empty() bool {
	return len(a.Commands) == 0 && a.Grant == nil && len(a.Shell) == 0 && len(a.Due) == 0 && len(a.Notices) == 0
}

// outbox: what waits for one machine
type outbox struct {
	mu      sync.Mutex
	words   []string
	grant   *kernel.SignedDoc
	shell   []ShellCmd
	due     []Due
	notices []Notice
	wake    chan struct{}

	shellRes  map[string]chan ShellResult
	dueRes    map[string]chan DueResult      // kind/id
	noticeRes map[string][]chan NoticeResult // kind → waiters, oldest first
}

var outboxes = struct {
	sync.Mutex
	m map[string]*outbox
}{m: map[string]*outbox{}}

// out: the machine's outbox
func (r *Router) out(machine string) *outbox {
	outboxes.Lock()
	defer outboxes.Unlock()
	o := outboxes.m[machine]
	if o == nil {
		o = &outbox{wake: make(chan struct{}, 1), shellRes: map[string]chan ShellResult{}, dueRes: map[string]chan DueResult{},
			noticeRes: map[string][]chan NoticeResult{}}
		outboxes.m[machine] = o
	}
	return o
}

func dropOutbox(machine string) {
	outboxes.Lock()
	delete(outboxes.m, machine)
	outboxes.Unlock()
}

func (o *outbox) poke() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// word: a content-free command (snapshot, free, pull, claude-prepare:<gen>), each once while it waits
func (o *outbox) word(w string) {
	o.mu.Lock()
	for _, x := range o.words {
		if x == w {
			o.mu.Unlock()
			return
		}
	}
	o.words = append(o.words, w)
	o.mu.Unlock()
	o.poke()
}

// setGrant: the grant the machine should hold (replaces one not yet taken)
func (o *outbox) setGrant(g kernel.SignedDoc) {
	o.mu.Lock()
	o.grant = &g
	o.mu.Unlock()
	o.poke()
}

// take: what is waiting, as one answer (the grant first, then words, shell, due, notices; at most a few each)
func (o *outbox) take() commandsAnswer {
	o.mu.Lock()
	defer o.mu.Unlock()
	var a commandsAnswer
	if o.grant != nil {
		a.Grant, o.grant = o.grant, nil
	}
	a.Commands, o.words = o.words, nil
	a.Shell, o.shell = o.shell, nil
	a.Due, o.due = o.due, nil
	a.Notices, o.notices = o.notices, nil
	return a
}

// next: the waiting answer, or wait up to d for one ({} when nothing happened)
func (o *outbox) next(d time.Duration, done <-chan struct{}) commandsAnswer {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		if a := o.take(); !a.empty() {
			return a
		}
		select {
		case <-o.wake:
		case <-t.C:
			return commandsAnswer{}
		case <-done:
			return commandsAnswer{}
		}
	}
}

var errNoAnswer = errors.New("no answer from the machine")

// runShell: one command under the held grant, waiting for its result
func (o *outbox) runShell(cmd string, timeout time.Duration) (ShellResult, error) {
	secs := int(timeout / time.Second)
	if secs < 1 || secs > 600 {
		secs = 600
	}
	id := randID()
	ch := make(chan ShellResult, 1)
	o.mu.Lock()
	o.shellRes[id] = ch
	o.shell = append(o.shell, ShellCmd{ID: id, Cmd: cmd, TimeoutSeconds: secs})
	o.mu.Unlock()
	o.poke()
	defer func() { o.mu.Lock(); delete(o.shellRes, id); o.mu.Unlock() }()
	select {
	case res := <-ch:
		if res.Error != "" {
			return res, fmt.Errorf("the machine refused or failed: %s", res.Error)
		}
		return res, nil
	case <-time.After(time.Duration(secs)*time.Second + 60*time.Second):
		return ShellResult{}, errNoAnswer
	}
}

func (o *outbox) shellResult(res ShellResult) {
	o.mu.Lock()
	ch := o.shellRes[res.ID]
	o.mu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
		}
	}
}

// sendDue: one due signal, waiting for the guard's answer
func (o *outbox) sendDue(d Due, wait time.Duration) (DueResult, error) {
	key := d.Kind + "/" + d.ID
	ch := make(chan DueResult, 1)
	o.mu.Lock()
	o.dueRes[key] = ch
	o.due = append(o.due, d)
	o.mu.Unlock()
	o.poke()
	defer func() { o.mu.Lock(); delete(o.dueRes, key); o.mu.Unlock() }()
	select {
	case res := <-ch:
		return res, nil
	case <-time.After(wait):
		return DueResult{}, errNoAnswer
	}
}

func (o *outbox) dueResult(res DueResult) {
	o.mu.Lock()
	ch := o.dueRes[res.Kind+"/"+res.ID]
	o.mu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
		}
	}
}

// sendNotice: one notice, waiting for the guard's answer (answers carry only the kind: the oldest waiter takes it)
func (o *outbox) sendNotice(n Notice, wait time.Duration) (NoticeResult, error) {
	ch := make(chan NoticeResult, 1)
	o.mu.Lock()
	o.noticeRes[n.Kind] = append(o.noticeRes[n.Kind], ch)
	o.notices = append(o.notices, n)
	o.mu.Unlock()
	o.poke()
	defer func() {
		o.mu.Lock()
		list := o.noticeRes[n.Kind]
		for i, c := range list {
			if c == ch {
				o.noticeRes[n.Kind] = append(list[:i:i], list[i+1:]...)
				break
			}
		}
		o.mu.Unlock()
	}()
	select {
	case res := <-ch:
		return res, nil
	case <-time.After(wait):
		return NoticeResult{}, errNoAnswer
	}
}

func (o *outbox) noticeResult(res NoticeResult) {
	o.mu.Lock()
	var ch chan NoticeResult
	if list := o.noticeRes[res.Kind]; len(list) > 0 {
		ch = list[0]
	}
	o.mu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
		}
	}
}

// ---- the router's uses -----------------------------------------------------------------------------------------

// errNoShell: the machine's held grant doesn't allow `shell` (Deyao opens a terminal with a phone-signed add-on)
var errNoShell = errors.New("this needs a terminal: the session's grant doesn't allow shell (ask for one: POST /api/requests/terminal)")

// Shell: a command in the session's machine under the grant it holds — only while that grant allows shell
func (r *Router) Shell(sid, cmd string, timeout time.Duration) (ShellResult, error) {
	var machine string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.State == "started" {
			machine = s.MachineID
		}
	})
	if machine == "" {
		return ShellResult{}, errors.New("the session has no running machine")
	}
	g, err := r.heldGrantDoc(sid)
	if err != nil || !grantAllows(g, "shell") {
		return ShellResult{}, errNoShell
	}
	return r.out(machine).runShell(cmd, timeout)
}

// delivery waits
var (
	deliverWait      = 60 * time.Second
	harnessUpMax     = 5 * time.Minute
	scheduleWaitStep = 5 * time.Second
	scheduleWaitMax  = 10 * time.Minute
)

// errSkip: not an attempt (the session is busy with another action); the next tick tries again
var errSkip = errors.New("busy")

// toSession: the session's running machine, resuming it first when it is paused (resume = true); waits for it to
// start and boot
func (r *Router) toSession(sid string, resume bool) (string, error) {
	var state, machine string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil {
			state, machine = s.State, s.MachineID
		}
	})
	switch state {
	case "":
		return "", errNoSession
	case "paused":
		if !resume {
			return "", errors.New("the session is paused")
		}
		if err := r.Resume(sid, ResumeIn{}); err != nil {
			if errors.Is(err, errBusy) {
				return "", errSkip
			}
			return "", err
		}
	case "pausing", "destroying", "approval", "resuming", "starting":
		if state != "starting" && state != "resuming" {
			return "", fmt.Errorf("%w: the session is %s", errSkip, state)
		}
	case "failed":
		return "", errors.New("the session has failed")
	}
	if err := r.waitStarted(sid); err != nil {
		return "", err
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil {
			machine = s.MachineID
		}
	})
	if machine == "" {
		return "", errors.New("the session has no running machine")
	}
	return machine, nil
}

// waitStarted: until the session is started (its machine pulled its secrets) or it fails
func (r *Router) waitStarted(sid string) error {
	deadline := time.Now().Add(scheduleWaitMax)
	for {
		var state, e string
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil {
				state, e = s.State, s.Error
			}
		})
		switch state {
		case "started":
			return nil
		case "", "paused", "failed", "destroying":
			return fmt.Errorf("the session didn't start (state %q %s)", state, e)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the session is still %s after %s", state, scheduleWaitMax)
		}
		time.Sleep(scheduleWaitStep)
	}
}

// deliverDue: a due signal into the session (resumed first when paused); retried while the guard is still booting
func (r *Router) deliverDue(sid string, d Due) error {
	machine, err := r.toSession(sid, true)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(harnessUpMax)
	for {
		res, err := r.out(machine).sendDue(d, deliverWait)
		if err == nil && res.OK {
			return nil
		}
		why := "no answer"
		if err == nil {
			why = res.Error
		}
		if strings.Contains(why, "booting") && time.Now().Before(deadline) {
			time.Sleep(scheduleWaitStep)
			continue
		}
		return errors.New("the machine refused or failed: " + why)
	}
}

// deliverNotice: a notice into the session (resume: resume it first when paused); retried while it boots
func (r *Router) deliverNotice(sid string, n Notice, resume bool) error {
	machine, err := r.toSession(sid, resume)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(harnessUpMax)
	for {
		res, err := r.out(machine).sendNotice(n, deliverWait)
		if err == nil && res.OK {
			return nil
		}
		why := "no answer"
		if err == nil {
			why = res.Error
		}
		if (strings.Contains(why, "booting") || strings.Contains(why, "target session not found")) && time.Now().Before(deadline) {
			time.Sleep(scheduleWaitStep)
			continue
		}
		return errors.New("the machine refused or failed: " + why)
	}
}

// deliverNoticeHook: a seam for tests (deliverNotice)
var deliverNoticeHook = func(r *Router, sid string, n Notice, resume bool) error { return r.deliverNotice(sid, n, resume) }
