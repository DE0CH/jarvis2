package main

// The session lifecycles (docs/DESIGN.md "Paths and lifecycles"), each a sequence of kernel steps the router carries:
//
//	new session   the router drafts (sink, source-x, P) and asks the log notary for its challenge; the phone signs it;
//	              notarized, root's ⊤ moved along it (→ the main grant on source-x); spawn from it, init, notarize the
//	              spawn cert, move the main grant onto the machine
//	pause         a kill into a fresh source (with the machine's final snapshot); the main grant moved onto it
//	resume        a spawn from that source; the main grant moved onto the new machine. A resume that changes what the
//	              source holds (a newer image, a prompt, a rollback, another model) is a new phone-made source whose
//	              snapshot is the paused one's; the paused source is burned.
//	destroy, end  a pause if it runs, the archive, then the burn (source, sink) by the gullible signer
//
// Every long step runs in its own goroutine; the session's `state` says where it is.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

type Router struct {
	cfg  Config
	st   *State
	k    *Kernel
	docs *DocStore

	locks sync.Map   // session id → *sync.Mutex: one lifecycle action at a time
	drain drainState // drain.go: the lifecycle goroutines running, refused once SIGTERM came
	ops   opsState   // sessionops.go: busy marks, restart jobs, uploads, repos

	snapMu  sync.Mutex
	snapped map[string]chan struct{}
	outs    outboxes // commands.go: what waits for each machine

	policy Policy

	setupMu   sync.Mutex
	setupSeen map[string]time.Time

	login     *loginHub // claudelogin.go: the Claude login
	loginOnce sync.Once

	muxOnce               sync.Once
	publicMux, machineMux *http.ServeMux
	appPatterns           map[string]bool // http.go: every app route's pattern (apicalls.go classifies them)
}

func NewRouter(cfg Config, st *State, k *Kernel, policy Policy) *Router {
	return &Router{cfg: cfg, st: st, k: k, docs: newDocStore(st.dir), policy: policy, setupSeen: map[string]time.Time{}, snapped: map[string]chan struct{}{}}
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var errBusy = errors.New("the session is in the middle of another action")

// lock: a session's lifecycle actions don't overlap; a clash is refused (409), not queued. kind names the
// action in /api/state's `busy` (sessionops.go). Each lock is a tracked lifecycle action (drain.go): refused with
// errDraining (503) once the router drains, waited for until its unlock.
func (r *Router) lock(id, kind string) (func(), error) {
	done, err := r.begin(id, kind)
	if err != nil {
		return nil, err
	}
	m, _ := r.locks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	if !mu.TryLock() {
		done()
		return nil, errBusy
	}
	r.ops.setBusy(id, kind)
	return func() { r.ops.setBusy(id, ""); mu.Unlock(); done() }, nil
}

func (r *Router) setState(id, state, errMsg string) {
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil {
			s.State, s.Error = state, errMsg
		}
	})
	if errMsg != "" {
		log.Printf("session %s: %s: %s", id, state, errMsg)
	}
}

// ---- new session ------------------------------------------------------------------------------------------------

type NewSession struct {
	RequestID      string         `json:"requestId"`
	Label          string         `json:"label"`
	Prompt         string         `json:"prompt"`
	Model          string         `json:"model"`
	PermissionMode string         `json:"permissionMode"` // fixed for the session's life (in its source's settings)
	Size           string         `json:"size"`
	Harness        string         `json:"harness"`
	Stores         []string       `json:"stores"`
	Repos          string         `json:"repos"`
	Content        []string       `json:"content"`     // content stores (content.go), in the source's settings
	OneShot        bool           `json:"oneShot"`     // destroyed once its prompt is done (autopilot.go)
	AutoPause      *bool          `json:"autoPause"`   // default on
	APIProxy       bool           `json:"apiProxy"`    // in the source's settings
	Attachments    *AttachmentsIn `json:"attachments"` // first-prompt attachments (uploads.go)
	Origin         *Origin        `json:"-"`           // inbox.go: who asked, from the credential (the handler sets it)
	Explanation    string         `json:"-"`           // a proposal's reason, shown with the approval (sessionapi.go)
	Task           *TaskConfig    `json:"-"`           // tasks.go: a task line's instance and parameters (into the settings)
	Snapshot       string         `json:"-"`           // a restore's: the snapshot the source names (its sha256)
	RestoreFrom    string         `json:"-"`           // restore.go: the record it restores
	RestoreShown   string         `json:"-"`           // what the approval's "restore" line says
	Import         *J1ImportRef   `json:"-"`           // jarvis1import.go: the Jarvis 1 session it imports (its manifest is the snapshot)
	Batch          string         `json:"-"`           // batches.go: the batch its approval belongs to
}

// CreateSession → the session's id. A requestId already on a session answers that session (idempotent). The phone's
// approval (its draft and challenge) exists when this returns.
func (r *Router) CreateSession(in NewSession) (string, error) {
	h, ok := r.policy.Harnesses[in.Harness]
	if !ok && isTaskHarness(in.Harness) {
		ok = true // a task line (tasks.go): the template's stores only, no harness stores
	}
	if !ok {
		in.Harness = "claude"
		if h, ok = r.policy.Harnesses[in.Harness]; !ok {
			return "", fmt.Errorf("no harness %s in the policy", in.Harness)
		}
	}
	if in.Size == "" {
		in.Size = "medium"
	}
	var err error
	if in.Model, err = sessionModel(in.Harness, in.Model); err != nil { // harness.go
		return "", err
	}
	in.PermissionMode = normMode(in.PermissionMode)
	stores, err := r.withHarnessStores(in.Stores, h.Stores)
	if err != nil {
		return "", err
	}
	content, err := r.checkContentStores(in.Content) // content.go: each an existing store
	if err != nil {
		return "", err
	}
	if in.Import != nil {
		in.Snapshot, in.RestoreShown = in.Import.Sha256, in.Import.Shown
	}
	s := &Session{ID: "s" + randID(), State: "approval", Created: time.Now().UTC(), Label: in.Label, Prompt: in.Prompt, Model: in.Model,
		PermissionMode: in.PermissionMode, Size: in.Size, Harness: in.Harness, Stores: stores, Repos: in.Repos, Content: content,
		RequestID: in.RequestID, Live: newLiveness(in), StartSnapshot: in.Snapshot, Image: r.cfg.SessionImage, RestoreFrom: in.RestoreFrom}
	if in.Import != nil {
		s.ImportFrom = in.Import.Session
	}
	var dup string
	r.st.Do(func(d *persisted) {
		if dup, err = admitSession(d, s, in); err == nil && dup == "" {
			d.Sessions[s.ID] = s
		}
	})
	if err != nil || dup != "" {
		return dup, err
	}
	s.taskConfig = in.Task
	drop := func(err error) (string, error) {
		r.st.Do(func(d *persisted) { delete(d.Sessions, s.ID) })
		return "", err
	}
	attach, err := r.attachmentRefs(s) // uploads.go: each file's sha256 and size
	if err != nil {
		return drop(err)
	}
	settings, err := r.sessionSettings(s, s.Prompt, "", attach)
	if err != nil {
		return drop(err)
	}
	src := kernel.Object{ID: newSourceID(), Image: r.cfg.SessionImage, Settings: settings, Snapshot: in.Snapshot}
	dr, err := r.makeDraft(kernel.Object{ID: kernel.Sink}, src, mainPair(s.ID, s.Stores))
	if err != nil {
		return drop(err)
	}
	opts := map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode, "repos": s.Repos}
	if len(s.Content) > 0 {
		opts["content"] = strings.Join(s.Content, ",")
	}
	liveOptions(s, opts)
	opsOptions(s, opts)
	if in.RestoreShown != "" {
		opts["restore"] = in.RestoreShown // the app shows it beside the signed snapshot hash
	}
	r.addApproval(&Approval{Kind: "new-session", Session: s.ID, Label: s.Label, Drafts: []Draft{dr}, Source: &src,
		Options: opts, Origin: in.Origin, Explanation: in.Explanation, Batch: in.Batch})
	return s.ID, nil
}

// deployKeyTokenStore: secrets opens it only inside a deploy-key call
const deployKeyTokenStore = "github-deploy-keys"

// withHarnessStores: the chosen stores plus the harness's, sorted
func (r *Router) withHarnessStores(chosen, harness []string) ([]string, error) {
	set := map[string]bool{}
	for _, n := range append(append([]string{}, chosen...), harness...) {
		if n == flyStore {
			return nil, fmt.Errorf("store %s is reserved and never goes to a session", n)
		}
		if n == deployKeyTokenStore {
			return nil, fmt.Errorf("store %s holds the deploy-key token: only a phone-approved deploy-key call opens it", n)
		}
		if !storeNameOK(n) {
			return nil, fmt.Errorf("bad store name %q", n)
		}
		set[n] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (r *Router) addApproval(a *Approval) {
	a.ID, a.Created = "a"+randID(), time.Now().UTC()
	if a.Origin == nil {
		a.Origin = takeOrigin(a.Session) // inbox.go: the caller the handler noted
	}
	if a.Source != nil && a.Source.Image != "" {
		img := a.Source.Image
		if img == r.cfg.SessionImage {
			a.ImageSig = r.cfg.SessionImageSig
		} else {
			a.ImageSig = r.cfg.ImageSigs[img]
		}
	}
	denied := false
	r.st.Do(func(d *persisted) {
		// a batch denied while this approval's drafts were being made: the approval goes the way the batch did
		if a.Batch != "" && d.Batches[a.Batch] == nil {
			denied = true
		}
		d.Approvals[a.ID] = a
	})
	if denied {
		r.Reject(a.ID)
	}
}

// loadImageSigs reads k8s/apps/session-image-sigs.txt as mounted ("<image> <sig>" per line; images.yml appends one per
// pin). The phone checks each signature itself (keys/ci.pub): the router can only pass one on or withhold it.
func loadImageSigs(path string) map[string]string {
	out := map[string]string{}
	if path == "" {
		return out
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("session image signatures: %v", err)
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

// ---- approvals -------------------------------------------------------------------------------------------------------

// Respond: the phone's signatures, one per draft in order → the session the approval was for. The certs are notarized
// here (a refusal leaves the approval in the Inbox); what follows runs as the approval's kind says.
func (r *Router) Respond(id string, sigs []string) (string, error) {
	var a *Approval
	r.expireApprovals(time.Now().UTC()) // an approval answered after inboxTTL is gone: the phone's answer comes too late
	r.st.Do(func(d *persisted) {
		if x := d.Approvals[id]; x != nil {
			c := *x
			a = &c
		}
	})
	if a == nil {
		return "", fmt.Errorf("no such approval (answered, denied or expired)")
	}
	if len(sigs) != len(a.Drafts) {
		return "", &badRequest{fmt.Sprintf("this approval has %d draft(s): one signature each, in order", len(a.Drafts))}
	}
	done, err := r.begin(a.Session, "approved")
	if err != nil {
		return "", err
	}
	ncs := []kernel.NotarizedCert{}
	for i, d := range a.Drafts {
		nc, err := r.notarizeDraft(d, sigs[i])
		if err != nil {
			done()
			return "", err
		}
		ncs = append(ncs, nc)
	}
	r.st.Do(func(d *persisted) { delete(d.Approvals, id) })
	outcome := func(o string) { r.st.Do(func(d *persisted) { noteOutcome(d, a.Origin, a.Kind, a.Session, o, 0) }) }
	switch a.Kind {
	case "new-session", "resume-upgrade":
		err = r.fromPhoneSource(a, ncs[0])
		if err != nil {
			done()
			outcome(outcomeFailed)
			r.setState(a.Session, "failed", err.Error())
			return "", err
		}
		outcome(outcomeApproved)
		go func() {
			defer done()
			r.startFrom(a.Session)
		}()
	default: // an add-on to a running machine (addons.go)
		defer done()
		if err := r.applyAddOn(a, ncs); err != nil {
			outcome(outcomeFailed)
			return "", err
		}
		outcome(outcomeApproved)
	}
	return a.Session, nil
}

// fromPhoneSource: a phone-made source becomes the session's: root's ⊤ moved along (sink, source-x, P) is its main
// grant. A resume out of a new source burns the paused one (it is never continued).
func (r *Router) fromPhoneSource(a *Approval, nc kernel.NotarizedCert) error {
	s, err := successionOf(nc.Cert)
	if err != nil {
		return err
	}
	top, err := r.rootGrant()
	if err != nil {
		return err
	}
	g, err := r.k.Move(top, nc)
	if err != nil {
		return err
	}
	var old *Chain
	r.st.Do(func(d *persisted) {
		x := d.Sessions[a.Session]
		if x == nil {
			return
		}
		if x.Chain != nil {
			c := x.Chain.clone()
			old = &c
		} else {
			x.Chain = &Chain{Steps: []ChainStep{}}
		}
		x.Image = s.Successor.Image
		x.State, x.Error = "starting", ""
	})
	if old != nil && old.Source.ID != "" && old.Machine == nil {
		if err := r.burn(a.Session, old.Source); err != nil {
			log.Printf("session %s: burning the paused source %s: %v", a.Session, old.Source.ID, err)
		}
	}
	certID := r.stepCert(a.Session, nc)
	gid := r.stepGrant(a.Session, g)
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[a.Session]; x != nil && x.Chain != nil {
			x.Chain.Origin, x.Chain.Source, x.Chain.Main = certID, s.Successor, gid
			x.Chain.Spawn, x.Chain.Machine, x.Chain.AddOns, x.Chain.Held = "", nil, nil, ""
		}
	})
	return nil
}

func (r *Router) Reject(id string) error { return r.RejectAs(id, outcomeDenied) }

// RejectAs: Reject, telling a requesting session the outcome (denied, or lapsed when it expired; outcomes.go)
func (r *Router) RejectAs(id, outcome string) error {
	var a *Approval
	r.st.Do(func(d *persisted) {
		a = d.Approvals[id]
		delete(d.Approvals, id)
		if a != nil {
			noteOutcome(d, a.Origin, a.Kind, a.Session, outcome, 0)
		}
	})
	if a == nil {
		return fmt.Errorf("no such approval")
	}
	r.st.Do(func(d *persisted) {
		s := d.Sessions[a.Session]
		switch {
		case s == nil:
		case a.Kind == "new-session":
			delete(d.Sessions, a.Session) // no machine was made
		case a.Kind == "resume-upgrade":
			s.State, s.Error = "paused", "" // nothing happened to the paused source
		}
	})
	return nil
}

// ---- start: spawn from the current source -------------------------------------------------------------------------

// the router's waits on the spawner's single-shot calls (tests shorten them)
var (
	initStep, initMax = 5 * time.Second, 12 * time.Minute // a session image's first pull on a Fly host takes minutes
	killStep, killMax = time.Second, 2 * time.Minute
)

// machineLimitWait / machineLimitStep: how long a start waits out Fly's org machine limit, and how often it tries
var machineLimitWait, machineLimitStep = 3 * time.Hour, time.Minute

func flyMachineLimit(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "machine limit")
}

// startFrom: spawn from the session's current source, wait for the spawner's init (the spawn cert), notarize it and
// move the main grant onto the machine — the grant the machine takes at boot (GET /m/grant)
func (r *Router) startFrom(sid string) {
	var s Session
	var c *Chain
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil && x.Chain != nil {
			s, c = *x, ptr(x.Chain.clone())
		}
	})
	if c == nil || c.Origin == "" {
		r.setState(sid, "failed", "start: the session has no source")
		return
	}
	r.setState(sid, "starting", "")
	origin, err := r.notarized(c.Origin)
	if err != nil {
		r.setState(sid, "failed", "start: "+err.Error())
		return
	}
	size := s.Size
	if size == "" {
		size = "medium"
	}
	machine, err := r.k.Spawn(origin, r.cfg.Region, size)
	// Fly's org machine limit (lessons/58): nothing was created and the source is still unspent, so wait for a machine
	// to go (sessions pause by themselves) instead of failing a start Deyao already approved. A drain doesn't wait.
	for waited := time.Duration(0); err != nil && flyMachineLimit(err) && waited < machineLimitWait; waited += machineLimitStep {
		if r.draining() || r.sleepUnlessDraining(machineLimitStep) {
			r.setState(sid, "paused", "start: "+errLimitDraining.Error())
			return
		}
		log.Printf("start: the Fly org is at its machine limit; trying again in %s", machineLimitStep)
		machine, err = r.k.Spawn(origin, r.cfg.Region, size)
	}
	if err != nil {
		// nothing was made: the source is unspent, so the session stays paused on it and a resume tries again
		r.setState(sid, "paused", "spawn: "+err.Error())
		return
	}
	r.st.Do(func(d *persisted) {
		d.Machines[machine] = sid
		if x := d.Sessions[sid]; x != nil {
			x.MachineID, x.PausedAt = machine, nil
		}
	})
	var cert kernel.SignedDoc
	for deadline := time.Now().Add(initMax); ; {
		cert, err = r.k.Init(machine)
		if err == nil || kernelStatus(err) != 409 && kernelStatus(err) != 502 || time.Now().After(deadline) {
			break
		}
		time.Sleep(initStep)
	}
	if err != nil {
		// without a spawn cert nothing can kill it: the spawner destroys a machine that runs the wrong image; one that
		// never came up stays for the Machines view (machines.go) and Fly
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[sid]; x != nil && x.MachineID == machine {
				x.MachineID = ""
			}
		})
		r.setState(sid, "failed", "init: "+err.Error())
		return
	}
	sp, _ := successionOf(cert)
	m := sp.Successor
	// the machine's keys from its spawn cert: from here on its requests are signed with them (it polls /m/boot)
	r.st.Do(func(d *persisted) {
		d.Started[machine] = &Started{ID: machine, Image: c.Source.Image, EncryptionKey: m.EncryptionKey, SigningKey: m.SigningKey}
	})
	nc, err := r.k.NotarizeNew(cert)
	if err != nil {
		r.setState(sid, "failed", "notarizing the spawn cert: "+err.Error())
		return
	}
	main, err := r.doc(c.Main)
	var g kernel.SignedDoc
	if err == nil {
		g, err = r.k.Move(main, nc)
	}
	if err != nil {
		r.killQuietly(sid, nc)
		r.setState(sid, "failed", "moving the grant onto the machine: "+err.Error())
		return
	}
	spawnID := r.stepCert(sid, nc)
	gid := r.stepGrant(sid, g)
	r.st.Do(func(d *persisted) {
		if st := d.Started[machine]; st != nil {
			st.Spawn = spawnID
		}
		if x := d.Sessions[sid]; x != nil && x.Chain != nil {
			x.Chain.Spawn, x.Chain.Machine, x.Chain.Main, x.Chain.Held, x.Chain.AddOns = spawnID, &m, gid, gid, nil
			x.State, x.Error = "initialising", ""
		}
	})
	log.Printf("session %s: machine %s spawned from %s", sid, machine, c.Source.ID)
}

func ptr[T any](v T) *T { return &v }

// killQuietly: a machine the router can't give a grant is killed (its spawn cert is notarized); the session fails
func (r *Router) killQuietly(sid string, spawn kernel.NotarizedCert) {
	cert, err := r.killUntilDestroyed(spawn, nil)
	if err != nil {
		log.Printf("session %s: kill after a failed start: %v", sid, err)
		return
	}
	if nc, err := r.k.NotarizeNew(cert); err == nil {
		r.docs.PutNotarized(nc)
	}
}

// killUntilDestroyed: the spawner's kill again until Fly reports the machine destroyed (409 before)
func (r *Router) killUntilDestroyed(spawn kernel.NotarizedCert, snap *SnapshotClaim) (kernel.SignedDoc, error) {
	deadline := time.Now().Add(killMax)
	for {
		d, err := r.k.Kill(spawn, snap)
		if err == nil || kernelStatus(err) != 409 || time.Now().After(deadline) {
			return d, err
		}
		time.Sleep(killStep)
	}
}

// ---- pause ------------------------------------------------------------------------------------------------------------

func (r *Router) Pause(id string) error {
	unlock, err := r.lock(id, "pausing")
	if err != nil {
		return err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" || s.MachineID == "" || s.Chain == nil || s.Chain.Spawn == "" {
		unlock()
		return fmt.Errorf("session %s isn't running", id)
	}
	r.setState(id, "pausing", "")
	go func() {
		defer unlock()
		if err := r.snapshotAndKill(id); err != nil {
			r.setState(id, "failed", "kill: "+err.Error())
		}
	}()
	return nil
}

// snapshotAndKill: the machine's final snapshot, then the spawner's kill into a fresh source naming it, notarized; the
// main grant moved onto that source. The session is paused.
func (r *Router) snapshotAndKill(id string) error {
	var machine, spawnID, mainID string
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil && x.Chain != nil {
			machine, spawnID, mainID = x.MachineID, x.Chain.Spawn, x.Chain.Main
		}
	})
	if machine == "" || spawnID == "" {
		return errors.New("no running machine")
	}
	r.lastSnapshot(id, machine)
	spawn, err := r.notarized(spawnID)
	if err != nil {
		return err
	}
	cert, err := r.killUntilDestroyed(spawn, r.snapshotClaim(machine))
	if err != nil {
		return err
	}
	nc, err := r.k.NotarizeNew(cert)
	if err != nil {
		return fmt.Errorf("notarizing the kill: %w", err)
	}
	kc, _ := successionOf(cert)
	certID := r.stepCert(id, nc)
	main, err := r.doc(mainID)
	var g kernel.SignedDoc
	if err == nil {
		g, err = r.k.Move(main, nc)
	}
	if err != nil {
		return fmt.Errorf("moving the main grant onto the paused source: %w", err)
	}
	gid := r.stepGrant(id, g)
	now := time.Now().UTC()
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil && x.Chain != nil {
			x.Chain.Origin, x.Chain.Source, x.Chain.Main = certID, kc.Successor, gid
			x.Chain.Spawn, x.Chain.Machine, x.Chain.AddOns, x.Chain.Held = "", nil, nil, ""
			x.State, x.Error, x.MachineID, x.PausedAt, x.Status = "paused", "", "", &now, ""
		}
	})
	r.dropOutbox(machine)
	return nil
}

// snapshotClaim: the machine's last uploaded snapshot (its sha256 and its signature over it), if any
func (r *Router) snapshotClaim(machine string) *SnapshotClaim {
	var c *SnapshotClaim
	r.st.Do(func(d *persisted) {
		if st := d.Started[machine]; st != nil && st.Snapshot != "" {
			c = &SnapshotClaim{Sha256: st.Snapshot, Sig: st.SnapshotSig}
		}
	})
	return c
}

// ---- resume -----------------------------------------------------------------------------------------------------------

// ResumeIn: what a resume may change. Size is the router's (the spawn's); the rest is in the source, so a change
// makes a new phone-made source.
type ResumeIn struct {
	Upgrade  bool   `json:"upgrade"`
	Prompt   string `json:"prompt"`
	Rollback string `json:"-"` // a restart's rollback marker (sessionops.go)
	ResumeOptions
}

func (r *Router) Resume(id string, in ResumeIn) error {
	if err := r.applyResumeOptions(id, in.ResumeOptions); err != nil { // sessionops.go: size, model, apiProxy
		return err
	}
	unlock, err := r.lock(id, "starting")
	if err != nil {
		return err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
			if x.Chain != nil {
				c := x.Chain.clone()
				s.Chain = &c
			}
		}
	})
	if s.ID == "" || s.State != "paused" || s.Chain == nil || s.Chain.Source.ID == "" {
		unlock()
		return fmt.Errorf("session %s isn't paused", id)
	}
	image := s.Chain.Source.Image
	if in.Upgrade {
		image = r.cfg.SessionImage
	}
	settings, err := r.sessionSettings(&s, in.Prompt, in.Rollback, nil)
	if err != nil {
		unlock()
		return err
	}
	if image == s.Chain.Source.Image && in.Prompt == "" && in.Rollback == "" && sameSettings(settings, s.Chain.Source.Settings) {
		r.setState(id, "resuming", "")
		go func() {
			defer unlock()
			r.startFrom(id)
		}()
		return nil
	}
	defer unlock()
	// a change to what the source holds: the phone signs a new source, starting from the paused one's snapshot
	src := kernel.Object{ID: newSourceID(), Image: image, Settings: settings, Snapshot: s.Chain.Source.Snapshot}
	dr, err := r.makeDraft(kernel.Object{ID: kernel.Sink}, src, mainPair(s.ID, s.Stores))
	if err != nil {
		return err
	}
	opts := map[string]string{"permissionMode": normMode(s.PermissionMode), "model": s.Model, "size": s.Size}
	if in.Upgrade {
		opts["upgrade"] = "1"
	}
	if in.Prompt != "" {
		opts["prompt"] = fmt.Sprintf("(%d characters)", len([]rune(in.Prompt)))
	}
	if in.Rollback != "" {
		opts["rollback"] = in.Rollback
	}
	r.setState(id, "approval", "")
	r.addApproval(&Approval{Kind: "resume-upgrade", Session: id, Label: s.Label, Drafts: []Draft{dr}, Source: &src, Options: opts})
	return nil
}

// sameSettings: two sources' settings hold the same start settings once what only a phone-made source applies (its
// prompt, attachments and rollback) is left out
func sameSettings(a, b string) bool {
	strip := func(s string) string {
		var x SessionSettings
		if json.Unmarshal([]byte(s), &x) != nil {
			return "?" + s
		}
		x.Prompt, x.Attachments, x.Rollback = "", nil, ""
		out, _ := json.Marshal(x)
		return string(out)
	}
	return strip(a) == strip(b)
}

// ---- destroy ------------------------------------------------------------------------------------------------------------

func (r *Router) Destroy(id string) error { return r.DestroyWith(id, false) }

// DestroyWith: a running session is paused first (its final snapshot), then archived (archive.go); a failed
// archive leaves it paused with the error, unless force. Then the destroy hooks, the burn, the records.
func (r *Router) DestroyWith(id string, force bool) error {
	return r.destroy(id, destroyOpts{force: force})
}

// destroyOpts: force = destroy even when the archive failed; report (oneshot.go) gets, once the source is burnt and
// the session is a record, the repos' state as the final snapshot recorded it and what the archive did
type destroyOpts struct {
	force  bool
	report func(s Session, changes map[string]any, archived *ArchiveInfo, aerr error)
}

func (r *Router) destroy(id string, o destroyOpts) error {
	unlock, err := r.lock(id, "destroying")
	if err != nil {
		return err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		unlock()
		return fmt.Errorf("no session %s", id)
	}
	r.setState(id, "destroying", "")
	go func() {
		defer unlock()
		if s.MachineID != "" && s.Chain != nil && s.Chain.Spawn != "" {
			if err := r.snapshotAndKill(id); err != nil {
				r.setState(id, "failed", "kill: "+err.Error())
				return
			}
			r.setState(id, "destroying", "")
		}
		var changes map[string]any
		if o.report != nil {
			changes = r.snapshotChanges(id) // archive.go: before finish() drops the snapshot
		}
		archived, aerr := r.archive(id)
		if aerr != nil && !o.force {
			r.setState(id, "paused", "archive: "+aerr.Error())
			return
		}
		if c := r.chainOf(id); c != nil && c.Source.ID != "" {
			if err := r.burn(id, c.Source); err != nil {
				log.Printf("session %s: burn: %v", id, err)
			}
		}
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				s = *x // the latest: titles and hook fields moved on since the destroy began
			}
		})
		for _, h := range onDestroy {
			h(r, s)
		}
		r.finish(id)
		r.st.Do(func(d *persisted) {
			if len(d.Records) > 0 && d.Records[0].ID == id {
				d.Records[0].Archive = archived
				if aerr != nil {
					d.Records[0].ArchiveError = aerr.Error()
				}
			}
		})
		if o.report != nil {
			o.report(s, changes, archived, aerr)
		}
	}()
	return nil
}

// burn: (source, sink) by the gullible signer, notarized — the source is never continued
func (r *Router) burn(sid string, src kernel.Object) error {
	cert, err := r.k.GullibleSign(src, kernel.Object{ID: kernel.Sink}, kernel.Top())
	if err != nil {
		return err
	}
	nc, err := r.k.NotarizeNew(cert)
	if err != nil {
		return err
	}
	r.stepCert(sid, nc)
	return nil
}

// finish: the session leaves the list for the records; its snapshots go
func (r *Router) finish(id string) {
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil {
			return
		}
		delete(d.Sessions, id)
		for a, ap := range d.Approvals {
			if ap.Session == id {
				delete(d.Approvals, a)
			}
		}
		for m, sid := range d.Machines {
			if sid == id {
				if st := d.Started[m]; st != nil && st.Snapshot != "" {
					os.Remove(r.st.snapshotPath(st.Snapshot))
				}
				r.dropOutbox(m)
			}
		}
		if s.Chain != nil && s.Chain.Source.Snapshot != "" {
			os.Remove(r.st.snapshotPath(s.Chain.Source.Snapshot))
		}
		s.State, s.MachineID = "destroyed", ""
		d.Records = append([]*Record{{Session: *s, DestroyedAt: time.Now().UTC()}}, d.Records...)
	})
}

// ---- the last snapshot --------------------------------------------------------------------------------------------------

// lastSnapshot: before a pause or destroy kills the machine, its final snapshot (or its "nothing to snapshot" while
// booting), waiting up to SnapshotWait with the reason shown in the app. A machine that never got past boot (no status
// report from it) isn't asked at all.
// silentAfter: a booted machine whose last report is older than this isn't asked for a snapshot
var silentAfter = 3 * time.Minute

var bootGrace = 90 * time.Second

var pulledMachines sync.Map // machine → its secrets pull went through (it is about to finish booting)

func markPulled(machine string)     { pulledMachines.Store(machine, true) }
func hasPulled(machine string) bool { _, ok := pulledMachines.Load(machine); return ok }

func (r *Router) lastSnapshot(id, machine string) {
	booted := func() (b bool) {
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				b = x.Booted == machine
			}
		})
		return
	}
	// a machine that has its secrets is seconds from booted: wait for it, or a pause right after a start would leave
	// its successor with no state at all
	for deadline := time.Now().Add(bootGrace); !booted() && hasPulled(machine) && time.Now().Before(deadline); {
		time.Sleep(time.Second)
	}
	if !booted() {
		log.Printf("session %s: %s never got past boot; nothing to snapshot", id, machine)
		return
	}
	var last time.Time
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil && x.Live != nil {
			last = x.Live.LastReport
		}
	})
	if time.Since(last) > silentAfter {
		log.Printf("session %s: %s silent since %s; not waiting for a snapshot", id, machine, last.Format(time.RFC3339))
		return
	}
	done := r.awaitSnapshot(machine)
	r.out(machine).word("snapshot")
	r.setWaiting(id, "waiting for the machine's last snapshot (up to "+waitText(r.cfg.SnapshotWait)+")")
	defer r.setWaiting(id, "")
	select {
	case <-done:
	case <-time.After(r.cfg.SnapshotWait):
		log.Printf("session %s: no snapshot from %s within %s; going on without it", id, machine, r.cfg.SnapshotWait)
	}
}

func (r *Router) setWaiting(id, what string) {
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			x.Waiting = what
		}
	})
}

// waitText: "10 min", "45 s"
func waitText(d time.Duration) string {
	if d >= time.Minute {
		return fmt.Sprintf("%d min", int(d.Round(time.Minute)/time.Minute))
	}
	return fmt.Sprintf("%d s", int(d/time.Second))
}

func (r *Router) awaitSnapshot(machine string) chan struct{} {
	r.snapMu.Lock()
	defer r.snapMu.Unlock()
	c := make(chan struct{})
	r.snapped[machine] = c
	return c
}

func (r *Router) snapshotArrived(machine string) {
	r.snapMu.Lock()
	defer r.snapMu.Unlock()
	if c := r.snapped[machine]; c != nil {
		close(c)
		delete(r.snapped, machine)
	}
}

func containsString(list []string, x string) bool {
	for _, s := range list {
		if s == x {
			return true
		}
	}
	return false
}
