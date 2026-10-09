package main

// The session flows of docs/DESIGN.md ("Flows (router, outside the core)"), each a chain of core
// primitives. Every long step runs in its own goroutine; the session's `state` says where it is.

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
	"sync"
	"time"
)

type Router struct {
	cfg  Config
	st   *State
	core *CoreClient

	cmdMu    sync.Mutex
	commands map[string]chan string     // machine id → pending commands (snapshot)
	execs    map[string]chan execItem   // machine id → holder-signed shell commands (grants.go)
	results  map[string]chan ExecResult // exec request id → its waiting caller
	hk       holders
	snapped  map[string]chan struct{}
	locks    sync.Map // session id → *sync.Mutex: one lifecycle action at a time
	ops      opsState // sessionops.go: busy marks, permission-mode/restart jobs, uploads, repos

	policy Policy

	setupMu   sync.Mutex
	setupSeen map[string]time.Time

	muxOnce               sync.Once
	publicMux, machineMux *http.ServeMux
}

func NewRouter(cfg Config, st *State, core *CoreClient, policy Policy) *Router {
	return &Router{cfg: cfg, st: st, core: core, policy: policy, setupSeen: map[string]time.Time{}, commands: map[string]chan string{}, execs: map[string]chan execItem{}, results: map[string]chan ExecResult{}, snapped: map[string]chan struct{}{}}
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var errBusy = errors.New("the session is in the middle of another action")

// lock: a session's lifecycle actions don't overlap; a clash is refused (409), not queued. kind names the
// action in /api/state's `busy` (sessionops.go).
func (r *Router) lock(id, kind string) (func(), error) {
	m, _ := r.locks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	if !mu.TryLock() {
		return nil, errBusy
	}
	r.ops.setBusy(id, kind)
	return func() { r.ops.setBusy(id, ""); mu.Unlock() }, nil
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

// ---- the core's primitives, as the router chains them ----------------------------------------------

type NewSession struct {
	RequestID      string         `json:"requestId"`
	Label          string         `json:"label"`
	Prompt         string         `json:"prompt"`
	Model          string         `json:"model"`
	PermissionMode string         `json:"permissionMode"`
	Size           string         `json:"size"`
	Harness        string         `json:"harness"`
	Stores         []string       `json:"stores"`
	Repos          string         `json:"repos"`
	OneShot        bool           `json:"oneShot"`     // destroyed once its prompt is done (autopilot.go)
	AutoPause      *bool          `json:"autoPause"`   // default on
	APIProxy       bool           `json:"apiProxy"`    // SESSION_API_PROXY (sessionops.go)
	Attachments    *AttachmentsIn `json:"attachments"` // first-prompt attachments (uploads.go)
}

const nullImage = "null" // a succession to it burns the predecessor (core.NullImage)

func (r *Router) machineEnv(s *Session) map[string]string {
	e := map[string]string{
		"JARVIS2_URL": r.cfg.MachineURL, "JARVIS2_SESSION_ID": s.ID,
		"SESSION_LABEL": s.Label, "SESSION_MODEL": s.Model, "SESSION_PERMISSION_MODE": s.PermissionMode,
		"JARVIS2_REPOS": s.Repos,
	}
	if s.Prompt != "" {
		e["SESSION_PROMPT"] = s.Prompt
	}
	for _, h := range envHooks {
		h(r, s, e)
	}
	return e
}

// succession: a challenge, before any machine exists. machine is set only for adding a store.
func (r *Router) succession(pred *Doc, machine string, stores []string, harness, mode, image string) (*Doc, error) {
	var predecessor any // JSON null = from null
	if pred != nil {
		predecessor = pred
	}
	if mode != "bypass" {
		mode = "auto"
	}
	opts := map[string]string{"harness": harness, "permissionMode": mode} // both signed (core Options)
	if image == nullImage {
		opts = map[string]string{}
	}
	return r.core.Call("/succession", map[string]any{"predecessor": predecessor, "machine": machine, "stores": stores, "options": opts, "image": image})
}

// startAndCertify: an approval → a machine on the approved image → its cert. The core's start is open (it
// can't lead to a secret); certify binds the approval to that one machine.
func (r *Router) startAndCertify(sid string, approval *Doc) {
	var a struct {
		Request struct {
			Image string `json:"image"`
		} `json:"request"`
	}
	approval.Decode(&a)
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
		}
	})
	r.setState(sid, "starting", "")
	d, err := r.core.Call("/start", map[string]any{"image": a.Request.Image, "region": r.cfg.Region, "size": s.Size, "env": r.machineEnv(&s)})
	if err != nil {
		r.setState(sid, "failed", "start: "+err.Error())
		return
	}
	var st struct {
		Machine *Started `json:"machine"`
	}
	if d.Decode(&st) != nil || st.Machine == nil {
		r.setState(sid, "failed", "start: unexpected answer")
		return
	}
	m := st.Machine
	r.st.Do(func(d *persisted) {
		d.Started[m.ID] = m
		d.Machines[m.ID] = sid
	})
	cert, err := r.core.Call("/certify", map[string]any{"approval": approval, "machine": m.ID})
	if err != nil {
		r.core.Call("/kill", map[string]string{"machine": m.ID})
		r.setState(sid, "failed", "certify: "+err.Error())
		return
	}
	r.st.Do(func(d *persisted) {
		d.Certs[m.ID] = cert
		if x := d.Sessions[sid]; x != nil {
			x.Cert, x.MachineID, x.Image, x.State, x.Error, x.PausedAt = cert, m.ID, m.Image, "initialising", "", nil
		}
	})
}

func (r *Router) addApproval(a *Approval) {
	a.ID, a.Created = randID(), time.Now().UTC()
	r.st.Do(func(d *persisted) { d.Approvals[a.ID] = a })
}

// ---- new session ------------------------------------------------------------------------------------

// CreateSession → the session's id. A requestId already on a session answers that session (idempotent).
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
	if in.PermissionMode != "bypass" {
		in.PermissionMode = "auto"
	}
	// the harness's stores come with it (the policy document); the app doesn't list them
	stores, err := r.withHarnessStores(in.Stores, h.Stores)
	if err != nil {
		return "", err
	}
	s := &Session{ID: "s" + randID(), State: "approval", Created: time.Now().UTC(), Label: in.Label, Prompt: in.Prompt, Model: in.Model,
		PermissionMode: in.PermissionMode, Size: in.Size, Harness: in.Harness, Stores: stores, Repos: in.Repos, RequestID: in.RequestID, Live: newLiveness(in)}
	var dup string
	r.st.Do(func(d *persisted) {
		if dup, err = admitSession(d, s, in); err == nil && dup == "" {
			d.Sessions[s.ID] = s
		}
	})
	if err != nil || dup != "" {
		return dup, err
	}
	ch, err := r.succession(nil, "", s.Stores, s.Harness, s.PermissionMode, r.cfg.SessionImage)
	if err != nil {
		r.st.Do(func(d *persisted) { delete(d.Sessions, s.ID) })
		return "", err
	}
	opts := map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode, "repos": s.Repos}
	liveOptions(s, opts)
	opsOptions(s, opts)
	go func() {
		r.addApproval(&Approval{Kind: "new-session", Session: s.ID, Label: s.Label, Challenge: ch,
			Options: opts})
	}()
	return s.ID, nil
}

// withHarnessStores: the chosen stores plus the harness's, sorted (the core refuses unknown ones)
func (r *Router) withHarnessStores(chosen, harness []string) ([]string, error) {
	set := map[string]bool{}
	for _, n := range append(append([]string{}, chosen...), harness...) {
		if n == flyStore {
			return nil, fmt.Errorf("store %s holds the core's Fly token and never goes to a session", n)
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

// ---- approvals ---------------------------------------------------------------------------------------

func (r *Router) Respond(id, signature string) (*Doc, string, error) {
	var a *Approval
	r.st.Do(func(d *persisted) { a = d.Approvals[id] })
	if a == nil {
		return nil, "", fmt.Errorf("no such approval")
	}
	ans, err := r.core.Call("/approve/by-phone", map[string]any{"challenge": a.Challenge, "signature": signature})
	if err != nil {
		return nil, "", err
	}
	r.st.Do(func(d *persisted) { delete(d.Approvals, id) })
	if a.Kind == "add-store" {
		// adding a store answers with the machine's new cert at once
		r.st.Do(func(d *persisted) {
			d.Certs[a.Machine] = ans
			if s := d.Sessions[a.Session]; s != nil {
				var c struct{ Stores []string }
				ans.Decode(&c)
				s.Cert, s.Stores = ans, c.Stores
			}
		})
		return ans, a.Session, nil
	}
	go r.startAndCertify(a.Session, ans)
	return ans, a.Session, nil
}

func (r *Router) Reject(id string) error {
	var a *Approval
	r.st.Do(func(d *persisted) {
		a = d.Approvals[id]
		delete(d.Approvals, id)
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
			s.State, s.Error = "paused", "" // nothing happened to the old machine
		}
	})
	return nil
}

// ---- pause ---------------------------------------------------------------------------------------------

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
	if s.ID == "" || s.MachineID == "" || s.Cert == nil {
		unlock()
		return fmt.Errorf("session %s isn't running", id)
	}
	r.setState(id, "pausing", "")
	go func() {
		defer unlock()
		done := r.awaitSnapshot(s.MachineID)
		r.send(s.MachineID, "snapshot")
		select {
		case <-done:
		case <-time.After(r.cfg.SnapshotWait):
			log.Printf("session %s: no snapshot from %s within %s; pausing without one", id, s.MachineID, r.cfg.SnapshotWait)
		}
		if _, err := r.core.Call("/kill", map[string]string{"machine": s.MachineID}); err != nil {
			r.setState(id, "failed", "kill: "+err.Error())
			return
		}
		now := time.Now().UTC()
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.State, x.MachineID, x.PausedAt, x.Status = "paused", "", &now, ""
			}
		})
	}()
	return nil
}

// ---- resume ----------------------------------------------------------------------------------------------

func (r *Router) Resume(id string, upgrade bool) error {
	unlock, err := r.lock(id, "starting")
	if err != nil {
		return err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" || s.State != "paused" || s.Cert == nil {
		unlock()
		return fmt.Errorf("session %s isn't paused", id)
	}
	r.setState(id, "resuming", "")
	go func() {
		defer unlock()
		image := s.Image // the same image, pinned by digest
		if upgrade {
			image = r.cfg.SessionImage
		}
		ch, err := r.succession(s.Cert, "", s.Stores, s.Harness, s.PermissionMode, image)
		if err != nil {
			r.setState(id, "paused", "resume: "+err.Error())
			return
		}
		// the permission mode is signed: a resume in another mode than the line's cert (raising to bypass) is a
		// change the iPhone approves, like a newer image
		if certMode(s.Cert) != normMode(s.PermissionMode) {
			r.setState(id, "approval", "")
			r.addApproval(&Approval{Kind: "resume-upgrade", Session: id, Label: s.Label, Challenge: ch,
				Options: map[string]string{"permissionMode": normMode(s.PermissionMode)}})
			return
		}
		if upgrade {
			// a change: the iPhone approves first; nothing happens to the old machine until then
			r.setState(id, "approval", "")
			r.addApproval(&Approval{Kind: "resume-upgrade", Session: id, Label: s.Label, Challenge: ch})
			return
		}
		a, err := r.core.Call("/approve/by-dead-machine", map[string]any{"challenge": ch})
		if err != nil {
			r.setState(id, "paused", "resume: "+err.Error())
			return
		}
		r.startAndCertify(id, a)
	}()
	return nil
}

// ---- destroy ---------------------------------------------------------------------------------------------

func (r *Router) Destroy(id string) error { return r.DestroyWith(id, false) }

// DestroyWith: a running session is paused first (its final snapshot), then archived (archive.go); a failed
// archive leaves it paused with the error, unless force. Then the destroy hooks, the burn, the records.
func (r *Router) DestroyWith(id string, force bool) error {
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
		if s.MachineID != "" && !r.snapshotAndKill(id, s.MachineID) {
			return
		}
		archived, aerr := r.archive(id)
		if aerr != nil && !force {
			r.setState(id, "paused", "archive: "+aerr.Error())
			return
		}
		if s.Cert != nil {
			// end the line: a succession to the null image, answered by the dead-machine responder → burn cert
			ch, err := r.succession(s.Cert, "", nil, "", "", nullImage)
			var a *Doc
			if err == nil {
				a, err = r.core.Call("/approve/by-dead-machine", map[string]any{"challenge": ch})
			}
			if err == nil {
				_, err = r.core.Call("/certify", map[string]any{"approval": a, "machine": ""})
			}
			if err != nil {
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
	}()
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
				os.Remove(r.st.snapshotPath(m))
				os.Remove(r.st.snapshotPath(m) + ".sig")
			}
		}
		s.State, s.MachineID = "destroyed", ""
		d.Records = append([]*Record{{Session: *s, DestroyedAt: time.Now().UTC()}}, d.Records...)
	})
}

// ---- add a store (asked by the machine) -------------------------------------------------------------------

func (r *Router) AddStore(machine, store string) error {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[d.Machines[machine]]; x != nil {
			s = *x
		}
	})
	if s.ID == "" || s.MachineID != machine || s.Cert == nil {
		return fmt.Errorf("this machine isn't a running session")
	}
	stores, err := r.withHarnessStores(append(append([]string{}, s.Stores...), store), nil)
	if err != nil {
		return err
	}
	ch, err := r.succession(s.Cert, machine, stores, s.Harness, certMode(s.Cert), "")
	if err != nil {
		return err
	}
	r.addApproval(&Approval{Kind: "add-store", Session: s.ID, Machine: machine, Label: s.Label, Challenge: ch,
		Options: map[string]string{"store": store}})
	return nil
}

// ---- downgrade in place (asked by the machine) -------------------------------------------------------------

// DowngradeBegin: the machine names a subset of its stores and its new key pair → the challenge it must sign
// with its old key
func (r *Router) DowngradeBegin(machine string, stores []string, encKey, sigKey string) (*Doc, error) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[d.Machines[machine]]; x != nil {
			s = *x
		}
	})
	if s.ID == "" || s.MachineID != machine || s.Cert == nil {
		return nil, fmt.Errorf("this machine isn't a running session")
	}
	return r.core.Call("/succession", map[string]any{"predecessor": s.Cert, "machine": machine, "stores": stores,
		"options": map[string]string{"harness": s.Harness, "permissionMode": certMode(s.Cert)}, "newEncryptionKey": encKey, "newSigningKey": sigKey})
}

// DowngradeFinish: the challenge signed with the machine's old key → its new cert; from now on the router
// knows the machine by its new signing key
func (r *Router) DowngradeFinish(machine string, challenge *Doc, signature string) (*Doc, error) {
	cert, err := r.core.Call("/approve/by-old-key", map[string]any{"challenge": challenge, "signature": signature})
	if err != nil {
		return nil, err
	}
	var c struct {
		Machine *Started `json:"machine"`
		Stores  []string `json:"stores"`
	}
	if cert.Decode(&c) != nil || c.Machine == nil || c.Machine.ID != machine {
		return nil, fmt.Errorf("the core's cert names another machine")
	}
	r.st.Do(func(d *persisted) {
		d.Certs[machine] = cert
		d.Started[machine] = c.Machine
		if s := d.Sessions[d.Machines[machine]]; s != nil {
			s.Cert, s.Stores = cert, c.Stores
		}
	})
	return cert, nil
}

// ---- commands to machines ---------------------------------------------------------------------------------

func (r *Router) queue(machine string) chan string {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	q := r.commands[machine]
	if q == nil {
		q = make(chan string, 8)
		r.commands[machine] = q
	}
	return q
}

func (r *Router) send(machine, cmd string) {
	select {
	case r.queue(machine) <- cmd:
	default:
	}
}

func (r *Router) awaitSnapshot(machine string) chan struct{} {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	c := make(chan struct{})
	r.snapped[machine] = c
	return c
}

func (r *Router) snapshotArrived(machine string) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	if c := r.snapped[machine]; c != nil {
		close(c)
		delete(r.snapped, machine)
	}
}

func normMode(m string) string {
	if m == "bypass" {
		return "bypass"
	}
	return "auto"
}

// certMode: the permission mode the line's cert signs (a machine succeeding itself keeps it)
func certMode(c *Doc) string {
	if c == nil {
		return "auto"
	}
	var x struct {
		Options struct {
			PermissionMode string `json:"permissionMode"`
		} `json:"options"`
	}
	json.Unmarshal([]byte(c.Payload), &x)
	return normMode(x.Options.PermissionMode)
}
