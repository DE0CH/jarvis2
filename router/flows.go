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
	"strings"
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
	Origin         *Origin        `json:"-"`           // inbox.go: who asked, from the credential (the handler sets it)
	Task           *TaskConfig    `json:"-"`           // tasks.go: a task line's instance and parameters (into the cert's config)
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
	if s.Label == "" && s.AppTitle != "" {
		// the title the Claude app showed: a resumed claude names a fresh Remote Control entry with it (Jarvis 1's
		// session-supervisor.sh), so the conversation keeps its title in the app
		e["SESSION_RESUME_TITLE"] = s.AppTitle
	}
	for _, h := range envHooks {
		h(r, s, e)
	}
	return e
}

// succession: a challenge, before any machine exists. machine is set only for adding a store. config and once:
// Options.Config and Options.Once (vouch.go); a core that doesn't vouch ignores them.
func (r *Router) succession(pred *Doc, machine string, stores []string, harness, mode, image, config, once string) (*Doc, error) {
	var predecessor any // JSON null = from null
	if pred != nil {
		predecessor = pred
	}
	if mode != "bypass" {
		mode = "auto"
	}
	opts := map[string]string{"harness": harness, "permissionMode": mode} // both signed (core Options)
	if config != "" {
		opts["config"] = config
	}
	if once != "" {
		opts["once"] = once
	}
	if image == nullImage {
		opts = map[string]string{}
	}
	return r.core.Call("/succession", map[string]any{"predecessor": predecessor, "machine": machine, "stores": stores, "options": opts, "image": image})
}

// the router's waits on the core's single-shot machine calls (tests shorten them)
var (
	initStep, initMax = 5 * time.Second, 12 * time.Minute // a session image's first pull on a Fly host takes minutes
	killStep, killMax = time.Second, 30 * time.Second
)

// startMachine: the core's start (one Fly create), then its init until Fly reports the machine up and the image's
// init command gave its keys → the core's signed "started" document. A machine that never comes up is killed.
// A core from before R2 answers "started" from /start itself (it waited and retried inside).
func (r *Router) startMachine(image, size string) (*Doc, error) {
	if size == "" {
		size = "medium"
	}
	d, err := r.core.Call("/start", map[string]any{"image": image, "region": r.cfg.Region, "size": size})
	if err != nil {
		return nil, err
	}
	var c struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	d.Decode(&c)
	if c.Kind != "created" {
		return d, nil
	}
	deadline := time.Now().Add(initMax)
	for {
		st, err := r.core.Call("/init", map[string]string{"machine": c.ID})
		if err == nil {
			return st, nil
		}
		var ce *CoreError
		retry := errors.As(err, &ce) && (ce.Status == 502 || ce.Status == 409 && strings.Contains(ce.Msg, "not started"))
		if !retry || time.Now().After(deadline) {
			r.killUntilDestroyed(map[string]any{"machine": c.ID})
			return nil, err
		}
		time.Sleep(initStep)
	}
}

// killUntilDestroyed: the core's kill (one Fly destroy) again until Fly reports the machine destroyed (409 before).
// A core from before R2 waited inside its kill.
func (r *Router) killUntilDestroyed(in map[string]any) (*Doc, error) {
	deadline := time.Now().Add(killMax)
	for {
		d, err := r.core.Call("/kill", in)
		var ce *CoreError
		if err == nil || !errors.As(err, &ce) || ce.Status != 409 || time.Now().After(deadline) {
			return d, err
		}
		time.Sleep(killStep)
	}
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
	d, err := r.startMachine(a.Request.Image, s.Size)
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
	// "started": the core's signed document (a core from before R2 reads "machine" instead); "carry": the line's
	// carried secrets, answered rebound to this machine beside the cert
	pred := ""
	var ap struct {
		Request struct {
			PredID string `json:"predecessorId"`
		} `json:"request"`
	}
	if approval.Decode(&ap) == nil {
		pred = ap.Request.PredID
	}
	cert, ans, err := r.core.CallAnswer("/certify", map[string]any{"approval": approval, "machine": m.ID, "started": d, "carry": r.readCarry(pred)})
	if err != nil {
		r.killUntilDestroyed(map[string]any{"machine": m.ID})
		r.setState(sid, "failed", "certify: "+err.Error())
		return
	}
	r.st.Do(func(d *persisted) {
		d.Certs[m.ID] = cert
		if x := d.Sessions[sid]; x != nil {
			x.Cert, x.MachineID, x.Image, x.State, x.Error, x.PausedAt = cert, m.ID, m.Image, "initialising", "", nil
		}
	})
	r.logInputs(ans.Entry) // vouch.go: the cert's input-log entry
	if p := predOf(cert); p != "" {
		r.carryAfter(p, m.ID, cert, ans) // carry.go: a resume carries the line's secrets, no store unlocked
	}
}

func (r *Router) addApproval(a *Approval) {
	a.ID, a.Created = randID(), time.Now().UTC()
	if a.Origin == nil {
		a.Origin = takeOrigin(a.Session) // inbox.go: the caller the handler noted
	}
	var ch struct {
		Request struct {
			Image string `json:"image"`
		} `json:"request"`
	}
	if a.Challenge != nil && a.Challenge.Decode(&ch) == nil && ch.Request.Image != "" && ch.Request.Image == r.cfg.SessionImage {
		a.ImageSig = r.cfg.SessionImageSig
	}
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
	s.taskConfig = in.Task
	config, err := r.sessionConfig(s) // vouch.go: the settings the phone signs with the line
	if err != nil {
		r.st.Do(func(d *persisted) { delete(d.Sessions, s.ID) })
		return "", err
	}
	ch, err := r.succession(nil, "", s.Stores, s.Harness, s.PermissionMode, r.cfg.SessionImage, config, "")
	if err != nil {
		r.st.Do(func(d *persisted) { delete(d.Sessions, s.ID) })
		return "", err
	}
	opts := map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode, "repos": s.Repos}
	liveOptions(s, opts)
	opsOptions(s, opts)
	go func() {
		r.addApproval(&Approval{Kind: "new-session", Session: s.ID, Label: s.Label, Challenge: ch,
			Options: opts, Origin: in.Origin})
	}()
	return s.ID, nil
}

// deployKeyTokenStore: the core opens it only inside a deploy-key call (core/deploykeys.go)
const deployKeyTokenStore = "github-deploy-keys"

// withHarnessStores: the chosen stores plus the harness's, sorted (the core refuses unknown ones)
func (r *Router) withHarnessStores(chosen, harness []string) ([]string, error) {
	set := map[string]bool{}
	for _, n := range append(append([]string{}, chosen...), harness...) {
		if n == flyStore {
			return nil, fmt.Errorf("store %s holds the core's Fly token and never goes to a session", n)
		}
		if n == deployKeyTokenStore {
			return nil, fmt.Errorf("store %s holds the deploy-key token: only a phone-approved deploy-key call opens it", n)
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
	in := map[string]any{"challenge": a.Challenge, "signature": signature}
	if a.Kind == "add-store" {
		in["carry"] = r.readCarry(a.Machine) // answered rebound to the machine's new cert
	}
	ans, extra, err := r.core.CallAnswer("/approve/by-phone", in)
	if err != nil {
		return nil, "", err
	}
	r.logInputs(extra.Entry) // an add-store's new cert (an approval for a new line has none)
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
		r.carryAfter(a.Machine, a.Machine, ans, extra) // its carried stores go on; the added one comes from its unlock
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
		r.lastSnapshot(id, s.MachineID)
		if _, err := r.killMachine(s.MachineID); err != nil { // vouch.go: with the snapshot's hash
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
		once := r.resumeOnce(&s) // vouch.go: a resume prompt or a rollback: only the phone approves one
		ch, err := r.succession(s.Cert, "", s.Stores, s.Harness, s.PermissionMode, image, lineConfig(&s), once)
		if err != nil {
			r.setState(id, "paused", "resume: "+err.Error())
			return
		}
		if once != "" {
			r.onceTaken(id) // the cert will carry them; nothing else delivers them
			r.setState(id, "approval", "")
			r.addApproval(&Approval{Kind: "resume-upgrade", Session: id, Label: s.Label, Challenge: ch,
				Options: map[string]string{"permissionMode": normMode(s.PermissionMode), "once": once}})
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
	return r.destroy(id, destroyOpts{force: force})
}

// destroyOpts: force = destroy even when the archive failed; report (oneshot.go) gets, once the line is
// burnt and the session is a record, the repos' state as the final snapshot recorded it and what the archive did
type destroyOpts struct {
	force  bool
	report func(s Session, changes map[string]any, archived *ArchiveInfo, aerr error)
}

func (r *Router) destroy(id string, o destroyOpts) error {
	force := o.force
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
		var changes map[string]any
		if o.report != nil {
			changes = r.snapshotChanges(id) // archive.go: before finish() drops the snapshot
		}
		archived, aerr := r.archive(id)
		if aerr != nil && !force {
			r.setState(id, "paused", "archive: "+aerr.Error())
			return
		}
		if s.Cert != nil {
			// end the line: a succession to the null image, answered by the dead-machine responder → burn cert
			ch, err := r.succession(s.Cert, "", nil, "", "", nullImage, "", "")
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
		if o.report != nil {
			o.report(s, changes, archived, aerr)
		}
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
				r.dropCarry(m) // the carried secrets go with the line (the core has burnt it too)
			}
		}
		s.State, s.MachineID = "destroyed", ""
		d.Records = append([]*Record{{Session: *s, DestroyedAt: time.Now().UTC()}}, d.Records...)
	})
}

// ---- add a store (asked by the machine) -------------------------------------------------------------------

func (r *Router) AddStore(machine, store string) error {
	var sid string
	r.st.Do(func(d *persisted) { sid = d.Machines[machine] })
	return r.AddStoreFrom(machine, store, Origin{Caller: Caller{Kind: "session", Session: sid}, Call: APICall{Method: "POST", Path: "/m/add-store", Args: map[string]any{"store": store}}}, "")
}

// AddStoreFrom: the add-store approval, with its caller and the caller's explanation (inbox.go)
func (r *Router) AddStoreFrom(machine, store string, o Origin, explanation string) error {
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
	ch, err := r.succession(s.Cert, machine, stores, s.Harness, certMode(s.Cert), "", lineConfig(&s), "")
	if err != nil {
		return err
	}
	r.addApproval(&Approval{Kind: "add-store", Session: s.ID, Machine: machine, Label: s.Label, Challenge: ch,
		Options: map[string]string{"store": store}, Origin: &o, Explanation: explanation})
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
	opts := map[string]string{"harness": s.Harness, "permissionMode": certMode(s.Cert)}
	if c := lineConfig(&s); c != "" {
		opts["config"] = c
	}
	return r.core.Call("/succession", map[string]any{"predecessor": s.Cert, "machine": machine, "stores": stores,
		"options": opts, "newEncryptionKey": encKey, "newSigningKey": sigKey})
}

// DowngradeFinish: the challenge signed with the machine's old key → its new cert; from now on the router
// knows the machine by its new signing key
func (r *Router) DowngradeFinish(machine string, challenge *Doc, signature string) (*Doc, error) {
	cert, ans, err := r.core.CallAnswer("/approve/by-old-key", map[string]any{"challenge": challenge, "signature": signature, "carry": r.readCarry(machine)})
	if err != nil {
		return nil, err
	}
	r.logInputs(ans.Entry)
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
	r.carryAfter(machine, machine, cert, ans) // the dropped stores leave the carried secrets at once
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

// lastSnapshot: before a pause or destroy kills the machine, its last snapshot (or its "nothing to snapshot"
// while booting), waiting up to SnapshotWait with the reason shown in the app. A machine that never got past boot
// (no status report from it) isn't asked at all: it has nothing to snapshot, and an older image may never answer
// (e.g. stuck pulling the secrets of a locked store).
func (r *Router) lastSnapshot(id, machine string) {
	booted := func() (b bool) {
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				b = x.Booted == machine
			}
		})
		return
	}
	// a machine that has its secrets is seconds from booted (repos, then its first report): wait for it, or a pause
	// right after a start would leave its successor with no state at all (its cert names the snapshot this machine
	// signs, and only that one: vouch.go)
	for deadline := time.Now().Add(bootGrace); !booted() && hasPulled(machine) && time.Now().Before(deadline); {
		time.Sleep(time.Second)
	}
	if !booted() {
		log.Printf("session %s: %s never got past boot; nothing to snapshot", id, machine)
		return
	}
	done := r.awaitSnapshot(machine)
	r.send(machine, "snapshot")
	r.setWaiting(id, "waiting for the machine's last snapshot (up to "+waitText(r.cfg.SnapshotWait)+")")
	defer r.setWaiting(id, "")
	select {
	case <-done:
	case <-time.After(r.cfg.SnapshotWait):
		log.Printf("session %s: no snapshot from %s within %s; going on from the last one", id, machine, r.cfg.SnapshotWait)
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
