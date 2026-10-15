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
	"slices"
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
	locks    sync.Map   // session id → *sync.Mutex: one lifecycle action at a time
	drain    drainState // drain.go: the lifecycle goroutines running, refused once SIGTERM came
	ops      opsState   // sessionops.go: busy marks, permission-mode/restart jobs, uploads, repos

	policy Policy

	setupMu   sync.Mutex
	setupSeen map[string]time.Time

	login     *loginHub // claudelogin.go: the Claude login
	loginOnce sync.Once

	muxOnce               sync.Once
	publicMux, machineMux *http.ServeMux
	appPatterns           map[string]bool // http.go: every app route's pattern (apicalls.go classifies them)
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
	Content        []string       `json:"content"`     // content stores (content.go), signed with the line
	OneShot        bool           `json:"oneShot"`     // destroyed once its prompt is done (autopilot.go)
	AutoPause      *bool          `json:"autoPause"`   // default on
	APIProxy       bool           `json:"apiProxy"`    // SESSION_API_PROXY (sessionops.go)
	Attachments    *AttachmentsIn `json:"attachments"` // first-prompt attachments (uploads.go)
	Origin         *Origin        `json:"-"`           // inbox.go: who asked, from the credential (the handler sets it)
	Explanation    string         `json:"-"`           // a session's proposal: its reason, shown with the approval (sessionapi.go)
	Task           *TaskConfig    `json:"-"`           // tasks.go: a task line's instance and parameters (into the cert's config)
	Import         *J1ImportRef   `json:"-"`           // jarvis1import.go: the paused Jarvis 1 session this line restores
	Batch          string         `json:"-"`           // batches.go: the batch its approval belongs to
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
	// the defaults are the router's: the core refuses rather than fills in (R2)
	if mode != "bypass" {
		mode = "auto"
	}
	if harness == "" {
		harness = "claude"
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
	in := map[string]any{"predecessor": predecessor, "machine": machine, "stores": sortedSet(stores), "options": opts, "image": image}
	if pred == nil {
		in["salt"] = randID() + randID() // a new line: two identical requests get different nonces
	}
	return r.core.Call("/succession", in)
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
	in := map[string]any{"image": image, "region": r.cfg.Region, "size": size}
	d, err := r.core.Call("/start", in)
	// Fly's org machine limit (lessons/58): nothing was created and the approval is still unused, so wait for a
	// machine to go (sessions pause by themselves) instead of failing a start Deyao already approved
	// A drain (drain.go) doesn't wait out the limit: the start ends with errLimitDraining and Deyao starts it again.
	for waited := time.Duration(0); err != nil && flyMachineLimit(err) && waited < machineLimitWait; waited += machineLimitStep {
		if r.draining() {
			return nil, errLimitDraining
		}
		log.Printf("start: the Fly org is at its machine limit; trying again in %s", machineLimitStep)
		if r.sleepUnlessDraining(machineLimitStep) {
			return nil, errLimitDraining
		}
		d, err = r.core.Call("/start", in)
	}
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

// machineLimitWait / machineLimitStep: how long a start waits out Fly's org machine limit, and how often it tries
var machineLimitWait, machineLimitStep = 3 * time.Hour, time.Minute

func flyMachineLimit(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "machine limit")
}

// killUntilDestroyed: the core's kill (one Fly destroy) again until Fly reports the machine destroyed (409 before).
// A core from before R2 waited inside its kill. A kill that failed on the way (Fly's API timing out, 502, or the core
// not answering) is tried again too, a few times over a few minutes: on 2026-10-15 one Fly destroy timeout left
// "Draft reply to image" failed for good (DECISIONS 170). A refusal (403, 400) is final.
func (r *Router) killUntilDestroyed(in map[string]any) (*Doc, error) {
	deadline := time.Now().Add(killMax)
	transient := 0
	for {
		d, err := r.core.Call("/kill", in)
		var ce *CoreError
		switch {
		case err == nil:
			return d, nil
		case errors.As(err, &ce) && ce.Status == 409 && time.Now().Before(deadline):
			time.Sleep(killStep)
		case (!errors.As(err, &ce) || ce.Status >= 500) && transient < killTransientTries:
			transient++
			log.Printf("kill %v: %v; trying again (%d of %d)", in["machine"], err, transient, killTransientTries)
			time.Sleep(killTransientStep)
		default:
			return d, err
		}
	}
}

// killTransientTries / killTransientStep: how often and how far apart a kill that failed on the way is tried again
var killTransientTries, killTransientStep = 4, 30 * time.Second

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
	img := ""
	if a.Challenge != nil && a.Challenge.Decode(&ch) == nil {
		img = ch.Request.Image
	}
	// a resume on the session's own image names an older CI build than the current one: its signature is in the list
	if img != "" && img == r.cfg.SessionImage {
		a.ImageSig = r.cfg.SessionImageSig
	} else if img != "" {
		a.ImageSig = r.cfg.ImageSigs[img]
	}
	denied := false
	r.st.Do(func(d *persisted) {
		// a batch denied while this approval's challenge was being made: the approval goes the way the batch did
		if a.Batch != "" && d.Batches[a.Batch] == nil {
			denied = true
		}
		d.Approvals[a.ID] = a
		linkFollowup(d, a) // apicalls.go: an approved call's sheet follows it
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

// loadImageOrder: the images of session-image-sigs.txt in line order (images.yml appends each pin)
func loadImageOrder(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			out = append(out, f[0])
		}
	}
	return out
}

// firstRouterLoginImage: the first pinned session image whose machine takes the Claude login from the router
// (machine/claudelogin.go, 2026-10-13 01:39). Every earlier image fetched it from Jarvis 1 with the store claude's
// JARVIS1_CREDENTIALS_*, which no longer exist: such a line resumes on the newest image (the phone approves).
const firstRouterLoginImage = ":sha-c5427052a542@"

// imageDigest: the sha256:… part of a ref@digest (the whole string when it names no digest)
func imageDigest(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// pinnedImage: the ref CI pinned and signed (ref:sha-…@digest) for image's digest. A session records the image its
// machine reports, which can be the bare repo@digest: CI's signature is over the pinned ref, so a resume on the
// session's own image names that, or the phone refuses it as unsigned. Unchanged when no pin has the digest.
func pinnedImage(image, current string, order []string) string {
	if !strings.Contains(image, "@") {
		return image
	}
	d := imageDigest(image)
	if imageDigest(current) == d {
		return current
	}
	for _, o := range order {
		if imageDigest(o) == d {
			return o
		}
	}
	return image
}

// legacyLoginImage: image (ref@digest) is a pin older than firstRouterLoginImage, by its digest's place in the pin
// order. Unknown when the order is missing or lacks the marker (a test router): false. A digest the order doesn't
// list at all is an image from before the list began: legacy.
func legacyLoginImage(image string, order []string) bool {
	digest := imageDigest
	mark := -1
	for i, o := range order {
		if strings.Contains(o, firstRouterLoginImage) {
			mark = i
			break
		}
	}
	if mark < 0 || image == "" {
		return false
	}
	d := digest(image)
	for i, o := range order {
		if digest(o) == d {
			return i < mark
		}
	}
	return true
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
	content, err := r.checkContentStores(in.Content) // content.go: each an existing store
	if err != nil {
		return "", err
	}
	s := &Session{ID: "s" + randID(), State: "approval", Created: time.Now().UTC(), Label: in.Label, Prompt: in.Prompt, Model: in.Model,
		PermissionMode: in.PermissionMode, Size: in.Size, Harness: in.Harness, Stores: stores, Repos: in.Repos, Content: content,
		RequestID: in.RequestID, Live: newLiveness(in)}
	if in.Import != nil {
		s.ImportFrom, s.ImportSha = in.Import.Session, in.Import.Sha256
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
	if len(s.Content) > 0 {
		opts["content"] = strings.Join(s.Content, ",")
	}
	liveOptions(s, opts)
	opsOptions(s, opts)
	if in.Import != nil {
		opts["restore"] = in.Import.Shown // the app shows it beside the signed "Restores machine" and hash
	}
	go func() {
		r.addApproval(&Approval{Kind: "new-session", Session: s.ID, Label: s.Label, Challenge: ch,
			Options: opts, Origin: in.Origin, Explanation: in.Explanation, Batch: in.Batch})
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
	r.expireApprovals(time.Now().UTC()) // an approval answered after inboxTTL is gone: the phone's answer comes too late
	r.st.Do(func(d *persisted) { a = d.Approvals[id] })
	if a == nil {
		return nil, "", fmt.Errorf("no such approval (answered, denied or expired)")
	}
	if a.Kind == "add-store" {
		return r.respondAddStore(a, signature)
	}
	in := map[string]any{"challenge": a.Challenge, "signature": signature}
	// a start the answer leads to is a tracked lifecycle action (drain.go): during a drain the answer is refused before
	// the core uses it up, so the approval stays in the Inbox for the phone to answer again
	done, err := r.begin(a.Session, "approved")
	if err != nil {
		return nil, "", err
	}
	ans, extra, err := r.core.CallAnswer("/approve/by-phone", in)
	if err != nil {
		done()
		return nil, "", err
	}
	r.logInputs(extra.Entry)
	r.st.Do(func(d *persisted) {
		delete(d.Approvals, id)
		if a.Kind == "new-session" { // outcomes.go: the core's approval, by the phone, of exactly the proposal
			noteOutcome(d, a.Origin, a.Kind, a.Session, outcomeApproved, 0, ans)
		}
	})
	go func() {
		defer done()
		r.startAndCertify(a.Session, ans)
	}()
	return ans, a.Session, nil
}

// selfSuccessionLocks: one new cert of a running machine at a time (an add-store answer, a downgrade's finish), so each
// call sends the core the machine's newest cert and carry and stores the answer before the next one reads them
var selfSuccessionLocks sync.Map

func selfSuccessionLock(machine string) func() {
	m, _ := selfSuccessionLocks.LoadOrStore(machine, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// respondAddStore: the phone's answer to "add store X to this running machine". The core answers every add-store onto
// the machine's newest cert, which the router sends beside it as current (core addOnto), so every approved store ends
// in the session whatever order and timing the phone answers in (2026-10-13: identity and yyc, filed 20 minutes apart
// and approved together; the second answer rebuilt the cert from the one both were filed against and yyc left). The
// router never stores an answer that loses a store the session holds: the live core (sha-06ab2452f8ad, until the held
// one goes live) ignores current and answers from the cert the challenge was made from, and then the approval is filed
// again from the newest cert for the phone to answer once more, instead of dropping a store.
func (r *Router) respondAddStore(a *Approval, signature string) (*Doc, string, error) {
	unlock := selfSuccessionLock(a.Machine)
	defer unlock()
	var cur *Doc
	var have []string
	chs := []*Doc{a.Challenge}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[a.Session]; s != nil && s.MachineID == a.Machine && s.State == "started" {
			cur, have = s.Cert, append([]string{}, s.Stores...)
		}
		if x := d.Approvals[a.ID]; x != nil { // as it is now that this answer holds the machine's lock
			chs = append([]*Doc{x.Challenge}, x.Earlier...)
		}
	})
	if cur == nil {
		r.st.Do(func(d *persisted) {
			delete(d.Approvals, a.ID)
			noteOutcome(d, a.Origin, a.Kind, a.Session, outcomeDropped, 0, nil)
		})
		return nil, "", fmt.Errorf("the session no longer runs on the machine this store was asked for")
	}
	store := a.Options["store"]
	done, err := r.begin(a.Session, "approved")
	if err != nil {
		return nil, "", err
	}
	defer done()
	// the phone signed the challenge it read: the current one, or one rebaseAddStores replaced while its page was open
	var ans *Doc
	var extra *Answer
	for i, ch := range chs {
		in := map[string]any{"challenge": ch, "signature": signature, "current": cur, "carry": r.readCarry(a.Machine)}
		ans, extra, err = r.core.CallAnswer("/approve/by-phone", in)
		var ce *CoreError
		if err == nil || !errors.As(err, &ce) || ce.Status != 403 || i == len(chs)-1 {
			break
		}
	}
	if err != nil {
		var ce *CoreError
		if errors.As(err, &ce) && ce.Status == 409 && containsString(have, store) {
			// this very challenge was answered before (the same store asked for twice from one cert): it is in already
			r.st.Do(func(d *persisted) {
				delete(d.Approvals, a.ID)
				noteOutcome(d, a.Origin, a.Kind, a.Session, outcomeApproved, 0, cur)
			})
			return cur, a.Session, nil
		}
		return nil, "", err
	}
	r.logInputs(extra.Entry) // the machine's new cert
	var c struct {
		Stores  []string `json:"stores"`
		Machine *Started `json:"machine"`
	}
	ans.Decode(&c)
	if c.Machine == nil || c.Machine.ID != a.Machine || !containsAll(c.Stores, append(have, store)) {
		log.Printf("add-store %s for %s: the core answered %v from a stale cert (the session holds %v): filed again", store, a.Session, c.Stores, have)
		harness, mode, config := "", certMode(cur), ""
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[a.Session]; s != nil {
				harness, config = s.Harness, lineConfig(s)
			}
		})
		ch, err := r.succession(cur, a.Machine, sortedSet(append(have, store)), harness, mode, "", config, "")
		if err != nil {
			r.st.Do(func(d *persisted) { delete(d.Approvals, a.ID) })
			return nil, "", fmt.Errorf("another store was added while this approval waited, and asking again failed: %v", err)
		}
		r.st.Do(func(d *persisted) {
			if x := d.Approvals[a.ID]; x != nil {
				x.Challenge = ch
			}
		})
		return nil, "", fmt.Errorf("another store was added to this session while this approval waited: approve it again")
	}
	r.st.Do(func(d *persisted) {
		delete(d.Approvals, a.ID)
		noteOutcome(d, a.Origin, a.Kind, a.Session, outcomeApproved, 0, ans) // the machine's new cert names the store
		d.Certs[a.Machine] = ans
		if s := d.Sessions[a.Session]; s != nil {
			s.Cert, s.Stores = ans, c.Stores
		}
	})
	r.carryAfter(a.Machine, a.Machine, ans, extra) // its carried stores go on; the added one comes from its unlock
	r.rebaseAddStores(a.Machine, ans)
	return ans, a.Session, nil
}

// rebaseAddStores: the machine has a new cert (an add-store answered, a downgrade finished), so every other add-store
// still waiting for it is made again from that cert: its challenge is then "the newest cert's stores plus X", the one
// the live core (sha-06ab2452f8ad answers a challenge exactly as made) answers without losing the store just added.
// Before this, a batch of two add-stores for one session (Allow all signs every item it read before the Face ID)
// had its second answered from the cert both were filed against: respondAddStore refused to store it and the phone
// showed the item failed (Deyao, 2026-10-15: "sometimes only the first request succeeds signing"). The phone reads an
// add-store's challenge again right before signing it (BatchReviewView) and checks it is the same ask. Called under
// the machine's selfSuccessionLock; a challenge the core won't make stays as it was (respondAddStore still refuses a
// stale answer, and files it again then).
func (r *Router) rebaseAddStores(machine string, cert *Doc) {
	var c struct {
		Stores []string `json:"stores"`
	}
	if cert == nil || cert.Decode(&c) != nil {
		return
	}
	type waiting struct{ id, store string }
	var todo []waiting
	harness, config := "", ""
	r.st.Do(func(d *persisted) {
		for id, x := range d.Approvals {
			if x.Kind == "add-store" && x.Machine == machine {
				todo = append(todo, waiting{id, x.Options["store"]})
			}
		}
		if s := d.Sessions[d.Machines[machine]]; s != nil {
			harness, config = s.Harness, lineConfig(s)
		}
	})
	sort.Slice(todo, func(i, j int) bool { return todo[i].id < todo[j].id })
	for _, w := range todo {
		if w.store == "" || containsString(c.Stores, w.store) {
			continue // already in (or nothing named): respondAddStore answers it as done
		}
		ch, err := r.succession(cert, machine, sortedSet(append(append([]string{}, c.Stores...), w.store)), harness, certMode(cert), "", config, "")
		if err != nil {
			log.Printf("add-store %s for %s: making it again from the new cert failed: %v", w.store, machine, err)
			continue
		}
		r.st.Do(func(d *persisted) {
			if x := d.Approvals[w.id]; x != nil {
				x.Earlier = append([]*Doc{x.Challenge}, x.Earlier...)
				if len(x.Earlier) > batchMaxItems {
					x.Earlier = x.Earlier[:batchMaxItems]
				}
				x.Challenge = ch
			}
		})
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

// containsAll: every name of want is in have
func containsAll(have, want []string) bool {
	for _, w := range want {
		if !containsString(have, w) {
			return false
		}
	}
	return true
}

func (r *Router) Reject(id string) error { return r.RejectAs(id, outcomeDenied) }

// RejectAs: Reject, telling a requesting session the outcome (denied, or lapsed when it expired; outcomes.go)
func (r *Router) RejectAs(id, outcome string) error {
	var a *Approval
	r.st.Do(func(d *persisted) {
		a = d.Approvals[id]
		delete(d.Approvals, id)
		if a != nil {
			noteOutcome(d, a.Origin, a.Kind, a.Session, outcome, 0, nil)
		}
	})
	if a == nil {
		return fmt.Errorf("no such approval")
	}
	r.st.Do(func(d *persisted) {
		s := d.Sessions[a.Session]
		switch {
		case s == nil:
		case a.Kind == "new-session" && a.Again:
			s.State, s.Error = "failed", "the start again was "+outcome // a failed line asked to start again stays
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
	// paused, or failed. With no machine (a start or certify that failed, or a start cut off by a router restart) the
	// line is where its last pause left it (the core marks a predecessor used only at certify). With one (a pause or
	// destroy whose kill failed, or one cut off) the pause is finished first: the machine's final snapshot (the same
	// one again if it took it already), the kill, then the resume, all on this one tap (DECISIONS 170).
	if s.ID == "" || !(s.State == "paused" || s.State == "failed") {
		unlock()
		return fmt.Errorf("session %s isn't paused or failed", id)
	}
	if s.Cert == nil {
		if s.State != "failed" || s.MachineID != "" {
			unlock()
			return fmt.Errorf("session %s has no line to resume", id)
		}
		return r.startAgain(s, unlock) // a new line whose first start failed
	}
	r.setState(id, "resuming", "")
	go func() {
		defer unlock()
		defer r.settleFollowups(id) // apicalls.go: a call waiting on this resume learns nothing more comes of it
		if s.MachineID != "" {
			r.setWaiting(id, "finishing the pause first")
			if !r.snapshotAndKill(id, s.MachineID) { // archive.go: failed again with the kill's error
				r.setWaiting(id, "")
				return
			}
			r.setWaiting(id, "")
			r.st.Do(func(d *persisted) {
				if x := d.Sessions[id]; x != nil {
					s = *x
				}
			})
		}
		// the same image: the dead-machine rule compares the cert's own image string (what Fly reported, repo@digest);
		// a phone approval names CI's pinned ref for that digest (ref:sha-…@digest), whose signature the phone checks
		own := certImage(s.Cert, s.Image)
		pinned := pinnedImage(own, r.cfg.SessionImage, r.cfg.ImageOrder)
		if !upgrade && slices.Contains(s.Stores, "claude") && legacyLoginImage(own, r.cfg.ImageOrder) {
			upgrade = true // its machine would fetch the Claude login from Jarvis 1: the newest image instead
			log.Printf("session %s: resume on the newest image (its image %s predates the router's Claude login)", id, own)
		}
		once := r.resumeOnce(&s) // vouch.go: a resume prompt or a rollback: only the phone approves one
		// the permission mode is signed: a resume in another mode than the line's cert (raising to bypass) is a
		// change the iPhone approves, like a newer image
		modeChange := certMode(s.Cert) != normMode(s.PermissionMode)
		phone := func(image string, opts map[string]string) {
			ch, err := r.succession(s.Cert, "", s.Stores, s.Harness, s.PermissionMode, image, lineConfig(&s), once)
			if err != nil {
				r.setState(id, "paused", "resume: "+err.Error())
				return
			}
			if once != "" {
				r.onceTaken(id) // the cert will carry them; nothing else delivers them
			}
			r.setState(id, "approval", "")
			r.addApproval(&Approval{Kind: "resume-upgrade", Session: id, Label: s.Label, Challenge: ch, Options: opts})
		}
		phoneImage := pinned
		if upgrade {
			phoneImage = r.cfg.SessionImage
		}
		switch {
		case once != "":
			phone(phoneImage, map[string]string{"permissionMode": normMode(s.PermissionMode), "once": once})
			return
		case modeChange:
			phone(phoneImage, map[string]string{"permissionMode": normMode(s.PermissionMode)})
			return
		case upgrade:
			// a change: the iPhone approves first; nothing happens to the old machine until then
			phone(phoneImage, nil)
			return
		}
		// the core compares the cert's stores, options and image with the challenge's: all of them from the cert
		stores, harness := certStoresHarness(s.Cert, s.Stores, s.Harness)
		ch, err := r.succession(s.Cert, "", stores, harness, s.PermissionMode, own, lineConfig(&s), "")
		if err != nil {
			r.setState(id, "paused", "resume: "+err.Error())
			return
		}
		a, err := r.core.Call("/approve/by-dead-machine", map[string]any{"challenge": ch})
		if refusedSameLine(err) {
			// the core won't answer this resume by itself: it becomes the resume-upgrade approval in the Inbox, on
			// the same image, so one tap (and Face ID) resumes it — never a retry or a call asking for it
			log.Printf("session %s: the core refused the unattended resume (%v): asking the phone", id, err)
			phone(pinned, nil)
			return
		}
		if err != nil {
			r.setState(id, "paused", "resume: "+err.Error())
			return
		}
		r.settleFollowups(id) // no approval follows: the machine starts now
		r.startAndCertify(id, a)
	}()
	return nil
}

// startAgain: a new line whose first start failed (the start or certify failed, or a router restart cut it off) gets
// its new-session approval again, built from the session as it is (vouch.go sessionConfig): one Face ID starts it.
// Its Deny leaves the session failed (Approval.Again) rather than removing it.
func (r *Router) startAgain(s Session, unlock func()) error {
	r.setState(s.ID, "resuming", "")
	go func() {
		defer unlock()
		defer r.settleFollowups(s.ID)
		config, err := r.sessionConfig(&s)
		var ch *Doc
		if err == nil {
			ch, err = r.succession(nil, "", s.Stores, s.Harness, s.PermissionMode, r.cfg.SessionImage, config, "")
		}
		if err != nil {
			r.setState(s.ID, "failed", "start again: "+err.Error())
			return
		}
		opts := map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode, "repos": s.Repos}
		if len(s.Content) > 0 {
			opts["content"] = strings.Join(s.Content, ",")
		}
		liveOptions(&s, opts)
		opsOptions(&s, opts)
		r.setState(s.ID, "approval", "")
		r.addApproval(&Approval{Kind: "new-session", Session: s.ID, Label: s.Label, Challenge: ch, Options: opts, Again: true})
	}()
	return nil
}

// refusedSameLine: the core's approve_by_dead_machine refusing a resume because it doesn't see the same line (store
// set, image or options differ, or a one-time input); the phone can still approve it (core/core.go)
func refusedSameLine(err error) bool {
	var ce *CoreError
	return errors.As(err, &ce) && ce.Status == 403 && strings.Contains(ce.Msg, "differ from the predecessor")
}

// certStoresHarness: the stores and harness the line's cert names (the fallbacks when it names none)
func certStoresHarness(c *Doc, stores []string, harness string) ([]string, string) {
	if c == nil {
		return stores, harness
	}
	var x struct {
		Stores  []string `json:"stores"`
		Options struct {
			Harness string `json:"harness"`
		} `json:"options"`
	}
	if json.Unmarshal([]byte(c.Payload), &x) != nil {
		return stores, harness
	}
	if x.Stores != nil {
		stores = x.Stores
	}
	if x.Options.Harness != "" {
		harness = x.Options.Harness
	}
	return stores, harness
}

// certImage: the image the line's cert says its machine ran (what Fly reported, repo@digest); fallback when the
// cert names none
func certImage(c *Doc, fallback string) string {
	if c == nil {
		return fallback
	}
	var x struct {
		Machine *struct {
			Image string `json:"image"`
		} `json:"machine"`
	}
	if json.Unmarshal([]byte(c.Payload), &x) != nil || x.Machine == nil || x.Machine.Image == "" {
		return fallback
	}
	return x.Machine.Image
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
		if s.MachineID != "" && !r.snapshotAndKillFor(id, s.MachineID, true, force) {
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
	return r.AddStoreFrom(machine, store, Origin{Caller: Caller{Kind: "session", Session: sid}, Call: APICall{Method: "POST", Path: "/m/add-store", Args: map[string]any{"store": store}}}, "", "")
}

// AddStoreFrom: the add-store approval, with its caller and the caller's explanation (inbox.go)
func (r *Router) AddStoreFrom(machine, store string, o Origin, explanation, batch string) error {
	_, err := r.addStoreApproval(machine, store, o, explanation, batch)
	return err
}

// addStoreApproval: AddStoreFrom → the approval's id
func (r *Router) addStoreApproval(machine, store string, o Origin, explanation, batch string) (string, error) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[d.Machines[machine]]; x != nil {
			s = *x
		}
	})
	if s.ID == "" || s.MachineID != machine || s.Cert == nil {
		return "", fmt.Errorf("this machine isn't a running session")
	}
	stores, err := r.withHarnessStores(append(append([]string{}, s.Stores...), store), nil)
	if err != nil {
		return "", err
	}
	ch, err := r.succession(s.Cert, machine, stores, s.Harness, certMode(s.Cert), "", lineConfig(&s), "")
	if err != nil {
		return "", err
	}
	a := &Approval{Kind: "add-store", Session: s.ID, Machine: machine, Label: s.Label, Challenge: ch,
		Options: map[string]string{"store": store}, Origin: &o, Explanation: explanation, Batch: batch}
	r.addApproval(a)
	return a.ID, nil
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
	harness := s.Harness
	if harness == "" {
		harness = "claude"
	}
	opts := map[string]string{"harness": harness, "permissionMode": certMode(s.Cert)}
	if c := lineConfig(&s); c != "" {
		opts["config"] = c
	}
	return r.core.Call("/succession", map[string]any{"predecessor": s.Cert, "machine": machine, "stores": sortedSet(stores),
		"options": opts, "newEncryptionKey": encKey, "newSigningKey": sigKey})
}

// DowngradeFinish: the challenge signed with the machine's old key → its new cert; from now on the router
// knows the machine by its new signing key
func (r *Router) DowngradeFinish(machine string, challenge *Doc, signature string) (*Doc, error) {
	unlock := selfSuccessionLock(machine)
	defer unlock()
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
	r.rebaseAddStores(machine, cert)          // a waiting add-store no longer brings back what the downgrade dropped
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
// silentAfter: a booted machine whose last report is older than this isn't asked for a snapshot
var silentAfter = 3 * time.Minute

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
	// a machine that has gone silent (stopped or gone: its agent reports at least every 60 s) can't answer: no wait,
	// so a pause that a router restart re-runs still reaches the kill
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

// sortedSet: the stores sorted, each once (the core takes them only so)
func sortedSet(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
