package main

// The session operations Jarvis 1 has beyond create/pause/resume/destroy (docs/PARITY.md "Session lifecycle"):
//
//   resume options    POST /api/sessions/:id/resume {size, model, apiProxy}: applied before the resume. The size
//                     is the spawn's (the router's word); the model and the API proxy are start settings in the
//                     source, so changing either makes the resume a new phone-made source (flows.go Resume).
//   restart           POST /api/sessions/:id/restart {rollback: {dropFromMarker}, prompt}: pause (if running) +
//                     resume. A prompt or a rollback is in a new phone-made source's settings (the phone signs
//                     it); the next machine applies the rollback to the snapshot it has verified
//                     (machine/rollback.go), since the router can't edit a machine-signed snapshot.
//   API proxy         New session / resume {apiProxy}: the source's settings `apiProxy`
//   idempotent create the New Session form's requestId: a repeat answers the session it already made
//   busy              /api/state: the lifecycle action holding a session ({kind, since}); `wake`: the last
//                     restart job ({kind, phase, error, finishedAt})
//
// The permission mode is a start setting fixed for the session's life: nothing changes it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SessionOps: the per-session settings of these operations (Session.Ops, persisted)
type SessionOps struct {
	APIProxy bool         `json:"apiProxy,omitempty"`
	Upload   string       `json:"upload,omitempty"` // first-prompt attachments (uploads.go)
	Attach   []AttachFile `json:"attachments,omitempty"`
}

// opsState: in memory only (a router restart forgets running jobs, as Jarvis 1 does)
type opsState struct {
	mu   sync.Mutex
	busy map[string]busyMark
	wake map[string]*wakeJob

	uploadMu sync.Mutex // uploads.go: one writer of an upload's files at a time
	reposMu  sync.Mutex // repos.go: the repo list file
	gh       ghCache
}

type busyMark struct {
	Kind  string    `json:"kind"`
	Since time.Time `json:"since"`
}

type wakeJob struct {
	Kind       string     `json:"kind"`
	Phase      string     `json:"phase"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

func (o *opsState) setBusy(id, kind string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.busy == nil {
		o.busy = map[string]busyMark{}
	}
	if kind == "" {
		delete(o.busy, id)
		return
	}
	o.busy[id] = busyMark{kind, time.Now().UTC()}
}

func (o *opsState) busyOf(id string) *busyMark {
	o.mu.Lock()
	defer o.mu.Unlock()
	if b, ok := o.busy[id]; ok {
		return &b
	}
	return nil
}

// startJob: one restart job per session at a time
func (o *opsState) startJob(id, kind string) (*wakeJob, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.wake == nil {
		o.wake = map[string]*wakeJob{}
	}
	if j := o.wake[id]; j != nil && j.FinishedAt == nil {
		return nil, errBusy
	}
	j := &wakeJob{Kind: kind, Phase: "starting", StartedAt: time.Now().UTC()}
	o.wake[id] = j
	return j, nil
}

func (o *opsState) phase(j *wakeJob, phase string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	j.Phase = phase
	if err != nil {
		j.Error = err.Error()
	}
	if phase == "done" || phase == "failed" {
		now := time.Now().UTC()
		j.FinishedAt = &now
	}
}

func (o *opsState) jobView(id string) map[string]any {
	o.mu.Lock()
	defer o.mu.Unlock()
	j := o.wake[id]
	if j == nil || (j.FinishedAt != nil && time.Since(*j.FinishedAt) > 10*time.Minute) {
		return nil
	}
	return map[string]any{"kind": j.Kind, "phase": j.Phase, "error": nullIfEmpty(j.Error), "startedAt": j.StartedAt, "finishedAt": j.FinishedAt}
}

func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		ss, _ := out["sessions"].([]map[string]any)
		if r == nil {
			return
		}
		for _, v := range ss {
			id, _ := v["id"].(string)
			if b := r.ops.busyOf(id); b != nil {
				v["busy"] = b
			}
			if j := r.ops.jobView(id); j != nil {
				v["wake"] = j
			}
		}
	})
}

// opsOptions: what the phone sees on the new-session approval
func opsOptions(s *Session, o map[string]string) {
	if s.Ops == nil {
		return
	}
	if s.Ops.APIProxy {
		o["apiProxy"] = "on"
	}
	if n := len(s.Ops.Attach); n > 0 {
		o["attachments"] = fmt.Sprintf("%d file(s)", n)
	}
}

func opsView(s *Session, v map[string]any) {
	v["apiProxy"] = "off"
	if s.Ops == nil {
		return
	}
	v["apiProxy"] = onOff(!s.Ops.APIProxy)
}

// ---- idempotent create -------------------------------------------------------------------------------------

// admitSession: under the state lock, before a new session is stored. A requestId seen on a live session
// answers that session (dup); attachments are bound to this session (uploads.go).
func admitSession(d *persisted, s *Session, in NewSession) (dup string, err error) {
	if in.RequestID != "" {
		for _, x := range d.Sessions {
			if x.RequestID == in.RequestID {
				return x.ID, nil
			}
		}
	}
	s.Ops = &SessionOps{APIProxy: in.APIProxy}
	if in.Attachments != nil && len(in.Attachments.Files) > 0 {
		files, err := bindUpload(d, s.ID, in.Attachments)
		if err != nil {
			return "", err
		}
		s.Ops.Upload, s.Ops.Attach = in.Attachments.UploadID, files
	}
	return "", nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- resume options -----------------------------------------------------------------------------------------

type ResumeOptions struct {
	Size     string `json:"size"`
	Model    string `json:"model"`
	APIProxy *bool  `json:"apiProxy"`
}

var sizeIDs = map[string]bool{"small": true, "medium": true, "large": true}

func (o ResumeOptions) check() error {
	if o.Size != "" && !sizeIDs[o.Size] {
		return fmt.Errorf("size is small, medium or large")
	}
	return nil
}

// resumeModel: a model of the session's own harness (harness.go's catalogue)
func resumeModel(harness, model string) error {
	if m, err := sessionModel(harness, model); err != nil || m != model {
		return fmt.Errorf("%q isn't a model of the %s harness (GET /api/models?harness=%s)", model, harness, harness)
	}
	return nil
}

// applyResumeOptions: only to a paused session (the size reaches the spawn; the model and the API proxy the next
// source's settings, which the phone signs when they change)
func (r *Router) applyResumeOptions(id string, o ResumeOptions) error {
	if err := o.check(); err != nil {
		return err
	}
	if o.Size == "" && o.Model == "" && o.APIProxy == nil {
		return nil
	}
	var err error
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		switch {
		case s == nil:
			err = errNoSession
		case s.State != "paused":
			err = fmt.Errorf("session %s isn't paused", id)
		case o.Model != "" && resumeModel(s.Harness, o.Model) != nil:
			err = resumeModel(s.Harness, o.Model)
		default:
			if o.Size != "" {
				s.Size = o.Size
			}
			if o.Model != "" {
				s.Model = o.Model
			}
			if o.APIProxy != nil {
				if s.Ops == nil {
					s.Ops = &SessionOps{}
				}
				s.Ops.APIProxy = *o.APIProxy
			}
		}
	})
	return err
}

// ---- restart: pause + resume, with a prompt and a transcript rollback ----------------------------------------------

type RestartRequest struct {
	Rollback *struct {
		DropFromMarker string `json:"dropFromMarker"`
	} `json:"rollback"`
	Prompt string `json:"prompt"`
	ResumeOptions
}

// Restart: a running session is paused (its signed snapshot), then resumed: with a prompt or a rollback, out of a new
// phone-made source (the phone signs it); without, from the paused source
func (r *Router) Restart(id string, in RestartRequest) (map[string]any, error) {
	if err := in.ResumeOptions.check(); err != nil {
		return nil, err
	}
	marker := ""
	if in.Rollback != nil {
		marker = strings.TrimSpace(in.Rollback.DropFromMarker)
		if len(marker) < 4 || len(marker) > 500 || strings.ContainsAny(marker, "\n\r\x00") {
			return nil, errors.New("rollback.dropFromMarker: 4–500 characters on one line")
		}
	}
	prompt, err := cleanResumePrompt(in.Prompt)
	if err != nil {
		return nil, err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, errNoSession
	}
	if s.State != "paused" && (s.MachineID == "" || (s.State != "started" && s.State != "initialising")) {
		return nil, fmt.Errorf("session is %s", s.State)
	}
	// the whole job is one tracked lifecycle action (drain.go): its pause and resume go on during a drain
	endJob, err := r.beginJob(id, "restart")
	if err != nil {
		return nil, err
	}
	j, err := r.ops.startJob(id, "restart")
	if err != nil {
		endJob()
		return nil, err
	}
	r.ops.setBusy(id, "restarting")
	go func() {
		defer endJob()
		defer r.ops.setBusy(id, "")
		fail := func(err error) { r.ops.phase(j, "failed", err) }
		if s.MachineID != "" {
			r.ops.phase(j, "snapshotting", nil)
			if err := r.Pause(id); err != nil {
				fail(err)
				return
			}
			if err := r.waitState(id, "paused", r.cfg.SnapshotWait+3*time.Minute); err != nil {
				fail(err)
				return
			}
		}
		r.ops.phase(j, "resuming", nil)
		if err := r.Resume(id, ResumeIn{Prompt: prompt, Rollback: marker, ResumeOptions: in.ResumeOptions}); err != nil {
			fail(err)
			return
		}
		r.ops.phase(j, "done", nil)
	}()
	return map[string]any{"started": true, "kind": "restart", "rollback": marker != ""}, nil
}

// waitState: polls until the session reaches state (or fails / disappears)
func (r *Router) waitState(id, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var st, msg string
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				st, msg = x.State, x.Error
			}
		})
		switch {
		case st == want:
			return nil
		case st == "":
			return errNoSession
		case st == "failed":
			return fmt.Errorf("the session failed: %s", msg)
		case time.Now().After(deadline):
			return fmt.Errorf("the session is still %s", st)
		}
		time.Sleep(opsPoll)
	}
}

var opsPoll = 500 * time.Millisecond

// ---- routes -------------------------------------------------------------------------------------------------

func (r *Router) registerSessionOps(app appRoute, m machineRoute) {
	app("POST /api/sessions/{id}/restart", func(w http.ResponseWriter, req *http.Request) {
		var in RestartRequest
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil && err != io.EOF {
			writeErr(w, fmt.Errorf("bad JSON: %v", err))
			return
		}
		out, err := r.Restart(req.PathValue("id"), in)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
	r.registerUploads(app, m) // uploads.go
	r.registerRepos(app)      // repos.go: repo list, GitHub picker, usage
}
