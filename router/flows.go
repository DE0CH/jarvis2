package main

// The session flows of SECRETS-CONTROLLER.md ("Flows (router, outside the core)"), each a chain of core
// primitives. Every long step runs in its own goroutine; the session's `state` says where it is.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
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
	commands map[string]chan string // machine id → pending commands (snapshot)
	snapped  map[string]chan struct{}
	locks    sync.Map // session id → *sync.Mutex: one lifecycle action at a time
}

func NewRouter(cfg Config, st *State, core *CoreClient) *Router {
	return &Router{cfg: cfg, st: st, core: core, commands: map[string]chan string{}, snapped: map[string]chan struct{}{}}
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var errBusy = errors.New("the session is in the middle of another action")

// lock: a session's lifecycle actions don't overlap; a clash is refused (409), not queued
func (r *Router) lock(id string) (func(), error) {
	m, _ := r.locks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	if !mu.TryLock() {
		return nil, errBusy
	}
	return mu.Unlock, nil
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

// ---- start a machine through the core ------------------------------------------------------------

type NewSession struct {
	RequestID      string   `json:"requestId"`
	Label          string   `json:"label"`
	Prompt         string   `json:"prompt"`
	Model          string   `json:"model"`
	PermissionMode string   `json:"permissionMode"`
	Size           string   `json:"size"`
	Harness        string   `json:"harness"`
	Stores         []string `json:"stores"`
	Repos          string   `json:"repos"`
}

func (r *Router) machineEnv(s *Session) map[string]string {
	e := map[string]string{
		"JARVIS2_URL": r.cfg.MachineURL, "JARVIS2_SESSION_ID": s.ID,
		"SESSION_LABEL": s.Label, "SESSION_MODEL": s.Model, "SESSION_PERMISSION_MODE": s.PermissionMode,
		"JARVIS2_REPOS": s.Repos,
	}
	if r.cfg.MachineAccessID != "" {
		e["JARVIS2_ACCESS_ID"], e["JARVIS2_ACCESS_SECRET"] = r.cfg.MachineAccessID, r.cfg.MachineSecret
	}
	if s.Prompt != "" {
		e["SESSION_PROMPT"] = s.Prompt
	}
	return e
}

func (r *Router) start(s *Session, image string) (*Started, error) {
	d, err := r.core.Call("/start", map[string]any{"image": image, "region": r.cfg.Region, "size": s.Size, "env": r.machineEnv(s)})
	if err != nil {
		return nil, err
	}
	var p struct {
		Kind    string   `json:"kind"`
		Machine *Started `json:"machine"`
	}
	if err := d.Decode(&p); err != nil || p.Kind != "started" || p.Machine == nil {
		return nil, fmt.Errorf("core /start: unexpected answer")
	}
	r.st.Do(func(d *persisted) { d.Started[p.Machine.ID] = p.Machine })
	return p.Machine, nil
}

func (r *Router) succession(pred *Doc, machine string, stores []string, harness string) (*Doc, error) {
	var predecessor any // JSON null = from null
	if pred != nil {
		predecessor = pred
	}
	return r.core.Call("/succession", map[string]any{"predecessor": predecessor, "machine": machine, "stores": stores, "options": map[string]string{"harness": harness}})
}

func (r *Router) addApproval(a *Approval) {
	a.ID, a.Created = randID(), time.Now().UTC()
	r.st.Do(func(d *persisted) { d.Approvals[a.ID] = a })
}

// ---- new session ------------------------------------------------------------------------------------

func (r *Router) CreateSession(in NewSession) {
	if in.Harness != "opencode" {
		in.Harness = "claude"
	}
	if in.Size == "" {
		in.Size = "medium"
	}
	if in.PermissionMode != "bypass" {
		in.PermissionMode = "auto"
	}
	sort.Strings(in.Stores)
	// a placeholder until the machine has its id (the session id)
	tmp := "pending-" + randID()
	s := &Session{ID: tmp, State: "starting", Created: time.Now().UTC(), Label: in.Label, Prompt: in.Prompt, Model: in.Model,
		PermissionMode: in.PermissionMode, Size: in.Size, Harness: in.Harness, Stores: in.Stores, Repos: in.Repos, RequestID: in.RequestID}
	r.st.Do(func(d *persisted) { d.Sessions[tmp] = s })
	go func() {
		m, err := r.start(s, r.cfg.SessionImage)
		if err != nil {
			r.setState(tmp, "failed", err.Error())
			return
		}
		r.st.Do(func(d *persisted) {
			delete(d.Sessions, tmp)
			s.ID, s.MachineID, s.Image, s.State = m.ID, m.ID, m.Image, "approval"
			d.Sessions[s.ID] = s
			d.Machines[m.ID] = s.ID
		})
		ch, err := r.succession(nil, m.ID, s.Stores, s.Harness)
		if err != nil {
			r.setState(s.ID, "failed", err.Error())
			r.core.Call("/kill", map[string]string{"machine": m.ID})
			return
		}
		r.addApproval(&Approval{Kind: "new-session", Session: s.ID, Machine: m.ID, Label: s.Label, Challenge: ch,
			Options: map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode, "repos": s.Repos}})
	}()
}

// ---- approvals ---------------------------------------------------------------------------------------

func (r *Router) Respond(id, signature string) (*Doc, string, error) {
	var a *Approval
	r.st.Do(func(d *persisted) { a = d.Approvals[id] })
	if a == nil {
		return nil, "", fmt.Errorf("no such approval")
	}
	cert, err := r.core.Call("/respond/phone", map[string]any{"challenge": a.Challenge, "signature": signature})
	if err != nil {
		return nil, "", err
	}
	r.st.Do(func(d *persisted) {
		delete(d.Approvals, id)
		d.Certs[a.Machine] = cert
		if s := d.Sessions[a.Session]; s != nil {
			s.Cert = cert
			s.MachineID = a.Machine
			if st := d.Started[a.Machine]; st != nil {
				s.Image = st.Image
			}
			if a.Kind == "add-store" {
				var c struct{ Stores []string }
				cert.Decode(&c)
				s.Stores = c.Stores
			} else {
				s.State = "initialising"
			}
		}
		d.Machines[a.Machine] = a.Session
	})
	if a.Kind != "add-store" {
		go r.init(a.Session, a.Machine)
	}
	return cert, a.Session, nil
}

func (r *Router) init(sessionID, machine string) {
	if _, err := r.core.Call("/init", map[string]string{"machine": machine}); err != nil {
		r.setState(sessionID, "failed", err.Error())
	}
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
	switch a.Kind {
	case "new-session", "resume-upgrade":
		// the machine never got a cert: kill it; a new session without a line just disappears
		go func() {
			r.core.Call("/kill", map[string]string{"machine": a.Machine})
			if a.Kind == "new-session" {
				r.st.Do(func(d *persisted) { delete(d.Sessions, a.Session) })
			} else {
				// the old machine was burned before asking: the line has ended
				r.finish(a.Session)
			}
		}()
	}
	return nil
}

// ---- pause ---------------------------------------------------------------------------------------------

func (r *Router) Pause(id string) error {
	unlock, err := r.lock(id)
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
	unlock, err := r.lock(id)
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
		fail := func(err error) { r.setState(id, "paused", "resume: "+err.Error()) }
		var burn *Doc
		image := s.Image
		if upgrade {
			// burn the old machine first (the dead-machine responder consumes it), then ask the iPhone
			ch, err := r.succession(s.Cert, "", s.Stores, s.Harness)
			if err != nil {
				fail(err)
				return
			}
			if burn, err = r.core.Call("/respond/dead", map[string]any{"challenge": ch}); err != nil {
				fail(err)
				return
			}
			image = r.cfg.SessionImage
		}
		m, err := r.start(&s, image)
		if err != nil {
			if upgrade {
				r.setState(id, "failed", "the old machine is burned and the new one didn't start: "+err.Error())
				return
			}
			fail(err)
			return
		}
		ch, err := r.succession(s.Cert, m.ID, s.Stores, s.Harness)
		if err != nil {
			r.core.Call("/kill", map[string]string{"machine": m.ID})
			fail(err)
			return
		}
		r.st.Do(func(d *persisted) { d.Machines[m.ID] = id })
		if upgrade {
			r.setState(id, "approval", "")
			r.addApproval(&Approval{Kind: "resume-upgrade", Session: id, Machine: m.ID, Label: s.Label, Challenge: ch, BurnCert: burn})
			return
		}
		cert, err := r.core.Call("/respond/dead", map[string]any{"challenge": ch})
		if err != nil {
			r.core.Call("/kill", map[string]string{"machine": m.ID})
			fail(err)
			return
		}
		r.st.Do(func(d *persisted) {
			d.Certs[m.ID] = cert
			if x := d.Sessions[id]; x != nil {
				x.Cert, x.MachineID, x.Image, x.State, x.PausedAt = cert, m.ID, m.Image, "initialising", nil
			}
		})
		r.init(id, m.ID)
	}()
	return nil
}

// ---- destroy ---------------------------------------------------------------------------------------------

func (r *Router) Destroy(id string) error {
	unlock, err := r.lock(id)
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
		if s.MachineID != "" {
			if _, err := r.core.Call("/kill", map[string]string{"machine": s.MachineID}); err != nil {
				r.setState(id, "failed", "kill: "+err.Error())
				return
			}
		}
		if s.Cert != nil {
			// end the line: burn the last machine (a succession to null, answered by the dead-machine responder)
			ch, err := r.succession(s.Cert, "", s.Stores, s.Harness)
			if err == nil {
				_, err = r.core.Call("/respond/dead", map[string]any{"challenge": ch})
			}
			if err != nil {
				log.Printf("session %s: burn: %v", id, err)
			}
		}
		r.finish(id)
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
	stores := append(append([]string{}, s.Stores...), store)
	sort.Strings(stores)
	ch, err := r.succession(s.Cert, machine, stores, s.Harness)
	if err != nil {
		return err
	}
	r.addApproval(&Approval{Kind: "add-store", Session: s.ID, Machine: machine, Label: s.Label, Challenge: ch,
		Options: map[string]string{"store": store}})
	return nil
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
