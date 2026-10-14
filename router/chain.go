package main

// A session's chain (docs/DESIGN.md "Paths and lifecycles"): sink → source → M1 → source → M2 → … → source → sink, each
// step a notarized succession cert, and the grants the mover and the merger made along it. The router keeps, per
// session, where the chain is (the current source and the cert it came out of, the current machine and its spawn cert)
// and which grants exist (the main grant, the add-ons on the running machine, the grant the machine should hold), and
// every document by ID in the document store (docstore.go). Nothing here is trusted: the kernel's parts made every
// document and check each one they are given; the guard checks what reaches the machine.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// Chain: where a session's chain is
type Chain struct {
	// Origin: the notarized cert the current source came out of: (sink, source) by the phone, or (M, source) by the
	// spawner (a kill)
	Origin string        `json:"origin"`
	Source kernel.Object `json:"source"`
	// Spawn: the current machine's notarized spawn cert (source, M, ⊤); "" while paused
	Spawn   string         `json:"spawn,omitempty"`
	Machine *kernel.Object `json:"machine,omitempty"`
	// Main: the session's main grant — on the source while paused, on the machine while it runs. Add-ons never touch
	// it: after an add-on's `until` the machine holds it again.
	Main   string  `json:"main"`
	AddOns []AddOn `json:"addOns,omitempty"`
	// Held: the grant the running machine should hold now (main, or main merged with the newest active add-on)
	Held  string      `json:"held,omitempty"`
	Steps []ChainStep `json:"steps"`
}

// ChainStep: one document of the chain, in order
type ChainStep struct {
	Kind string    `json:"kind"` // cert | grant
	ID   string    `json:"id"`
	At   time.Time `json:"at"`
}

// AddOn: something added to the running machine out of the sink (DESIGN "Adding to a running machine")
type AddOn struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"`   // terminal | command
	Grant  string    `json:"grant"`  // the add-on's own grant on the machine (phone-signed path)
	Merged string    `json:"merged"` // main narrowed to the add-on's conditions, merged with it
	Until  time.Time `json:"until"`
	Cmd    string    `json:"cmd,omitempty"`  // command: the command the grant names by hash
	Once   string    `json:"once,omitempty"` // command: its once id
	Run    bool      `json:"run,omitempty"`  // command: sent to the machine
	Added  time.Time `json:"added"`
	Filing string    `json:"filing,omitempty"` // the session's filing it answers (outcomes.go)
}

func (c Chain) clone() Chain {
	x := c
	x.AddOns = append([]AddOn(nil), c.AddOns...)
	x.Steps = append([]ChainStep(nil), c.Steps...)
	if c.Machine != nil {
		m := *c.Machine
		x.Machine = &m
	}
	return x
}

// active: the add-ons whose until hasn't passed, oldest first
func (c *Chain) active(now time.Time) []AddOn {
	out := []AddOn{}
	for _, a := range c.AddOns {
		if now.Before(a.Until) {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Added.Before(out[j].Added) })
	return out
}

func newSourceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "source-" + hex.EncodeToString(b)
}

// ---- the start settings (a source's `settings`, docs/API-grants.md "Start settings") ---------------------------------

// SessionSettings: exactly the guard's Settings (machine/settings.go), field for field
type SessionSettings struct {
	V              int             `json:"v"`
	Session        string          `json:"session"`
	Harness        string          `json:"harness"`
	PermissionMode string          `json:"permissionMode"`
	Title          string          `json:"title,omitempty"`
	Model          string          `json:"model,omitempty"`
	Repos          []string        `json:"repos,omitempty"`
	Content        []string        `json:"content,omitempty"`
	OneShot        bool            `json:"oneShot,omitempty"`
	APIProxy       bool            `json:"apiProxy,omitempty"`
	Prompt         string          `json:"prompt,omitempty"`
	Attachments    []AttachmentRef `json:"attachments,omitempty"`
	Rollback       string          `json:"rollback,omitempty"`
	Task           *TaskConfig     `json:"task,omitempty"`
}

type AttachmentRef struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type TaskConfig struct {
	Instance string         `json:"instance"`
	Name     string         `json:"name"`
	Params   map[string]any `json:"params"`
}

func splitRepos(s string) []string {
	out := []string{}
	for _, u := range strings.Split(s, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// sessionSettings: the settings a phone-made source carries (prompt, attachments and rollback only there)
func (r *Router) sessionSettings(s *Session, prompt, rollback string, attach []AttachmentRef) (string, error) {
	st := SessionSettings{V: 1, Session: s.ID, Harness: s.Harness, PermissionMode: normMode(s.PermissionMode), Title: s.Label, Model: s.Model,
		Repos: splitRepos(s.Repos), Content: s.Content, Prompt: prompt, Attachments: attach, Rollback: rollback}
	if st.Harness == "" {
		st.Harness = "claude"
	}
	if len(st.Repos) == 0 {
		st.Repos = nil
	}
	if s.Live != nil {
		st.OneShot = s.Live.OneShot
	}
	if s.Ops != nil {
		st.APIProxy = s.Ops.APIProxy
	}
	if s.taskConfig != nil {
		st.Task = s.taskConfig
	} else if isTaskHarness(s.Harness) {
		r.st.Do(func(d *persisted) {
			if i := instanceBySession(tasksOf(d), s.ID); i != nil {
				st.Task = &TaskConfig{Instance: i.ID, Name: i.Name, Params: map[string]any{}}
				for k, v := range i.Params {
					st.Task.Params[k] = v
				}
			}
		})
	}
	b, err := json.Marshal(st)
	return string(b), err
}

func normMode(m string) string {
	if m == "bypass" {
		return "bypass"
	}
	return "auto"
}

// ---- pairs ---------------------------------------------------------------------------------------------------------

func storeElems(stores []string) []string {
	out := []string{}
	for _, s := range sortedSet(stores) {
		out = append(out, "store:"+s)
	}
	return out
}

// mainPair: what the phone gives a session out of the sink: its stores, on the condition that it is this session
func mainPair(sid string, stores []string) kernel.Pair {
	return kernel.Pair{Allowed: kernel.Only(storeElems(stores)...), Conditions: kernel.CanonConditions("session:" + sid)}
}

// untilCond: an `until` condition, minute precision (the guard parses 2026-10-14T12:10Z and full RFC 3339)
func untilCond(t time.Time) string { return "until:" + t.UTC().Format(time.RFC3339) }

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

// ---- drafts: certs the phone signs -----------------------------------------------------------------------------------

// Draft: one succession cert for the phone to sign — its exact payload and the log notary's challenge for it (made
// over the payload's hash, so it exists before the signature)
type Draft struct {
	Payload   string           `json:"payload"`
	Challenge kernel.SignedDoc `json:"challenge"`
}

// draftPayload: (pred, succ, P) as the phone signs it
func draftPayload(pred, succ kernel.Object, p kernel.Pair) (string, error) {
	b, err := json.Marshal(kernel.Succession{Kind: "succession", Signer: kernel.RolePhone, Predecessor: pred, Successor: succ,
		Allowed: p.Allowed, Conditions: condsOrEmpty(p.Conditions)})
	return string(b), err
}

func (r *Router) makeDraft(pred, succ kernel.Object, p kernel.Pair) (Draft, error) {
	payload, err := draftPayload(pred, succ, p)
	if err != nil {
		return Draft{}, err
	}
	ch, err := r.k.Challenge(kernel.SHA256Hex(payload), kernel.AboutSuccession)
	if err != nil {
		return Draft{}, err
	}
	r.docs.Put(ch)
	return Draft{Payload: payload, Challenge: ch}, nil
}

// notarizeDraft: the phone's signature on a draft → the notarized cert (the notarizer checks the phone's key and the
// table; the router checks nothing it couldn't be fooled on)
func (r *Router) notarizeDraft(d Draft, sig string) (kernel.NotarizedCert, error) {
	if sig == "" {
		return kernel.NotarizedCert{}, &badRequest{"a signature for every draft"}
	}
	nc, err := r.k.Notarize(kernel.SignedDoc{Payload: d.Payload, Sig: sig}, d.Challenge)
	if err != nil {
		return nc, err
	}
	r.docs.PutNotarized(nc)
	return nc, nil
}

// ---- steps, recorded ---------------------------------------------------------------------------------------------------

func (r *Router) stepCert(sid string, nc kernel.NotarizedCert) string {
	id := r.docs.PutNotarized(nc)
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Chain != nil {
			s.Chain.Steps = append(s.Chain.Steps, ChainStep{Kind: "cert", ID: id, At: time.Now().UTC()})
		}
	})
	return id
}

func (r *Router) stepGrant(sid string, g kernel.SignedDoc) string {
	id := r.docs.Put(g)
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Chain != nil {
			s.Chain.Steps = append(s.Chain.Steps, ChainStep{Kind: "grant", ID: id, At: time.Now().UTC()})
		}
	})
	return id
}

// chainOf: a copy of the session's chain (nil when it has none)
func (r *Router) chainOf(sid string) *Chain {
	var c *Chain
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Chain != nil {
			x := s.Chain.clone()
			c = &x
		}
	})
	return c
}

func (r *Router) doc(id string) (kernel.SignedDoc, error) {
	d, ok := r.docs.Get(id)
	if !ok {
		return d, fmt.Errorf("document %.12s… isn't on the volume", id)
	}
	return d, nil
}

func (r *Router) notarized(id string) (kernel.NotarizedCert, error) {
	nc, ok := r.docs.Notarized(id)
	if !ok {
		return nc, fmt.Errorf("notarized cert %.12s… isn't on the volume", id)
	}
	return nc, nil
}

// ---- the grant the machine holds ---------------------------------------------------------------------------------------

// heldNow: the grant the running machine should hold: the newest active add-on's merged grant, else the main grant
func heldNow(c *Chain, now time.Time) string {
	act := c.active(now)
	for i := len(act) - 1; i >= 0; i-- {
		if act[i].Merged != "" {
			return act[i].Merged
		}
	}
	return c.Main
}

// refreshHeld: the machine's held grant brought up to date (an add-on ended or began, the main grant changed); a change
// reaches the machine in /m/commands `grant`
func (r *Router) refreshHeld(sid string) {
	now := time.Now()
	var machine, held string
	r.st.Do(func(d *persisted) {
		s := d.Sessions[sid]
		if s == nil || s.Chain == nil || s.Chain.Machine == nil || s.MachineID == "" {
			return
		}
		c := s.Chain
		keep := c.AddOns[:0]
		for _, a := range c.AddOns {
			if now.Before(a.Until.Add(time.Hour)) { // ended add-ons stay visible for an hour, then go
				keep = append(keep, a)
			}
		}
		c.AddOns = keep
		if h := heldNow(c, now); h != c.Held {
			c.Held, machine, held = h, s.MachineID, h
		}
	})
	if machine == "" || held == "" {
		return
	}
	if g, ok := r.docs.Get(held); ok {
		r.out(machine).setGrant(g)
		log.Printf("session %s: machine %s now holds grant %.12s…", sid, machine, held)
	}
}

// grantAllows: the grant document's allowed set names x (the guard decides; this only spares a doomed request)
func grantAllows(d kernel.SignedDoc, x string) bool {
	g, err := grantOf(d)
	return err == nil && g.Allowed.Contains(x)
}

// heldGrantDoc: the grant the session's running machine holds now
func (r *Router) heldGrantDoc(sid string) (kernel.SignedDoc, error) {
	var held string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Chain != nil && s.MachineID != "" {
			held = s.Chain.Held
		}
	})
	if held == "" {
		return kernel.SignedDoc{}, errors.New("the session has no running machine with a grant")
	}
	return r.doc(held)
}

// machineHoldsStore: the session's running machine holds a grant naming store:<name>
func (r *Router) machineHoldsStore(sid, store string) bool {
	d, err := r.heldGrantDoc(sid)
	return err == nil && grantAllows(d, "store:"+store)
}

// holdersOf: the running machines whose held grant names store:<name>, by session
func (r *Router) holdersOf(store string) map[string]string {
	type m struct{ sid, machine, held string }
	var ms []m
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.MachineID != "" && s.Chain != nil && s.Chain.Held != "" {
				ms = append(ms, m{s.ID, s.MachineID, s.Chain.Held})
			}
		}
	})
	out := map[string]string{}
	for _, x := range ms {
		if g, ok := r.docs.Get(x.held); ok && grantAllows(g, "store:"+store) {
			out[x.sid] = x.machine
		}
	}
	return out
}

// pullHolders: every running machine whose held grant names the store pulls again → their session ids
func (r *Router) pullHolders(store string) []string {
	out := []string{}
	for sid, machine := range r.holdersOf(store) {
		r.out(machine).word("pull")
		out = append(out, sid)
	}
	sort.Strings(out)
	return out
}

func (r *Router) grantLoop() {
	for {
		time.Sleep(grantTick)
		var ids []string
		r.st.Do(func(d *persisted) {
			for id, s := range d.Sessions {
				if s.Chain != nil && s.MachineID != "" && len(s.Chain.AddOns) > 0 {
					ids = append(ids, id)
				}
			}
		})
		for _, id := range ids {
			r.refreshHeld(id)
		}
	}
}

var grantTick = 10 * time.Second
