package main

// Adding to a running machine (docs/DESIGN.md "Adding to a running machine"): the phone signs (sink, source-a, P_add)
// and (source-a, M, ⊤); root's ⊤ moved along both is the add-on's grant on M. Widening happens only out of the sink.
//
//	terminal --minutes N   P_add = ({shell}, {session:S, until:T}), N ≤ 10. The router moves M's main grant along the
//	                       identity edge (M, M, (everything, {session:S, until:T})) so the conditions match, merges, and
//	                       the machine holds the merged grant until T; then the main grant again (it stays untouched).
//	command --cmd C        the same with ({shell}, {session:S, cmd:<sha256 C>, once:<id>, until:T}), T = 10 minutes on:
//	                       the router sends C once under it, keeps the result, and hands the machine its main grant back.
//	add-store X            P_add = ({store:X}, {session:S}): the main grant's own conditions, so it merges straight into
//	                       a new main grant; the phone unlocks X under the same Face ID.
//
// Narrowing is the other way: the main grant moved along (M, M, P) for a smaller P (the identity signer signs any P).

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

const (
	terminalMaxMinutes = 10 // a terminal lasts at most 10 minutes (refused at filing)
	commandWindow      = 10 * time.Minute
	commandMaxLen      = 4000
	commandKeep        = 10   // results kept per session
	commandOutputKeep  = 4096 // bytes of stdout / stderr kept
)

// CommandRun: an approved command's result
type CommandRun struct {
	Approval string    `json:"approval"`
	Cmd      string    `json:"cmd"`
	Code     int       `json:"code"`
	Stdout   string    `json:"stdout"`
	Stderr   string    `json:"stderr"`
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
}

// AddOnIn: a terminal, a command or a store for a running session
type AddOnIn struct {
	Kind    string // terminal | command | add-store
	Session string
	Minutes int
	Cmd     string
	Store   string
}

func onceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hex(s string) string { return kernel.SHA256Hex(s) }

// checkAddOn: the request in its one form, refused when it can't be drafted (a terminal over 10 minutes, an empty
// command, a reserved store, a session that doesn't run)
func (r *Router) checkAddOn(in AddOnIn) (AddOnIn, error) {
	switch in.Kind {
	case "terminal":
		if in.Minutes == 0 {
			in.Minutes = terminalMaxMinutes
		}
		if in.Minutes < 1 || in.Minutes > terminalMaxMinutes {
			return in, &badRequest{fmt.Sprintf("a terminal lasts 1 to %d minutes", terminalMaxMinutes)}
		}
		in.Cmd, in.Store = "", ""
	case "command":
		if in.Cmd == "" || len(in.Cmd) > commandMaxLen {
			return in, &badRequest{fmt.Sprintf("cmd: the command, 1 to %d bytes", commandMaxLen)}
		}
		in.Minutes, in.Store = 0, ""
	case "add-store":
		if _, err := r.withHarnessStores([]string{in.Store}, nil); err != nil {
			return in, &badRequest{err.Error()}
		}
		in.Minutes, in.Cmd = 0, ""
	default:
		return in, &badRequest{"unknown add-on " + in.Kind}
	}
	var ok bool
	r.st.Do(func(d *persisted) {
		s := d.Sessions[in.Session]
		ok = s != nil && s.State == "started" && s.MachineID != "" && s.Chain != nil && s.Chain.Machine != nil
		if ok && in.Kind == "add-store" && containsString(s.Stores, in.Store) {
			ok = false
		}
	})
	if !ok {
		if in.Kind == "add-store" {
			return in, &badRequest{fmt.Sprintf("session %q isn't running, or already holds %s", in.Session, in.Store)}
		}
		return in, &badRequest{fmt.Sprintf("session %q isn't running", in.Session)}
	}
	return in, nil
}

// FileAddOn: the phone's approval for an add-on: two drafts under one Face ID → the approval's id
func (r *Router) FileAddOn(in AddOnIn, o *Origin, explanation, batch string) (string, error) {
	in, err := r.checkAddOn(in)
	if err != nil {
		return "", err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[in.Session]; x != nil {
			s = *x
			c := x.Chain.clone()
			s.Chain = &c
		}
	})
	if s.Chain == nil || s.Chain.Machine == nil {
		return "", &badRequest{"the session isn't running"}
	}
	m := *s.Chain.Machine
	now := time.Now().UTC()
	conds := []string{"session:" + s.ID}
	allowed := kernel.Only("shell")
	a := &Approval{Kind: in.Kind, Session: s.ID, Machine: m.ID, Label: s.Label, Origin: o, Explanation: explanation, Batch: batch,
		Options: map[string]string{}}
	switch in.Kind {
	case "terminal":
		t := now.Add(time.Duration(in.Minutes) * time.Minute).Truncate(time.Second)
		conds = append(conds, untilCond(t))
		a.Until, a.Options["minutes"] = &t, fmt.Sprint(in.Minutes)
	case "command":
		t := now.Add(commandWindow).Truncate(time.Second)
		a.Once, a.Cmd, a.Until = onceID(), in.Cmd, &t
		conds = append(conds, "cmd:"+sha256Hex(in.Cmd), "once:"+a.Once, untilCond(t))
	case "add-store":
		allowed, a.Store, a.Options["store"] = kernel.Only("store:"+in.Store), in.Store, in.Store
	}
	src := kernel.Object{ID: newSourceID()}
	d1, err := r.makeDraft(kernel.Object{ID: kernel.Sink}, src, kernel.Pair{Allowed: allowed, Conditions: kernel.CanonConditions(conds...)})
	if err != nil {
		return "", err
	}
	d2, err := r.makeDraft(src, m, kernel.Top())
	if err != nil {
		return "", err
	}
	a.Drafts = []Draft{d1, d2}
	r.addApproval(a)
	return a.ID, nil
}

// applyAddOn: the two notarized certs → the add-on's grant on M; merged as its kind says; the machine gets the grant
func (r *Router) applyAddOn(a *Approval, ncs []kernel.NotarizedCert) error {
	if len(ncs) != 2 {
		return errors.New("an add-on is two certs")
	}
	var c *Chain
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[a.Session]; s != nil && s.MachineID == a.Machine && s.Chain != nil && s.Chain.Machine != nil {
			x := s.Chain.clone()
			c = &x
		}
	})
	if c == nil {
		return errors.New("the session no longer runs on the machine this was asked for")
	}
	top, err := r.rootGrant()
	if err != nil {
		return err
	}
	ga, err := r.k.Move(top, ncs[0])
	if err == nil {
		ga, err = r.k.Move(ga, ncs[1])
	}
	if err != nil {
		return err
	}
	r.stepCert(a.Session, ncs[0])
	r.stepCert(a.Session, ncs[1])
	gaID := r.stepGrant(a.Session, ga)
	if a.Kind == "add-store" {
		main, err := r.doc(c.Main)
		if err != nil {
			return err
		}
		merged, err := r.k.Merge(main, ga)
		if err != nil {
			return err
		}
		mid := r.stepGrant(a.Session, merged)
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[a.Session]; s != nil && s.Chain != nil {
				s.Chain.Main = mid
				s.Stores = sortedSet(append(s.Stores, a.Store))
			}
		})
		if err := r.remergeAddOns(a.Session); err != nil {
			log.Printf("session %s: re-merging its add-on onto the new main grant: %v", a.Session, err)
		}
		r.refreshHeld(a.Session)
		return nil
	}
	g, err := grantOf(ga)
	if err != nil {
		return err
	}
	merged, err := r.narrowAndMerge(a.Session, *c.Machine, c.Main, ga, g.Conditions)
	if err != nil {
		return err
	}
	add := AddOn{ID: a.ID, Kind: a.Kind, Grant: gaID, Merged: merged, Cmd: a.Cmd, Once: a.Once, Added: time.Now().UTC()}
	if a.Origin != nil {
		add.Filing = a.Origin.Filing
	}
	if a.Until != nil {
		add.Until = *a.Until
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[a.Session]; s != nil && s.Chain != nil {
			s.Chain.AddOns = append(s.Chain.AddOns, add)
		}
	})
	r.refreshHeld(a.Session)
	if a.Kind == "command" {
		go r.runApprovedCommand(a.Session, add)
	}
	return nil
}

// narrowAndMerge: main moved along (M, M, (everything, conds)), merged with the add-on's grant → the merged grant's ID
func (r *Router) narrowAndMerge(sid string, m kernel.Object, mainID string, ga kernel.SignedDoc, conds kernel.Conditions) (string, error) {
	main, err := r.doc(mainID)
	if err != nil {
		return "", err
	}
	idCert, err := r.k.IdentitySign(m, kernel.Pair{Allowed: kernel.Everything(), Conditions: conds})
	if err != nil {
		return "", err
	}
	nc, err := r.k.NotarizeNew(idCert)
	if err != nil {
		return "", err
	}
	narrowed, err := r.k.Move(main, nc)
	if err != nil {
		return "", err
	}
	merged, err := r.k.Merge(narrowed, ga)
	if err != nil {
		return "", err
	}
	r.stepCert(sid, nc)
	r.stepGrant(sid, narrowed)
	return r.stepGrant(sid, merged), nil
}

// remergeAddOns: the active add-ons merged again onto the current main grant (after the main grant changed)
func (r *Router) remergeAddOns(sid string) error {
	c := r.chainOf(sid)
	if c == nil || c.Machine == nil {
		return nil
	}
	for _, a := range c.active(time.Now()) {
		ga, err := r.doc(a.Grant)
		if err != nil {
			return err
		}
		g, err := grantOf(ga)
		if err != nil {
			return err
		}
		merged, err := r.narrowAndMerge(sid, *c.Machine, c.Main, ga, g.Conditions)
		if err != nil {
			return err
		}
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil && s.Chain != nil {
				for i := range s.Chain.AddOns {
					if s.Chain.AddOns[i].ID == a.ID {
						s.Chain.AddOns[i].Merged = merged
					}
				}
			}
		})
	}
	return nil
}

// runApprovedCommand: the command, once, under its merged grant; the result kept; then the add-on ends
func (r *Router) runApprovedCommand(sid string, a AddOn) {
	res, err := r.Shell(sid, a.Cmd, 10*time.Minute)
	run := CommandRun{Approval: a.ID, Cmd: clip(a.Cmd, 200), Code: res.Code, Stdout: tail(res.Stdout, commandOutputKeep),
		Stderr: tail(res.Stderr, commandOutputKeep), At: time.Now().UTC()}
	if err != nil {
		run.Error = err.Error()
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil {
			s.Commands = append(s.Commands, run)
			if len(s.Commands) > commandKeep {
				s.Commands = s.Commands[len(s.Commands)-commandKeep:]
			}
			if s.Chain != nil {
				for i := range s.Chain.AddOns {
					if s.Chain.AddOns[i].ID == a.ID {
						s.Chain.AddOns[i].Run, s.Chain.AddOns[i].Until = true, time.Now().UTC()
					}
				}
			}
		}
	})
	log.Printf("session %s: approved command %s ran (code %d, %v)", sid, a.ID, res.Code, err)
	r.refreshHeld(sid)
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// Narrow: the session's main grant moved along (M, M, (only the stores kept, ∅)) — its stores narrowed in place.
// Only stores the session holds can be kept; keeping none is allowed.
func (r *Router) Narrow(sid string, keep []string) ([]string, error) {
	c := r.chainOf(sid)
	var have []string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil {
			have = append([]string{}, s.Stores...)
		}
	})
	if c == nil || c.Machine == nil {
		return nil, &badRequest{"the session isn't running"}
	}
	for _, k := range keep {
		if !containsString(have, k) {
			return nil, &badRequest{fmt.Sprintf("the session doesn't hold %s", k)}
		}
	}
	keep = sortedSet(keep)
	main, err := r.doc(c.Main)
	if err != nil {
		return nil, err
	}
	idCert, err := r.k.IdentitySign(*c.Machine, kernel.Pair{Allowed: kernel.Only(storeElems(keep)...), Conditions: kernel.Conditions{}})
	if err != nil {
		return nil, err
	}
	nc, err := r.k.NotarizeNew(idCert)
	if err != nil {
		return nil, err
	}
	g, err := r.k.Move(main, nc)
	if err != nil {
		return nil, err
	}
	r.stepCert(sid, nc)
	gid := r.stepGrant(sid, g)
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Chain != nil {
			s.Chain.Main, s.Stores = gid, keep
		}
	})
	if err := r.remergeAddOns(sid); err != nil {
		log.Printf("session %s: re-merging its add-on onto the narrowed grant: %v", sid, err)
	}
	r.refreshHeld(sid)
	return keep, nil
}
