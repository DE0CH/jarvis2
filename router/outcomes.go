package main

// Outcomes (Deyao, 2026-10-13: "Approving an Inbox request should send a message or something to notify the session
// that requested it"): when an Inbox item a SESSION filed is decided — approved, denied, lapsed after inboxTTL, dropped
// (it left without a decision), or failed after approval — the requesting session gets a request-outcome notice (one
// per filing: a batch's items arrive together). The notice names only the filing id the session's guard gave the
// filing (header X-Jarvis2-Filing, kept with the Inbox item) and per item strictly formatted values: the item's index,
// the outcome (a word), the Inbox id or session id, an HTTP status. The guard builds the text from what it kept of the
// filing and texts built into its image, never from router prose; a denial, a lapse or a drop is the router's word, and
// the text says so.
//
// A paused session isn't started for this: the outcomes wait in the router's state and go in once it runs again. A
// destroyed session's outcomes go with it. Deyao's own words (a note, a reason) never travel.

import (
	"errors"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	outcomeApproved = "approved"
	outcomeDenied   = "denied"
	outcomeLapsed   = "lapsed"  // nobody answered within inboxTTL
	outcomeDropped  = "dropped" // left the Inbox without a decision (the session paused, what it was about went away)
	outcomeFailed   = "failed"  // approved, but carrying it out failed

	outcomeMaxPerSession = 100
	outcomeMaxAttempts   = 20
)

var (
	outcomeSettle    = 30 * time.Second // a batch's items are delivered together: until all are decided, or this long after the last
	outcomeTickEvery = 15 * time.Second
	outcomeRefRE     = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// Outcome: one decided item of a session's filing, kept until it is delivered (persisted)
type Outcome struct {
	ID          string     `json:"id"`
	Session     string     `json:"session"` // the requesting session
	Filing      string     `json:"filing"`  // the guard's id of its filing
	Item        int        `json:"item"`    // the item's index in a batch (0 otherwise)
	Batch       string     `json:"batch,omitempty"`
	Ref         string     `json:"ref"`  // the Inbox id, or the session the approval was for
	Kind        string     `json:"kind"` // what was asked (for listing)
	Outcome     string     `json:"outcome"`
	Status      int        `json:"status,omitempty"` // an approved API call: its HTTP status
	At          time.Time  `json:"at"`
	DeliveredAt *time.Time `json:"deliveredAt,omitempty"`
	Attempts    int        `json:"attempts,omitempty"`
	Error       string     `json:"error,omitempty"` // the last delivery error (or why it was given up)
}

// OutcomeItem: one item in a request-outcome notice
type OutcomeItem struct {
	Item    int    `json:"item"`
	Outcome string `json:"outcome"`
	Ref     string `json:"ref"`
	Status  int    `json:"status"`
}

// noteOutcome (under the state lock): the item an Origin filed was decided. Only a session's own filing (with the
// guard's filing id) gets one; the first decision of an item stands.
func noteOutcome(d *persisted, o *Origin, kind, ref, outcome string, status int) {
	if o == nil || !textIDRE.MatchString(o.Filing) || (o.Caller.Kind != "session" && o.Caller.Kind != "actions") || o.Caller.Session == "" {
		return
	}
	sid := o.Caller.Session
	if s := d.Sessions[sid]; s == nil || s.State == "destroyed" || s.State == "destroying" {
		return
	}
	if !outcomeRefRE.MatchString(ref) {
		return
	}
	if d.Outcomes == nil {
		d.Outcomes = map[string][]*Outcome{}
	}
	for _, x := range d.Outcomes[sid] {
		if x.Filing == o.Filing && x.Item == o.Item {
			return
		}
	}
	list := append(d.Outcomes[sid], &Outcome{ID: randID(), Session: sid, Filing: o.Filing, Item: o.Item, Batch: o.Batch, Ref: ref,
		Kind: kind, Outcome: outcome, Status: status, At: time.Now().UTC()})
	if len(list) > outcomeMaxPerSession { // the oldest delivered one goes, else the oldest
		drop := 0
		for i, x := range list {
			if x.DeliveredAt != nil {
				drop = i
				break
			}
		}
		list = append(list[:drop:drop], list[drop+1:]...)
	}
	d.Outcomes[sid] = list
	log.Printf("[outcome] %s: %s %s %s", sid, kind, ref, outcome)
	select {
	case outcomeKick <- struct{}{}:
	default:
	}
}

var outcomeKick = make(chan struct{}, 1)

// ---- delivery ---------------------------------------------------------------------------------------------

type outcomeGroup struct {
	sid    string
	filing string
	ids    []string
	notice Notice
}

// batchItems: how many items a batch had when filed (0 when it is gone or not a batch)
func batchItems(d *persisted, id string) int {
	if b := d.Batches[id]; b != nil {
		return len(b.Entries)
	}
	return 0
}

// readyOutcomes (under the lock): each started session's undelivered outcomes, grouped by filing; a batch's group is
// ready once every item is decided or outcomeSettle after its newest
func readyOutcomes(d *persisted, now time.Time) []outcomeGroup {
	out := []outcomeGroup{}
	for sid, list := range d.Outcomes {
		s := d.Sessions[sid]
		if s == nil || s.State == "destroyed" {
			delete(d.Outcomes, sid)
			continue
		}
		if s.State != "started" || s.MachineID == "" {
			continue // a paused session gets them at its next start; nothing boots it for this
		}
		groups := map[string]*outcomeGroup{}
		newest := map[string]time.Time{}
		batchOf := map[string]string{}
		order := []string{}
		for _, x := range list {
			if x.DeliveredAt != nil || x.Filing == "" {
				continue
			}
			g := groups[x.Filing]
			if g == nil {
				g = &outcomeGroup{sid: sid, filing: x.Filing, notice: Notice{Kind: "request-outcome", Filing: x.Filing}}
				groups[x.Filing] = g
				order = append(order, x.Filing)
			}
			g.ids = append(g.ids, x.ID)
			g.notice.Items = append(g.notice.Items, OutcomeItem{Item: x.Item, Outcome: x.Outcome, Ref: x.Ref, Status: x.Status})
			if x.At.After(newest[x.Filing]) {
				newest[x.Filing] = x.At
			}
			if x.Batch != "" {
				batchOf[x.Filing] = x.Batch
			}
		}
		for _, f := range order {
			g := groups[f]
			if b := batchOf[f]; b != "" {
				decided := map[int]bool{}
				for _, x := range list {
					if x.Filing == f {
						decided[x.Item] = true
					}
				}
				if n := batchItems(d, b); (n == 0 || len(decided) < n) && now.Sub(newest[f]) < outcomeSettle {
					continue
				}
			}
			sort.Slice(g.notice.Items, func(i, j int) bool { return g.notice.Items[i].Item < g.notice.Items[j].Item })
			out = append(out, *g)
		}
	}
	return out
}

// deliverOutcomeHook: a seam for tests (a running session only: nothing resumes a session for this)
var deliverOutcomeHook = func(r *Router, sid string, n Notice) error { return deliverNoticeHook(r, sid, n, false) }

var outcomeRun = struct {
	sync.Mutex
	busy    map[string]bool
	ticking sync.Mutex
}{busy: map[string]bool{}}

var outcomeWG sync.WaitGroup

func (r *Router) outcomeLoop() {
	t := time.NewTicker(outcomeTickEvery)
	defer t.Stop()
	for {
		r.outcomeTick()
		select {
		case <-t.C:
		case <-outcomeKick:
			time.Sleep(2 * time.Second) // let a batch's other answers land
		}
	}
}

// outcomeTick: deliver every ready group, each outside the lock and once at a time
func (r *Router) outcomeTick() {
	if !outcomeRun.ticking.TryLock() {
		return
	}
	defer outcomeRun.ticking.Unlock()
	var ready []outcomeGroup
	r.st.Do(func(d *persisted) { ready = readyOutcomes(d, time.Now().UTC()) })
	for _, g := range ready {
		key := g.sid + " " + g.filing
		outcomeRun.Lock()
		if outcomeRun.busy[key] {
			outcomeRun.Unlock()
			continue
		}
		outcomeRun.busy[key] = true
		outcomeRun.Unlock()
		outcomeWG.Add(1)
		go func(g outcomeGroup) {
			defer outcomeWG.Done()
			defer func() { outcomeRun.Lock(); delete(outcomeRun.busy, key); outcomeRun.Unlock() }()
			err := deliverOutcomeHook(r, g.sid, g.notice)
			if errors.Is(err, errSkip) {
				return // not running right now: the next tick (or the next start)
			}
			now := time.Now().UTC()
			ids := map[string]bool{}
			for _, id := range g.ids {
				ids[id] = true
			}
			r.st.Do(func(d *persisted) {
				for _, x := range d.Outcomes[g.sid] {
					if !ids[x.ID] {
						continue
					}
					if err == nil {
						x.DeliveredAt, x.Error = &now, ""
						continue
					}
					x.Attempts++
					x.Error = trimTo(err.Error(), 300)
					if x.Attempts >= outcomeMaxAttempts || errors.Is(err, errNoSession) || strings.Contains(err.Error(), "no filing of this session") {
						x.DeliveredAt = &now // given up; the session can still read it (GET /m/api/requests/outcomes)
						x.Error = "not delivered: " + x.Error
					}
				}
			})
			if err != nil {
				log.Printf("[outcome] %s: delivering %d item(s) failed: %v", g.sid, len(g.ids), err)
			} else {
				log.Printf("[outcome] %s: %d item(s) delivered", g.sid, len(g.ids))
			}
		}(g)
	}
}

// ---- the session reads its own (jarvis2-request wait / outcomes) -----------------------------------------------

type outcomeView struct {
	Ref       string     `json:"ref"`
	Batch     string     `json:"batch,omitempty"`
	Item      int        `json:"item"`
	Kind      string     `json:"kind"`
	Outcome   string     `json:"outcome"`
	Status    int        `json:"status,omitempty"`
	At        time.Time  `json:"at"`
	Delivered *time.Time `json:"delivered,omitempty"`
	Error     string     `json:"error,omitempty"`
}

func (r *Router) registerOutcomes(m machineRoute) {
	m("GET /m/api/requests/outcomes", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		sid, err := r.machineSession(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		out := []outcomeView{}
		r.st.Do(func(d *persisted) {
			for _, x := range d.Outcomes[sid] {
				out = append(out, outcomeView{Ref: x.Ref, Batch: x.Batch, Item: x.Item, Kind: x.Kind, Outcome: x.Outcome, Status: x.Status,
					At: x.At, Delivered: x.DeliveredAt, Error: x.Error})
			}
		})
		sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
		writeJSON(w, 200, map[string]any{"outcomes": out})
	})
}

func init() {
	onDestroy = append(onDestroy, func(r *Router, s Session) {
		r.st.Do(func(d *persisted) { delete(d.Outcomes, s.ID) })
	})
}
