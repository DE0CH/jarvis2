package main

// What the router does by itself with a running session, from the status its machine reports (registry.go):
// Jarvis 1's autoPauseTick and oneShotTick (server.js) over grants instead of Fly exec.
//
//   auto-pause      idle (no background jobs) for 1 h → Pause; per-session off switch
//   one-shot        the supervisor's ~/.claude/.one-shot-done marker → Destroy
//   stale prompt    "waiting" for 1 h → Escape in the tmux pane (holder "status")
//   attention DMs   idle / waiting / dead for 5 min → one DM per episode; the idle one can be muted
//   downgrade DM    a new safeguard refusal or refusal fallback in a transcript, or the "switch model?" dialog
//   stall nudge     idle with background jobs for 15 min → Jarvis 1's watchdog text as a peer message
//   login repair    the session's credentials expire before Jarvis 1's shared pair, or its transcript ends on
//                   "Please run /login" → write the pair (holder "login"), then deliver "continue"
//
// One tick at a time (a single loop). The decisions are made under the state lock by planTick (pure, tested);
// the actions run outside it. A command the machine refuses (no grant) is recorded as the session's
// needsGrant and not retried for grantRetry.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Liveness: a session's reported status, its settings, and the loop's clocks (unexported: in memory only, as
// in Jarvis 1, so a router restart just restarts them)
type Liveness struct {
	AutoPauseOff    bool      `json:"autoPauseOff,omitempty"`
	NotifyIdleOff   bool      `json:"notifyIdleOff,omitempty"`
	OneShot         bool      `json:"oneShot,omitempty"`
	NeedsGrant      string    `json:"needsGrant,omitempty"` // a holder the machine refused; the app offers a grant
	DowngradeSeenAt int64     `json:"downgradeSeenAt,omitempty"`
	Reg             *Registry `json:"registry,omitempty"`
	LastReport      time.Time `json:"lastReport,omitempty"`

	idleSince       time.Time
	waiting         *waitEpisode
	settled         *settledEpisode
	stall           *stallClock
	loginRepaired   *repairMark
	loginBusy       bool
	grantRetry      map[string]time.Time // holder → not before
	oneShotFiring   bool
	dialogCheckedAt int64 // statusUpdatedAt of the waiting episode whose pane was checked for the dialog
	dialogReported  bool
}

type waitEpisode struct {
	at        time.Time
	statusAt  int64
	cancelled bool
}

type settledEpisode struct {
	kind     string
	since    time.Time
	notified bool
}

type stallClock struct {
	at       time.Time
	statusAt int64
}

type repairMark struct {
	uuid string
	at   time.Time
}

type pilotConfig struct {
	IdlePause, WaitingCancel, Attention, StallNudge, StaleReport, GrantRetry, RepairEvery, DowngradeLookback time.Duration
}

var defaultPilot = pilotConfig{
	IdlePause: time.Hour, WaitingCancel: time.Hour, Attention: 5 * time.Minute, StallNudge: 15 * time.Minute,
	StaleReport: 3 * time.Minute, GrantRetry: 10 * time.Minute, RepairEvery: 10 * time.Minute, DowngradeLookback: 15 * time.Minute,
}

const pilotTick = 30 * time.Second

var routerStarted = time.Now()

// autoPauseVeto: another feature (the scheduler: a wakeup or cron due soon) can hold off an auto-pause. It runs
// inside the tick's r.st.Do, so it gets the locked state and must not take the lock itself.
var autoPauseVeto func(d *persisted, session string) bool

// ---- create, env and view hooks ---------------------------------------------------------------------------

func newLiveness(in NewSession) *Liveness {
	return &Liveness{OneShot: in.OneShot, AutoPauseOff: in.OneShot || (in.AutoPause != nil && !*in.AutoPause)}
}

func init() {
	envHooks = append(envHooks, func(_ *Router, s *Session, e map[string]string) { liveEnv(s, e) })
}

// liveEnv: what the machine's env needs (session-supervisor.sh reads SESSION_ONE_SHOT)
func liveEnv(s *Session, e map[string]string) {
	if s.Live != nil && s.Live.OneShot {
		e["SESSION_ONE_SHOT"] = "1"
	}
}

// liveOptions: what the phone sees on the new-session approval
func liveOptions(s *Session, o map[string]string) {
	if s.Live != nil && s.Live.OneShot {
		o["oneShot"] = "1"
	}
	if s.Live != nil && s.Live.AutoPauseOff {
		o["autoPause"] = "off"
	}
}

func onOff(off bool) string {
	if off {
		return "off"
	}
	return "on"
}

// liveView: the status fields of /api/state, named as in Jarvis 1 (called under the state lock)
func liveView(s *Session, v map[string]any) {
	l := s.Live
	if l == nil {
		l = &Liveness{}
	}
	v["autoPause"], v["notifyIdle"], v["oneShot"] = onOff(l.AutoPauseOff), onOff(l.NotifyIdleOff), l.OneShot
	v["needsGrant"] = l.NeedsGrant
	if !l.LastReport.IsZero() {
		v["lastReport"] = l.LastReport
	}
	if s.State != "started" || s.MachineID == "" || l.Reg == nil || time.Since(l.LastReport) > defaultPilot.StaleReport {
		return
	}
	g := l.Reg
	v["status"], v["aiTitle"], v["liveName"], v["nameSource"] = g.Status, g.AiTitle, g.LiveName, g.NameSource
	v["bgTasks"], v["statusUpdatedAt"], v["bridgeSessionId"], v["sessionId"] = g.BgTasks, g.StatusUpdatedAt, g.BridgeSessionID, g.SessionID
	v["authFailed"], v["credsExpiresAt"], v["sessionsInside"] = g.AuthFailed, g.CredsExpiresAt, g.SessionsInside
	v["oneShotDone"], v["refusals"] = g.OneShotDone, orEmptyR(g.Refusals)
	if !l.AutoPauseOff && !l.idleSince.IsZero() && idleEligible(g) {
		v["pauseInMs"] = max(int64(0), time.Until(l.idleSince.Add(defaultPilot.IdlePause)).Milliseconds())
	}
}

func orEmptyR(r []Refusal) []Refusal {
	if r == nil {
		return []Refusal{}
	}
	return r
}

// ---- routes -----------------------------------------------------------------------------------------------

func (r *Router) registerAutopilot(app appRoute, m machineRoute) {
	m("POST /m/status", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Raw string `json:"raw"`
		}
		json.Unmarshal(body, &in)
		reg := parseRegistry(in.Raw)
		r.st.Do(func(d *persisted) {
			s := d.Sessions[d.Machines[machine]]
			if s == nil || s.MachineID != machine {
				return
			}
			if s.Live == nil {
				s.Live = &Liveness{}
			}
			s.Live.Reg, s.Live.LastReport = reg, time.Now().UTC()
			s.Status = ""
			if reg != nil {
				s.Status = reg.Status
				if reg.AiTitle != "" {
					s.Title = reg.AiTitle
				}
				if reg.NameSource != "" && reg.NameSource != "derived" && reg.LiveName != "" {
					s.UserTitle = reg.LiveName // Deyao named it himself (Jarvis 1's pickTitle userName)
				}
			}
		})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	toggle := func(field string) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			var in struct {
				On      *bool `json:"on"`
				Enabled *bool `json:"enabled"` // Jarvis 1's name
			}
			json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
			on := true
			if in.On != nil {
				on = *in.On
			} else if in.Enabled != nil {
				on = *in.Enabled
			}
			found := false
			r.st.Do(func(d *persisted) {
				s := d.Sessions[req.PathValue("id")]
				if s == nil {
					return
				}
				found = true
				if s.Live == nil {
					s.Live = &Liveness{}
				}
				if field == "autoPause" {
					s.Live.AutoPauseOff, s.Live.idleSince = !on, time.Time{}
				} else {
					s.Live.NotifyIdleOff = !on
				}
			})
			if !found {
				writeJSON(w, 404, map[string]string{"error": "no such session"})
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true, field: onOff(!on)})
		}
	}
	app("POST /api/sessions/{id}/auto-pause", toggle("autoPause"))
	app("POST /api/sessions/{id}/notify-idle", toggle("notifyIdle"))
}

// ---- the loop ---------------------------------------------------------------------------------------------

type pilotAction struct {
	Kind    string // dm | escape | dialog | nudge | login | pause | destroy
	Session string
	Text    string // dm, nudge
	Repair  string // login: the uuid of the "Please run /login" reply being repaired
	Name    string
}

func (r *Router) startAutopilot() {
	go func() {
		for range time.Tick(pilotTick) {
			r.autopilotTick()
		}
	}()
}

func (r *Router) autopilotTick() {
	running := false
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			running = running || (s.State == "started" && s.MachineID != "")
		}
	})
	if !running {
		return
	}
	storedExp := int64(0)
	if l, err := r.sharedLogin(); err == nil {
		storedExp = l.ExpiresAt
	} else if !errorsIsNoLogin(err) {
		log.Printf("[login] Jarvis 1's credentials: %v", err)
	}
	var acts []pilotAction
	r.st.Do(func(d *persisted) {
		acts = planTick(d, time.Now(), storedExp, defaultPilot, r.busy, func(id string) bool { return autoPauseVeto != nil && autoPauseVeto(d, id) })
	})
	for _, a := range acts {
		r.runAction(a)
	}
}

// busy: a lifecycle action holds the session (TryLock + Unlock: never waits)
func (r *Router) busy(id string) bool {
	m, ok := r.locks.Load(id)
	if !ok {
		return false
	}
	mu := m.(*sync.Mutex)
	if mu.TryLock() {
		mu.Unlock()
		return false
	}
	return true
}

func idleEligible(g *Registry) bool { return g != nil && g.Status == "idle" && g.BgTasks == 0 }

// attentionKind: the state a session settled into, or "" while it works. nil = no live claude inside.
func attentionKind(g *Registry) string {
	switch {
	case g != nil && g.Status == "waiting":
		return "waiting"
	case g != nil && g.Status == "idle" && g.BgTasks == 0:
		return "idle"
	case g != nil && g.Status != "":
		return ""
	}
	return "dead"
}

// sessionName: as Jarvis 1 names a session in its DMs
func sessionName(s *Session, g *Registry) string {
	names := []string{s.Label, s.Title, s.ID}
	if g != nil {
		names = append([]string{g.AiTitle, g.LiveName}, names...)
	}
	for _, n := range names {
		if n != "" {
			return n
		}
	}
	return s.ID
}

func (l *Liveness) mayExec(holder string, now time.Time) bool {
	return l.grantRetry == nil || !now.Before(l.grantRetry[holder])
}

// planTick: one pass over the sessions; it moves the clocks and returns what to do. Called under the state lock.
func planTick(d *persisted, now time.Time, storedExp int64, c pilotConfig, busy, veto func(string) bool) []pilotAction {
	var out []pilotAction
	add := func(a pilotAction) { out = append(out, a) }
	for id, s := range d.Sessions {
		if s.Live == nil {
			s.Live = &Liveness{}
		}
		l := s.Live
		if s.State != "started" || s.MachineID == "" {
			l.idleSince, l.waiting, l.settled, l.stall, l.dialogCheckedAt, l.dialogReported = time.Time{}, nil, nil, nil, 0, false
			if s.MachineID == "" {
				l.Reg = nil // paused: the next machine reports afresh
			}
			continue
		}
		g := l.Reg
		if l.LastReport.IsZero() || now.Sub(l.LastReport) > c.StaleReport {
			g = nil // no report lately: the machine (or its agent) isn't answering
		}
		operating := busy(id)
		name := sessionName(s, g)

		// one-shot: the prompt is done → destroy
		if l.OneShot && g != nil && g.OneShotDone && !l.oneShotFiring && !operating {
			l.oneShotFiring = true
			add(pilotAction{Kind: "destroy", Session: id, Name: name})
			continue
		}

		// "needs you" / idle / dead DM, once per settled episode
		if operating || l.OneShot {
			l.settled = nil
		} else if kind := attentionKind(g); kind == "" {
			l.settled = nil
		} else if l.settled == nil || l.settled.kind != kind {
			l.settled = &settledEpisode{kind: kind, since: now}
		} else if !l.settled.notified && now.Sub(l.settled.since) >= c.Attention {
			l.settled.notified = true
			if !(kind == "idle" && l.NotifyIdleOff) {
				add(pilotAction{Kind: "dm", Session: id, Text: attentionText(kind, name)})
			}
		}

		// model downgrade: new refusal events in the transcripts, or the "switch model?" dialog on screen
		if g != nil && !operating {
			since := max(l.DowngradeSeenAt, routerStarted.Add(-c.DowngradeLookback).UnixMilli())
			if ev := freshRefusals(g.Refusals, since); len(ev) > 0 {
				l.DowngradeSeenAt = ev[len(ev)-1].At
				l.dialogReported = true
				add(pilotAction{Kind: "dm", Session: id, Text: downgradeText(name, ev)})
			} else if g.Status != "waiting" {
				l.dialogCheckedAt, l.dialogReported = 0, false
			} else if !l.dialogReported && l.dialogCheckedAt != g.StatusUpdatedAt && l.mayExec("status", now) {
				l.dialogCheckedAt = g.StatusUpdatedAt
				add(pilotAction{Kind: "dialog", Session: id, Name: name})
			}
		}

		// stall nudge: idle with background jobs, no turn for StallNudge → a peer message, repeated every StallNudge
		if operating || l.OneShot || c.StallNudge <= 0 || g == nil || g.Status != "idle" || g.BgTasks == 0 {
			l.stall = nil
		} else if l.stall == nil || l.stall.statusAt != g.StatusUpdatedAt {
			l.stall = &stallClock{at: now, statusAt: g.StatusUpdatedAt}
		} else if stalled := now.Sub(l.stall.at); stalled >= c.StallNudge {
			l.stall.at = now
			add(pilotAction{Kind: "nudge", Session: id, Text: nudgeText(g.BgTasks, stalled)})
		}

		// Claude login: Jarvis 1's pair expires later than the session's, or the session stopped on "Please run /login"
		if g != nil && !operating && !l.loginBusy && s.Harness != "opencode" && storedExp > now.UnixMilli() && l.mayExec("login", now) {
			write := g.CredsExpiresAt < storedExp
			repair := ""
			if u := g.AuthFailed; u != "" && g.Status == "idle" && (l.loginRepaired == nil || (l.loginRepaired.uuid != u && now.Sub(l.loginRepaired.at) >= c.RepairEvery)) {
				repair = u
				l.loginRepaired = &repairMark{uuid: u, at: now}
			}
			if write || repair != "" {
				l.loginBusy = true
				add(pilotAction{Kind: "login", Session: id, Repair: repair, Name: name})
			}
		}

		// a prompt unanswered for WaitingCancel → Escape (once per waiting episode)
		if g == nil || g.Status != "waiting" || operating {
			l.waiting = nil
		} else if l.waiting == nil || l.waiting.statusAt != g.StatusUpdatedAt {
			l.waiting = &waitEpisode{at: now, statusAt: g.StatusUpdatedAt}
		} else if !l.waiting.cancelled && now.Sub(l.waiting.at) >= c.WaitingCancel && l.mayExec("status", now) {
			l.waiting.cancelled = true
			add(pilotAction{Kind: "escape", Session: id, Name: name})
		}

		// auto-pause after IdlePause of plain idle
		if l.AutoPauseOff || l.OneShot || veto(id) || !idleEligible(g) {
			l.idleSince = time.Time{}
			continue
		}
		if l.idleSince.IsZero() {
			l.idleSince = now
		}
		if now.Sub(l.idleSince) >= c.IdlePause && !operating {
			add(pilotAction{Kind: "pause", Session: id, Name: name})
		}
	}
	return out
}

func attentionText(kind, name string) string {
	switch kind {
	case "waiting":
		return fmt.Sprintf("🟠 Session “%s” needs you — Claude is waiting for your input.", name)
	case "idle":
		return fmt.Sprintf("🟢 Session “%s” is idle — Claude finished and is waiting.", name)
	}
	return fmt.Sprintf("🔴 Session “%s” isn't running a live Claude session — it may have died or need a re-login.", name)
}

// nudgeText: Jarvis 1's lib/stall.js nudgeText
func nudgeText(bgTasks int, stalled time.Duration) string {
	jobs := fmt.Sprintf("%d background jobs have", bgTasks)
	if bgTasks == 1 {
		jobs = "1 background job has"
	}
	return fmt.Sprintf("Jarvis watchdog: this session has been idle for %d min while %s been running, and none has finished or woken you. ", int(stalled.Round(time.Minute)/time.Minute), jobs) +
		"Check on them now: read their output, and if a job is hung or no longer needed, stop it and continue the task another way. " +
		"If a job is legitimately still running, make sure it will end on its own (a timeout or deadline), then end your turn — this check repeats while the state lasts. " +
		"This is an automated message from Jarvis, not from Deyao, and not an answer to any open question."
}

// freshRefusals: events newer than since (ms), de-duplicated by uuid
func freshRefusals(ev []Refusal, since int64) []Refusal {
	seen := map[string]bool{}
	var out []Refusal
	for _, e := range ev {
		if e.At <= since || (e.UUID != "" && seen[e.UUID]) {
			continue
		}
		seen[e.UUID] = true
		out = append(out, e)
	}
	return out
}

// downgradeText: lib/downgrade.js message — a fallback (the model actually changed) wins
func downgradeText(name string, ev []Refusal) string {
	cat := func(e Refusal) string {
		if e.Category != "" {
			return " (" + e.Category + ")"
		}
		return ""
	}
	or := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	for i := len(ev) - 1; i >= 0; i-- {
		if e := ev[i]; e.Kind == "fallback" {
			return fmt.Sprintf("🟡 Session “%s”: %s's safeguards flagged a message%s — Claude Code switched it to %s.", name, or(e.From, "the model"), cat(e), or(e.To, "a fallback model"))
		}
	}
	e := ev[len(ev)-1]
	return fmt.Sprintf("🟡 Session “%s”: %s's safeguards flagged a message%s and the turn stopped (no fallback model).", name, or(e.Model, "the model"), cat(e))
}

var ansiSeq = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func stripANSI(s string) string { return ansiSeq.ReplaceAllString(s, "") }

func promptOnScreen(screen string) bool {
	return strings.Contains(strings.ToLower(stripANSI(screen)), "safeguards flagged")
}

// ---- running the actions ----------------------------------------------------------------------------------

func (r *Router) runAction(a pilotAction) {
	switch a.Kind {
	case "dm":
		r.DM(a.Text)
	case "pause":
		if err := r.Pause(a.Session); err != nil {
			log.Printf("[autopause] %s: %v", a.Session, err)
			return
		}
		log.Printf("[autopause] paused idle session %s (%s)", a.Session, a.Name)
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
				s.Live.idleSince = time.Time{}
			}
		})
	case "destroy":
		if err := r.Destroy(a.Session); err != nil {
			log.Printf("[oneshot] %s: %v", a.Session, err)
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
					s.Live.oneShotFiring = false // the next tick looks again
				}
			})
			return
		}
		log.Printf("[oneshot] %s (%s) finished its prompt; destroying", a.Session, a.Name)
	case "escape":
		go func() {
			_, err := r.execAs(a.Session, "status", "tmux send-keys -t claude Escape", 20*time.Second)
			if err != nil {
				log.Printf("[autopause] %s: cancelling the stale prompt failed: %v", a.Session, err)
				r.st.Do(func(d *persisted) {
					if s := d.Sessions[a.Session]; s != nil && s.Live != nil && s.Live.waiting != nil {
						s.Live.waiting.cancelled = false
					}
				})
				return
			}
			log.Printf("[autopause] %s (%s): cancelled a prompt unanswered for %s", a.Session, a.Name, defaultPilot.WaitingCancel)
		}()
	case "dialog":
		go func() {
			res, err := r.execAs(a.Session, "status", "tmux capture-pane -p -t claude", 20*time.Second)
			if err != nil || !promptOnScreen(res.Stdout) {
				return
			}
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
					s.Live.dialogReported = true
				}
			})
			r.DM(fmt.Sprintf("🟡 Session “%s”: the safeguards flagged a message — Claude Code is asking whether to switch to another model.", a.Name))
		}()
	case "nudge":
		go func() {
			if err := r.Deliver(a.Session, "jarvis", a.Text); err != nil {
				r.noteRefusal(a.Session, "scheduler", err)
				log.Printf("[stall] nudge for %s failed (retried next interval): %v", a.Session, err)
				return
			}
			log.Printf("[stall] %s nudged", a.Session)
		}()
	case "login":
		go func() {
			defer r.st.Do(func(d *persisted) {
				if s := d.Sessions[a.Session]; s != nil && s.Live != nil {
					s.Live.loginBusy = false
				}
			})
			r.repairLogin(a)
		}()
	}
}

// execAs: r.Exec, recording a refusal as the session's needsGrant (and backing off) and clearing it on success
func (r *Router) execAs(session, holder, cmd string, timeout time.Duration) (ExecResult, error) {
	res, err := r.Exec(session, holder, cmd, timeout)
	if err != nil && res.Error != "" {
		r.noteRefusal(session, holder, err)
	} else if err == nil {
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[session]; s != nil && s.Live != nil {
				delete(s.Live.grantRetry, holder)
				if s.Live.NeedsGrant == holder {
					s.Live.NeedsGrant = ""
				}
			}
		})
	}
	return res, err
}

// noteRefusal: the machine refused (or the delivery through a grant failed): the app offers a grant, and the
// loop leaves that holder alone for GrantRetry
func (r *Router) noteRefusal(session, holder string, err error) {
	if err == nil || !strings.Contains(err.Error(), "refused") {
		return
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[session]; s != nil && s.Live != nil {
			if s.Live.grantRetry == nil {
				s.Live.grantRetry = map[string]time.Time{}
			}
			s.Live.grantRetry[holder] = time.Now().Add(defaultPilot.GrantRetry)
			s.Live.NeedsGrant = holder
		}
	})
}
