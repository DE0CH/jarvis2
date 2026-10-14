package main

// Wakeups and crons (Jarvis 1's lib/wakeup.js, lib/cron.js, in the target design's shape: docs/API-grants.md "due").
// A session arms one through its machine's local API proxy, which keeps the prompt in the guard's records (in the
// snapshot) and sends the router only an id, a time and a period. At a due time the router sends the machine a
// content-free due signal {kind, id, run} — resuming the session first when it is paused — and the guard types the
// text it kept, by its own replay rules. The app can list and cancel them, never arm one: there would be no text on
// the machine to deliver.
//
// They belong to their session (persisted.Schedules, keyed by session id) and end with it: once the session is
// gone from the list, the tick drops them. A session with pending ones must not be destroyed by an automatic
// path (PendingSchedule).

import (
	"errors"
	"fmt"
	"log"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // crons evaluate "HH:MM" in an IANA zone; the router image may have no zoneinfo
)

const (
	wakeupDefault      = "default"
	scheduleMaxPrompt  = 3500
	wakeupMaxDelay     = 90 * 24 * time.Hour
	cronMinEvery       = 15 * 60
	cronDefaultEvery   = 24 * 60 * 60
	cronMaxEvery       = 90 * 24 * 60 * 60
	cronMaxUntil       = 400 * 24 * time.Hour
	resumePromptMax    = 4000 // a resume's prompt (in a phone-made source's settings)
	scheduleTick       = 30 * time.Second
	scheduleMaxAttempt = 5
)

var scheduleNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// textIDRE: the id the guard gave a wakeup, cron or watch when the session armed it (what a due signal names)
var textIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// errAppArmed: the app can't arm one: the text lives on the machine, put there by the session
var errAppArmed = &badRequest{"a wakeup, cron or watch is armed by the session itself (its machine keeps the text): the app can list and cancel them"}

type Wakeup struct {
	Name    string `json:"name"`
	ID      string `json:"id"`      // the guard's id for its text
	At      int64  `json:"at"`      // ms epoch
	ArmedAt int64  `json:"armedAt"` // ms epoch: the arming's identity (compare-and-clear)
}

type Cron struct {
	Name        string `json:"name"`
	ID          string `json:"id"`    // the guard's id for its text
	Every       int64  `json:"every"` // seconds
	TZ          string `json:"tz"`
	NextAt      int64  `json:"nextAt"`          // ms epoch
	Until       *int64 `json:"until,omitempty"` // ms epoch
	ArmedAt     int64  `json:"armedAt"`
	Runs        int    `json:"runs"` // run numbers count up from 1 (the due signal's run is Runs+1)
	LastFiredAt *int64 `json:"lastFiredAt,omitempty"`
}

// Schedule: one session's wakeups, crons and watches
type Schedule struct {
	Wakeups map[string]*Wakeup `json:"wakeups,omitempty"`
	Crons   map[string]*Cron   `json:"crons,omitempty"`
	Watches map[string]*Watch  `json:"watches,omitempty"` // watches.go
}

func (s *Schedule) empty() bool {
	return len(s.Wakeups) == 0 && len(s.Crons) == 0 && len(s.Watches) == 0
}

// sched: the session's schedule, made on demand (callers hold the state lock)
func sched(d *persisted, sid string) *Schedule {
	if d.Schedules == nil {
		d.Schedules = map[string]*Schedule{}
	}
	s := d.Schedules[sid]
	if s == nil {
		s = &Schedule{}
		d.Schedules[sid] = s
	}
	if s.Wakeups == nil {
		s.Wakeups = map[string]*Wakeup{}
	}
	if s.Crons == nil {
		s.Crons = map[string]*Cron{}
	}
	if s.Watches == nil {
		s.Watches = map[string]*Watch{}
	}
	return s
}

// ---- validation (lib/wakeup.js, lib/cron.js normalize) ---------------------------------------------------

type badRequest struct{ msg string }

func (e *badRequest) Error() string { return e.msg }

func bad(format string, a ...any) error { return &badRequest{fmt.Sprintf(format, a...)} }

var spaceRE = regexp.MustCompile(`\s+`)

func cleanPrompt(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
}

// parseTime: an ISO-8601 time (as Date.parse takes it) or a number of ms since the epoch
func parseTime(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false
		}
		return int64(math.Round(x)), true
	case string:
		s := strings.TrimSpace(x)
		for _, f := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z07:00", "2006-01-02T15:04Z07:00", "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"} {
			if t, err := time.Parse(f, s); err == nil {
				return t.UnixMilli(), true
			}
		}
	}
	return 0, false
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}

func wakeupName(v any) (string, error) {
	s := wakeupDefault
	if v != nil {
		if x := strings.TrimSpace(fmt.Sprint(v)); x != "" {
			s = x
		}
	}
	if !scheduleNameRE.MatchString(s) {
		return "", bad("name must be 1-40 chars of letters, digits, _ or -")
	}
	return s, nil
}

// textID: the guard's id in a request (the proxy adds it; the text stays on the machine)
func textID(b map[string]any) (string, error) {
	id, _ := b["id"].(string)
	if !textIDRE.MatchString(id) {
		return "", bad("id: the machine's id for the text (32 hex); arm through the session's local API")
	}
	if _, ok := b["prompt"]; ok {
		return "", bad("the prompt stays on the machine: the router takes only its id")
	}
	return id, nil
}

func normalizeWakeup(b map[string]any, now time.Time) (*Wakeup, error) {
	name, err := wakeupName(b["name"])
	if err != nil {
		return nil, err
	}
	id, err := textID(b)
	if err != nil {
		return nil, err
	}
	ms := now.UnixMilli()
	var at int64
	if v, ok := b["delaySeconds"]; ok && v != nil {
		d, ok := number(v)
		if !ok || d <= 0 {
			return nil, bad("delaySeconds must be a positive number")
		}
		at = ms + int64(math.Round(d*1000))
	} else if v, ok := b["at"]; ok && v != nil {
		if at, ok = parseTime(v); !ok {
			return nil, bad("at must be an ISO-8601 time or ms epoch")
		}
	} else {
		return nil, bad("give at (ISO time) or delaySeconds")
	}
	if at <= ms {
		return nil, bad("the wakeup time is in the past")
	}
	if at-ms > wakeupMaxDelay.Milliseconds() {
		return nil, bad("the wakeup is more than %d days away", int(wakeupMaxDelay.Hours()/24))
	}
	return &Wakeup{Name: name, ID: id, At: at, ArmedAt: ms}, nil
}

// nextTimeOfDay: the next instant after now whose wall-clock time in loc is hh:mm
func nextTimeOfDay(hh, mm int, loc *time.Location, now time.Time) time.Time {
	l := now.In(loc)
	for d := -1; d <= 2; d++ {
		day := l.AddDate(0, 0, d)
		t := time.Date(day.Year(), day.Month(), day.Day(), hh, mm, 0, 0, loc)
		if t.After(now) {
			return t
		}
	}
	return now.Add(24 * time.Hour) // unreachable
}

var hhmmRE = regexp.MustCompile(`^(\d{1,2}):(\d{2})$`)

func normalizeCron(b map[string]any, now time.Time) (*Cron, error) {
	name := strings.TrimSpace(fmt.Sprint(orDefault(b["name"], "")))
	if !scheduleNameRE.MatchString(name) {
		return nil, bad("name must be 1-40 chars of letters, digits, _ or -")
	}
	id, err := textID(b)
	if err != nil {
		return nil, err
	}
	every := int64(cronDefaultEvery)
	if v, ok := b["everySeconds"]; ok && v != nil {
		f, ok := number(v)
		if !ok {
			return nil, bad("everySeconds must be %d–%d", cronMinEvery, cronMaxEvery)
		}
		every = int64(math.Round(f))
	}
	if every < cronMinEvery || every > cronMaxEvery {
		return nil, bad("everySeconds must be %d–%d", cronMinEvery, cronMaxEvery)
	}
	tz := "UTC"
	if v, ok := b["tz"].(string); ok && v != "" {
		tz = v
	}
	loc, err := time.LoadLocation(tz)
	if err != nil || tz == "Local" {
		return nil, bad("unknown time zone %q", tz)
	}
	ms := now.UnixMilli()
	var next int64
	switch {
	case b["time"] != nil:
		m := hhmmRE.FindStringSubmatch(strings.TrimSpace(fmt.Sprint(b["time"])))
		if m == nil {
			return nil, bad("time must be HH:MM")
		}
		hh, _ := strconv.Atoi(m[1])
		mm, _ := strconv.Atoi(m[2])
		if hh > 23 || mm > 59 {
			return nil, bad("time must be HH:MM")
		}
		next = nextTimeOfDay(hh, mm, loc, now).UnixMilli()
	case b["delaySeconds"] != nil:
		d, ok := number(b["delaySeconds"])
		if !ok || d <= 0 {
			return nil, bad("delaySeconds must be a positive number")
		}
		next = ms + int64(math.Round(d*1000))
	case b["at"] != nil:
		var ok bool
		if next, ok = parseTime(b["at"]); !ok {
			return nil, bad("at must be an ISO-8601 time or ms epoch")
		}
		if next <= ms {
			return nil, bad("the first firing is in the past")
		}
	default:
		next = ms + every*1000
	}
	c := &Cron{Name: name, ID: id, Every: every, TZ: tz, NextAt: next, ArmedAt: ms}
	if v, ok := b["until"]; ok && v != nil && v != "" {
		u, ok := parseTime(v)
		if !ok || u <= next {
			return nil, bad("until must be a time after the first firing")
		}
		if u-ms > cronMaxUntil.Milliseconds() {
			return nil, bad("until is more than 400 days away")
		}
		c.Until = &u
	}
	return c, nil
}

func orDefault(v any, def any) any {
	if v == nil {
		return def
	}
	return v
}

// advanceCron: the next occurrence strictly after now (a session unreachable for a while fires once, not a
// backlog), or ok=false once past until
func advanceCron(c *Cron, now time.Time) (int64, bool) {
	next, ms, step := c.NextAt, now.UnixMilli(), c.Every*1000
	if next <= ms {
		next += ((ms - next + 1 + step - 1) / step) * step
	}
	if c.Until != nil && next > *c.Until {
		return 0, false
	}
	return next, true
}

// ---- views (lib/wakeup.js view, lib/cron.js view) -------------------------------------------------------

func iso(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

func wakeupView(w *Wakeup) map[string]any {
	return map[string]any{"name": w.Name, "id": w.ID, "at": w.At, "atIso": iso(w.At)}
}

func cronView(c *Cron) map[string]any {
	v := map[string]any{"name": c.Name, "id": c.ID, "everySeconds": c.Every, "tz": c.TZ, "nextAt": c.NextAt,
		"nextAtIso": iso(c.NextAt), "until": nil, "untilIso": nil, "armedAtIso": iso(c.ArmedAt), "runs": c.Runs, "lastFiredIso": nil}
	if c.TZ == "" {
		v["tz"] = "UTC"
	}
	if c.Until != nil {
		v["until"], v["untilIso"] = *c.Until, iso(*c.Until)
	}
	if c.LastFiredAt != nil {
		v["lastFiredIso"] = iso(*c.LastFiredAt)
	}
	return v
}

// scheduleView: a session's wakeups, crons and watches in its /api/state view (callers hold the state lock)
func scheduleView(d *persisted, sid string, v map[string]any) {
	ws, cs := []map[string]any{}, []map[string]any{}
	if sc := d.Schedules[sid]; sc != nil {
		for _, w := range sortedWakeups(sc) {
			ws = append(ws, wakeupView(w))
		}
		for _, c := range sortedCrons(sc) {
			cs = append(cs, cronView(c))
		}
	}
	v["wakeups"], v["crons"], v["watches"] = ws, cs, watchesViewOf(d, sid)
}

func sortedWakeups(s *Schedule) []*Wakeup {
	out := []*Wakeup{}
	if s != nil {
		for _, w := range s.Wakeups {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out
}

func sortedCrons(s *Schedule) []*Cron {
	out := []*Cron{}
	if s != nil {
		for _, c := range s.Crons {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextAt < out[j].NextAt })
	return out
}

// ---- the session's side of it ---------------------------------------------------------------------------

var errNoSession = errors.New("no such session")

// liveSession: the session, refused when it is gone or going (Jarvis 1 answers 409 "session is destroying")
func (r *Router) liveSession(d *persisted, sid string) (*Session, error) {
	s := d.Sessions[sid]
	if s == nil {
		return nil, errNoSession
	}
	if s.State == "destroyed" || s.State == "destroying" {
		return nil, fmt.Errorf("session is %s", s.State)
	}
	return s, nil
}

func (r *Router) ListWakeups(sid string) ([]*Wakeup, error) {
	var out []*Wakeup
	var err error
	r.st.Do(func(d *persisted) {
		if d.Sessions[sid] == nil {
			err = errNoSession
			return
		}
		for _, w := range sortedWakeups(d.Schedules[sid]) {
			c := *w
			out = append(out, &c)
		}
	})
	if out == nil {
		out = []*Wakeup{}
	}
	return out, err
}

func (r *Router) ArmWakeup(sid string, w *Wakeup) error {
	var err error
	r.st.Do(func(d *persisted) {
		if _, err = r.liveSession(d, sid); err == nil {
			sched(d, sid).Wakeups[w.Name] = w
		}
	})
	if err == nil {
		schedRun.forget(sid + "/w/" + w.Name)
		log.Printf("[wakeup] %s %q (%s) scheduled for %s", sid, w.Name, w.ID, iso(w.At))
	}
	return err
}

// CancelWakeups: the named ones, or every one with all
func (r *Router) CancelWakeups(sid string, names []string, all bool) ([]string, error) {
	var err error
	out := []string{}
	r.st.Do(func(d *persisted) {
		if d.Sessions[sid] == nil {
			err = errNoSession
			return
		}
		s := sched(d, sid)
		if all {
			names = nil
			for n := range s.Wakeups {
				names = append(names, n)
			}
			sort.Strings(names)
		}
		for _, n := range names {
			delete(s.Wakeups, n)
			out = append(out, n)
		}
	})
	for _, n := range out {
		schedRun.forget(sid + "/w/" + n)
	}
	return out, err
}

func (r *Router) ListCrons(sid string) ([]*Cron, error) {
	var out []*Cron
	var err error
	r.st.Do(func(d *persisted) {
		if d.Sessions[sid] == nil {
			err = errNoSession
			return
		}
		for _, c := range sortedCrons(d.Schedules[sid]) {
			x := *c
			out = append(out, &x)
		}
	})
	if out == nil {
		out = []*Cron{}
	}
	return out, err
}

func (r *Router) ArmCron(sid string, c *Cron) error {
	var err error
	r.st.Do(func(d *persisted) {
		if _, err = r.liveSession(d, sid); err == nil {
			sched(d, sid).Crons[c.Name] = c
		}
	})
	if err == nil {
		schedRun.forget(sid + "/c/" + c.Name)
		log.Printf("[cron] %s armed %q (%s) every %ds, next %s", sid, c.Name, c.ID, c.Every, iso(c.NextAt))
	}
	return err
}

func (r *Router) CancelCron(sid, name string) error {
	var err error
	r.st.Do(func(d *persisted) {
		if d.Sessions[sid] == nil {
			err = errNoSession
			return
		}
		delete(sched(d, sid).Crons, name)
	})
	schedRun.forget(sid + "/c/" + name)
	return err
}

// PendingSchedule: the session's armed wakeups, crons and watches ("wakeup <name>", "cron <name>", "watch <name>"). Automatic paths
// (auto-destroy, one-shot clean-up, retirement) must not destroy a session while this is non-empty.
func (r *Router) PendingSchedule(sid string) []string {
	out := []string{}
	r.st.Do(func(d *persisted) {
		s := d.Schedules[sid]
		for _, w := range sortedWakeups(s) {
			out = append(out, "wakeup "+w.Name)
		}
		for _, c := range sortedCrons(s) {
			out = append(out, "cron "+c.Name)
		}
		for _, w := range sortedWatches(s) {
			out = append(out, "watch "+w.Name)
		}
	})
	return out
}

// ScheduleDueWithin: a wakeup or cron fires within d (auto-pause should leave such a session running)
func (r *Router) ScheduleDueWithin(sid string, d time.Duration) bool {
	due := false
	r.st.Do(func(p *persisted) { due = scheduleDueWithin(p, sid, d) })
	return due
}

// scheduleDueWithin: the same, for callers that hold the state lock (the autopilot's veto)
func scheduleDueWithin(p *persisted, sid string, d time.Duration) bool {
	lim := time.Now().Add(d).UnixMilli()
	s := p.Schedules[sid]
	for _, w := range sortedWakeups(s) {
		if w.At < lim {
			return true
		}
	}
	for _, c := range sortedCrons(s) {
		if c.NextAt < lim {
			return true
		}
	}
	return false
}

// ---- firing -------------------------------------------------------------------------------------------

// scheduler: in-memory run state, keyed "<sid>/w/<name>", "<sid>/c/<name>", "<sid>/resume"
type scheduler struct {
	mu       sync.Mutex
	busy     map[string]bool
	attempts map[string]*attempt
	ticking  sync.Mutex
}

type attempt struct {
	n      int
	nextAt time.Time
}

func (s *scheduler) init() {
	s.mu.Lock()
	if s.busy == nil {
		s.busy, s.attempts = map[string]bool{}, map[string]*attempt{}
	}
	s.mu.Unlock()
}

func (s *scheduler) forget(key string) {
	s.init()
	s.mu.Lock()
	delete(s.attempts, key)
	s.mu.Unlock()
}

// claim: the key is free and not backing off → mark it busy
func (s *scheduler) claim(key string, now time.Time) bool {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[key] {
		return false
	}
	if a := s.attempts[key]; a != nil && now.Before(a.nextAt) {
		return false
	}
	s.busy[key] = true
	return true
}

func (s *scheduler) release(key string) {
	s.mu.Lock()
	delete(s.busy, key)
	s.mu.Unlock()
}

// failed: record a failed attempt → drop (after scheduleMaxAttempt)
func (s *scheduler) failed(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.attempts[key]
	if a == nil {
		a = &attempt{}
		s.attempts[key] = a
	}
	a.n++
	if a.n >= scheduleMaxAttempt {
		delete(s.attempts, key)
		return true
	}
	a.nextAt = now.Add(time.Duration(min(a.n, 4)) * 2 * time.Minute)
	return false
}

// schedRun: the scheduler's in-memory run state (lost on a restart, which only makes due items due again)
var schedRun scheduler

func (r *Router) scheduleLoop() {
	for {
		time.Sleep(scheduleTick)
		r.scheduleTick(time.Now())
	}
}

// scheduleTick: one pass; non-reentrant, each item re-read inside its busy section before it fires
func (r *Router) scheduleTick(now time.Time) {
	if !schedRun.ticking.TryLock() {
		return
	}
	defer schedRun.ticking.Unlock()
	type due struct {
		sid, kind, name string
		armedAt         int64
		label           string
	}
	var items []due
	r.st.Do(func(d *persisted) {
		for sid, s := range d.Schedules {
			ss := d.Sessions[sid]
			if ss == nil {
				delete(d.Schedules, sid) // the session is gone: its schedule goes with it
				continue
			}
			if ss.State == "destroyed" || ss.State == "destroying" {
				continue
			}
			label := sessionTitle(*ss)
			for _, w := range s.Wakeups {
				if w.At <= now.UnixMilli() {
					items = append(items, due{sid, "w", w.Name, w.ArmedAt, label})
				}
			}
			for _, c := range s.Crons {
				if c.NextAt <= now.UnixMilli() {
					items = append(items, due{sid, "c", c.Name, c.ArmedAt, label})
				}
			}
			if s.empty() {
				delete(d.Schedules, sid)
			}
		}
	})
	for _, it := range items {
		key := it.sid + "/" + it.kind + "/" + it.name
		if !schedRun.claim(key, now) {
			continue
		}
		go func() {
			defer schedRun.release(key)
			var err error
			var what string
			switch it.kind {
			case "w":
				what = fmt.Sprintf("Scheduled wakeup “%s” for session “%s”", it.name, it.label)
				err = r.fireWakeup(it.sid, it.name, it.armedAt)
			default:
				what = fmt.Sprintf("Recurring wakeup “%s” for session “%s”", it.name, it.label)
				err = r.fireCron(it.sid, it.name, it.armedAt)
			}
			if err == nil {
				schedRun.forget(key)
				return
			}
			if errors.Is(err, errSkip) {
				log.Printf("[schedule] %s: %v — next tick", key, err)
				return
			}
			drop := schedRun.failed(key, time.Now())
			log.Printf("[schedule] %s failed (drop=%v): %v", key, drop, err)
			if drop {
				r.dropFailed(it.sid, it.kind, it.name, it.armedAt)
				r.DM(fmt.Sprintf("%s could not be delivered after %d attempts: %s", what, scheduleMaxAttempt, trimTo(err.Error(), 300)))
			}
		}()
	}
}

// dropFailed: after too many failures a wakeup is dropped; a cron skips this occurrence
func (r *Router) dropFailed(sid, kind, name string, armedAt int64) {
	r.st.Do(func(d *persisted) {
		s := d.Schedules[sid]
		if s == nil {
			return
		}
		switch kind {
		case "w":
			if w := s.Wakeups[name]; w != nil && w.ArmedAt == armedAt {
				delete(s.Wakeups, name)
			}
		case "c":
			if c := s.Crons[name]; c != nil && c.ArmedAt == armedAt {
				if next, ok := advanceCron(c, time.Now()); ok {
					c.NextAt = next
				} else {
					delete(s.Crons, name)
				}
			}
		}
	})
}

// deliverDueHook: a seam for tests (commands.go deliverDue)
var deliverDueHook = func(r *Router, sid string, d Due) error { return r.deliverDue(sid, d) }

func (r *Router) fireWakeup(sid, name string, armedAt int64) error {
	var w Wakeup
	r.st.Do(func(d *persisted) {
		if s := d.Schedules[sid]; s != nil && s.Wakeups[name] != nil {
			w = *s.Wakeups[name]
		}
	})
	if w.Name == "" || w.ArmedAt != armedAt || w.At > time.Now().UnixMilli() {
		return nil // cancelled, replaced or already fired
	}
	if err := deliverDueHook(r, sid, Due{Kind: "wakeup", ID: w.ID}); err != nil {
		return err
	}
	log.Printf("[wakeup] %s %q delivered", sid, name)
	r.st.Do(func(d *persisted) { // compare-and-clear: never one re-armed meanwhile
		if s := d.Schedules[sid]; s != nil && s.Wakeups[name] != nil && s.Wakeups[name].ArmedAt == armedAt {
			delete(s.Wakeups, name)
		}
	})
	return nil
}

func (r *Router) fireCron(sid, name string, armedAt int64) error {
	var c Cron
	r.st.Do(func(d *persisted) {
		if s := d.Schedules[sid]; s != nil && s.Crons[name] != nil {
			c = *s.Crons[name]
		}
	})
	if c.Name == "" || c.ArmedAt != armedAt || c.NextAt > time.Now().UnixMilli() {
		return nil
	}
	if err := deliverDueHook(r, sid, Due{Kind: "cron", ID: c.ID, Run: c.Runs + 1}); err != nil {
		return err
	}
	log.Printf("[cron] %s %q delivered", sid, name)
	now := time.Now()
	r.st.Do(func(d *persisted) {
		s := d.Schedules[sid]
		if s == nil || s.Crons[name] == nil || s.Crons[name].ArmedAt != armedAt {
			return // cancelled or replaced meanwhile
		}
		cur := s.Crons[name]
		next, ok := advanceCron(cur, now)
		if !ok {
			delete(s.Crons, name)
			log.Printf("[cron] %s %q reached its end", sid, name)
			return
		}
		ms := now.UnixMilli()
		cur.NextAt, cur.Runs, cur.LastFiredAt = next, cur.Runs+1, &ms
	})
	return nil
}
