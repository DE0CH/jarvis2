package main

// The Fly budget cap and "Also on Fly" (Jarvis 1 lib/budget.js, server.js budgetTick / scanFlyAccount).
//
// Fly has no spend cap and no billing alerts, so the router ESTIMATES this month's spend: every tick it sums
// the $/hour of everything accruing in the sessions' app (started machines by their guest size, provisioned
// volumes) and adds rate × elapsed to a month-to-date total kept in the router's state (a Riemann sum,
// blind while the router is down, bounded by maxDeltaH per gap). FLY_BUDGET_WARN_USD (default 25) → one DM;
// FLY_BUDGET_USD (default 30; 0 = off) → pause every running session (r.Pause: snapshot, then the core's
// kill) and DM, and keep pausing anything started while the month stays over the cap.
//
// Volume snapshots count too (DECISIONS 176): the sessions' volumes are backed up at every kill (core/volumes.go) and
// Fly bills their snapshots' stored size, including those of volumes already deleted (kept for their retention). Every
// snapshotEvery the router lists the snapshots of each volume Fly still has and of each volume a session or record
// names a backup of (still within its retention), sums their sizes once each, takes off Fly's free 10 GB and adds that
// GB-month rate to the burn.
//
// The router has no Fly token that can change anything: FLY_READ_TOKEN is read-only on app jarvis2-sessions
// (infra/fly-read-token.sh). It lists machines, volumes and the volumes' snapshots, nothing else.

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	hoursPerMonth = 730
	maxDeltaH     = 6 // the longest gap one sample may bill for
	budgetTickDur = 2 * time.Minute
	sessionsApp   = "jarvis2-sessions"
)

// rates (USD) from fly.io/docs/about/pricing (its "Started Fly Machines" calculator, read 2026-10-15; volumes and
// volume snapshots from its "Persistent storage" section, read 2026-10-15: USD 0.15 per provisioned GB-month, snapshots
// USD 0.08 per stored GB-month with the first 10 GB free): a vCPU-second
// shared 8.465e-7 / performance 1.2732e-5, each CPU with 0.25 GB (shared) or 2 GB (performance) of RAM included, every
// further GB-second 2.316e-6, all times the region's markup (lhr, where sessions run: 1.134615385)
var rates = struct {
	sharedCPUPerHour, performanceCPUPerHour, ramPerGBHour, volumePerGBHour float64
	sharedRAMIncluded, performanceRAMIncluded                              float64
	snapshotPerGBHour, snapshotFreeGB                                      float64
}{
	8.465e-7 * 3600 * lhrMarkup, 1.2732e-5 * 3600 * lhrMarkup, 2.316e-6 * 3600 * lhrMarkup, 0.15 / hoursPerMonth,
	0.25, 2,
	0.08 / hoursPerMonth, 10,
}

// flySnapshot: one volume snapshot as Fly lists it (GET /volumes/:id/snapshots; size in bytes, stored)
type flySnapshot struct {
	ID     string `json:"id"`
	Size   int64  `json:"size"`
	Status string `json:"status"`
}

// snapshotReader: a flyReader that also lists a volume's snapshots (the real one; test fakes may not)
type snapshotReader interface {
	Snapshots(volume string) ([]flySnapshot, error)
}

const snapshotEvery = 30 * time.Minute

// snapCache: each volume's snapshots, listed at most every snapshotEvery
var snapCache = struct {
	sync.Mutex
	at    map[string]time.Time
	snaps map[string][]flySnapshot
}{at: map[string]time.Time{}, snaps: map[string][]flySnapshot{}}

// hourlySnapshotCost: the stored snapshot GB past the free ones, per hour
func hourlySnapshotCost(storedBytes int64) float64 {
	gb := float64(storedBytes) / 1e9
	return max(0, gb-rates.snapshotFreeGB) * rates.snapshotPerGBHour
}

// snapshotVolumes: every volume whose snapshots may still be billed — the ones Fly lists, and those a session's or a
// record's backup names while its retention runs
func (r *Router) snapshotVolumes(vs []flyVolume, now time.Time) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, v := range vs {
		add(v.ID)
	}
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			for _, b := range s.Backups {
				if b.ExpiresAt.After(now) {
					add(b.Volume)
				}
			}
		}
		for _, rec := range d.Records {
			for _, b := range rec.Backups {
				if b.ExpiresAt.After(now) {
					add(b.Volume)
				}
			}
		}
	})
	sort.Strings(out)
	return out
}

// snapshotStorage: the stored bytes of every billed snapshot (each counted once) → bytes, snapshots, the first error
func snapshotStorage(fly flyReader, volumes []string, now time.Time) (int64, int, error) {
	sr, ok := fly.(snapshotReader)
	if !ok {
		return 0, 0, nil
	}
	var firstErr error
	ids := map[string]int64{}
	for _, v := range volumes {
		snapCache.Lock()
		at, have := snapCache.at[v]
		list := snapCache.snaps[v]
		snapCache.Unlock()
		if !have || now.Sub(at) >= snapshotEvery {
			got, err := sr.Snapshots(v)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("snapshots of %s: %w", v, err)
				}
			} else {
				list = got
				snapCache.Lock()
				snapCache.at[v], snapCache.snaps[v] = now, got
				snapCache.Unlock()
			}
		}
		for _, s := range list {
			if s.Status == "failed" {
				continue
			}
			ids[s.ID] = s.Size
		}
	}
	var total int64
	for _, n := range ids {
		total += n
	}
	return total, len(ids), firstErr
}

const lhrMarkup = 1.134615385

type flyGuest struct {
	CPUKind  string `json:"cpu_kind"`
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"memory_mb"`
}

type flyMachine struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	Region    string `json:"region"`
	CreatedAt string `json:"created_at"`
	Config    struct {
		Guest *flyGuest `json:"guest"`
	} `json:"config"`
}

type flyVolume struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	State             string `json:"state"`
	Region            string `json:"region"`
	SizeGB            int    `json:"size_gb"`
	AttachedMachineID string `json:"attached_machine_id"`
	CreatedAt         string `json:"created_at"`
}

// hourlyMachineCost: $/hour while started (a stopped machine bills cents a month for its rootfs: ignored)
func hourlyMachineCost(g *flyGuest) float64 {
	if g == nil {
		return 0
	}
	cpus := float64(g.CPUs)
	if cpus == 0 {
		cpus = 1
	}
	rate, included := rates.sharedCPUPerHour, rates.sharedRAMIncluded
	if g.CPUKind == "performance" {
		rate, included = rates.performanceCPUPerHour, rates.performanceRAMIncluded
	}
	return cpus*rate + max(0, float64(g.MemoryMB)/1024-cpus*included)*rates.ramPerGBHour
}

func hourlyVolumeCost(sizeGB int) float64 { return float64(sizeGB) * rates.volumePerGBHour }

type burn struct {
	RatePerHour   float64
	Running       int
	Volumes       int
	SnapshotBytes int64
	Snapshots     int
}

func burnRate(ms []flyMachine, vs []flyVolume) burn {
	var b burn
	for _, m := range ms {
		if m.State == "started" {
			b.RatePerHour += hourlyMachineCost(m.Config.Guest)
			b.Running++
		}
	}
	for _, v := range vs {
		if v.State != "destroyed" {
			b.RatePerHour += hourlyVolumeCost(v.SizeGB)
			b.Volumes++
		}
	}
	return b
}

// ---- the accumulator (pure) -------------------------------------------------------------------------

type BudgetState struct {
	Month        string     `json:"month"` // UTC "YYYY-MM"
	SpentUSD     float64    `json:"spentUsd"`
	LastSampleAt *time.Time `json:"lastSampleAt,omitempty"`
	Warned       bool       `json:"warned"`
	Capped       bool       `json:"capped"`
	CappedAt     *time.Time `json:"cappedAt,omitempty"`
	RatePerHour  float64    `json:"ratePerHour"`
}

type budgetActions struct{ Enforce, CapDM, WarnDM bool }

// applySample: fold one sample in. Enforce: the month is over the cap (every tick, so a session started
// after the cap is caught too); CapDM: first crossing of the cap this month; WarnDM: first crossing of the
// warn line (none once capped, or in the same tick)
func applySample(prev *BudgetState, now time.Time, ratePerHour, capUSD, warnUSD float64) (BudgetState, budgetActions, float64) {
	month := now.UTC().Format("2006-01")
	s := BudgetState{Month: month}
	if prev != nil && prev.Month == month {
		s = *prev
	}
	deltaH := 0.0
	if s.LastSampleAt != nil {
		deltaH = now.Sub(*s.LastSampleAt).Hours()
		if !(deltaH > 0) {
			deltaH = 0
		}
		deltaH = math.Min(deltaH, maxDeltaH)
	}
	t := now.UTC()
	s.SpentUSD += ratePerHour * deltaH
	s.LastSampleAt, s.RatePerHour = &t, ratePerHour
	var a budgetActions
	switch {
	case capUSD > 0 && s.SpentUSD >= capUSD:
		a.Enforce = true
		if !s.Capped {
			a.CapDM, s.Capped, s.CappedAt = true, true, &t
		}
		s.Warned = true
	case warnUSD > 0 && s.SpentUSD >= warnUSD && !s.Warned:
		a.WarnDM, s.Warned = true, true
	}
	return s, a, deltaH
}

// budgetThresholds: FLY_BUDGET_USD (default 30, 0 = off) and FLY_BUDGET_WARN_USD (default 25, or 80% of a
// cap set without one)
func budgetThresholds(getenv func(string) string) (capUSD, warnUSD float64) {
	capUSD = 30
	if v, err := strconv.ParseFloat(getenv("FLY_BUDGET_USD"), 64); err == nil {
		capUSD = v
	}
	warnUSD = 25
	if v, err := strconv.ParseFloat(getenv("FLY_BUDGET_WARN_USD"), 64); err == nil {
		warnUSD = v
	} else if getenv("FLY_BUDGET_USD") != "" {
		warnUSD = math.Round(capUSD*0.8*100) / 100
	}
	return
}

// ---- Fly, read only ----------------------------------------------------------------------------------

type flyReader interface {
	Machines() ([]flyMachine, error)
	Volumes() ([]flyVolume, error)
}

type flyAPI struct {
	base, app, token string
	http             *http.Client
}

func (f *flyAPI) get(p string, out any) error {
	req, _ := http.NewRequest("GET", f.base+"/v1/apps/"+f.app+p, nil)
	auth := f.token
	if !strings.HasPrefix(auth, "FlyV1 ") && !strings.HasPrefix(auth, "Bearer ") {
		auth = "Bearer " + auth
	}
	req.Header.Set("Authorization", auth)
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Fly %s: HTTP %d", p, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (f *flyAPI) Machines() ([]flyMachine, error) {
	var ms []flyMachine
	return ms, f.get("/machines", &ms)
}

func (f *flyAPI) Volumes() ([]flyVolume, error) {
	var vs []flyVolume
	return vs, f.get("/volumes", &vs)
}

func (f *flyAPI) Snapshots(volume string) ([]flySnapshot, error) {
	var ss []flySnapshot
	return ss, f.get("/volumes/"+volume+"/snapshots", &ss)
}

// ---- the tick ---------------------------------------------------------------------------------------

type flyOther struct {
	Kind    string `json:"kind"` // machine | volume
	App     string `json:"app"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Region  string `json:"region"`
	Created string `json:"created"`
	Detail  string `json:"detail"`
}

var budgetView struct {
	sync.Mutex
	budget map[string]any
	fly    map[string]any
}

// the effects, swappable in tests
var (
	budgetPause = func(r *Router, sid string) error { return r.Pause(sid) }
	budgetDM    = func(r *Router, text string) { r.DM(text) }
)

func usd(n float64) string { return fmt.Sprintf("USD %.2f", n) }

// alsoOnFly: what Fly has in the sessions' app that isn't a running session of the router's: machines it
// never started (or no session uses any more) and volumes (sessions use none)
func (r *Router) alsoOnFly(ms []flyMachine, vs []flyVolume) []flyOther {
	out := []flyOther{}
	r.st.Do(func(d *persisted) {
		for _, m := range ms {
			sid, known := d.Machines[m.ID]
			detail := ""
			if g := m.Config.Guest; g != nil {
				detail = fmt.Sprintf("%d×%s · %d GB", g.CPUs, g.CPUKind, int(math.Round(float64(g.MemoryMB)/1024)))
			}
			switch s := d.Sessions[sid]; {
			case !known:
				detail = strings.TrimPrefix(detail+" · not started by this router", " · ")
			case s == nil || s.MachineID != m.ID:
				if m.State != "started" {
					continue // a session's old machine, stopped: Fly keeps it a while
				}
				detail = strings.TrimPrefix(detail+" · its session ("+sid+") no longer runs on it", " · ")
			default:
				continue
			}
			out = append(out, flyOther{"machine", sessionsApp, m.ID, m.Name, m.State, m.Region, m.CreatedAt, detail})
		}
	})
	for _, v := range vs {
		if v.State == "destroyed" {
			continue
		}
		at := " · not attached"
		if v.AttachedMachineID != "" {
			at = " · attached to " + v.AttachedMachineID
		}
		out = append(out, flyOther{"volume", sessionsApp, v.ID, v.Name, v.State, v.Region, v.CreatedAt, fmt.Sprintf("%d GB%s", v.SizeGB, at)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// budgetTick: one sample. Returns what it did, for tests.
func (r *Router) budgetTick(fly flyReader, now time.Time, capUSD, warnUSD float64) (budgetActions, []string, error) {
	ms, err := fly.Machines()
	if err != nil {
		r.setFlyView(map[string]any{"apps": 1, "machines": 0, "volumes": 0, "other": []flyOther{}, "error": err.Error(), "checkedAt": now.UTC()})
		return budgetActions{}, nil, err
	}
	vs, verr := fly.Volumes()
	view := map[string]any{"apps": 1, "app": sessionsApp, "machines": len(ms), "volumes": len(vs), "other": r.alsoOnFly(ms, vs), "error": nil, "checkedAt": now.UTC()}
	if verr != nil {
		view["error"] = "volumes: " + verr.Error()
	}
	r.setFlyView(view)
	if !(capUSD > 0) {
		return budgetActions{}, nil, nil
	}
	b := burnRate(ms, vs)
	stored, nsnap, serr := snapshotStorage(fly, r.snapshotVolumes(vs, now), now)
	b.SnapshotBytes, b.Snapshots = stored, nsnap
	b.RatePerHour += hourlySnapshotCost(stored)
	if serr != nil {
		log.Printf("[budget] %v (counted from the last list)", serr)
	}
	var state BudgetState
	var act budgetActions
	r.st.Do(func(d *persisted) {
		state, act, _ = applySample(d.Budget, now, b.RatePerHour, capUSD, warnUSD)
		d.Budget = &state
	})
	budgetView.Lock()
	budgetView.budget = map[string]any{"month": state.Month, "spentUsd": state.SpentUSD, "capUsd": capUSD, "warnUsd": warnUSD,
		"warned": state.Warned, "capped": state.Capped, "cappedAt": state.CappedAt, "ratePerHour": b.RatePerHour,
		"perMonth": b.RatePerHour * hoursPerMonth, "running": b.Running, "volumes": b.Volumes,
		"snapshots": b.Snapshots, "snapshotGb": float64(b.SnapshotBytes) / 1e9, "sampledAt": state.LastSampleAt}
	budgetView.Unlock()
	var paused, unknown []string
	if act.Enforce {
		for _, m := range ms {
			if m.State != "started" {
				continue
			}
			var sid, name string
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[d.Machines[m.ID]]; s != nil && s.MachineID == m.ID {
					sid, name = s.ID, s.Label
					if name == "" {
						name = s.Title
					}
					if name == "" {
						name = s.ID
					}
				}
			})
			if sid == "" {
				unknown = append(unknown, m.ID)
				continue
			}
			// a session another action holds (starting, being destroyed…) is skipped; the next tick tries again
			if err := budgetPause(r, sid); err != nil {
				log.Printf("[budget] pause %s: %v", sid, err)
				continue
			}
			log.Printf("[budget] paused %s (%s): month over the cap", sid, m.ID)
			paused = append(paused, name)
		}
		if act.CapDM || len(paused) > 0 {
			msg := fmt.Sprintf("Fly budget cap (Jarvis 2): an estimated %s of %s spent in %s. ", usd(state.SpentUSD), usd(capUSD), state.Month)
			if len(paused) > 0 {
				msg += fmt.Sprintf("Paused %d running session(s): %s. They resume from the app. ", len(paused), strings.Join(paused, ", "))
			} else {
				msg += "No running sessions to pause. "
			}
			if len(unknown) > 0 {
				msg += fmt.Sprintf("%d machine(s) on Fly that are no session of the router's are still running (%s); the router can't stop them. ", len(unknown), strings.Join(unknown, ", "))
			}
			msg += fmt.Sprintf("Anything started before the month ends is paused again. The burn rate was %s a month.", usd(b.RatePerHour*hoursPerMonth))
			budgetDM(r, msg)
		}
	} else if act.WarnDM {
		budgetDM(r, fmt.Sprintf("Fly spend (Jarvis 2): an estimated %s of %s in %s (%d%%), %d session(s) running at %s a month. At %s running sessions are paused.",
			usd(state.SpentUSD), usd(capUSD), state.Month, int(state.SpentUSD/capUSD*100), b.Running, usd(b.RatePerHour*hoursPerMonth), usd(capUSD)))
	}
	return act, paused, nil
}

func (r *Router) setFlyView(v map[string]any) {
	budgetView.Lock()
	budgetView.fly = v
	budgetView.Unlock()
}

func (r *Router) budgetLoop() {
	token := os.Getenv("FLY_READ_TOKEN")
	if token == "" {
		log.Printf("[budget] FLY_READ_TOKEN unset: no budget cap, no Also on Fly")
		r.setFlyView(map[string]any{"apps": 0, "machines": 0, "volumes": 0, "other": []flyOther{}, "error": "FLY_READ_TOKEN not set", "checkedAt": nil})
		return
	}
	fly := &flyAPI{base: "https://api.machines.dev", app: sessionsApp, token: token, http: &http.Client{Timeout: 30 * time.Second}}
	capUSD, warnUSD := budgetThresholds(os.Getenv)
	for {
		if _, _, err := r.budgetTick(fly, time.Now(), capUSD, warnUSD); err != nil {
			log.Printf("[budget] %v", err)
		}
		time.Sleep(budgetTickDur)
	}
}

func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		budgetView.Lock()
		defer budgetView.Unlock()
		out["budget"] = budgetView.budget // null until the first sample, or with the cap off
		out["fly"] = budgetView.fly
		out["flyApp"] = sessionsApp
	})
}
