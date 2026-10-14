package main

// Memory-starvation watch and the one-tap Upgrade (Jarvis 1's lib/memory.js + POST /api/sessions/:id/upgrade).
//
// A session that runs builds, agents and a few Chromes thrashes: for minutes its machine is too short on memory to
// do anything, then the kernel OOM-kills the biggest process, and the Claude app shows "Can't reach your computer"
// (2026-10-12, the YYC AI megathread session). The machine reports its RAM every 10 s (machine/memory.go,
// POST /m/memory); Watch decides when it is starving:
//   - the kernel OOM-killed something since the last sample (oom_kill went up),
//   - memory pressure: PSI "full" avg60 ≥ memPSIFullPct, or MemAvailable < memLowAvailPct of MemTotal,
//   - or the machine stopped reporting (memSilent) while its last sample was already short (< memShortAvailPct).
// An episode is DMed once, shown on the session as memAlert {since, reason, detail, nextSize} with an Upgrade
// button, and ends after memClear of healthy samples (or with the machine: an upgrade replaces it).
//
// Upgrade (POST /api/sessions/:id/upgrade): the machine's agent frees memory first (command "free": the harness
// SIGSTOPped, every other process of the session SIGKILLed, the list kept in the snapshot), then the usual pause
// (its signed snapshot) and resume on the next size; once the new machine is up it gets the canned "upgraded"
// delivery (the text is built into the image, the router names only the two sizes).

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	memPSIFullPct    = 10.0 // PSI memory full avg60 (%) that counts as thrashing
	memLowAvailPct   = 5.0  // MemAvailable below this % of MemTotal counts as starving
	memShortAvailPct = 15.0 // a machine that goes silent with less than this left was starving
	memClear         = 15 * time.Minute
	memSilent        = 90 * time.Second // no memory report for this long = not answering
	memFreeWait      = 5 * time.Second  // after "free", before the snapshot
)

// the next size up for the Upgrade button ("" = already the biggest); a session with no size runs medium
var nextSize = map[string]string{"small": "medium", "medium": "large", "": "large"}

var sizeGB = map[string]int{"small": 2, "medium": 4, "large": 8}

type MemProc struct {
	RssKb int64  `json:"rssKb"`
	Comm  string `json:"comm"`
}

// MemSample: what the machine reports (machine/memory.go memSample)
type MemSample struct {
	TotalKb   int64     `json:"totalKb"`
	AvailKb   int64     `json:"availKb"`
	OOMKills  *int64    `json:"oomKills"`
	PSIFull60 *float64  `json:"psiFull60"`
	Top       []MemProc `json:"top"`
}

type MemAlert struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail"`
}

// memState: one machine's watch (in memory only, as in Jarvis 1)
type memState struct {
	machine      string
	last         *MemSample
	lastAt       time.Time
	oomKills     *int64
	alert        *MemAlert
	healthySince time.Time
}

func (s MemSample) availPct() float64 { return 100 * float64(s.AvailKb) / float64(s.TotalKb) }

func describeMem(s *MemSample) string {
	if s == nil {
		return ""
	}
	var top []string
	for _, p := range s.Top {
		if p.RssKb > 100*1024 {
			top = append(top, fmt.Sprintf("%s %.1f GB", p.Comm, float64(p.RssKb)/1048576))
		}
	}
	out := fmt.Sprintf("%d MB free of %.1f GB", s.AvailKb/1024, float64(s.TotalKb)/1048576)
	if len(top) > 0 {
		out += " (biggest: " + strings.Join(top, ", ") + ")"
	}
	return out
}

// observe: a sample (or nil when the machine went silent) → true when a new starvation episode begins (DM it)
func (m *memState) observe(sample *MemSample, now time.Time) bool {
	reason := ""
	if sample != nil {
		switch {
		case m.oomKills != nil && sample.OOMKills != nil && *sample.OOMKills > *m.oomKills:
			n := *sample.OOMKills - *m.oomKills
			reason = fmt.Sprintf("the kernel killed %d process%s for lack of memory", n, map[bool]string{true: "", false: "es"}[n == 1])
		case sample.PSIFull60 != nil && *sample.PSIFull60 >= memPSIFullPct:
			reason = fmt.Sprintf("it is thrashing (stalled on memory %.0f%% of the last minute)", *sample.PSIFull60)
		case sample.availPct() < memLowAvailPct:
			reason = "it is almost out of memory"
		}
		if sample.OOMKills != nil {
			m.oomKills = sample.OOMKills
		}
		m.last, m.lastAt = sample, now
	} else if m.last != nil && m.last.availPct() < memShortAvailPct {
		reason = "its machine stopped answering while short of memory"
	}
	if reason != "" {
		m.healthySince = time.Time{}
		detail := describeMem(sample)
		if detail == "" {
			detail = describeMem(m.last)
		}
		if m.alert == nil {
			m.alert = &MemAlert{Since: now, Reason: reason, Detail: detail}
			return true
		}
		m.alert.Reason, m.alert.Detail = reason, detail
		return false
	}
	if m.alert != nil && sample != nil { // healthy: the episode ends after memClear of these
		if m.healthySince.IsZero() {
			m.healthySince = now
		}
		if now.Sub(m.healthySince) >= memClear {
			m.alert, m.healthySince = nil, time.Time{}
		}
	}
	return false
}

func memMessage(name, size string, a *MemAlert) string {
	msg := fmt.Sprintf("🔴 Session “%s” is running out of memory: %s.", name, a.Reason)
	if a.Detail != "" {
		msg += " Now " + a.Detail + "."
	}
	if next := nextSize[size]; next != "" {
		return msg + fmt.Sprintf("\nOne tap moves it to %s (%d GB): the Upgrade button on its card in the Jarvis 2 app.", next, sizeGB[next])
	}
	return msg + "\nIt is already on the biggest size."
}

// memView: the session's memAlert and latest memory sample in /api/state (under the state lock)
func memView(s *Session, v map[string]any) {
	if s.Live == nil || s.Live.mem == nil || s.State != "started" || s.Live.mem.machine != s.MachineID {
		return
	}
	m := s.Live.mem
	if m.alert != nil {
		v["memAlert"] = map[string]any{"since": m.alert.Since, "reason": m.alert.Reason, "detail": m.alert.Detail, "nextSize": nextSize[s.Size]}
	}
	if m.last != nil && time.Since(m.lastAt) < memSilent {
		v["memory"] = map[string]any{"totalMb": m.last.TotalKb / 1024, "availMb": m.last.AvailKb / 1024, "at": m.lastAt}
	}
}

// memSilentTick: machines that stopped reporting (called by the autopilot tick under the state lock) → DMs
func memSilentTick(d *persisted, now time.Time) []string {
	var dms []string
	for _, s := range d.Sessions {
		if s.Live == nil || s.Live.mem == nil {
			continue
		}
		m := s.Live.mem
		if s.State != "started" || s.MachineID != m.machine {
			s.Live.mem = nil
			continue
		}
		if !m.lastAt.IsZero() && now.Sub(m.lastAt) >= memSilent && m.observe(nil, now) {
			dms = append(dms, memMessage(sessionName(s, s.Live.Reg), s.Size, m.alert))
		}
	}
	return dms
}

func (r *Router) registerMemory(app appRoute, m machineRoute) {
	m("POST /m/memory", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in MemSample
		if err := json.Unmarshal(body, &in); err != nil || in.TotalKb <= 0 || in.AvailKb < 0 || len(in.Top) > 10 {
			writeJSON(w, 400, map[string]string{"error": "bad memory sample"})
			return
		}
		dm := ""
		r.st.Do(func(d *persisted) {
			s := d.Sessions[d.Machines[machine]]
			if s == nil || s.MachineID != machine {
				return
			}
			if s.Live == nil {
				s.Live = &Liveness{}
			}
			if s.Live.mem == nil || s.Live.mem.machine != machine {
				s.Live.mem = &memState{machine: machine}
			}
			if s.Live.mem.observe(&in, time.Now().UTC()) {
				dm = memMessage(sessionName(s, s.Live.Reg), s.Size, s.Live.mem.alert)
			}
		})
		if dm != "" {
			log.Printf("[memory] %s", dm)
			r.DM(dm)
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/upgrade", func(w http.ResponseWriter, req *http.Request) {
		out, err := r.Upgrade(req.PathValue("id"))
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
}

// Upgrade: free the machine's memory, pause (its signed snapshot), resume on the next size, then tell the
// session what happened
func (r *Router) Upgrade(id string) (map[string]any, error) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, errNoSession
	}
	if s.State != "started" || s.MachineID == "" {
		return nil, fmt.Errorf("session is %s, not running", s.State) // "session is …" → 409
	}
	from := s.Size
	if from == "" {
		from = "medium"
	}
	to := nextSize[s.Size]
	if to == "" {
		return nil, fmt.Errorf("session is already on the biggest size (%s)", from)
	}
	// the whole job is one tracked lifecycle action (drain.go): its pause and resume go on during a drain
	endJob, err := r.beginJob(id, "upgrade")
	if err != nil {
		return nil, err
	}
	j, err := r.ops.startJob(id, "upgrade")
	if err != nil {
		endJob()
		return nil, err
	}
	r.ops.setBusy(id, "upgrading")
	go func() {
		defer endJob()
		defer r.ops.setBusy(id, "")
		fail := func(err error) {
			log.Printf("[memory] upgrade of %s failed: %v", id, err)
			r.ops.phase(j, "failed", err)
		}
		r.ops.phase(j, "freeing", nil)
		r.out(s.MachineID).word("free")
		time.Sleep(memFreeWait)
		r.ops.phase(j, "snapshotting", nil)
		if err := r.Pause(id); err != nil {
			fail(err)
			return
		}
		if err := r.waitState(id, "paused", r.cfg.SnapshotWait+3*time.Minute); err != nil {
			fail(err)
			return
		}
		if err := r.applyResumeOptions(id, ResumeOptions{Size: to}); err != nil {
			fail(err)
			return
		}
		r.ops.phase(j, "resuming", nil)
		if err := r.Resume(id, ResumeIn{}); err != nil {
			fail(err)
			return
		}
		r.ops.phase(j, "done", nil)
		log.Printf("[memory] %s upgraded %s → %s", id, from, to)
		if err := deliverNoticeHook(r, id, Notice{Kind: "upgraded", From: from, To: to}, false); err != nil {
			log.Printf("[memory] telling %s about its upgrade: %v", id, err)
		}
	}()
	return map[string]any{"started": true, "kind": "upgrade", "from": from, "to": to}, nil
}
