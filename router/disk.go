package main

// Disk watch and Upgrade disk (2026-10-15: a session's work filled its machine's 8 GB root disk unnoticed, and the
// pause that followed lost everything; snapshots.go is the fix for the loss, this is the warning and the remedy).
//
// The machine reports its root disk with every memory sample (machine/memory.go: diskTotalKb, diskAvailKb, the
// filesystem that holds $HOME). Below diskLowKb or diskLowPct free, an episode starts: one DM, and the session shows
// diskAlert {since, detail, nextDiskGb} with an Upgrade disk button; it ends once the free space is back over twice
// those marks. Upgrade disk (POST /api/sessions/{id}/upgrade-disk) is a pause (its final snapshot) and a resume on
// a machine with the next disk size (16, 32, … 512 GB): Fly's rootfs.size_gb, which the core sets when it creates
// the machine (core/fly.go). A core from before disk sizes ignores it: the router notices (the created document
// names no disk) and says so instead of pretending.

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	diskLowKb  = 3 << 19 // 1.5 GiB in KiB
	diskLowPct = 10.0
)

// diskSize: a root disk size the router asks for (GB)
func diskSize(gb int) bool { return gb >= 16 && gb <= 512 && gb&(gb-1) == 0 }

// nextDisk: the disk Upgrade disk moves to: 16 GB from Fly's default (8 GB), then doubling; 0 = none bigger
func nextDisk(gb int) int {
	n := 16
	if gb >= 16 {
		n = 2 * gb
	}
	if !diskSize(n) {
		return 0
	}
	return n
}

type DiskAlert struct {
	Since  time.Time `json:"since"`
	Detail string    `json:"detail"`
}

// diskState: one machine's disk watch (in memory only, beside its memory watch)
type diskState struct {
	totalKb, availKb int64
	at               time.Time
	alert            *DiskAlert
}

func describeDisk(availKb, totalKb int64) string {
	return fmt.Sprintf("%.1f GB free of %.1f GB", float64(availKb)/1048576, float64(totalKb)/1048576)
}

// observeDisk: a sample → true when a new low-disk episode begins (DM it)
func (s *diskState) observe(totalKb, availKb int64, now time.Time) bool {
	if totalKb <= 0 || availKb < 0 {
		return false
	}
	s.totalKb, s.availKb, s.at = totalKb, availKb, now
	pct := 100 * float64(availKb) / float64(totalKb)
	if availKb < diskLowKb || pct < diskLowPct {
		detail := describeDisk(availKb, totalKb)
		if s.alert == nil {
			s.alert = &DiskAlert{Since: now, Detail: detail}
			return true
		}
		s.alert.Detail = detail
		return false
	}
	if s.alert != nil && availKb >= 2*diskLowKb && pct >= 2*diskLowPct {
		s.alert = nil
	}
	return false
}

func diskMessage(name string, gb int, a *DiskAlert) string {
	msg := fmt.Sprintf("🔴 Session “%s” is running out of disk: %s. A full disk stops its work (its pause still keeps everything).", name, a.Detail)
	if n := nextDisk(gb); n != 0 {
		msg += fmt.Sprintf("\nOne tap moves it to a machine with a %d GB disk: the Upgrade disk button on its card in the Jarvis 2 app.", n)
	}
	return msg
}

// diskView: the session's disk and diskAlert in /api/state (under the state lock)
func diskView(s *Session, v map[string]any) {
	if s.Live == nil || s.Live.disk == nil || s.State != "started" || s.Live.diskMachine != s.MachineID {
		return
	}
	d := s.Live.disk
	if d.alert != nil {
		v["diskAlert"] = map[string]any{"since": d.alert.Since, "detail": d.alert.Detail, "nextDiskGb": nextDisk(s.Disk)}
	}
	if time.Since(d.at) < memSilent {
		v["diskUsage"] = map[string]any{"totalMb": d.totalKb / 1024, "availMb": d.availKb / 1024, "at": d.at}
	}
}

// diskSample: the disk part of a memory report (under the state lock) → the DM to send, if any
func diskSample(s *Session, machine string, in MemSample, now time.Time) string {
	if in.DiskTotalKb == 0 {
		return "" // a machine image from before disk reports
	}
	if s.Live.disk == nil || s.Live.diskMachine != machine {
		s.Live.disk, s.Live.diskMachine = &diskState{}, machine
	}
	if s.Live.disk.observe(in.DiskTotalKb, in.DiskAvailKb, now) {
		return diskMessage(sessionName(s, s.Live.Reg), s.Disk, s.Live.disk.alert)
	}
	return ""
}

// diskRefused: the live core created a machine without the disk asked for (a core from before disk sizes)
var diskRefused atomic.Bool

func (r *Router) noteDiskAnswer(asked, got int) {
	if asked == 0 {
		return
	}
	if got != asked {
		diskRefused.Store(true)
		log.Printf("[disk] asked the core for a %d GB disk; it created the machine with Fly's default (a core from before disk sizes)", asked)
		return
	}
	diskRefused.Store(false)
}

func (r *Router) registerDisk(app appRoute) {
	app("POST /api/sessions/{id}/upgrade-disk", func(w http.ResponseWriter, req *http.Request) {
		out, err := r.UpgradeDisk(req.PathValue("id"))
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
}

// UpgradeDisk: pause (the final snapshot), then resume on the next disk size; the session comes back on its old
// disk when the start on the bigger one fails
func (r *Router) UpgradeDisk(id string) (map[string]any, error) {
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
	from, to := s.Disk, nextDisk(s.Disk)
	if to == 0 {
		return nil, bad("the session already has the biggest disk (%d GB)", from)
	}
	endJob, err := r.beginJob(id, "upgrade-disk")
	if err != nil {
		return nil, err
	}
	j, err := r.ops.startJob(id, "upgrade-disk")
	if err != nil {
		endJob()
		return nil, err
	}
	r.ops.setBusy(id, "upgrading disk")
	go func() {
		defer endJob()
		defer r.ops.setBusy(id, "")
		fail := func(err error) {
			log.Printf("[disk] upgrade of %s failed: %v", id, err)
			r.ops.phase(j, "failed", err)
		}
		r.ops.phase(j, "snapshotting", nil)
		if err := r.Pause(id); err != nil {
			fail(err)
			return
		}
		if err := r.waitState(id, "paused", r.cfg.SnapshotWait+3*time.Minute); err != nil {
			fail(err)
			return
		}
		r.ops.phase(j, "resuming", nil)
		setDisk := func(gb int) {
			r.st.Do(func(d *persisted) {
				if x := d.Sessions[id]; x != nil {
					x.Disk = gb
				}
			})
		}
		setDisk(to)
		if err := r.resumeWithPrompt(id, false, ""); err != nil {
			setDisk(from)
			fail(err)
			return
		}
		if msg := r.waitStartOutcome(id, upgradeStartWait); msg != "" {
			setDisk(from)
			if err := r.resumeOnSize(id, s.Size); err != nil {
				fail(fmt.Errorf("%d GB disk: %s; resuming it on its old disk failed too: %v", to, msg, err))
				return
			}
			fail(fmt.Errorf("%d GB disk: %s; it is back on its old disk", to, msg))
			return
		}
		if diskRefused.Load() {
			setDisk(from)
			fail(fmt.Errorf("the live core created the machine with Fly's default disk: bigger disks need the core release that waits for Deyao's go"))
			return
		}
		r.ops.phase(j, "done", nil)
		log.Printf("[disk] %s moved to a %d GB disk", id, to)
	}()
	return map[string]any{"started": true, "kind": "upgrade-disk", "fromGb": from, "toGb": to}, nil
}
