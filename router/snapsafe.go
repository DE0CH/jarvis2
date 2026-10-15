package main

// A pause never loses a session's state (2026-10-15: session sb8e0273d6c308894's final snapshot failed with "no space
// left on device", the machine was destroyed anyway and the resume started with an empty conversation).
//
//   - The machine's final snapshot streams to the router (snapstream.go): it needs no free disk on the machine.
//   - A machine whose final snapshot fails (an error, the wait running out, a machine that went silent) and that has
//     no volume is KEPT, never destroyed: the session goes "failed" with snapshotFailed set, and Deyao gets a "needs
//     you" DM. Pause again retries; Destroy anyway (force) goes on without it.
//   - A machine with a volume (a core with volumes, core/volumes.go) goes on to the kill: the core stops it, takes the
//     volume's backup snapshot and destroys it only once that exists. The kill's signed record names the backup; the
//     session lists it (backups) for recovery by hand. No resume or restore reads a backup (Deyao, 2026-10-15).
//   - A line whose last machine left no signed snapshot (while an earlier machine of it did, or it had booted) is
//     marked noSnapshot: Resume refuses (it would start the session empty), says why on the session, and Deyao gets a
//     DM naming the backup. Destroy still archives the newest signed snapshot it has.
//   - A kill that doesn't finish (the core still can't destroy it after killMax) leaves the session failed with its
//     machine, and DMs too.

import (
	"fmt"
	"log"
	"time"
)

// Volume: a machine's Fly volume as the core's started document names it (core/volumes.go VolumeInfo)
type Volume struct {
	ID     string `json:"id"`
	SizeGB int    `json:"sizeGb"`
	Path   string `json:"path"`
}

// Backup: a kill's volume backup (core/volumes.go Backup), with the machine it came from
type Backup struct {
	Machine       string    `json:"machine"`
	Volume        string    `json:"volume"`
	Snapshot      string    `json:"snapshot"`
	At            time.Time `json:"at"`
	RetentionDays int       `json:"retentionDays"`
	ExpiresAt     time.Time `json:"expiresAt"`
	SizeBytes     int64     `json:"sizeBytes,omitempty"`
	Signed        bool      `json:"signedSnapshot"` // the machine signed its own snapshot too
}

const maxBackupsKept = 20

// machineVolume: the volume the machine's cert names (nil: a machine of a core without volumes)
func (r *Router) machineVolume(machine string) *Volume {
	var cert *Doc
	var st *Started
	r.st.Do(func(d *persisted) { cert, st = d.Certs[machine], d.Started[machine] })
	if cert != nil {
		var c struct {
			Machine *struct {
				Volume *Volume `json:"volume"`
			} `json:"machine"`
		}
		if cert.Decode(&c) == nil && c.Machine != nil && c.Machine.Volume != nil {
			return c.Machine.Volume
		}
	}
	if st != nil {
		return st.Volume
	}
	return nil
}

// finalSnapshotAndKill: a pause's or destroy's end of a running machine. false: the machine is still there (kept
// after a failed snapshot, or a kill that didn't finish), the session failed with the reason, Deyao DMed.
func (r *Router) finalSnapshotAndKill(id, machine string, force bool) bool {
	return r.finalSnapshotAndKillFor(id, machine, false, force)
}

// finalSnapshotAndKillFor: destroying = a destroy's (archive.go snapshotAndKill: its kill falls back, DECISIONS 181)
func (r *Router) finalSnapshotAndKillFor(id, machine string, destroying, force bool) bool {
	serr := r.lastSnapshot(id, machine)
	vol := r.machineVolume(machine)
	if serr != nil && vol == nil && !force {
		r.keepMachine(id, machine, serr)
		return false
	}
	if serr != nil {
		log.Printf("session %s: %s's final snapshot: %v; going on (%s)", id, machine, serr, map[bool]string{true: "its volume is backed up first", false: "destroy anyway"}[vol != nil])
	}
	if vol != nil {
		r.setWaiting(id, "stopping the machine and taking its volume's backup snapshot (up to "+waitText(killMax)+")")
	}
	kd, err := r.killMachine(machine) // vouch.go: with the snapshot's hash
	if err != nil && destroying {
		kd, err = r.destroyKillFallback(id, machine, force, err)
	}
	r.setWaiting(id, "")
	if err != nil {
		r.killFailed(id, machine, vol != nil, err)
		if destroying {
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[id]; s != nil {
					s.Error += destroyAnywayHint
				}
			})
		}
		return false
	}
	r.recordKill(id, machine, kd, serr)
	return true
}

func (r *Router) dmName(id string) string {
	name := id
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil {
			var g *Registry
			if s.Live != nil {
				g = s.Live.Reg
			}
			name = sessionName(s, g)
		}
	})
	return name
}

// keepMachine: the final snapshot failed and the machine has no volume: it stays, so nothing is lost
func (r *Router) keepMachine(id, machine string, serr error) {
	msg := fmt.Sprintf("the final snapshot failed (%v): its machine %s is kept, nothing is lost. Pause again once it can snapshot, or Destroy anyway (that drops what changed since its last snapshot)", serr, machine)
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil {
			s.State, s.Error, s.SnapshotFailed = "failed", msg, serr.Error()
		}
	})
	log.Printf("session %s: %s", id, msg)
	r.DM(fmt.Sprintf("🔴 Session “%s” needs you — its final snapshot failed (%v), so its machine was kept instead of destroyed: nothing is lost. Free what blocks it (or give it more disk), then Pause again; Destroy anyway drops what changed since its last snapshot.", r.dmName(id), serr))
}

// killFailed: the core still refuses or can't finish the kill: the machine (with its volume) stays
func (r *Router) killFailed(id, machine string, hasVolume bool, err error) {
	what := "its machine is kept"
	if hasVolume {
		what = "its machine (perhaps stopped) and its volume are kept"
	}
	r.setState(id, "failed", "kill: "+err.Error()+" — "+what+": Pause again to retry")
	r.DM(fmt.Sprintf("🔴 Session “%s” needs you — its pause couldn't finish (%v); %s, nothing was destroyed. Pause it again to retry.", r.dmName(id), err, what))
}

// recordKill: the kill's record — the backup goes on the session's list; a kill that names no snapshot of a line
// that had state marks it noSnapshot (Resume refuses) and DMs
func (r *Router) recordKill(id, machine string, kd *Doc, serr error) {
	var k struct {
		Snapshot string `json:"snapshot"`
		Backup   *struct {
			Volume        string    `json:"volume"`
			Snapshot      string    `json:"snapshot"`
			At            time.Time `json:"at"`
			RetentionDays int       `json:"retentionDays"`
			SizeBytes     int64     `json:"sizeBytes"`
			Signed        bool      `json:"signedSnapshot"`
		} `json:"backup"`
	}
	if kd != nil {
		kd.Decode(&k)
	}
	var b *Backup
	if k.Backup != nil && k.Backup.Snapshot != "" {
		x := k.Backup
		b = &Backup{Machine: machine, Volume: x.Volume, Snapshot: x.Snapshot, At: x.At, RetentionDays: x.RetentionDays,
			ExpiresAt: x.At.Add(time.Duration(x.RetentionDays) * 24 * time.Hour), SizeBytes: x.SizeBytes, Signed: x.Signed}
	}
	older, _, olderAt := r.latestSnapshot(id) // archive.go: the newest signed snapshot the router still holds
	if older == machine {
		older = ""
	}
	reason := ""
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil {
			return
		}
		s.SnapshotFailed = ""
		if b != nil {
			s.Backups = append([]Backup{*b}, s.Backups...)
			if len(s.Backups) > maxBackupsKept {
				s.Backups = s.Backups[:maxBackupsKept]
			}
		}
		if k.Snapshot != "" || (s.Booted != machine && older == "") {
			s.NoSnapshot, s.noSnapshotDMed = "", false // a snapshot, or a line with no state yet (its first machine never booted)
			return
		}
		why := "it sent none"
		if serr != nil {
			why = serr.Error()
		}
		reason = fmt.Sprintf("machine %s left no snapshot (%s)", machine, why)
		s.NoSnapshot, s.noSnapshotDMed = reason, true
	})
	if reason == "" {
		return
	}
	log.Printf("session %s: %s; it won't resume", id, reason)
	r.DM(fmt.Sprintf("🔴 Session “%s” needs you — %s, so it won't resume (it would start empty). %s", r.dmName(id), reason, stateLeft(b, older, olderAt)))
}

// stateLeft: where the session's last state is, for the DM and the refusal
func stateLeft(b *Backup, older string, olderAt time.Time) string {
	out := ""
	if b != nil {
		out = fmt.Sprintf("Its last state is in the Fly volume backup %s (volume %s, kept until %s) for recovery by hand.", b.Snapshot, b.Volume, b.ExpiresAt.Format("2006-01-02"))
	} else {
		out = "Its machine had no volume, so there is no volume backup."
	}
	if older != "" {
		out += fmt.Sprintf(" The newest signed snapshot is machine %s's from %s (Destroy archives it).", older, olderAt.UTC().Format("2006-01-02 15:04 UTC"))
	}
	return out
}

// resumeRefusal: nil, or why Resume won't start the session (noSnapshot), DMed once per refusal episode
func (r *Router) resumeRefusal(id string) error {
	var reason string
	var b *Backup
	dm := false
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil || s.NoSnapshot == "" {
			return
		}
		reason = s.NoSnapshot
		if len(s.Backups) > 0 {
			x := s.Backups[0]
			b = &x
		}
		if !s.noSnapshotDMed {
			s.noSnapshotDMed, dm = true, true
		}
	})
	if reason == "" {
		return nil
	}
	older, _, olderAt := r.latestSnapshot(id)
	msg := fmt.Sprintf("session %s won't resume: its %s, so it would start empty. %s", id, reason, stateLeft(b, older, olderAt))
	if dm {
		r.DM("🔴 Session “" + r.dmName(id) + "” needs you — a resume was refused: " + msg)
	}
	return fmt.Errorf("%s", msg)
}

// backupsView: the session's backups in /api/state and the records
func backupsView(s *Session, v map[string]any) {
	v["backups"] = orEmptyBackups(s.Backups)
	v["noSnapshot"] = nullIfEmpty(s.NoSnapshot)
	v["snapshotFailed"] = nullIfEmpty(s.SnapshotFailed)
}

func orEmptyBackups(b []Backup) []Backup {
	if b == nil {
		return []Backup{}
	}
	return b
}

// destroyKillFallback: a destroy's kill that failed (DECISIONS 181). A refused snapshot claim (a machine from an
// earlier core: this core has no key for it) is killed without the claim, the session marked so its archive says
// so; a kill still failing is no obstacle when Fly no longer has the machine, or with force (the router stops taking
// the machine's calls; it is an orphan on the Machines tab, whose Destroy tries the kill again)
func (r *Router) destroyKillFallback(id, machine string, force bool, err error) (*Doc, error) {
	var kd *Doc
	if refusedSnapshot(err) {
		log.Printf("session %s: the core refused %s's snapshot (%v): killed without it (a destroy restores nothing)", id, machine, err)
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.SnapshotNote = snapshotFromEarlierCore
			}
		})
		if kd, err = r.killUntilDestroyed(map[string]any{"machine": machine}); err == nil {
			return kd, nil
		}
	}
	gone, ferr := flyMachineGone(machine)
	switch {
	case ferr == nil && gone:
		log.Printf("session %s: the kill of %s failed (%v) but Fly has no such machine: destroying on", id, machine, err)
		return nil, nil
	case force:
		log.Printf("session %s: the kill of %s failed (%v): destroyed anyway; the machine is left to the Machines tab", id, machine, err)
		r.st.Do(func(d *persisted) { delete(d.Started, machine) })
		return nil, nil
	}
	return nil, err
}
