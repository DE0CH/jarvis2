package main

// Volumes: each session machine keeps its state (the snapshot's paths: ~/workspace, ~/artifacts, the transcripts,
// ~/.claude.json, …) on a Fly volume of its own, mounted at /data (the machine bind-mounts those paths onto it). The
// core, the only holder of the Fly token, makes it with the machine and ends it with the machine's kill:
//
//   kill = (the machine's own signed snapshot, as before, or none) → stop the machine → an on-demand snapshot of the
//          volume (the backup) → only once Fly reports that snapshot "created": destroy the machine, delete the
//          volume. The kill's signed record names the backup (volume id, snapshot id, retention).
//
// The backup is data for recovery by hand (Deyao, 2026-10-15): no resume or restore reads it. A successor always gets
// a new, empty volume and its state from the predecessor's signed snapshot, exactly as before, so a volume never
// carries one line's data into another machine. Retention (DECISIONS 174): backupRetentionDays when the machine
// signed its own snapshot (the backup is a second copy), noSnapshotRetentionDays when it didn't (the backup is then
// the only copy of the machine's last state). Fly keeps a deleted volume's snapshots for their retention, reachable
// by the volume id the record names.
//
// More disk = Extend: the live machine's volume grows (Fly can't shrink one); the router asks for the size a
// successor's volume gets in each StartRequest (DiskGB).
//
// A Fly without VolumeFly (the CI fake, the tests' plain fake) makes machines without volumes: everything else is
// unchanged.

import (
	"fmt"
	"sort"
	"time"
)

const (
	volumePath              = "/data" // where the machine finds its volume (machine/volume.go)
	volumeName              = "jarvis2_state"
	defaultDiskGB           = 10  // a session's volume when the router asks for no size
	maxDiskGB               = 500 // the largest volume a start or Extend makes
	backupRetentionDays     = 3   // the backup of a machine that signed its own snapshot
	noSnapshotRetentionDays = 60  // the backup of one that didn't: Fly's longest
	backupAfterSlack        = 30 * time.Second
)

// VolumeFly: the Fly calls volumes need (FlyAPI; single calls, no waiting, like Fly)
type VolumeFly interface {
	CreateVolume(region string, sizeGB, retentionDays int) (string, error)
	CreateWithVolume(r StartRequest, guest map[string]any, env map[string]string, volume, path string) (string, error)
	Stop(machine string) error
	SetRetention(volume string, days int) error
	CreateSnapshot(volume string) error
	Snapshots(volume string) ([]VolumeSnapshot, error)
	ExtendVolume(volume string, sizeGB int) (needsRestart bool, err error)
	DeleteVolume(volume string) error
}

type VolumeSnapshot struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"` // waiting → running → created (Fly)
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// VolumeInfo: a machine's volume, in its "created" and "started" documents and so in its cert
type VolumeInfo struct {
	ID     string `json:"id"`
	SizeGB int    `json:"sizeGb"`
	Path   string `json:"path"`
}

// Backup: what a kill's signed record names
type Backup struct {
	Volume        string    `json:"volume"`
	Snapshot      string    `json:"snapshot"`
	At            time.Time `json:"at"`
	RetentionDays int       `json:"retentionDays"`
	SizeBytes     int64     `json:"sizeBytes,omitempty"`
	Signed        bool      `json:"signedSnapshot"` // the machine signed its own snapshot too
}

type killProgress struct {
	retention int       // set on the volume before the snapshot (0 = not yet)
	requested time.Time // the on-demand snapshot was asked for
}

type volState struct {
	live     map[string]*VolumeInfo   // a machine this core made → its volume (until the kill deletes it)
	backups  map[string]*Backup       // a killed machine → its backup
	progress map[string]*killProgress // a kill under way
	orphans  map[string]bool          // volumes whose delete failed: tried again at every kill
}

func newVolState() volState {
	return volState{live: map[string]*VolumeInfo{}, backups: map[string]*Backup{}, progress: map[string]*killProgress{}, orphans: map[string]bool{}}
}

func (c *Core) volumeFly() (VolumeFly, bool) {
	vf, ok := c.fly.(VolumeFly)
	return vf, ok
}

// diskSize: the volume a start makes (0 = the default)
func diskSize(gb int) (int, error) {
	switch {
	case gb == 0:
		return defaultDiskGB, nil
	case gb < 1 || gb > maxDiskGB:
		return 0, fail(400, "diskGb: 1 to %d (0 = %d)", maxDiskGB, defaultDiskGB)
	}
	return gb, nil
}

// createMachine: Start's Fly create, with a new empty volume when Fly has volumes. The volume goes again if the
// machine can't be made.
func (c *Core) createMachine(r StartRequest, guest map[string]any, env map[string]string) (string, *VolumeInfo, error) {
	vf, ok := c.volumeFly()
	if !ok {
		id, err := c.fly.Create(r, guest, env)
		return id, nil, err
	}
	gb, err := diskSize(r.DiskGB)
	if err != nil {
		return "", nil, err
	}
	vid, err := vf.CreateVolume(r.Region, gb, backupRetentionDays)
	if err != nil {
		return "", nil, fmt.Errorf("volume: %w", err)
	}
	id, err := vf.CreateWithVolume(r, guest, env, vid, volumePath)
	if err != nil {
		if derr := vf.DeleteVolume(vid); derr != nil {
			c.mu.Lock()
			c.vol.orphans[vid] = true
			c.mu.Unlock()
		}
		return "", nil, err
	}
	v := &VolumeInfo{ID: vid, SizeGB: gb, Path: volumePath}
	c.mu.Lock()
	c.vol.live[id] = v
	c.mu.Unlock()
	return id, v, nil
}

// backupVolume: the kill's first part for a machine with a volume — stop it, snapshot the volume, wait until Fly
// reports the snapshot created. nil once the backup exists (or there is nothing to back up: no volume, or a machine
// that never got a cert and so never held a session's state); 409 while a step is under way (the router asks again),
// 502 when Fly refuses one. signed: the machine signed its own snapshot (the backup's retention follows it).
func (c *Core) backupVolume(id string, signed bool) error {
	c.mu.Lock()
	v, certified := c.vol.live[id], c.latest[id] != ""
	done := c.vol.backups[id] != nil
	p := c.vol.progress[id]
	if p == nil {
		p = &killProgress{}
		c.vol.progress[id] = p
	}
	c.mu.Unlock()
	vf, ok := c.volumeFly()
	if v == nil || !ok || !certified || done {
		return nil
	}
	if p.retention == 0 {
		days := backupRetentionDays
		if !signed {
			days = noSnapshotRetentionDays // the backup is the only copy of the machine's last state
		}
		if err := vf.SetRetention(v.ID, days); err != nil {
			return fail(502, "fly volume retention: %v", err)
		}
		p.retention = days
	}
	fm, err := c.fly.Inspect(id)
	if err != nil {
		return fail(502, "fly: %v", err)
	}
	switch fm.State {
	case "stopped", "suspended", "destroyed":
	default:
		serr := vf.Stop(id)
		if fm, err = c.fly.Inspect(id); err != nil {
			return fail(502, "fly: %v", err)
		}
		if fm.State != "stopped" && fm.State != "destroyed" {
			return fail(409, "machine %s is %s, stopping it for its volume backup (stop: %v)", id, fm.State, serr)
		}
	}
	if p.requested.IsZero() {
		at := c.now().UTC()
		if err := vf.CreateSnapshot(v.ID); err != nil {
			return fail(502, "fly volume snapshot: %v", err)
		}
		p.requested = at
		c.logf("machine %s: volume %s snapshot asked for", id, v.ID)
		return fail(409, "machine %s: the volume backup snapshot was asked for", id)
	}
	snaps, err := vf.Snapshots(v.ID)
	if err != nil {
		return fail(502, "fly volume snapshots: %v", err)
	}
	s := newestSince(snaps, p.requested.Add(-backupAfterSlack))
	switch {
	case s == nil:
		return fail(409, "machine %s: waiting for the volume backup snapshot to appear", id)
	case s.Status == "created":
	case s.Status == "failed" || s.Status == "error":
		p.requested = time.Time{} // asked again on the next call
		return fail(502, "machine %s: the volume backup snapshot %s %s", id, s.ID, s.Status)
	default:
		return fail(409, "machine %s: the volume backup snapshot is %s", id, orNull(s.Status))
	}
	c.mu.Lock()
	c.vol.backups[id] = &Backup{Volume: v.ID, Snapshot: s.ID, At: s.CreatedAt.UTC(), RetentionDays: p.retention, SizeBytes: s.Size, Signed: signed}
	c.mu.Unlock()
	c.logf("machine %s: volume %s backed up as %s (%d days)", id, v.ID, s.ID, p.retention)
	return nil
}

func newestSince(snaps []VolumeSnapshot, since time.Time) *VolumeSnapshot {
	var out []VolumeSnapshot
	for _, s := range snaps {
		if !s.CreatedAt.Before(since) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return &out[0]
}

// dropVolume: after Fly confirmed the machine destroyed, its volume goes (its snapshots stay for their retention);
// a delete that fails is tried again at the next kill
func (c *Core) dropVolume(id string) {
	vf, ok := c.volumeFly()
	c.mu.Lock()
	v := c.vol.live[id]
	delete(c.vol.live, id)
	delete(c.vol.progress, id)
	todo := []string{}
	if v != nil {
		c.vol.orphans[v.ID] = true
	}
	for o := range c.vol.orphans {
		todo = append(todo, o)
	}
	c.mu.Unlock()
	if !ok {
		return
	}
	for _, vid := range todo {
		if err := vf.DeleteVolume(vid); err != nil {
			c.logf("volume %s: delete: %v (tried again at the next kill)", vid, err)
			continue
		}
		c.mu.Lock()
		delete(c.vol.orphans, vid)
		c.mu.Unlock()
	}
}

// backupOf: the killed machine's backup for its signed record (callers hold c.mu)
func (c *Core) backupOf(id string) any {
	if b := c.vol.backups[id]; b != nil {
		return b
	}
	return nil
}

// Extend: the live machine's volume grows to sizeGB (More disk). Fly says whether the machine must restart to see
// it; the router then pauses and resumes it (the successor's volume is made at the new size).
func (c *Core) Extend(id string, sizeGB int) (SignedDoc, error) {
	vf, ok := c.volumeFly()
	if !ok {
		return SignedDoc{}, fail(501, "this core's Fly has no volumes")
	}
	c.mu.Lock()
	v := c.vol.live[id]
	live := c.signing[id] != "" && !c.isKilled(id)
	var cur VolumeInfo
	if v != nil {
		cur = *v
	}
	c.mu.Unlock()
	if v == nil || !live {
		return SignedDoc{}, fail(409, "machine %s has no volume of this core", id)
	}
	if sizeGB <= cur.SizeGB || sizeGB > maxDiskGB {
		return SignedDoc{}, fail(400, "sizeGb: more than the volume's %d GB, at most %d", cur.SizeGB, maxDiskGB)
	}
	restart, err := vf.ExtendVolume(cur.ID, sizeGB)
	if err != nil {
		return SignedDoc{}, fail(502, "fly volume extend: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v := c.vol.live[id]; v != nil {
		v.SizeGB = sizeGB
	}
	c.logf("machine %s: volume %s extended to %d GB (restart: %v)", id, cur.ID, sizeGB, restart)
	return c.sign(map[string]any{"kind": "extended", "id": id, "volume": cur.ID, "sizeGb": sizeGB, "needsRestart": restart})
}
