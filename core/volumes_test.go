package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// volFly: the tests' fake Fly with volumes (volumes.go)
type volFly struct {
	*fakeFly
	n         int
	vols      map[string]*fakeVol
	mounts    map[string]string // machine → volume
	stopSlow  bool              // a stop leaves the machine "stopping"
	snapFail  bool              // the next snapshot comes out failed
	calls     []string
	clock     func() time.Time
	createErr error
}

type fakeVol struct {
	size      int
	retention int
	deleted   bool
	snaps     []VolumeSnapshot
}

func withVolumes(c *Core, f *fakeFly) *volFly {
	v := &volFly{fakeFly: f, vols: map[string]*fakeVol{}, mounts: map[string]string{}, clock: c.now}
	c.fly = v
	return v
}

func (v *volFly) log(s string, a ...any) { v.calls = append(v.calls, fmt.Sprintf(s, a...)) }

func (v *volFly) CreateVolume(region string, sizeGB, retention int) (string, error) {
	v.n++
	id := fmt.Sprintf("vol_%d", v.n)
	v.vols[id] = &fakeVol{size: sizeGB, retention: retention}
	v.log("create-volume %s %d", id, sizeGB)
	return id, nil
}
func (v *volFly) CreateWithVolume(r StartRequest, guest map[string]any, env map[string]string, volume, path string) (string, error) {
	if v.createErr != nil {
		return "", v.createErr
	}
	id, err := v.fakeFly.Create(r, guest, env)
	v.mounts[id] = volume + ":" + path
	return id, err
}
func (v *volFly) Stop(id string) error {
	v.log("stop %s", id)
	if v.stopSlow {
		v.machines[id].state = "stopping"
	} else {
		v.machines[id].state = "stopped"
	}
	return nil
}
func (v *volFly) SetRetention(vol string, days int) error {
	v.vols[vol].retention = days
	v.log("retention %s %d", vol, days)
	return nil
}
func (v *volFly) CreateSnapshot(vol string) error {
	fv := v.vols[vol]
	st := "running"
	if v.snapFail {
		st, v.snapFail = "failed", false
	}
	fv.snaps = append(fv.snaps, VolumeSnapshot{ID: fmt.Sprintf("vs_%s_%d", vol, len(fv.snaps)+1), Status: st, Size: 123, CreatedAt: v.clock()})
	v.log("snapshot %s", vol)
	return nil
}
func (v *volFly) Snapshots(vol string) ([]VolumeSnapshot, error) {
	return append([]VolumeSnapshot{}, v.vols[vol].snaps...), nil
}
func (v *volFly) finishSnapshots(vol string) {
	for i := range v.vols[vol].snaps {
		if v.vols[vol].snaps[i].Status == "running" {
			v.vols[vol].snaps[i].Status = "created"
		}
	}
}
func (v *volFly) ExtendVolume(vol string, size int) (bool, error) {
	v.vols[vol].size = size
	v.log("extend %s %d", vol, size)
	return true, nil
}
func (v *volFly) DeleteVolume(vol string) error {
	if fv := v.vols[vol]; fv != nil {
		fv.deleted = true
	}
	v.log("delete-volume %s", vol)
	return nil
}
func (v *volFly) Destroy(id string) error {
	v.log("destroy %s", id)
	return v.fakeFly.Destroy(id)
}

func volumeOf(t *testing.T, v *volFly, machine string) string {
	t.Helper()
	vol, _, _ := strings.Cut(v.mounts[machine], ":")
	if vol == "" {
		t.Fatalf("machine %s has no volume", machine)
	}
	return vol
}

func status(err error) int {
	if e, ok := err.(*Err); ok {
		return e.Status
	}
	return 0
}

// every machine gets its own new, empty volume at /data, named in its cert; the size is the router's ask
func TestAStartMakesTheMachinesOwnVolume(t *testing.T) {
	c, f, p := setup(t)
	v := withVolumes(c, f)
	d, id := newLine(t, c, p, "default")
	vol := volumeOf(t, v, id)
	if v.mounts[id] != vol+":/data" || v.vols[vol].size != defaultDiskGB || v.vols[vol].retention != backupRetentionDays {
		t.Fatalf("volume %s %+v", v.mounts[id], v.vols[vol])
	}
	cert := certOf(t, d)
	if cert.Machine.Volume == nil || cert.Machine.Volume.ID != vol || cert.Machine.Volume.Path != "/data" || cert.Machine.Volume.SizeGB != defaultDiskGB {
		t.Fatalf("the cert names %+v", cert.Machine.Volume)
	}
	created := pl(t)(c.Start(StartRequest{Image: img, Region: "lhr", Size: "large", DiskGB: 40}))
	if vv, _ := created["volume"].(map[string]any); vv == nil || vv["sizeGb"] != float64(40) {
		t.Fatalf("created %v", created)
	}
	if _, err := c.Start(StartRequest{Image: img, Region: "lhr", Size: "large", DiskGB: maxDiskGB + 1}); status(err) != 400 {
		t.Fatalf("a %d GB disk: %v", maxDiskGB+1, err)
	}
	// a machine Fly can't make leaves no volume behind
	v.createErr = fmt.Errorf("no capacity")
	before := len(v.vols)
	if _, err := c.Start(StartRequest{Image: img, Region: "lhr", Size: "large"}); err == nil {
		t.Fatal("started anyway")
	}
	if len(v.vols) != before+1 || !v.vols[fmt.Sprintf("vol_%d", v.n)].deleted {
		t.Fatal("the failed start's volume wasn't deleted")
	}
}

// the kill: stop, the volume's snapshot, and only once Fly reports it created the destroy and the volume's delete;
// the signed record names the backup
func TestAKillBacksTheVolumeUpBeforeDestroying(t *testing.T) {
	c, f, p := setup(t)
	v := withVolumes(c, f)
	_, id := newLine(t, c, p, "default")
	vol := volumeOf(t, v, id)
	sum := strings.Repeat("ab", 32)
	claim := &SnapshotClaim{Sha256: sum, Sig: machineSign(f.machines[id].sig, sum)}

	v.stopSlow = true
	if _, err := c.KillWithSnapshot(id, claim); status(err) != 409 || !strings.Contains(err.Error(), "stopping") {
		t.Fatalf("stopping: %v", err)
	}
	v.stopSlow = false
	if _, err := c.KillWithSnapshot(id, claim); status(err) != 409 || !strings.Contains(err.Error(), "asked for") {
		t.Fatalf("snapshot asked: %v", err)
	}
	if _, err := c.KillWithSnapshot(id, claim); status(err) != 409 || !strings.Contains(err.Error(), "running") {
		t.Fatalf("snapshot running: %v", err)
	}
	if f.machines[id].destroyed || v.vols[vol].deleted || c.isKilled(id) {
		t.Fatal("destroyed before the backup was created")
	}
	v.finishSnapshots(vol)
	k := pl(t)(c.KillWithSnapshot(id, claim))
	b, _ := k["backup"].(map[string]any)
	if k["snapshot"] != sum || b == nil || b["volume"] != vol || b["snapshot"] != "vs_"+vol+"_1" || b["retentionDays"] != float64(backupRetentionDays) || b["signedSnapshot"] != true {
		t.Fatalf("record %v", k)
	}
	if !f.machines[id].destroyed || !v.vols[vol].deleted {
		t.Fatal("machine or volume left")
	}
	want := []string{"stop " + id, "snapshot " + vol, "destroy " + id, "delete-volume " + vol}
	got := []string{}
	for _, x := range v.calls {
		for _, w := range want {
			if x == w && (len(got) == 0 || got[len(got)-1] != x) {
				got = append(got, x)
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order %v", v.calls)
	}
	if k2 := pl(t)(c.KillWithSnapshot(id, nil)); k2["backup"] == nil {
		t.Fatal("asked again: the backup is gone from the record")
	}
}

// without the machine's own snapshot the backup is the only copy: Fly's longest retention, set before the snapshot;
// a failed snapshot destroys nothing and is asked for again
func TestABackupWithoutTheMachinesSnapshotIsKeptLongest(t *testing.T) {
	c, f, p := setup(t)
	v := withVolumes(c, f)
	_, id := newLine(t, c, p, "default")
	vol := volumeOf(t, v, id)
	v.snapFail = true
	c.KillWithSnapshot(id, nil) // stop + ask
	if _, err := c.KillWithSnapshot(id, nil); status(err) != 502 {
		t.Fatalf("a failed snapshot: %v", err)
	}
	if f.machines[id].destroyed {
		t.Fatal("destroyed after a failed backup")
	}
	c.KillWithSnapshot(id, nil) // asked again
	v.finishSnapshots(vol)
	k := pl(t)(c.KillWithSnapshot(id, nil))
	b, _ := k["backup"].(map[string]any)
	if b == nil || b["retentionDays"] != float64(noSnapshotRetentionDays) || b["signedSnapshot"] != false || v.vols[vol].retention != noSnapshotRetentionDays {
		t.Fatalf("record %v, volume %+v", k, v.vols[vol])
	}
	if k["snapshot"] != "" {
		t.Fatalf("a snapshot named: %v", k)
	}
}

// a machine that never got a cert never held a session's state: no backup, its volume just goes
func TestAnUncertifiedMachineHasNoBackup(t *testing.T) {
	c, f, _ := setup(t)
	v := withVolumes(c, f)
	created := pl(t)(c.Start(StartRequest{Image: img, Region: "lhr", Size: "large"}))
	id := created["id"].(string)
	pl(t)(c.Init(id))
	k := pl(t)(c.KillWithSnapshot(id, nil))
	if k["backup"] != nil || !v.vols[volumeOf(t, v, id)].deleted {
		t.Fatalf("record %v", k)
	}
	for _, x := range v.calls {
		if strings.HasPrefix(x, "snapshot") || strings.HasPrefix(x, "stop") {
			t.Fatalf("backed up: %v", v.calls)
		}
	}
}

// More disk: only growth, only a live machine's own volume; a Fly without volumes says so
func TestExtendGrowsTheLiveVolumeOnly(t *testing.T) {
	c, f, p := setup(t)
	if _, err := c.Extend("m1", 20); status(err) != 501 {
		t.Fatalf("no volumes: %v", err)
	}
	v := withVolumes(c, f)
	_, id := newLine(t, c, p, "default")
	vol := volumeOf(t, v, id)
	if _, err := c.Extend(id, defaultDiskGB); status(err) != 400 {
		t.Fatalf("no growth: %v", err)
	}
	d := pl(t)(c.Extend(id, 20))
	if d["kind"] != "extended" || d["sizeGb"] != float64(20) || d["needsRestart"] != true || v.vols[vol].size != 20 {
		t.Fatalf("extend %v", d)
	}
	if _, err := c.Extend("nope", 40); status(err) != 409 {
		t.Fatalf("another machine: %v", err)
	}
}

// a core that takes the line over (continuity.go) knows the live machines' volumes and the kills' backups
func TestTheLineStateCarriesVolumesAndBackups(t *testing.T) {
	c, f, p := setup(t)
	v := withVolumes(c, f)
	_, a := newLine(t, c, p, "default")
	_, b := newLine(t, c, p, "default")
	c.KillWithSnapshot(b, nil)
	c.KillWithSnapshot(b, nil)
	v.finishSnapshots(volumeOf(t, v, b))
	pl(t)(c.KillWithSnapshot(b, nil))
	c.mu.Lock()
	st := c.lineSnapshot()
	c.mu.Unlock()
	raw, _ := json.Marshal(st)
	var back lineState
	json.Unmarshal(raw, &back)
	c2, _, _ := newCore(t)
	c2.mu.Lock()
	c2.restoreLine(back, false)
	c2.mu.Unlock()
	if c2.vol.live[a] == nil || c2.vol.live[a].ID != volumeOf(t, v, a) || c2.vol.backups[b] == nil || c2.vol.backups[b].Snapshot == "" {
		t.Fatalf("live %v backups %v", c2.vol.live, c2.vol.backups)
	}
}
