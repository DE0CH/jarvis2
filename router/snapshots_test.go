package main

// 2026-10-15 (session sb8e0273d6c308894): a restart paused a session whose work had filled its machine's root disk;
// the snapshot couldn't be written, the router killed the machine anyway, and the resume started empty. These tests
// attempt each step of that again.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// streamTo: POST /m/snapshot/stream as the machine sends it (signed over "stream", no Content-Length)
func (m testMachine) streamTo(t *testing.T, r *Router, body string, signedOver string) (int, map[string]any) {
	t.Helper()
	q := httptest.NewRequest("POST", "/m/snapshot/stream", strings.NewReader(body))
	q.ContentLength = -1
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig, _ := signP256(m.key, []byte("POST /m/snapshot/stream "+ts+" "+signedOver))
	q.Header.Set("X-Machine", m.id)
	q.Header.Set("X-Time", ts)
	q.Header.Set("X-Sig", sig)
	w := httptest.NewRecorder()
	r.MachineHandler().ServeHTTP(w, q)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (m testMachine) commit(t *testing.T, r *Router, sum string) int {
	t.Helper()
	sig, _ := signP256(m.key, []byte(sum))
	b, _ := json.Marshal(map[string]string{"sha256": sum, "sig": sig})
	code, _ := m.do(t, r.MachineHandler(), "POST", "/m/snapshot/commit", string(b))
	return code
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestASnapshotStreamsThenCommits(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	body := strings.Repeat("snapshot bytes ", 5000)
	// signed over anything but "stream": refused before a byte is kept
	if code, _ := m.streamTo(t, r, body, sha(body)); code != 401 {
		t.Fatalf("a stream signed over a hash: %d", code)
	}
	code, out := m.streamTo(t, r, body, streamedBody)
	if code != 200 || out["sha256"] != sha(body) || int(out["size"].(float64)) != len(body) {
		t.Fatalf("%d %v", code, out)
	}
	if r.hasFinalSnapshot("mA") {
		t.Fatal("streamed bytes count as the final snapshot before the machine committed them")
	}
	if code := m.commit(t, r, sha("other bytes")); code != 404 {
		t.Fatalf("a commit of bytes that weren't streamed: %d", code)
	}
	other := newTestMachine(r, "mX")
	sig, _ := signP256(other.key, []byte(sha(body)))
	b, _ := json.Marshal(map[string]string{"sha256": sha(body), "sig": sig})
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/snapshot/commit", string(b)); code != 403 {
		t.Fatalf("a commit signed by another machine's key: %d", code)
	}
	if code := m.commit(t, r, sha(body)); code != 200 {
		t.Fatalf("commit: %d", code)
	}
	if got, _ := os.ReadFile(r.st.snapshotPath("mA")); string(got) != body || !r.hasFinalSnapshot("mA") {
		t.Fatal("the committed snapshot isn't in place")
	}
	if code := m.commit(t, r, sha(body)); code != 200 { // asked twice: the same one again
		t.Fatalf("commit again: %d", code)
	}
}

// heldRig: s1 runs on m2 (resumed from m1, whose snapshot the rig wrote), booted and reporting
func heldRig(t *testing.T) (*rig, *v2Core, testMachine, *[]string) {
	rg, vc := v2Rig(t)
	rg.r.cfg.SnapshotWait = 2 * time.Second
	m := newTestMachine(rg.r, "m2")
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Booted, s.Cert, s.Label = "started", "m2", "m2", v2Cert(rg, "m2", `{"v":1}`), "k-matrix clone"
		s.Live = &Liveness{LastReport: time.Now()}
		d.Machines["m2"] = "s1"
		d.Certs["m2"] = s.Cert
	})
	var mu sync.Mutex
	dms := []string{}
	old := dmHook
	dmHook = func(s string) { mu.Lock(); dms = append(dms, s); mu.Unlock() }
	t.Cleanup(func() { dmHook = old })
	return rg, vc, m, &dms
}

func kills(vc *v2Core) []map[string]any {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return append([]map[string]any(nil), vc.bodies["/kill"]...)
}

// answer: the machine's agent, answering the next snapshot command with fn
func answer(rg *rig, machine string, fn func()) {
	go func() {
		for i := 0; i < 400; i++ {
			rg.r.cmdMu.Lock()
			waiting := rg.r.snapped[machine] != nil
			rg.r.cmdMu.Unlock()
			if waiting {
				fn()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

func TestAFailedFinalSnapshotHoldsTheMachine(t *testing.T) {
	rg, vc, m, dms := heldRig(t)
	r := rg.r
	// the machine's disk is full: its snapshot fails, and it says so
	answer(rg, "m2", func() {
		m.do(t, r.MachineHandler(), "POST", "/m/snapshot/failed", `{"error":"write /run/jarvis2/final-snapshot.tar.gz: no space left on device"}`)
	})
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	err := r.waitState("s1", "paused", 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "no space left on device") {
		t.Fatalf("the pause went on: %v", err)
	}
	if k := kills(vc); len(k) != 0 {
		t.Fatalf("the machine was killed without its snapshot: %v", k)
	}
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	if s.MachineID != "m2" || s.Held == nil || s.Held.Machine != "m2" || s.Held.For != "pause" || !strings.Contains(s.Held.Reason, "no space left") {
		t.Fatalf("not held: %+v %+v", s, s.Held)
	}
	if len(*dms) != 1 || !strings.Contains((*dms)[0], "needs you") || !strings.Contains((*dms)[0], "no space left on device") || !strings.Contains((*dms)[0], "k-matrix clone") {
		t.Fatalf("DMs %v", *dms)
	}
	// /api/state shows it
	r.st.Do(func(d *persisted) {
		if v := sessionView(d.Sessions["s1"], d); v["held"] == nil {
			t.Error("held isn't in the session's view")
		}
	})

	// a destroy (even forced past an archive failure) and a session's own actions don't kill it either
	answer(rg, "m2", func() {
		m.do(t, r.MachineHandler(), "POST", "/m/snapshot/failed", `{"error":"still full"}`)
	})
	if err := r.DestroyWith("s1", true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "held again", func() bool {
		var st string
		r.st.Do(func(d *persisted) { st = d.Sessions["s1"].State })
		return st == "failed"
	})
	if k := kills(vc); len(k) != 0 {
		t.Fatalf("a forced destroy killed the held machine: %v", k)
	}

	// pausing again retries: this time the snapshot arrives, and the kill names it
	body := "the session's files"
	answer(rg, "m2", func() {
		m.streamTo(t, r, body, streamedBody)
		m.commit(t, r, sha(body))
	})
	waitFor(t, "unlocked", func() bool {
		u, err := r.lock("s1", "t")
		if err == nil {
			u()
		}
		return err == nil
	})
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	k := kills(vc)
	if len(k) != 1 {
		t.Fatalf("kills %v", k)
	}
	snap, _ := k[0]["snapshot"].(map[string]any)
	if snap == nil || snap["sha256"] != sha(body) {
		t.Fatalf("the kill doesn't name the snapshot: %v", k[0])
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions["s1"]; s.Held != nil || s.MachineID != "" {
			t.Errorf("still held: %+v", s)
		}
	})
}

func TestASnapshotThatNeverComesHoldsTheMachine(t *testing.T) {
	rg, vc, _, dms := heldRig(t)
	r := rg.r
	r.cfg.SnapshotWait, r.cfg.NoAccess = 300*time.Millisecond, true
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := r.waitState("s1", "paused", 5*time.Second); err == nil || !strings.Contains(err.Error(), "no final snapshot arrived") {
		t.Fatalf("%v", err)
	}
	if len(kills(vc)) != 0 || len(*dms) != 1 {
		t.Fatalf("kills %v, DMs %v", kills(vc), *dms)
	}
	// Deyao's explicit choice: pause without the snapshot
	waitFor(t, "unlocked", func() bool {
		u, err := r.lock("s1", "t")
		if err == nil {
			u()
		}
		return err == nil
	})
	code, out := appDo(t, r, "POST", "/api/sessions/s1/pause?withoutSnapshot=1", "")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if k := kills(vc); len(k) != 1 || k[0]["snapshot"] != nil {
		t.Fatalf("kills %v", k)
	}
}

// a machine still booting that restored its predecessor's snapshot answers with it: its kill names those bytes
func TestABootingMachineKeepsItsPredecessorsSnapshot(t *testing.T) {
	rg, vc, m, _ := heldRig(t)
	r := rg.r
	predSum, _, _ := fileSha256(r.st.snapshotPath("m1"))
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.Booted, s.Live = "", nil // never reported: still booting
		d.Certs["m2"] = rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m1", "line": "m1", "snapshot": predSum,
			"machine": map[string]string{"id": "m2", "signingKey": rg.mkey.pub()}})
		s.Cert = d.Certs["m2"]
	})
	answer(rg, "m2", func() {
		q := httptest.NewRequest("POST", "/m/snapshot", strings.NewReader(""))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sig, _ := signP256(m.key, []byte("POST /m/snapshot "+ts+" "+sha("")))
		ssig, _ := signP256(m.key, []byte(predSum))
		for k, v := range map[string]string{"X-Machine": "m2", "X-Time": ts, "X-Sig": sig, "X-Snapshot-None": "booting", "X-Snapshot-Same": predSum, "X-Snapshot-Sig": ssig} {
			q.Header.Set(k, v)
		}
		r.MachineHandler().ServeHTTP(httptest.NewRecorder(), q)
	})
	if err := r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	k := kills(vc)
	snap, _ := k[0]["snapshot"].(map[string]any)
	if len(k) != 1 || snap == nil || snap["sha256"] != predSum {
		t.Fatalf("the kill doesn't carry the predecessor's snapshot on: %v", k)
	}
}

// the resume after a machine that left no snapshot: the phone approves a fallback to the line's newest state, on the
// newest image; Deyao's explicit "start empty" is the only empty start
func TestAResumeWithNoSnapshotFallsBack(t *testing.T) {
	rg, vc, _, dms := heldRig(t)
	r := rg.r
	r.cfg.SessionImage = newestImage
	m1Sum, _, _ := fileSha256(r.st.snapshotPath("m1"))
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID = "paused", "" // m2 was killed without a snapshot
		s.LiveSync = &LiveSync{Signed: map[string]*LiveSigned{
			"bbbb.jsonl": {Machine: "m2", At: "1791700000", Sig: "s", Sha256: strings.Repeat("c", 64), Size: 900},
		}}
	})
	if err := r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "approval", func() bool { a = approvalOf(rg, "s1"); return a != nil })
	if vc.last("/approve/by-dead-machine") != nil {
		t.Fatal("an unattended resume with no snapshot")
	}
	req := vc.last("/succession")
	if req["image"] != newestImage {
		t.Fatalf("the fallback isn't on the newest image: %v", req["image"])
	}
	opts, _ := req["options"].(map[string]any)
	var once OnceInputs
	json.Unmarshal([]byte(opts["once"].(string)), &once)
	fb := once.Fallback
	if fb == nil || fb.Lost != "m2" || fb.Machine != "m1" || fb.Sha256 != m1Sum || len(fb.Transcripts) != 1 || fb.Transcripts[0].Name != "bbbb.jsonl" {
		t.Fatalf("once %+v / %+v", once, fb)
	}
	if !strings.Contains(once.Prompt, "left no final snapshot") || !strings.Contains(once.Prompt, "m1") {
		t.Fatalf("the prompt doesn't say so: %q", once.Prompt)
	}
	if len(*dms) != 1 || !strings.Contains((*dms)[0], "left no final snapshot") {
		t.Fatalf("DMs %v", *dms)
	}

	// Deyao chooses an empty start: the unattended resume, no fallback
	r.RejectAs(a.ID, outcomeDenied)
	if err := r.applyResumeOptions("s1", ResumeOptions{StartEmpty: true}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "unlocked", func() bool {
		u, err := r.lock("s1", "t")
		if err == nil {
			u()
		}
		return err == nil
	})
	if err := r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "dead-machine resume", func() bool { return vc.last("/approve/by-dead-machine") != nil })
}

// a line with no state at all: nothing to fall back on, so the resume is the usual one
func TestAResumeOfALineWithNoStateNeedsNoFallback(t *testing.T) {
	rg, vc, _, _ := heldRig(t)
	r := rg.r
	os.Remove(r.st.snapshotPath("m1") + ".sig")
	r.st.Do(func(d *persisted) { s := d.Sessions["s1"]; s.State, s.MachineID = "paused", "" })
	if err := r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "dead-machine resume", func() bool { return vc.last("/approve/by-dead-machine") != nil })
}
