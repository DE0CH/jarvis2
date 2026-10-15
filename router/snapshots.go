package main

// A machine's final snapshot, and what happens when it doesn't come (2026-10-15: a restart paused session
// sb8e0273d6c308894 while its work had filled the machine's 8 GB root disk; the machine couldn't write its snapshot
// to /run/jarvis2 first, the router waited it out and killed the machine anyway, and the resume started empty).
//
//   - The snapshot streams (POST /m/snapshot/stream): the machine makes it while it sends it, nothing touches its
//     disk. The router hashes it on the way onto the volume (<machine>.tar.gz.pending) and answers the hash; the
//     machine checks it, signs it, and commits it (POST /m/snapshot/commit), which puts it in place. A machine that
//     can't snapshot says so with the reason (POST /m/snapshot/failed).
//   - A machine whose final snapshot fails or doesn't arrive is never killed: it is HELD (Session.Held, state
//     failed, the reason in the app and a "needs you" DM). Pausing it again retries; only Deyao's explicit
//     "without the snapshot" (POST /api/sessions/{id}/pause?withoutSnapshot=1, or destroy?withoutSnapshot=1) kills it
//     anyway. A session's own actions can't ask for that.
//   - A machine that never got past boot has nothing of its own; one that restored its predecessor's snapshot
//     answers with that snapshot (X-Snapshot-Same, signed by itself), so its kill names those bytes and the line
//     keeps them.
//   - A resume whose predecessor left no snapshot never starts empty by itself when the line had state: it becomes the
//     phone's approval of a fallback (fallback.go).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// HeldMachine: a session's machine kept because its final snapshot failed or didn't arrive
type HeldMachine struct {
	Machine string    `json:"machine"`
	Since   time.Time `json:"since"`
	For     string    `json:"for"` // pause | destroy
	Reason  string    `json:"reason"`
}

// snapResult: what a machine answered to a snapshot command
type snapResult struct {
	err string // "" = a snapshot (or "nothing to snapshot") arrived
}

// bootSnapshotWait: how long a machine that never got past boot gets to answer (it answers at once, if at all)
var bootSnapshotWait = 20 * time.Second

func (r *Router) registerSnapshots(m machineRoute) {
	r.machineMux.Handle("POST /m/snapshot/stream", r.requireMachineStreamed(r.snapshotStream))
	m("POST /m/snapshot/commit", r.snapshotCommit)
	m("POST /m/snapshot/failed", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &in)
		msg := strings.TrimSpace(in.Error)
		if msg == "" {
			msg = "the machine gave no reason"
		}
		log.Printf("machine %s: its snapshot failed: %s", machine, msg)
		r.snapshotDone(machine, snapResult{err: clip(msg, 300)})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}

// requireMachineStreamed: a machine's request whose body streams (its hash isn't known when it is signed): the
// signature names streamedBody instead, and is checked before a byte is read
const streamedBody = "stream"

func (r *Router) requireMachineStreamed(fn func(w http.ResponseWriter, req *http.Request, machine string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		machine, t, sig := req.Header.Get("X-Machine"), req.Header.Get("X-Time"), req.Header.Get("X-Sig")
		ts, _ := strconv.ParseInt(t, 10, 64)
		if d := time.Since(time.Unix(ts, 0)); d > 120*time.Second || d < -120*time.Second {
			writeJSON(w, 401, map[string]string{"error": "X-Time too far off"})
			return
		}
		var key string
		r.st.Do(func(d *persisted) {
			if s := d.Started[machine]; s != nil {
				key = s.SigningKey
			}
		})
		msg := req.Method + " " + req.URL.Path + " " + t + " " + streamedBody
		if key == "" || !verifyP256(key, []byte(msg), sig) {
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the core started"})
			return
		}
		fn(w, req, machine)
	})
}

// snapshotStream: the bytes onto the volume as the machine's pending snapshot, hashed on the way → {sha256, size}
func (r *Router) snapshotStream(w http.ResponseWriter, req *http.Request, machine string) {
	p := r.st.snapshotPath(machine)
	os.MkdirAll(filepath.Dir(p), 0o700)
	f, err := os.CreateTemp(filepath.Dir(p), ".upload-*")
	if err != nil {
		writeErr(w, err)
		return
	}
	tmp := f.Name()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(req.Body, snapshotMax+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > snapshotMax {
		err = fmt.Errorf("body over %d bytes", int64(snapshotMax))
	}
	if err != nil {
		os.Remove(tmp)
		log.Printf("machine %s: snapshot stream: %v", machine, err)
		writeErr(w, err)
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := os.Rename(tmp, p+".pending"); err != nil {
		os.Remove(tmp)
		writeErr(w, err)
		return
	}
	os.WriteFile(p+".pending.sha256", []byte(sum), 0o600)
	log.Printf("machine %s: snapshot streamed (%d bytes, %s)", machine, n, sum[:12])
	writeJSON(w, 200, map[string]any{"sha256": sum, "size": n})
}

// snapshotCommit: {sha256, sig}: the streamed snapshot with that hash, signed by the machine's current key, is its
// final one. Committing the one already in place again is fine (a machine asked twice); 404 = no such bytes here.
func (r *Router) snapshotCommit(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
	var in struct {
		Sha256 string `json:"sha256"`
		Sig    string `json:"sig"`
	}
	if json.Unmarshal(body, &in) != nil || len(in.Sha256) != 64 || in.Sig == "" {
		writeJSON(w, 400, map[string]string{"error": "body: {sha256, sig}"})
		return
	}
	var key string
	r.st.Do(func(d *persisted) {
		if s := d.Started[machine]; s != nil {
			key = s.SigningKey
		}
	})
	if !verifyP256(key, []byte(in.Sha256), in.Sig) {
		writeJSON(w, 403, map[string]string{"error": "the snapshot isn't signed by this machine's current key"})
		return
	}
	p := r.st.snapshotPath(machine)
	if have, _ := readTrimmed(p + ".sha256"); have == in.Sha256 {
		if _, err := os.Stat(p + ".sig"); err == nil {
			r.snapshotDone(machine, snapResult{})
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	if pending, _ := readTrimmed(p + ".pending.sha256"); pending != in.Sha256 {
		writeJSON(w, 404, map[string]string{"error": "no streamed snapshot with that sha256"})
		return
	}
	if err := os.Rename(p+".pending", p); err != nil {
		writeErr(w, err)
		return
	}
	os.Remove(p + ".pending.sha256")
	os.WriteFile(p+".sha256", []byte(in.Sha256), 0o600)
	os.WriteFile(p+".sig", []byte(in.Sig), 0o600)
	log.Printf("machine %s: final snapshot committed (%s)", machine, in.Sha256[:12])
	r.snapshotDone(machine, snapResult{})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func readTrimmed(p string) (string, error) {
	b, err := os.ReadFile(p)
	return strings.TrimSpace(string(b)), err
}

// keepSameSnapshot: a machine still booting answered with the snapshot it restored (X-Snapshot-Same + its signature
// over that hash): when that is its predecessor's snapshot here, the same bytes become this machine's snapshot
func (r *Router) keepSameSnapshot(machine, sum, sig string) error {
	var pred, key string
	r.st.Do(func(d *persisted) {
		if s := d.Started[machine]; s != nil {
			key = s.SigningKey
		}
		if cert := d.Certs[machine]; cert != nil {
			var c struct {
				PredID string `json:"predecessorId"`
			}
			cert.Decode(&c)
			pred = c.PredID
		}
	})
	if pred == "" || pred == machine {
		return errors.New("it has no predecessor")
	}
	if !verifyP256(key, []byte(sum), sig) {
		return errors.New("not signed by its current key")
	}
	pp, p := r.st.snapshotPath(pred), r.st.snapshotPath(machine)
	if _, err := os.Stat(pp + ".sig"); err != nil {
		return errors.New("its predecessor's snapshot isn't here")
	}
	have, err := readTrimmed(pp + ".sha256")
	if err != nil || have == "" {
		if have, _, err = fileSha256(pp); err != nil {
			return err
		}
	}
	if have != sum {
		return fmt.Errorf("its predecessor's snapshot is %s, not %s", have, sum)
	}
	os.Remove(p)
	if err := os.Link(pp, p); err != nil {
		if err := copyFile(pp, p); err != nil {
			return err
		}
	}
	os.WriteFile(p+".sha256", []byte(sum), 0o600)
	return os.WriteFile(p+".sig", []byte(sig), 0o600)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// hasFinalSnapshot: the machine's signed snapshot is here
func (r *Router) hasFinalSnapshot(machine string) bool {
	_, err := os.Stat(r.st.snapshotPath(machine) + ".sig")
	return err == nil
}

// dropSnapshotLeftovers: a killed machine's bytes that were streamed but never committed
func (r *Router) dropSnapshotLeftovers(machine string) {
	p := r.st.snapshotPath(machine)
	os.Remove(p + ".pending")
	os.Remove(p + ".pending.sha256")
}

// hold: the machine stays (state failed with the reason, Held set) and Deyao is told, by DM and in the app
func (r *Router) hold(id, machine, what, reason string) {
	now := time.Now().UTC()
	name := id
	r.st.Do(func(d *persisted) {
		x := d.Sessions[id]
		if x == nil {
			return
		}
		x.State, x.Waiting = "failed", ""
		x.Error = "snapshot: " + reason + ". Its machine is kept (still running, still billed), so nothing is lost: " +
			"pause it again to retry, or pause or destroy it without the snapshot (losing the work since its last one)."
		x.Held = &HeldMachine{Machine: machine, Since: now, For: what, Reason: reason}
		name = sessionName(x, nil)
		if x.Live != nil {
			name = sessionName(x, x.Live.Reg)
		}
	})
	log.Printf("session %s: %s held: %s", id, machine, reason)
	r.DM(heldText(name, what, reason))
}

func heldText(name, what, reason string) string {
	return fmt.Sprintf("🔴 Session “%s” needs you — its %s stopped: %s. Its machine is kept (still running and billed) so nothing is lost. "+
		"In the Jarvis 2 app: Pause again to retry, or pause or destroy it without the snapshot.", name, what, reason)
}

// askSnapshot: send the snapshot command and wait up to d → the answer, and whether one came
func (r *Router) askSnapshot(id, machine string, d time.Duration) (snapResult, bool) {
	done := r.awaitSnapshot(machine)
	r.send(machine, "snapshot")
	r.setWaiting(id, "waiting for the machine's last snapshot (up to "+waitText(d)+")")
	defer r.setWaiting(id, "")
	select {
	case res := <-done:
		return res, true
	case <-time.After(d):
		r.cmdMu.Lock()
		if r.snapped[machine] == done {
			delete(r.snapped, machine)
		}
		r.cmdMu.Unlock()
		return snapResult{}, false
	}
}

func (r *Router) awaitSnapshot(machine string) chan snapResult {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	c := make(chan snapResult, 1)
	r.snapped[machine] = c
	return c
}

// snapshotArrived: a snapshot (or "nothing to snapshot") came from the machine
func (r *Router) snapshotArrived(machine string) { r.snapshotDone(machine, snapResult{}) }

func (r *Router) snapshotDone(machine string, res snapResult) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	if c := r.snapped[machine]; c != nil {
		c <- res
		delete(r.snapped, machine)
	}
}
