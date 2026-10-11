package main

// Carried secrets (docs/DESIGN.md "Carried secrets"): every pull that goes through answers a carry blob — the
// machine's secrets per store, sealed under a key only the core holds, bound to that machine. The router keeps it
// next to the machine's snapshot (snapshots/<machine>.carry on its volume) and hands it back to the core on the
// machine's next pull and, right after a successor is certified (a resume) or the machine gets a new cert (an
// add-store, a downgrade), to the core with the call that makes the new cert, which answers it rebound to that machine
// beside the cert, keeping only the stores the cert names (the core before R2: its carry/forward). The router can't open, alter or move it to another line; it can only lose it, and then the
// session waits for an unlock (the app's "Waiting for store X" → Unlock…). Destroy deletes it with the snapshot.
//
// A core that predates carried secrets (the held production core until Deyao releases the new one) answers no
// carry and has no /carry/forward (404): nothing is kept and nothing changes.

import (
	"errors"
	"log"
	"os"
	"strings"
	"sync"
)

func (s *State) carryPath(machine string) string {
	return strings.TrimSuffix(s.snapshotPath(machine), ".tar.gz") + ".carry"
}

// carryLock: one carry read-modify-write per machine at a time (a pull and a forward can race)
var carryLocks sync.Map

func carryLock(machine string) func() {
	m, _ := carryLocks.LoadOrStore(machine, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (r *Router) readCarry(machine string) string {
	if machine == "" {
		return ""
	}
	b, err := os.ReadFile(r.st.carryPath(machine))
	if err != nil {
		return ""
	}
	return string(b)
}

func (r *Router) saveCarry(machine, blob string) {
	if blob == "" {
		return
	}
	p := r.st.carryPath(machine)
	if err := os.WriteFile(p+".tmp", []byte(blob), 0o600); err != nil {
		log.Printf("carry for %s: %v", machine, err)
		return
	}
	os.Rename(p+".tmp", p)
}

func (r *Router) dropCarry(machine string) { os.Remove(r.st.carryPath(machine)) }

// carryForPull: the blob to send with a machine's pull — its own, else its predecessor's (a resumed machine whose
// forward didn't happen)
func (r *Router) carryForPull(machine string, cert *Doc) string {
	if b := r.readCarry(machine); b != "" {
		return b
	}
	return r.readCarry(predOf(cert))
}

// pulled: a pull went through; keep the new blob for this machine (the predecessor's is spent)
func (r *Router) pulled(machine string, cert, answer *Doc) {
	var a struct {
		Carry string `json:"carry"`
	}
	if answer.Decode(&a) != nil || a.Carry == "" {
		return // a core without carried secrets
	}
	r.saveCarry(machine, a.Carry)
	if p := predOf(cert); p != "" && p != machine {
		r.dropCarry(p)
	}
}

// carryAfter: a new cert's carry — the blob the core answered beside it (rebound to `to`), else (the core before R2)
// its /carry/forward
func (r *Router) carryAfter(from, to string, cert *Doc, ans *Answer) {
	if ans == nil || ans.Carry == "" {
		r.forwardCarry(from, cert, to)
		return
	}
	defer carryLock(to)()
	if from != to {
		defer carryLock(from)()
	}
	r.saveCarry(to, ans.Carry)
	if from != to {
		r.dropCarry(from)
	}
}

// forwardCarry: the core before R2: the line's blob (held for `from`: the predecessor, or the machine itself) rebound to the machine
// the new cert names. Best effort: without it the machine's own pull still reads the predecessor's blob, and a
// missing blob only means waiting for an unlock.
func (r *Router) forwardCarry(from string, cert *Doc, to string) {
	defer carryLock(to)()
	if from != to {
		defer carryLock(from)()
	}
	blob := r.readCarry(from)
	if blob == "" {
		return
	}
	d, err := r.core.Call("/carry/forward", map[string]any{"carry": blob, "cert": cert})
	if err != nil {
		var ce *CoreError
		if !(errors.As(err, &ce) && ce.Status == 404) {
			log.Printf("carry forward %s → %s: %v", from, to, err)
		}
		return
	}
	var a struct {
		Carry string `json:"carry"`
	}
	if d.Decode(&a) != nil || a.Carry == "" {
		return
	}
	r.saveCarry(to, a.Carry)
	if from != to {
		r.dropCarry(from)
	}
}

func predOf(cert *Doc) string {
	if cert == nil {
		return ""
	}
	var c struct {
		PredID string `json:"predecessorId"`
	}
	cert.Decode(&c)
	return c.PredID
}
