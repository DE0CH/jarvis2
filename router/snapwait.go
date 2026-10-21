package main

// How long a pause or destroy waits for the machine's final snapshot (DECISIONS 214): for as long as the snapshot
// makes progress, with no overall limit (a large upload or a bad network may take very long). The wait ends when
//
//   - the snapshot arrives (committed, carried over, "nothing to snapshot"), or the machine reports it failed;
//   - nothing has moved for SnapshotStall (SNAPSHOT_STALL_SECONDS, default 10 min): the stream is stuck, or the
//     supervisor is stuck before it (the freeze, the repos' state);
//   - nothing has moved for silentAfter (3 min) and the machine's last status report is older than that too: the
//     machine is gone (its supervisor reports at least every 60 s, also while the session is frozen).
//
// What counts as progress: the snapshot command being sent (the clock starts), every read of the snapshot's body as
// it arrives at the router (POST /m/snapshot-stream, or the whole-file POST /m/snapshot of an older image), and a
// progress report (POST /m/snapshot-progress, snapprogress.go) whose numbers moved (phase, bytes read, measured,
// sent). A report that repeats the same numbers is a live machine making no progress, so it doesn't count.

import (
	"fmt"
	"io"
	"time"
)

// snapWait: one awaited final snapshot
type snapWait struct {
	done  chan struct{}
	moved time.Time    // the last sign of progress
	prog  SnapProgress // the last progress report's numbers
}

func (r *Router) awaitSnapshot(machine string) chan struct{} {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	w := &snapWait{done: make(chan struct{}), moved: time.Now()}
	r.snapped[machine] = w
	return w.done
}

func (r *Router) snapshotArrived(machine string) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	if w := r.snapped[machine]; w != nil {
		close(w.done)
		delete(r.snapped, machine)
	}
}

// stopAwaiting: the wait ended without the snapshot (a late one still lands as the machine's snapshot file, which
// the next pause finds), so later progress reports aren't shown any more
func (r *Router) stopAwaiting(machine string, done chan struct{}) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	if w := r.snapped[machine]; w != nil && w.done == done {
		delete(r.snapped, machine)
	}
}

// snapshotMoved: a sign of progress on the machine's awaited snapshot (no-op when none is awaited)
func (r *Router) snapshotMoved(machine string) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	if w := r.snapped[machine]; w != nil {
		w.moved = time.Now()
	}
}

// snapshotReported: a progress report; it counts as progress only when its numbers moved
func (r *Router) snapshotReported(machine string, p SnapProgress) {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	if w := r.snapped[machine]; w != nil && p != w.prog {
		w.prog, w.moved = p, time.Now()
	}
}

// snapshotQuiet: how long the awaited snapshot has shown no progress
func (r *Router) snapshotQuiet(machine string) time.Duration {
	r.cmdMu.Lock()
	defer r.cmdMu.Unlock()
	if w := r.snapped[machine]; w != nil {
		return time.Since(w.moved)
	}
	return 0
}

// waitSnapshot: until done closes (nil), or the snapshot stalls or the machine is gone (the error says which)
func (r *Router) waitSnapshot(machine string, done chan struct{}) error {
	stall := r.cfg.SnapshotStall
	if stall <= 0 {
		stall = 10 * time.Minute
	}
	poll := min(max(stall/20, 10*time.Millisecond), time.Second)
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-tick.C:
		}
		quiet := r.snapshotQuiet(machine)
		if quiet >= stall {
			r.stopAwaiting(machine, done)
			return fmt.Errorf("the machine's snapshot made no progress for %s", waitText(quiet))
		}
		if quiet >= silentAfter {
			if last := r.lastReport(machine); time.Since(last) >= silentAfter {
				r.stopAwaiting(machine, done)
				return fmt.Errorf("the machine went silent during its snapshot (last report %s, no progress for %s)",
					last.UTC().Format("2006-01-02 15:04 UTC"), waitText(quiet))
			}
		}
	}
}

// lastReport: when the machine's supervisor last reported its status (zero: never, or not the session's machine)
func (r *Router) lastReport(machine string) (t time.Time) {
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine && s.Live != nil {
			t = s.Live.LastReport
		}
	})
	return
}

// movedReader: a snapshot body as it arrives; every read is progress
type movedReader struct {
	r       io.Reader
	router  *Router
	machine string
}

func (m movedReader) Read(b []byte) (int, error) {
	n, err := m.r.Read(b)
	if n > 0 {
		m.router.snapshotMoved(m.machine)
	}
	return n, err
}
