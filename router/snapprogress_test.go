package main

import (
	"strings"
	"testing"
)

func TestSnapProgressText(t *testing.T) {
	for _, c := range []struct {
		p    SnapProgress
		want string
	}{
		{SnapProgress{Phase: "uploading", Done: 1.2e9, Total: 3.4e9, ElapsedMs: 30000}, "uploading snapshot 1.2/3.4 GB (35%), 40 MB/s, 55 s left"},
		{SnapProgress{Phase: "uploading", Done: 0, Total: 500e6, ElapsedMs: 200}, "uploading snapshot 0/500 MB (0%)"},
		{SnapProgress{Phase: "writing", Done: 100e6, Total: 400e6, ElapsedMs: 10000}, "writing snapshot 100/400 MB (25%), 10 MB/s, 30 s left"},
		{SnapProgress{Phase: "uploading", Done: 5e9, Total: 4e9, ElapsedMs: 100000}, "uploading snapshot 5.0/5.0 GB (100%), 50 MB/s"}, // files grew past the measure
		{SnapProgress{Phase: "uploading", Done: 1e9, Total: 9e9, ElapsedMs: 10000}, "uploading snapshot 1.0/9.0 GB (11%), 100 MB/s, 1 min 20 s left"},
		{SnapProgress{Phase: "measuring", Total: 2.5e9}, "measuring the snapshot (2.5 GB so far)"},
		{SnapProgress{Phase: "rm -rf", Total: 1}, ""},
		{SnapProgress{Phase: "uploading", Done: -1}, ""},
	} {
		if got := snapProgressText(c.p); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.p, got, c.want)
		}
	}
}

// a report while the router awaits the machine's snapshot becomes the session's waiting line (and a lifecycle note);
// without a waiter it is dropped; nonsense is refused
func TestSnapProgressRoute(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sP", "pausing", "mP", false)
	m := newTestMachine(r, "mP")
	waiting := func() string {
		var s string
		r.st.Do(func(d *persisted) { s = d.Sessions["sP"].Waiting })
		return s
	}
	body := jsonString(map[string]any{"phase": "uploading", "done": 1.2e9, "total": 3.4e9, "sent": 6e8, "elapsedMs": 30000})
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/snapshot-progress", body); code != 200 || waiting() != "" {
		t.Fatalf("no waiter: %d %q", code, waiting())
	}
	r.awaitSnapshot("mP")
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/snapshot-progress", body); code != 200 || !strings.HasPrefix(waiting(), "uploading snapshot 1.2/3.4 GB") {
		t.Fatalf("awaited: %d %q", code, waiting())
	}
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/snapshot-progress", jsonString(map[string]any{"phase": "x"})); code != 400 {
		t.Fatalf("nonsense: %d", code)
	}
	r.snapshotArrived("mP")
	r.setWaiting("sP", "")
	if m.do(t, r.MachineHandler(), "POST", "/m/snapshot-progress", body); waiting() != "" {
		t.Fatalf("after the snapshot arrived: %q", waiting())
	}
}
