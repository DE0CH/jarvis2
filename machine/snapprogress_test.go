package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// the snapshot is measured first, then counted as writeSnapshot reads its files; the router gets the numbers
// (throttled) and the log a line per progressLogEvery plus the last one
func TestSnapshotProgress(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, "workspace", "repo"), 0o755)
	big := make([]byte, 3<<20)
	rand.Read(big) // incompressible: the compressed bytes are about the same
	os.WriteFile(filepath.Join(home, "workspace", "repo", "big.bin"), big, 0o644)
	os.WriteFile(filepath.Join(home, "workspace", "small.txt"), []byte("hello"), 0o644)
	os.MkdirAll(filepath.Join(home, ".paseo", "models"), 0o755)
	os.WriteFile(filepath.Join(home, ".paseo", "models", "skip.bin"), make([]byte, 1<<20), 0o644) // left out: not counted

	oldPost, oldLog := progressPostEvery, progressLogEvery
	progressPostEvery, progressLogEvery = 0, time.Hour
	defer func() { progressPostEvery, progressLogEvery = oldPost, oldLog }()

	var mu sync.Mutex
	var reports []map[string]any
	var lines []string
	p := &snapProgress{stop: make(chan struct{})}
	p.report = func(m map[string]any) error { mu.Lock(); reports = append(reports, m); mu.Unlock(); return nil }
	p.logf = func(f string, a ...any) { mu.Lock(); lines = append(lines, fmt.Sprintf(f, a...)); mu.Unlock() }
	beginProgress(p)
	want := int64(len(big) + 5)
	if p.total.Load() != want {
		t.Fatalf("measured %d, want %d", p.total.Load(), want)
	}
	p.setPhase("uploading")
	var out bytes.Buffer
	_, n, err := writeSnapshot(&out)
	if err != nil {
		t.Fatal(err)
	}
	p.tick(true)
	p.end(nil)
	if p.done.Load() != want || p.sent.Load() != n || n == 0 {
		t.Fatalf("done %d sent %d (wrote %d)", p.done.Load(), p.sent.Load(), n)
	}
	if curProgress.Load() != nil {
		t.Fatal("still counting after end")
	}
	mu.Lock()
	if len(reports) < 2 || reports[0]["phase"] != "measuring" || reports[len(reports)-1]["phase"] != "uploading" || reports[len(reports)-1]["done"] != want {
		t.Fatalf("reports %v", reports)
	}
	if last := lines[len(lines)-1]; !strings.Contains(last, "snapshot: uploading done, 0.00 GB read") {
		t.Fatalf("log %q", lines)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "(100%)") {
		t.Fatalf("no 100%% line: %q", lines)
	}
	mu.Unlock()
	// a router without the route: reported once, then only logged; the snapshot isn't held up
	q := &snapProgress{stop: make(chan struct{}), logf: p.logf}
	calls := 0
	q.report = func(map[string]any) error { calls++; return fmt.Errorf("HTTP 404") }
	beginProgress(q)
	q.setPhase("uploading")
	writeSnapshot(io.Discard)
	q.tick(true)
	q.end(nil)
	if calls != 1 {
		t.Fatalf("reported %d times to a router without the route", calls)
	}
}
