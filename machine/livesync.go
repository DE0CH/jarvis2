package main

// Live transcript sync (Jarvis 1's session-image/sync-live-transcripts): every JARVIS2_LIVE_SYNC_SECONDS
// (default 300) each conversation transcript under ~/.claude/projects that changed since its last copy goes to
// the router (POST /m/live-transcript, X-Name = its file name, the whole file — the Storage Box's WebDAV has
// no append), which puts it at claude-records/.live/<session id>/ for Jarvis 1's transcript search
// (router/livesync.go). The machine holds no Storage Box credentials. Jarvis's peer-message relays ("You are a
// delivery relay…") are plumbing and are skipped, as in Jarvis 1.

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const liveSyncMaxBytes = 256 << 20 // the router refuses more

type liveSyncer struct {
	sent map[string]time.Time // file → the modification time last sent
	send func(name string, body []byte) error
}

func liveSyncInterval() time.Duration {
	if n, err := strconv.Atoi(os.Getenv("JARVIS2_LIVE_SYNC_SECONDS")); err == nil && n >= 5 {
		return time.Duration(n) * time.Second
	}
	return 300 * time.Second
}

// once: one pass over the transcripts; the number sent
func (l *liveSyncer) once() int {
	files, _ := filepath.Glob(filepath.Join(claudeHome, ".claude/projects/*/*.jsonl"))
	n := 0
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if t, ok := l.sent[f]; ok && !fi.ModTime().After(t) {
			continue
		}
		if fi.Size() > liveSyncMaxBytes {
			l.sent[f] = fi.ModTime()
			log.Printf("live sync: %s is %d bytes, over the limit; not sent", filepath.Base(f), fi.Size())
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.Contains(body[:min(len(body), 4000)], []byte("You are a delivery relay")) {
			l.sent[f] = fi.ModTime()
			continue
		}
		if err := l.send(filepath.Base(f), body); err != nil {
			log.Printf("live sync: %s: %v", filepath.Base(f), err)
			continue // tried again next pass
		}
		l.sent[f] = fi.ModTime()
		n++
	}
	return n
}

// liveSync: the agent's loop (started by agent())
func liveSync(c *client) {
	l := &liveSyncer{sent: map[string]time.Time{}, send: func(name string, body []byte) error {
		b, _, status, err := c.raw("POST", "/m/live-transcript", body, "X-Name", name)
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("HTTP %d %s", status, bytes.TrimSpace(b[:min(len(b), 200)]))
		}
		return nil
	}}
	every := liveSyncInterval()
	for {
		time.Sleep(every)
		l.once()
	}
}
