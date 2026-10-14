package main

// Transcript rollback (Jarvis 1's restart {rollback: {dropFromMarker}}, archive.js editSnapshotTranscript).
// The router can't edit a snapshot: the source names its sha256, and the guard takes only those bytes. A rollback is
// a start setting of a source the phone made ("rollback", approved on the phone with the restart; boot.go), and this
// machine applies it AFTER it has verified and unpacked the snapshot: in every
// conversation transcript (~/.claude/projects/<dir>/<id>.jsonl), the first line containing the marker and
// everything after it are dropped. Nothing in the env or from the router alone asks for one.

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type rollbackResult struct {
	Name    string `json:"name"`
	Before  int    `json:"before"`
	After   int    `json:"after"`
	Dropped int    `json:"dropped"`
}

// applyRollback: called at boot once the snapshot the source names is restored, with the marker from the settings of a
// source the phone made (boot.go)
func applyRollback(marker string) {
	if marker == "" {
		return
	}
	home, _ := os.UserHomeDir()
	res, err := rollbackTranscripts(home, marker)
	if err != nil {
		log.Printf("rollback: %v", err)
	}
	for _, r := range res {
		if r.Dropped > 0 {
			log.Printf("rollback: %s: %d → %d lines", r.Name, r.Before, r.After)
		}
	}
}

// rollbackTranscripts: the conversation transcripts directly under ~/.claude/projects/<dir>/ (not subagents')
func rollbackTranscripts(home, marker string) ([]rollbackResult, error) {
	if len(marker) < 4 {
		return nil, fmt.Errorf("marker too short")
	}
	paths, err := filepath.Glob(filepath.Join(home, ".claude", "projects", "*", "*.jsonl"))
	if err != nil {
		return nil, err
	}
	var out []rollbackResult
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return out, err
		}
		kept, before, after, cut := truncateAtMarker(body, marker)
		rel, _ := filepath.Rel(home, p)
		r := rollbackResult{Name: rel, Before: before, After: after, Dropped: before - after}
		out = append(out, r)
		if !cut {
			continue
		}
		tmp := p + ".rollback"
		if err := os.WriteFile(tmp, kept, fi.Mode().Perm()); err != nil {
			return out, err
		}
		if err := os.Rename(tmp, p); err != nil {
			return out, err
		}
	}
	return out, nil
}

// truncateAtMarker: Jarvis 1's rule — the lines before the first one containing the marker, newline-ended
func truncateAtMarker(body []byte, marker string) (kept []byte, before, after int, cut bool) {
	lines := strings.Split(string(body), "\n")
	nonEmpty := func(ls []string) int {
		n := 0
		for _, l := range ls {
			if strings.TrimSpace(l) != "" {
				n++
			}
		}
		return n
	}
	before = nonEmpty(lines)
	for i, l := range lines {
		if strings.Contains(l, marker) {
			var b bytes.Buffer
			for _, k := range lines[:i] {
				b.WriteString(k + "\n")
			}
			return b.Bytes(), before, nonEmpty(lines[:i]), true
		}
	}
	return body, before, before, false
}
