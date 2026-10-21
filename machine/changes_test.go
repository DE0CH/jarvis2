package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// the repo check before a snapshot can't hang it (2026-10-21): a script that never ends (bash and a child holding
// the pipe) is killed at the time limit, and the snapshot goes on with no changes file content
func TestWriteChangesGivesUpAtItsTimeLimit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	defer func(s string, d time.Duration) { changesScript, changesTimeout = s, d }(changesScript, changesTimeout)
	changesScript, changesTimeout = "echo partial; sleep 30 & sleep 30", 300*time.Millisecond
	t0 := time.Now()
	writeChanges()
	if el := time.Since(t0); el > 10*time.Second {
		t.Fatalf("took %s", el)
	}
	b, err := os.ReadFile(filepath.Join(home, changesFile))
	if err != nil || len(b) != 0 {
		t.Fatalf("%q %v", b, err)
	}
}

func TestWriteChangesWritesTheRepos(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	defer func(s string) { changesScript = s }(changesScript)
	changesScript = "echo 'jarvis3 13 0'"
	writeChanges()
	if b, _ := os.ReadFile(filepath.Join(home, changesFile)); string(b) != "jarvis3 13 0\n" {
		t.Fatalf("%q", b)
	}
}
