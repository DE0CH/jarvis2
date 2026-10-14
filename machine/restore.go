package main

// The snapshot a machine starts from (docs/DESIGN.md "Target design": "restore only the snapshot whose hash the source
// names"), and the repos' state recorded in every snapshot (for the router's uncommitted-work check of a paused
// session).
//
// A source names a snapshot by its sha256: the spawner's kill took it from the machine's own signed snapshot claim, or
// the phone approved it (a restore of a destroyed session, a Jarvis 1 import). The router serves the bytes at
// GET /m/snapshot; the guard takes exactly the bytes whose hash the source names, nothing else. They are either a Jarvis
// 2 snapshot (a tar.gz relative to $HOME) or a Jarvis 1 import's manifest (jarvis1import.go), told apart by content.

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// restoreTmp: where the snapshot lands while it is checked (a var: tests move it)
var restoreTmp = dir + "/restore.tar.gz"

// changesFile: the repos' state when the snapshot was taken (router/archive.go reads it); in snapshotPaths
const changesFile = ".jarvis2-changes.txt"

// repoChangesSH: one "<repo> <uncommitted files> <unpushed commits, -1 = no upstream>" line per repo
const repoChangesSH = `cd ~/workspace 2>/dev/null || exit 0; for d in */; do d=${d%/}; [ -d "$d/.git" ] || continue; ` +
	`u=$(git -C "$d" status --porcelain 2>/dev/null | wc -l); ` +
	`if git -C "$d" rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then p=$(git -C "$d" rev-list @{u}..HEAD --count 2>/dev/null || echo 0); else p=-1; fi; ` +
	`echo "$d $u $p"; done`

// writeChanges: before every snapshot; a failure only leaves the router without the check
func writeChanges() {
	home, _ := os.UserHomeDir()
	out, err := exec.Command("bash", "-c", repoChangesSH).Output()
	if err != nil {
		log.Printf("repo changes: %v", err)
	}
	os.WriteFile(filepath.Join(home, changesFile), out, 0o600)
}

// restoreSnapshot: the bytes whose sha256 the source names, unpacked into $HOME (or imported, for a Jarvis 1 manifest)
func restoreSnapshot(g *guard, sum string) error {
	tmp := restoreTmp
	defer os.Remove(tmp)
	got, _, err := g.c.download("/m/snapshot", tmp) // streamed to disk, hashed on the way
	if err != nil {
		return err
	}
	if got != sum {
		return errors.New("the snapshot isn't the one the source names")
	}
	if man, ok := readJ1Manifest(tmp, ""); ok {
		return importJarvis1(g.c, man)
	}
	n, err := unpackFile(tmp)
	if err != nil {
		return err
	}
	log.Printf("restored the snapshot the source names (%d files)", n)
	return nil
}
