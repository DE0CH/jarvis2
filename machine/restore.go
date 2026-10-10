package main

// Restoring a destroyed session's archived snapshot into a NEW line (router/restore.go), and the repos'
// state recorded in every snapshot (for the router's uncommitted-work check of a paused session).
//
// A new line (a cert with no predecessor) whose machine env carries JARVIS2_RESTORE_CERT restores the
// snapshot the router serves at /m/restore-snapshot, after checking:
//   - the old cert is a succession cert signed by the core (the key the core put in this machine's Fly
//     config), for another machine;
//   - the snapshot is signed by that cert's machine signing key (same format as a pause snapshot);
//   - a snapshot from a line that held a sensitive store doesn't land in a line that holds none.
// The env is the router's word, so which old snapshot comes back is not phone-approved: a malicious router
// can swap in another of Deyao's own signed snapshots, or none (router/restore.go has the reasoning).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

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

// restoreArchived: the archived snapshot into a new line's first machine, when the router asks for one
func restoreArchived(c *client, coreKey, me string, cert *Cert) error {
	raw := os.Getenv("JARVIS2_RESTORE_CERT")
	if raw == "" || cert.PredID != "" {
		return nil
	}
	var doc SignedDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("JARVIS2_RESTORE_CERT isn't a signed document: %w", err)
	}
	old, err := checkRestoreCert(coreKey, me, cert, &doc)
	if err != nil {
		return err
	}
	body, hdr, status, err := c.raw("GET", "/m/restore-snapshot", nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("a restore was asked for but the router serves no snapshot (HTTP %d)", status)
	}
	if err := checkSnapshotSig(old.Machine.SigningKey, body, hdr.Get("X-Snapshot-Sig")); err != nil {
		return err
	}
	n, err := unpack(body)
	if err != nil {
		return err
	}
	log.Printf("restored the archived snapshot of %s (line %s, %d files)", old.Machine.ID, old.Line, n)
	return nil
}

// checkRestoreCert: the old line's cert, core-signed, for another machine; sensitive stays sensitive
func checkRestoreCert(coreKey, me string, cert *Cert, doc *SignedDoc) (*Cert, error) {
	var old Cert
	if err := verifyDoc(coreKey, doc, &old); err != nil || old.Kind != "succession-cert" || old.Machine == nil {
		return nil, fmt.Errorf("the restore cert isn't a succession cert signed by the core (%v)", err)
	}
	if old.Machine.ID == me {
		return nil, errors.New("the restore cert names this machine")
	}
	if old.Sensitive && !cert.Sensitive {
		return nil, errors.New("the snapshot comes from a line with a sensitive store; this line holds none")
	}
	return &old, nil
}

func checkSnapshotSig(signingKey string, body []byte, sig string) error {
	sum := sha256.Sum256(body)
	if !verify(signingKey, []byte(hex.EncodeToString(sum[:])), sig) {
		return errors.New("the snapshot isn't signed by the machine its cert names")
	}
	return nil
}
