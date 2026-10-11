package main

// Restoring a destroyed session's archived snapshot into a NEW line (router/restore.go), and the repos'
// state recorded in every snapshot (for the router's uncommitted-work check of a paused session).
//
// A new line (a cert with no predecessor) whose cert names a restore (Config.restore: the old machine and the
// snapshot's sha256, which the phone approved) restores the snapshot the router serves at /m/restore-snapshot,
// after checking:
//   - its sha256 is the one the cert names;
//   - the old cert (/m/restore-cert) is a succession cert signed by the core, for the machine the cert names;
//   - the snapshot is signed by that cert's machine signing key (same format as a pause snapshot);
//   - a snapshot from a line that held a sensitive store doesn't land in a line that holds none.

import (
	"crypto/sha256"
	"encoding/hex"
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

// restoreArchived: the archived snapshot into a new line's first machine, only when the cert names it
// (Config.restore: the old line's machine and the snapshot's sha256, approved on the phone with the new line)
func restoreArchived(c *client, coreKey, me string, cert *Cert, v Vouched) error {
	ref := v.Config.Restore
	if cert.PredID != "" || ref == nil {
		return nil
	}
	var rc struct {
		Cert *SignedDoc `json:"cert"`
	}
	if err := c.json("GET", "/m/restore-cert", nil, &rc); err != nil || rc.Cert == nil {
		return fmt.Errorf("the cert names a restore but the router serves no old cert (%v)", err)
	}
	old, err := checkRestoreCert(coreKey, me, cert, rc.Cert)
	if err != nil {
		return err
	}
	if old.Machine.ID != ref.Machine {
		return fmt.Errorf("the old cert is for %s, the cert names %s", old.Machine.ID, ref.Machine)
	}
	body, hdr, status, err := c.raw("GET", "/m/restore-snapshot", nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("a restore was asked for but the router serves no snapshot (HTTP %d)", status)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != ref.Sha256 {
		return errors.New("the archived snapshot isn't the one the cert names")
	}
	if err := checkSnapshotSig(old.Machine.SigningKey, body, hdr.Get("X-Snapshot-Sig")); err != nil {
		return err
	}
	n, err := unpack(body)
	if err != nil {
		return err
	}
	restoredArchive = true
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
