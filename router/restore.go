package main

// Restoring a destroyed session (Jarvis 1 POST /api/records/:id/restore). The destroy burnt the old line, so
// a restore is a NEW line from null — the phone approves it like any new session — whose first machine
// restores the archived snapshot.
//
// What the machine trusts (machine/restore.go): the core's succession challenge has no room for "restore
// from" (core Options carry only the harness, and the core is off-limits), so the router passes the old
// line's signer cert in the machine's env (JARVIS2_RESTORE_CERT) and serves the archived snapshot at
// /m/restore-snapshot. The machine accepts it only on a line's FIRST machine (a cert with no predecessor),
// checks the old cert against the core key (a core-signed succession cert, another machine), the snapshot
// against that cert's machine signing key, and refuses a snapshot from a line that held a sensitive store
// into a line that holds none.
//
// The risk this leaves (docs/PARITY.md): the restore choice is not signed by the phone. A malicious router
// can make a new line, which Deyao approved as "restore X", restore some other old snapshot of Deyao's
// (signed by one of his own machines), or none. It can't forge a snapshot or bring one from outside Deyao's
// own lines; and the router holds every snapshot in plaintext anyway, so the mix-up moves no data to anyone
// who didn't already have it (confidentiality-neutral), apart from the sensitive-store rule above.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	envHooks = append(envHooks, func(_ *Router, s *Session, env map[string]string) {
		if s.RestoreCert != nil && s.Cert == nil { // only the new line's first machine
			b, _ := json.Marshal(s.RestoreCert)
			env["JARVIS2_RESTORE_CERT"] = string(b)
		}
	})
}

func (r *Router) restoresDir(sid string) string {
	return filepath.Join(r.cfg.DataDir, "restores", sid)
}

// RestoreRecord: the record's archived snapshot onto the volume, then a new session with the record's
// options, waiting for the phone (approval kind new-session, options.restore names what it restores)
func (r *Router) RestoreRecord(recordID, requestID string) (string, error) {
	rec := r.record(recordID)
	if rec == nil {
		return "", errors.New("no such previous session")
	}
	if rec.Archive == nil {
		return "", errors.New("this session was destroyed without an archive: nothing to restore")
	}
	box := r.box()
	if box == nil {
		return "", errNoStorageBox
	}
	h, ok := r.policy.Harnesses[rec.Harness]
	if !ok {
		return "", fmt.Errorf("no harness %s in the policy", rec.Harness)
	}
	stores, err := r.withHarnessStores(rec.Stores, h.Stores)
	if err != nil {
		return "", err
	}
	sid := "s" + randID()
	dir := r.restoresDir(sid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		os.RemoveAll(dir)
		return "", err
	}
	for _, f := range []string{"snapshot.tar.gz", "snapshot.sig", "cert.json"} {
		found, err := box.Download(rec.Archive.Dir+"/jarvis2/"+f, filepath.Join(dir, f))
		if err != nil {
			return fail(err)
		}
		if !found {
			return fail(fmt.Errorf("the archive has no jarvis2/%s", f))
		}
	}
	cert, err := r.checkRestoreFiles(dir)
	if err != nil {
		return fail(err)
	}
	label := rec.Label
	if label == "" {
		label = rec.Archive.Title
	}
	s := &Session{ID: sid, State: "approval", Created: time.Now().UTC(), Label: label, Model: rec.Model, PermissionMode: rec.PermissionMode,
		Size: rec.Size, Harness: rec.Harness, Stores: stores, Repos: rec.Repos, RequestID: requestID, RestoreFrom: recordID, RestoreCert: cert}
	r.st.Do(func(d *persisted) { d.Sessions[sid] = s })
	ch, err := r.succession(nil, "", s.Stores, s.Harness, r.cfg.SessionImage)
	if err != nil {
		r.st.Do(func(d *persisted) { delete(d.Sessions, sid) })
		return fail(err)
	}
	what := label
	if what == "" {
		what = recordID
	}
	r.addApproval(&Approval{Kind: "new-session", Session: sid, Label: s.Label, Challenge: ch,
		Options: map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode, "repos": s.Repos,
			"restore": fmt.Sprintf("%s (destroyed %s)", what, rec.DestroyedAt.UTC().Format("2006-01-02"))}})
	return sid, nil
}

// checkRestoreFiles: the router's own early check (the machine checks again, and only its check counts):
// the cert is the core's and the snapshot is signed by the cert's machine
func (r *Router) checkRestoreFiles(dir string) (*Doc, error) {
	b, err := os.ReadFile(filepath.Join(dir, "cert.json"))
	if err != nil {
		return nil, err
	}
	var cert Doc
	if json.Unmarshal(b, &cert) != nil || cert.Payload == "" {
		return nil, errors.New("the archive's cert.json isn't a signed document")
	}
	var c struct {
		Kind    string `json:"kind"`
		Machine *struct {
			ID         string `json:"id"`
			SigningKey string `json:"signingKey"`
		} `json:"machine"`
	}
	if cert.Decode(&c) != nil || c.Kind != "succession-cert" || c.Machine == nil {
		return nil, errors.New("the archive's cert.json isn't a succession cert")
	}
	if key, err := r.core.Key(); err == nil && key["signingKey"] != "" && !verifyP256(key["signingKey"], []byte(cert.Payload), cert.Sig) {
		return nil, errors.New("the archive's cert isn't signed by this core (was the core recovered since?)")
	}
	sig, err := os.ReadFile(filepath.Join(dir, "snapshot.sig"))
	if err != nil {
		return nil, err
	}
	sum, err := sha256hex(filepath.Join(dir, "snapshot.tar.gz"))
	if err != nil {
		return nil, err
	}
	if !verifyP256(c.Machine.SigningKey, []byte(sum), strings.TrimSpace(string(sig))) {
		return nil, errors.New("the archived snapshot isn't signed by the machine its cert names")
	}
	return &cert, nil
}

// restoreFilesFor: the restore files a machine may fetch — only the first machine of a restoring session
func (r *Router) restoreFilesFor(machine string) string {
	var sid string
	r.st.Do(func(d *persisted) {
		s := d.Sessions[d.Machines[machine]]
		if s == nil || s.RestoreCert == nil || s.MachineID != machine || certField(d.Certs[machine], "predecessorId") != "" {
			return
		}
		sid = s.ID
	})
	if sid == "" {
		return ""
	}
	dir := r.restoresDir(sid)
	if _, err := os.Stat(filepath.Join(dir, "snapshot.tar.gz")); err != nil {
		return ""
	}
	return dir
}

// tidyRestores: once a restoring session is past its first boot (or gone), its restore files go; a session
// that came up is noted on the record it was restored from
func (r *Router) tidyRestores() {
	ents, _ := os.ReadDir(filepath.Join(r.cfg.DataDir, "restores"))
	for _, e := range ents {
		sid := e.Name()
		var state, from string
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil {
				state, from = s.State, s.RestoreFrom
			}
		})
		switch state {
		case "approval", "starting", "initialising":
			continue
		case "started":
			r.markRestored(from, sid)
		}
		os.RemoveAll(filepath.Join(r.cfg.DataDir, "restores", sid))
	}
}

func (r *Router) markRestored(recordID, sid string) {
	if recordID == "" {
		return
	}
	now := time.Now().UTC()
	r.st.Do(func(d *persisted) {
		for _, x := range d.Records {
			if x.ID == recordID {
				x.Restored = append(x.Restored, RestoreMark{Session: sid, At: now})
			}
		}
	})
	if box := r.box(); box != nil {
		err := updateIndex(box, func(list []map[string]any) []map[string]any {
			for _, e := range list {
				if e["id"] == recordID {
					prev, _ := e["restored"].([]any)
					e["restored"] = append(prev, map[string]any{"sessionId": sid, "at": now})
				}
			}
			return list
		})
		if err != nil {
			log.Printf("record %s: restored by %s, not noted in the index: %v", recordID, sid, err)
		}
	}
}
