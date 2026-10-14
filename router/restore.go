package main

// Restoring a destroyed session (Jarvis 1 POST /api/records/:id/restore). The destroy burnt the old source, so a
// restore is a NEW session out of the sink — the phone signs (sink, source-x, P) like any new session — whose source
// names the archived snapshot by its sha256. The router downloads the archive's snapshot onto its volume and serves it
// at GET /m/snapshot; the guard takes exactly the bytes whose hash the phone signed. The router checks the archive's
// own signatures first (the spawn cert's machine signed the snapshot), only to refuse a broken archive early.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

func (r *Router) restoresDir(sid string) string {
	return filepath.Join(r.cfg.DataDir, "restores", sid)
}

// RestoreRecord: the record's archived snapshot onto the volume, then a new session with the record's options,
// waiting for the phone (approval kind new-session, its source naming the snapshot; options.restore says what it is)
func (r *Router) RestoreRecord(recordID, requestID string) (string, error) {
	rec := r.record(recordID)
	if rec == nil {
		return "", errors.New("no such previous session")
	}
	if rec.Archive == nil {
		return "", errors.New("this session was destroyed without an archive: nothing to restore")
	}
	if rec.Archive.Signer == "" {
		return "", errHandIndex // records.go
	}
	box := r.box()
	if box == nil {
		return "", errNoStorageBox
	}
	dir := r.restoresDir("r" + randID())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	for _, f := range []string{"snapshot.tar.gz", "snapshot.sig", "spawn.json"} {
		found, err := box.Download(rec.Archive.Dir+"/jarvis2/"+f, filepath.Join(dir, f))
		if err != nil {
			return "", err
		}
		if !found {
			return "", fmt.Errorf("the archive has no jarvis2/%s", f)
		}
	}
	sum, err := checkRestoreFiles(dir)
	if err != nil {
		return "", err
	}
	if err := os.Rename(filepath.Join(dir, "snapshot.tar.gz"), r.st.snapshotPath(sum)); err != nil {
		return "", err
	}
	label := rec.Label
	if label == "" {
		label = rec.Archive.Title
	}
	what := label
	if what == "" {
		what = recordID
	}
	auto := rec.Live == nil || !rec.Live.AutoPauseOff
	return r.CreateSession(NewSession{RequestID: requestID, Label: label, Model: rec.Model, PermissionMode: rec.PermissionMode, Size: rec.Size,
		Harness: rec.Harness, Stores: rec.Stores, Repos: rec.Repos, Content: rec.Content, AutoPause: &auto, Snapshot: sum, RestoreFrom: recordID,
		RestoreShown: fmt.Sprintf("%s (destroyed %s)", what, rec.DestroyedAt.UTC().Format("2006-01-02"))})
}

// checkRestoreFiles: the router's own early check (the guard checks the hash the phone signed, and only its check
// counts): the snapshot is signed by the machine the archive's spawn cert names → the snapshot's sha256
func checkRestoreFiles(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "spawn.json"))
	if err != nil {
		return "", err
	}
	var nc kernel.NotarizedCert
	if json.Unmarshal(b, &nc) != nil || nc.Cert.Payload == "" {
		return "", errors.New("the archive's spawn.json isn't a notarized cert")
	}
	s, err := successionOf(nc.Cert)
	if err != nil || s.Signer != kernel.RoleSpawner || s.Successor.SigningKey == "" {
		return "", errors.New("the archive's spawn.json isn't a spawn cert naming a machine's key")
	}
	sig, err := os.ReadFile(filepath.Join(dir, "snapshot.sig"))
	if err != nil {
		return "", err
	}
	sum, err := sha256hex(filepath.Join(dir, "snapshot.tar.gz"))
	if err != nil {
		return "", err
	}
	if !kernel.Verify(s.Successor.SigningKey, []byte(sum), string(trimSpaceBytes(sig))) {
		return "", errors.New("the archived snapshot isn't signed by the machine its spawn cert names")
	}
	return sum, nil
}

func trimSpaceBytes(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// tidyRestores: a restoring session that came up is noted on the record it was restored from (once)
func (r *Router) tidyRestores() {
	type up struct{ sid, from string }
	var ups []up
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.RestoreFrom != "" && s.State == "started" {
				ups = append(ups, up{s.ID, s.RestoreFrom})
				s.RestoreFrom = ""
			}
		}
	})
	for _, u := range ups {
		r.markRestored(u.from, u.sid)
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
