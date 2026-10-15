package main

// The live copies go into the archive before any of them goes (2026-10-15: destroying session sb8e0273d6c308894
// deleted claude-records/.live/sb8e0273d6c308894/, which held its ORIGINAL conversation — its machine's snapshot had
// failed, the session went on under a new conversation, and the archive took only the latest snapshot's
// transcripts, so the original had no other copy).
//
//   - An archive copies EVERY transcript in the session's .live dir that the snapshot doesn't already hold
//     byte-identical (same size and sha256) into the record: transcript-<uuid>.jsonl, or transcript-<uuid>.live.jsonl
//     when the snapshot holds a different version of that conversation. Each copy is read back and checked (size and
//     sha256) before it counts. The record lists them all (ArchiveInfo.Live).
//   - A session with no snapshot but live copies still gets a record: the live transcripts and session.json, which
//     notes that there is no snapshot (nothing to restore).
//   - clearArchivedLive deletes only the .live files the archive accounted for, each still the size it had then; the
//     dir goes only once it is empty. Anything else (no archive, a failed one, a file that came or changed since)
//     stays, and the record says so (Record.LiveKept). There is no other path that deletes .live copies.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LiveCopy: one .live transcript as the archive accounted for it
type LiveCopy struct {
	Name   string `json:"name"` // its name in claude-records/.live/<session id>/
	Size   int64  `json:"size"`
	Sha256 string `json:"sha256"`
	// In: where the record holds it — "snapshot" (the signed snapshot has it byte-identical, and so its transcript-…
	// file), else the file in the archive dir it was copied to
	In string `json:"in"`
}

type fileSum struct {
	size int64
	sha  string
}

// sumFile: a local file's size and sha256
func sumFile(p string) (fileSum, error) {
	f, err := os.Open(p)
	if err != nil {
		return fileSum{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fileSum{}, err
	}
	return fileSum{n, hex.EncodeToString(h.Sum(nil))}, nil
}

// boxSum: a Storage Box file's size and sha256 (downloaded into tmp); ok false when it is missing
func boxSum(box *StorageBox, p, tmp string) (fileSum, bool, error) {
	f, err := os.CreateTemp(tmp, "livesum-*")
	if err != nil {
		return fileSum{}, false, err
	}
	f.Close()
	defer os.Remove(f.Name())
	found, err := box.Download(p, f.Name())
	if err != nil || !found {
		return fileSum{}, false, err
	}
	s, err := sumFile(f.Name())
	return s, err == nil, err
}

// archiveLive: every .live transcript of the session into dir, unless held (snapshot transcript name → sum) has it
// byte-identical; taken: the file names dir already uses. Returns the accounting (sorted by name) and the archive
// names it added (for the record's transcripts). Any error: nothing may be deleted from .live.
func (r *Router) archiveLive(box *StorageBox, sid, dir string, held map[string]fileSum, taken map[string]bool) ([]LiveCopy, []string, error) {
	listed, err := box.List(liveDir(sid))
	if err != nil {
		return nil, nil, fmt.Errorf("listing the live copies: %w", err)
	}
	if len(listed) == 0 {
		return nil, nil, nil
	}
	tmp := filepath.Join(r.cfg.DataDir, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(listed))
	for n := range listed {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []LiveCopy
	var added []string
	for _, name := range names {
		if !liveNameRE.MatchString(name) {
			log.Printf("[livesync] %s: %q in the live dir isn't a transcript: left there", sid, name)
			continue
		}
		c, dest, err := r.archiveLiveFile(box, sid, dir, name, listed[name], tmp, held, taken)
		if err != nil {
			return nil, nil, fmt.Errorf("copying the live transcript %s into the archive: %w", name, err)
		}
		if c == nil {
			continue // gone since the listing
		}
		out = append(out, *c)
		if dest != "" {
			added = append(added, dest)
			taken[dest] = true
		}
	}
	return out, added, nil
}

// archiveLiveFile: one .live transcript; dest = the archive file it now has ("" when the snapshot holds it)
func (r *Router) archiveLiveFile(box *StorageBox, sid, dir, name string, listedSize int64, tmp string, held map[string]fileSum, taken map[string]bool) (*LiveCopy, string, error) {
	f, err := os.CreateTemp(tmp, "live-*")
	if err != nil {
		return nil, "", err
	}
	f.Close()
	defer os.Remove(f.Name())
	found, err := box.Download(liveDir(sid)+"/"+name, f.Name())
	if err != nil {
		return nil, "", err
	}
	if !found {
		return nil, "", nil
	}
	sum, err := sumFile(f.Name())
	if err != nil {
		return nil, "", err
	}
	if sum.size != listedSize {
		return nil, "", fmt.Errorf("it changed while being read (%d bytes listed, %d read)", listedSize, sum.size)
	}
	c := &LiveCopy{Name: name, Size: sum.size, Sha256: sum.sha}
	if h, ok := held[name]; ok && h == sum {
		c.In = "snapshot"
		return c, "", nil
	}
	stem := strings.TrimSuffix(name, ".jsonl")
	for i := 1; i <= 50; i++ {
		dest := "transcript-" + name
		if _, inSnapshot := held[name]; inSnapshot || i > 1 {
			dest = "transcript-" + stem + ".live.jsonl" // the snapshot's version of this conversation differs
			if i > 1 {
				dest = "transcript-" + stem + ".live-" + strconv.Itoa(i) + ".jsonl"
			}
		}
		if taken[dest] {
			continue
		}
		have, exists, err := boxSum(box, dir+"/"+dest, tmp)
		if err != nil {
			return nil, "", err
		}
		if exists && have != sum {
			continue // another file by that name (a dir shared with another record)
		}
		if !exists {
			if err := box.PutFile(dir+"/"+dest, f.Name()); err != nil {
				return nil, "", err
			}
			if have, exists, err = boxSum(box, dir+"/"+dest, tmp); err != nil {
				return nil, "", fmt.Errorf("reading the copy back: %w", err)
			}
			if !exists || have != sum {
				return nil, "", fmt.Errorf("the copy %s doesn't match (%d bytes %s, want %d bytes %s)", dest, have.size, have.sha, sum.size, sum.sha)
			}
		}
		c.In = dest
		return c, dest, nil
	}
	return nil, "", fmt.Errorf("no free name for it in %s", dir)
}

// archiveLiveOnly: a session with no signed snapshot but live copies: a record of the live transcripts alone, its
// session.json noting that there is no snapshot (so nothing to restore). nil when there is no live copy either.
func (r *Router) archiveLiveOnly(box *StorageBox, s *Session) (*ArchiveInfo, error) {
	listed, err := box.List(liveDir(s.ID))
	if err != nil {
		return nil, fmt.Errorf("listing the live copies: %w", err)
	}
	if len(listed) == 0 {
		return nil, nil
	}
	title := sessionTitle(*s)
	dir, err := r.pickArchiveDir(box, s, title)
	if err != nil {
		return nil, err
	}
	if err := box.Mkcols(dir); err != nil {
		return nil, err
	}
	live, added, err := r.archiveLive(box, s.ID, dir, map[string]fileSum{}, map[string]bool{})
	if err != nil {
		return nil, err
	}
	why := "the session left no signed snapshot"
	if s.NoSnapshot != "" {
		why += " (" + s.NoSnapshot + ")"
	}
	why += ": this record holds only its live transcript copies, so it can't be restored"
	if added == nil {
		added = []string{}
	}
	info := &ArchiveInfo{Dir: dir, Title: title, Transcripts: added, Live: live, NoSnapshot: why}
	now := time.Now().UTC()
	meta := map[string]any{
		"id": s.ID, "jarvis": 2, "title": title, "label": s.Label, "aiTitle": s.Title, "created": s.Created,
		"destroyedAt": now, "archiveDir": dir, "environment": strings.Join(s.Stores, ","), "stores": s.Stores,
		"repos": s.Repos, "model": s.Model, "permissionMode": s.PermissionMode, "size": s.Size, "harness": s.Harness,
		"image": s.Image, "line": certField(s.Cert, "line"), "snapshot": nil, "noSnapshot": why, "live": live,
	}
	mb, _ := json.MarshalIndent(meta, "", " ")
	if err := box.PutBytes(dir+"/session.json", mb); err != nil {
		return nil, err
	}
	man, _ := json.Marshal(map[string]any{"id": s.ID, "archiveDir": dir, "transcripts": added, "artifacts": []string{}, "snapshot": nil})
	if err := box.PutBytes(dir+"/restore-"+s.ID+".json", man); err != nil {
		return nil, err
	}
	entry := map[string]any{"id": s.ID, "jarvis": 2, "title": title, "label": s.Label, "archiveDir": dir, "created": s.Created,
		"destroyedAt": now, "transcripts": len(added), "artifacts": 0, "environment": strings.Join(s.Stores, ","), "repos": s.Repos,
		"model": s.Model, "size": s.Size, "harness": s.Harness, "permissionMode": s.PermissionMode, "restored": []any{}, "noSnapshot": why}
	if err := updateIndex(box, func(list []map[string]any) []map[string]any {
		out := []map[string]any{entry}
		for _, e := range list {
			if e["id"] != s.ID {
				out = append(out, e)
			}
		}
		return out
	}); err != nil {
		return nil, fmt.Errorf("indexing the archive: %w", err)
	}
	log.Printf("session %s: no snapshot; archived its %d live transcript(s) to %s", s.ID, len(added), dir)
	return info, nil
}

// clearArchivedLive: the .live files the archive accounted for go (each only while it is still the size it had);
// "" when the dir is gone, else what was kept and why (for the record and the log)
func (r *Router) clearArchivedLive(sid string, archived *ArchiveInfo, aerr error) string {
	liveDirs.Delete(sid)
	box := r.box()
	if box == nil || recordsOff() {
		return ""
	}
	listed, err := box.List(liveDir(sid))
	if err != nil {
		msg := fmt.Sprintf("the live copies in %s/ were kept (listing them failed: %v)", liveDir(sid), err)
		log.Printf("[livesync] %s: %s", sid, msg)
		return msg
	}
	if len(listed) == 0 {
		if listed != nil { // an empty dir
			box.Delete(liveDir(sid) + "/")
		}
		return ""
	}
	done := map[string]LiveCopy{}
	if archived != nil && aerr == nil {
		for _, c := range archived.Live {
			done[c.Name] = c
		}
	}
	var kept []string
	for name, size := range listed {
		c, ok := done[name]
		if !ok || c.Size != size {
			kept = append(kept, name)
			continue
		}
		if err := box.Delete(liveDir(sid) + "/" + name); err != nil {
			log.Printf("[livesync] %s: removing the archived live copy %s: %v", sid, name, err)
			kept = append(kept, name)
		}
	}
	if len(kept) == 0 {
		if err := box.Delete(liveDir(sid) + "/"); err != nil {
			log.Printf("[livesync] %s: removing the empty live dir: %v", sid, err)
		}
		return ""
	}
	sort.Strings(kept)
	why := "not in the archive"
	switch {
	case aerr != nil:
		why = "the archive failed: " + aerr.Error()
	case archived == nil:
		why = "there is no archive"
	}
	msg := fmt.Sprintf("kept %d live transcript(s) in %s/ (%s): %s", len(kept), liveDir(sid), why, strings.Join(kept, ", "))
	log.Printf("[livesync] %s: %s", sid, msg)
	return msg
}
