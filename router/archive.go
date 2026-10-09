package main

// Archives of destroyed sessions, previous sessions and restoring one (Jarvis 1 lib/archive.js, server.js
// destroySession / records). docs/PARITY.md "Previous sessions".
//
// Destroy (flows.go) pauses a running session first, so its machine signs and uploads a final snapshot,
// then archive() writes it to the Storage Box with the router's own credentials, in Jarvis 1's layout so its
// transcript search indexes it:
//
//	claude-records/<yyyy-mm-dd> <title>/
//	  transcript-<id>.jsonl         every ~/.claude/projects/*/*.jsonl in the snapshot
//	  artifacts/**                  everything under ~/artifacts (symlinks followed inside the snapshot)
//	  session.json                  what the session was (title, stores, repos, model, …)
//	  restore-<session id>.json     which of the files are this session's (the dir may be shared)
//	  jarvis2/snapshot.tar.gz       the machine-signed snapshot, as it came from the machine
//	  jarvis2/snapshot.sig          its signature: the signer's signing key over sha256hex(snapshot)
//	  jarvis2/cert.json             the signer's core-signed succession cert (names its signing key)
//	  jarvis2/core-cert.json        the master-signed statement naming the core's key
//
// and adds the session to claude-records/.index/jarvis2-destroyed-sessions.json (Jarvis 1 keeps its own
// index, .index/destroyed-sessions.json; a separate file keeps each Jarvis's Previous list and purge to its
// own sessions). A reader verifies jarvis2/: core-cert against the master key → cert against the core key →
// snapshot against the cert's machine signing key.
//
// Restore (a destroyed session back as a NEW line): see restoreRecord.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	recordsRoot  = "claude-records"
	recordsIndex = recordsRoot + "/.index/jarvis2-destroyed-sessions.json"
	// changesFile: the repos' state, written by the machine into every snapshot (machine/restore.go)
	changesFile = ".jarvis2-changes.txt"
)

// repoChangesSH: one "<repo> <uncommitted files> <unpushed commits, -1 = no upstream>" line per repo under
// ~/workspace (the same script as Jarvis 1's REPO_CHANGES_SH and machine/restore.go's)
const repoChangesSH = `cd ~/workspace 2>/dev/null || exit 0; for d in */; do d=${d%/}; [ -d "$d/.git" ] || continue; ` +
	`u=$(git -C "$d" status --porcelain 2>/dev/null | wc -l); ` +
	`if git -C "$d" rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then p=$(git -C "$d" rev-list @{u}..HEAD --count 2>/dev/null || echo 0); else p=-1; fi; ` +
	`echo "$d $u $p"; done`

// ArchiveInfo: what a destroy put on the Storage Box
type ArchiveInfo struct {
	Dir         string       `json:"dir"`
	Title       string       `json:"title"`       // the title it was archived under
	Transcripts []string     `json:"transcripts"` // file names in Dir, oldest first
	Artifacts   int          `json:"artifacts"`
	Signer      string       `json:"signer"` // the machine whose snapshot it is
	SnapshotAt  time.Time    `json:"snapshotAt"`
	Last        *TailMessage `json:"last,omitempty"`
}

type RestoreMark struct {
	Session string    `json:"sessionId"`
	At      time.Time `json:"at"`
}

// ---- the Storage Box: the router's own credentials --------------------------------------------------

var (
	sboxOnce sync.Once
	sbox     *StorageBox
	indexMu  sync.Mutex // the index is read-modify-write and WebDAV has no append
)

func (r *Router) box() *StorageBox {
	sboxOnce.Do(func() { sbox = recordsBoxFromEnv() })
	return sbox
}

// recordsOff: RECORDS_OFF=1 (the e2e test, which has no Storage Box) destroys without archiving
func recordsOff() bool { return os.Getenv("RECORDS_OFF") == "1" }

// ---- the archive dir ---------------------------------------------------------------------------------

// archiveDirFor: the dir for a title (archivedir.go's layout); a leading "." would hide it from the search
func archiveDirFor(s *Session, title string) string {
	c := *s
	c.ArchiveDir, c.UserTitle, c.Label, c.Title = "", "", strings.TrimLeft(title, ". "), ""
	return (&Router{}).archiveDir(c)
}

// pickArchiveDir: the session's dir, made unique against what is already on the box (Jarvis 1 or another
// session may have the same date and title) and kept on the session, so a retried destroy and the destroy
// hooks (the Discord export) use the same one
func (r *Router) pickArchiveDir(box *StorageBox, s *Session, title string) (string, error) {
	if s.ArchiveDir != "" {
		return s.ArchiveDir, nil
	}
	base := archiveDirFor(s, title)
	dir := base
	for i := 2; ; i++ {
		taken, err := box.Exists(dir + "/session.json")
		if err != nil {
			return "", err
		}
		if !taken {
			break
		}
		if i > 50 {
			return "", fmt.Errorf("no free archive dir next to %s", base)
		}
		dir = base + " " + strconv.Itoa(i)
	}
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[s.ID]; x != nil {
			x.ArchiveDir = dir
		}
	})
	s.ArchiveDir = dir
	return dir, nil
}

// ---- the snapshot to archive ---------------------------------------------------------------------------

// latestSnapshot: the newest snapshot any of the session's machines left on the volume, and that machine's
// cert (its signing key checks the snapshot)
func (r *Router) latestSnapshot(sessionID string) (machine string, cert *Doc, at time.Time) {
	var machines []string
	certs := map[string]*Doc{}
	r.st.Do(func(d *persisted) {
		for m, sid := range d.Machines {
			if sid == sessionID {
				machines = append(machines, m)
				certs[m] = d.Certs[m]
			}
		}
	})
	for _, m := range machines {
		p := r.st.snapshotPath(m)
		fi, err := os.Stat(p)
		if err != nil || certs[m] == nil {
			continue
		}
		if _, err := os.Stat(p + ".sig"); err != nil {
			continue
		}
		if machine == "" || fi.ModTime().After(at) {
			machine, cert, at = m, certs[m], fi.ModTime()
		}
	}
	return
}

// ---- destroy: snapshot + kill, then archive ------------------------------------------------------------

// snapshotAndKill: what Pause does to a running machine (flows.go); false (state failed) when the kill fails
func (r *Router) snapshotAndKill(id, machine string) bool {
	done := r.awaitSnapshot(machine)
	r.send(machine, "snapshot")
	select {
	case <-done:
	case <-time.After(r.cfg.SnapshotWait):
		log.Printf("session %s: no snapshot from %s within %s; destroying from the last one", id, machine, r.cfg.SnapshotWait)
	}
	if _, err := r.core.Call("/kill", map[string]string{"machine": machine}); err != nil {
		r.setState(id, "failed", "kill: "+err.Error())
		return false
	}
	now := time.Now().UTC()
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			x.MachineID, x.PausedAt, x.Status = "", &now, ""
		}
	})
	return true
}

// archive: the session's latest snapshot onto the Storage Box (layout at the top). nil when there is
// nothing to archive (no snapshot: the session never ran or never snapshotted) or records are off. Then the
// destroy hooks run (the Discord export into the same dir).
func (r *Router) archive(id string) (*ArchiveInfo, error) {
	if recordsOff() {
		return nil, nil
	}
	if m, _, _ := r.latestSnapshot(id); m == "" {
		log.Printf("session %s: no snapshot to archive", id)
		return nil, nil
	}
	box := r.box()
	if box == nil {
		return nil, errNoStorageBox
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, fmt.Errorf("no session %s", id)
	}
	info, err := r.archiveSnapshot(box, &s)
	if err == nil && info != nil {
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.ArchiveDir = info.Dir
			}
		})
	}
	return info, err
}

func (r *Router) archiveSnapshot(box *StorageBox, s *Session) (*ArchiveInfo, error) {
	machine, cert, at := r.latestSnapshot(s.ID)
	if machine == "" {
		log.Printf("session %s: no snapshot to archive", s.ID)
		return nil, nil
	}
	snap := r.st.snapshotPath(machine)
	facts, err := readSnapshotFacts(snap)
	if err != nil {
		return nil, fmt.Errorf("reading the snapshot: %w", err)
	}
	title := sessionTitle(*s)
	if s.Label == "" && s.UserTitle == "" && facts.Tail != nil && facts.Tail.Title != "" {
		title = facts.Tail.Title // the title the app showed, from the transcript
	}
	dir, err := r.pickArchiveDir(box, s, title)
	if err != nil {
		return nil, err
	}
	if err := box.Mkcols(dir + "/jarvis2"); err != nil {
		return nil, err
	}
	tmp := filepath.Join(r.cfg.DataDir, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, err
	}
	up, err := uploadSnapshotFiles(box, dir, snap, tmp)
	if err != nil {
		return nil, err
	}
	// the signed snapshot and what verifies it
	sig, err := os.ReadFile(snap + ".sig")
	if err != nil {
		return nil, err
	}
	certJSON, _ := json.Marshal(cert)
	if err := box.PutFile(dir+"/jarvis2/snapshot.tar.gz", snap); err != nil {
		return nil, err
	}
	if err := box.PutBytes(dir+"/jarvis2/snapshot.sig", []byte(strings.TrimSpace(string(sig)))); err != nil {
		return nil, err
	}
	if err := box.PutBytes(dir+"/jarvis2/cert.json", certJSON); err != nil {
		return nil, err
	}
	if st, b, err := r.core.Raw("GET", "/core-cert", nil); err == nil && st == 200 {
		if err := box.PutBytes(dir+"/jarvis2/core-cert.json", b); err != nil {
			return nil, err
		}
	}
	info := &ArchiveInfo{Dir: dir, Title: title, Transcripts: up.transcripts, Artifacts: up.artifacts, Signer: machine, SnapshotAt: at.UTC()}
	if facts.Tail != nil {
		info.Last = snippet(*facts.Tail)
	}
	now := time.Now().UTC()
	meta := map[string]any{
		"id": s.ID, "jarvis": 2, "title": title, "label": s.Label, "aiTitle": s.Title, "created": s.Created,
		"destroyedAt": now, "archiveDir": dir, "environment": strings.Join(s.Stores, ","), "stores": s.Stores,
		"repos": s.Repos, "model": s.Model, "permissionMode": s.PermissionMode, "size": s.Size, "harness": s.Harness,
		"image": s.Image, "line": certField(cert, "line"), "snapshotMachine": machine, "snapshotAt": info.SnapshotAt,
		"unresolvedArtifactLinks": up.unresolved,
	}
	mb, _ := json.MarshalIndent(meta, "", " ")
	if err := box.PutBytes(dir+"/session.json", mb); err != nil {
		return nil, err
	}
	man, _ := json.Marshal(map[string]any{"id": s.ID, "archiveDir": dir, "transcripts": up.transcripts, "artifacts": up.artifactNames,
		"snapshot": "jarvis2/snapshot.tar.gz", "signer": machine})
	if err := box.PutBytes(dir+"/restore-"+s.ID+".json", man); err != nil {
		return nil, err
	}
	entry := map[string]any{"id": s.ID, "jarvis": 2, "title": title, "label": s.Label, "archiveDir": dir, "created": s.Created,
		"destroyedAt": now, "transcripts": len(up.transcripts), "artifacts": up.artifacts, "last": info.Last,
		"environment": strings.Join(s.Stores, ","), "repos": s.Repos, "model": s.Model, "size": s.Size, "harness": s.Harness,
		"permissionMode": s.PermissionMode, "restored": []any{}}
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
	log.Printf("session %s: archived to %s (%d transcript(s), %d artifact file(s))", s.ID, dir, len(up.transcripts), up.artifacts)
	return info, nil
}

type uploaded struct {
	transcripts   []string // archive names, oldest first
	artifacts     int
	artifactNames []string
	unresolved    []string
}

// uploadSnapshotFiles: the transcripts and ~/artifacts out of the snapshot, as plain files. Two passes: the
// first learns the names, the modification times and the symlinks under artifacts/ (followed when they
// point inside the snapshot, like Jarvis 1's `find -L`), the second uploads.
func uploadSnapshotFiles(box *StorageBox, dir, snap, tmp string) (*uploaded, error) {
	type entry struct {
		at time.Time
	}
	regular := map[string]entry{}
	links := map[string]string{}
	err := walkTar(snap, func(h *tar.Header, _ io.Reader) error {
		name := path.Clean(h.Name)
		switch h.Typeflag {
		case tar.TypeReg:
			regular[name] = entry{h.ModTime}
		case tar.TypeSymlink:
			if strings.HasPrefix(name, "artifacts/") {
				links[name] = h.Linkname
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := &uploaded{}
	dests := map[string][]string{} // snapshot name → archive names
	var transcripts []string
	for name := range regular {
		if isTranscript(name) {
			transcripts = append(transcripts, name)
			dests[name] = append(dests[name], "transcript-"+path.Base(name))
		} else if strings.HasPrefix(name, "artifacts/") {
			dests[name] = append(dests[name], name)
		}
	}
	for l, target := range links {
		t := resolveLink(l, target)
		if t == "" {
			out.unresolved = append(out.unresolved, l)
			continue
		}
		hit := false
		for name := range regular {
			switch {
			case name == t:
				dests[name] = append(dests[name], l)
				hit = true
			case strings.HasPrefix(name, t+"/"):
				dests[name] = append(dests[name], l+strings.TrimPrefix(name, t))
				hit = true
			}
		}
		if !hit {
			out.unresolved = append(out.unresolved, l)
		}
	}
	sort.Slice(transcripts, func(i, j int) bool {
		a, b := regular[transcripts[i]].at, regular[transcripts[j]].at
		if a.Equal(b) {
			return transcripts[i] < transcripts[j]
		}
		return a.Before(b)
	})
	for _, t := range transcripts {
		out.transcripts = append(out.transcripts, "transcript-"+path.Base(t))
	}
	sort.Strings(out.unresolved)
	made := map[string]bool{}
	err = walkTar(snap, func(h *tar.Header, body io.Reader) error {
		name := path.Clean(h.Name)
		ds := dests[name]
		if h.Typeflag != tar.TypeReg || len(ds) == 0 {
			return nil
		}
		f, err := os.CreateTemp(tmp, "archive-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		_, err = io.Copy(f, body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		for _, d := range ds {
			if p := path.Dir(d); p != "." && !made[p] {
				if err := box.Mkcols(dir + "/" + p); err != nil {
					return err
				}
				made[p] = true
			}
			if err := box.PutFile(dir+"/"+d, f.Name()); err != nil {
				return err
			}
			if strings.HasPrefix(d, "artifacts/") {
				out.artifacts++
				out.artifactNames = append(out.artifactNames, strings.TrimPrefix(d, "artifacts/"))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out.artifactNames)
	return out, nil
}

// resolveLink: a symlink's target as a path in the snapshot ("" when it points outside it)
func resolveLink(link, target string) string {
	const home = "/home/claude/"
	var t string
	if path.IsAbs(target) {
		if !strings.HasPrefix(target, home) {
			return ""
		}
		t = path.Clean(strings.TrimPrefix(target, home))
	} else {
		t = path.Clean(path.Join(path.Dir(link), target))
	}
	if t == "." || t == ".." || strings.HasPrefix(t, "../") || path.IsAbs(t) {
		return ""
	}
	return t
}

func walkTar(p string, fn func(h *tar.Header, body io.Reader) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(h, tr); err != nil {
			return err
		}
	}
}

func updateIndex(box *StorageBox, fn func([]map[string]any) []map[string]any) error {
	indexMu.Lock()
	defer indexMu.Unlock()
	raw, err := box.Get(recordsIndex)
	if err != nil {
		return err
	}
	var list []map[string]any
	if raw != nil {
		if err := json.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("%s is not a JSON array: %w", recordsIndex, err)
		}
	}
	next := fn(list)
	if err := box.Mkcols(path.Dir(recordsIndex)); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(next, "", " ")
	return box.PutBytes(recordsIndex, b)
}

// ---- the uncommitted-work check ----------------------------------------------------------------------

type RepoChange struct {
	Name        string `json:"name"`
	Uncommitted int    `json:"uncommitted"`
	Unpushed    int    `json:"unpushed"` // -1: the branch has no upstream
}

func parseRepoChanges(text string) []RepoChange {
	out := []RepoChange{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		u, _ := strconv.Atoi(f[1])
		p, err := strconv.Atoi(f[2])
		if err != nil {
			p = 0
		}
		out = append(out, RepoChange{f[0], u, p})
	}
	return out
}

// Changes: a running session's repos (a command under the archive holder's grant), or a paused session's as
// its last snapshot recorded them
func (r *Router) Changes(id string) map[string]any {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	no := func(reason string) map[string]any {
		return map[string]any{"checked": false, "reason": reason, "repos": []RepoChange{}}
	}
	switch {
	case s.ID == "":
		return no("no such session")
	case s.MachineID != "" && s.State == "started":
		res, err := r.Exec(id, "archive", repoChangesSH, 20*time.Second)
		if err != nil {
			return no(err.Error())
		}
		return map[string]any{"checked": true, "repos": parseRepoChanges(res.Stdout), "status": s.Status}
	case s.MachineID == "" && s.State == "paused":
		m, _, _ := r.latestSnapshot(id)
		if m == "" {
			return no("it has no pause snapshot")
		}
		facts, err := readSnapshotFacts(r.st.snapshotPath(m))
		if err != nil {
			return no(err.Error())
		}
		if facts.Changes == nil {
			return no("its pause snapshot has no record of the repos' state — resume it and check again")
		}
		return map[string]any{"checked": true, "paused": true, "repos": parseRepoChanges(*facts.Changes), "status": ""}
	}
	return no("session is " + s.State)
}

// ---- tails ------------------------------------------------------------------------------------------

// PausedTail: the end of a paused session's conversation, from its snapshot on the volume
func (r *Router) PausedTail(id string) (*Tail, int, error) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, 404, errors.New("no such session")
	}
	if s.MachineID != "" {
		return nil, 409, fmt.Errorf("the session is %s, not paused — its pause snapshot (if any) is out of date", s.State)
	}
	m, _, _ := r.latestSnapshot(id)
	if m == "" {
		return nil, 404, errors.New("this session has no pause snapshot")
	}
	facts, err := readSnapshotFacts(r.st.snapshotPath(m))
	if err != nil {
		return nil, 500, err
	}
	if facts.Tail == nil {
		return &Tail{Messages: []TailMessage{}}, 200, nil
	}
	return facts.Tail, 200, nil
}

func (r *Router) record(id string) *Record {
	var rec *Record
	r.st.Do(func(d *persisted) {
		for _, x := range d.Records {
			if x.ID == id {
				c := *x
				rec = &c
			}
		}
	})
	return rec
}

// RecordTail: the end of a destroyed session's conversation, from its archive (a Range read)
func (r *Router) RecordTail(id string) (*Tail, int, error) {
	rec := r.record(id)
	if rec == nil {
		return nil, 404, errors.New("no such previous session")
	}
	if rec.Archive == nil || len(rec.Archive.Transcripts) == 0 {
		return nil, 404, errors.New("this session was destroyed without an archived transcript")
	}
	box := r.box()
	if box == nil {
		return nil, 500, errNoStorageBox
	}
	p := rec.Archive.Dir + "/" + rec.Archive.Transcripts[len(rec.Archive.Transcripts)-1]
	text, err := box.GetTail(p, tailBytes)
	if err != nil {
		return nil, 500, err
	}
	if text == nil {
		return nil, 404, fmt.Errorf("transcript missing: %s", p)
	}
	if len(text) > tailBytes {
		text = text[len(text)-tailBytes:]
	}
	t := tailOf(text)
	return &t, 200, nil
}

// ---- forget / purge a record ------------------------------------------------------------------------

// DeleteRecord: off the list (and the box's index); with purge its archive too — the whole dir unless
// another Jarvis 2 record shares it, then only this session's own files
func (r *Router) DeleteRecord(id string, purge bool) (map[string]any, error) {
	rec := r.record(id)
	if rec == nil {
		return nil, errors.New("no such previous session")
	}
	box := r.box()
	out := map[string]any{"ok": true}
	if purge && rec.Archive != nil {
		if box == nil {
			return nil, errNoStorageBox
		}
		dir := rec.Archive.Dir
		if !regexp.MustCompile(`^claude-records/[^/.][^/]*$`).MatchString(dir) {
			return nil, fmt.Errorf("refusing to delete '%s': not a claude-records/<folder> archive dir", dir)
		}
		keep := map[string]bool{}
		shared := []string{}
		r.st.Do(func(d *persisted) {
			for _, o := range d.Records {
				if o.ID != id && o.Archive != nil && o.Archive.Dir == dir {
					shared = append(shared, o.ID)
					for _, t := range o.Archive.Transcripts {
						keep[t] = true
					}
				}
			}
		})
		if len(shared) == 0 {
			if err := box.Delete(dir + "/"); err != nil {
				return nil, err
			}
			out["purged"] = map[string]any{"dir": dir, "removed": "folder"}
		} else {
			files := []string{"restore-" + id + ".json"}
			for _, t := range rec.Archive.Transcripts {
				if !keep[t] {
					files = append(files, t)
				}
			}
			for _, f := range files {
				if err := box.Delete(dir + "/" + f); err != nil {
					return nil, err
				}
			}
			out["purged"] = map[string]any{"dir": dir, "removed": "files", "files": files, "sharedWith": shared}
		}
	}
	if box != nil {
		if err := updateIndex(box, func(list []map[string]any) []map[string]any {
			out := []map[string]any{}
			for _, e := range list {
				if e["id"] != id {
					out = append(out, e)
				}
			}
			return out
		}); err != nil {
			return nil, err
		}
	}
	r.st.Do(func(d *persisted) {
		keep := d.Records[:0]
		for _, x := range d.Records {
			if x.ID != id {
				keep = append(keep, x)
			}
		}
		d.Records = keep
	})
	return out, nil
}

// ---- routes ---------------------------------------------------------------------------------------

func (r *Router) registerArchive(app appRoute, m machineRoute) {
	app("GET /api/sessions/{id}/changes", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, r.Changes(req.PathValue("id")))
	})
	app("GET /api/sessions/{id}/tail", func(w http.ResponseWriter, req *http.Request) {
		t, st, err := r.PausedTail(req.PathValue("id"))
		if err != nil {
			writeJSON(w, st, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, t)
	})
	app("GET /api/records/{id}/tail", func(w http.ResponseWriter, req *http.Request) {
		t, st, err := r.RecordTail(req.PathValue("id"))
		if err != nil {
			writeJSON(w, st, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, t)
	})
	app("DELETE /api/records/{id}", func(w http.ResponseWriter, req *http.Request) {
		out, err := r.DeleteRecord(req.PathValue("id"), req.URL.Query().Get("purge") == "1")
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	app("POST /api/records/{id}/restore", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			RequestID string `json:"requestId"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		if in.RequestID == "" {
			in.RequestID = randID()
		}
		sid, err := r.RestoreRecord(req.PathValue("id"), in.RequestID)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"id": sid, "requestId": in.RequestID})
	})
	m("GET /m/restore-snapshot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		dir := r.restoreFilesFor(machine)
		if dir == "" {
			writeJSON(w, 404, map[string]string{"error": "no restore for this machine"})
			return
		}
		sig, err := os.ReadFile(filepath.Join(dir, "snapshot.sig"))
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no restore snapshot"})
			return
		}
		w.Header().Set("X-Snapshot-Sig", strings.TrimSpace(string(sig)))
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeFile(w, req, filepath.Join(dir, "snapshot.tar.gz"))
	})
}

// sha256hex: what a machine signs for a snapshot
func sha256hex(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (r *Router) archiveLoop() {
	for {
		r.tidyRestores()
		time.Sleep(time.Minute)
	}
}
