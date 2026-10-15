package main

// A resume whose predecessor left no final snapshot (its machine died, or a pause without the snapshot that Deyao
// chose) never starts empty by itself when the line had state (2026-10-15). It becomes the phone's approval of a
// FALLBACK, a one-time input of the successor's cert (OnceInputs.Fallback, machine/fallback.go):
//
//   - the newest snapshot the line has (another of its machines' signed snapshots, still on the volume), and
//   - the newest live copy of each conversation transcript (livesync.go), as the line's machine sent and signed it,
//
// plus a resume prompt that tells the session what was restored and that work after the snapshot is gone. The phone
// shows all of it; the successor checks every byte against the cert (hashes) and the line's machine signatures. Only
// Deyao's explicit choice starts such a line empty (POST /api/sessions/{id}/resume {"startEmpty": true}). The image is
// the newest: older images refuse a one-time input they don't know.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// FallbackRef: OnceInputs.Fallback (machine/vouch.go FallbackRef)
type FallbackRef struct {
	Lost        string    `json:"lost"`              // the predecessor that left no snapshot
	Machine     string    `json:"machine,omitempty"` // the line's machine whose snapshot it restores ("" = none: transcripts only)
	Sha256      string    `json:"sha256,omitempty"`
	TakenAt     string    `json:"takenAt,omitempty"` // when that snapshot reached the router (RFC 3339)
	Transcripts []LiveRef `json:"transcripts,omitempty"`
}

// LiveRef: one live transcript copy the fallback takes
type LiveRef struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// LiveSigned: how a machine sent a live transcript copy (its request signature), so a successor can check it
type LiveSigned struct {
	Machine string `json:"machine"`
	At      string `json:"at"` // the request's X-Time
	Sig     string `json:"sig"`
	Sha256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// fallbackMaxTranscripts: the newest this many conversations (the cert's one-time inputs are at most 16 KB)
const fallbackMaxTranscripts = 40

// lineFallback: nil when the predecessor left its snapshot, or the line has nothing to fall back on (its state was
// empty, so an empty start loses nothing)
func (r *Router) lineFallback(s *Session) *FallbackRef {
	pred := certMachine(s.Cert)
	if pred == "" || r.hasFinalSnapshot(pred) {
		return nil
	}
	fb := &FallbackRef{Lost: pred}
	r.st.Do(func(d *persisted) {
		x := d.Sessions[s.ID]
		if x == nil || x.LiveSync == nil {
			return
		}
		var names []string
		for n := range x.LiveSync.Signed {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool { return x.LiveSync.Signed[names[i]].At > x.LiveSync.Signed[names[j]].At })
		for _, n := range names[:min(len(names), fallbackMaxTranscripts)] {
			l := x.LiveSync.Signed[n]
			fb.Transcripts = append(fb.Transcripts, LiveRef{Name: n, Sha256: l.Sha256, Size: l.Size})
		}
		sort.Slice(fb.Transcripts, func(i, j int) bool { return fb.Transcripts[i].Name < fb.Transcripts[j].Name })
	})
	if m, _, at := r.latestSnapshot(s.ID); m != "" {
		p := r.st.snapshotPath(m)
		sum, err := readTrimmed(p + ".sha256")
		if err != nil || sum == "" {
			sum, _, err = fileSha256(p)
		}
		if err == nil {
			fb.Machine, fb.Sha256, fb.TakenAt = m, sum, at.UTC().Format(time.RFC3339)
		}
	}
	if fb.Machine == "" && len(fb.Transcripts) == 0 {
		return nil
	}
	return fb
}

// withFallback: the session's one-time inputs with the fallback and the prompt that says what happened
func withFallback(once string, fb *FallbackRef) string {
	var o OnceInputs
	if once != "" {
		json.Unmarshal([]byte(once), &o)
	}
	o.Fallback = fb
	note := fallbackText(fb)
	if o.Prompt != "" {
		note += "\n\n" + o.Prompt
	}
	o.Prompt = note
	b, _ := json.Marshal(o)
	return string(b)
}

// fallbackText: the resume prompt of a fallback (the phone shows it with the rest of the one-time inputs)
func fallbackText(fb *FallbackRef) string {
	from := "no snapshot of its files (none was left), so ~/workspace and ~/artifacts start empty"
	if fb.Machine != "" {
		from = "the snapshot of machine " + fb.Machine + " taken " + fb.TakenAt + ", so ~/workspace and ~/artifacts are as they were then"
	}
	return fmt.Sprintf("Jarvis: this session's last machine (%s) left no final snapshot. It resumed from %s, plus the newest live copies of %d conversation transcript(s). "+
		"Work done after that snapshot (files, commits not pushed) may be gone: check what is missing (git status, the transcript, ~/artifacts) before carrying on. "+
		"This is an automated message from Jarvis, not from Deyao, and not an answer to any open question.", fb.Lost, from, len(fb.Transcripts))
}

func fallbackDMText(name string, fb *FallbackRef) string {
	from := "its newest conversation copies (no snapshot of its files is left)"
	if fb.Machine != "" {
		from = "its snapshot of " + fb.TakenAt + " plus its newest conversation copies"
	}
	return fmt.Sprintf("🟠 Session “%s” needs you — its last machine left no final snapshot. Approve its resume in the Inbox: it comes back from %s.", name, from)
}

func (r *Router) registerFallback(m machineRoute) {
	// the line's machine M: same session as the asking machine
	sameLine := func(asker, other string) bool {
		ok := false
		r.st.Do(func(d *persisted) {
			sid := d.Machines[asker]
			ok = sid != "" && d.Machines[other] == sid && d.Certs[other] != nil
		})
		return ok
	}
	m("GET /m/fallback/cert", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		other := req.URL.Query().Get("machine")
		if !sameLine(machine, other) {
			writeJSON(w, 404, map[string]string{"error": "no such machine on this line"})
			return
		}
		var cert *Doc
		r.st.Do(func(d *persisted) { cert = d.Certs[other] })
		writeJSON(w, 200, map[string]any{"cert": cert})
	})
	m("GET /m/fallback/snapshot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		other := req.URL.Query().Get("machine")
		if !sameLine(machine, other) {
			writeJSON(w, 404, map[string]string{"error": "no such machine on this line"})
			return
		}
		p := r.st.snapshotPath(other)
		sig, err := os.ReadFile(p + ".sig")
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no snapshot"})
			return
		}
		w.Header().Set("X-Snapshot-Sig", strings.TrimSpace(string(sig)))
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeFile(w, req, p)
	})
	m("GET /m/fallback/transcript", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		name := req.URL.Query().Get("name")
		var sid string
		var l *LiveSigned
		r.st.Do(func(d *persisted) {
			sid = d.Machines[machine]
			if s := d.Sessions[sid]; s != nil && s.LiveSync != nil {
				l = s.LiveSync.Signed[name]
			}
		})
		box := r.box()
		if l == nil || !liveNameRE.MatchString(name) || box == nil {
			writeJSON(w, 404, map[string]string{"error": "no live copy of that transcript"})
			return
		}
		b, err := box.Get(liveDir(sid) + "/" + name)
		if err != nil {
			log.Printf("[fallback] %s %s: %v", sid, name, err)
			writeJSON(w, 502, map[string]string{"error": "Storage Box: " + err.Error()})
			return
		}
		w.Header().Set("X-Live-Machine", l.Machine)
		w.Header().Set("X-Live-Time", l.At)
		w.Header().Set("X-Live-Sig", l.Sig)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write(b)
	})
}
