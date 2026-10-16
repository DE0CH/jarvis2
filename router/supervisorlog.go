package main

// The supervisor's log (Deyao, 2026-10-16): each session machine's supervisor (machine/supervisor.go) pushes its own
// log lines here (POST /m/supervisor-log), from its first second (also while it boots, before its first status
// report). The router keeps them per session on its volume (supervisor-log/<session>.jsonl), for the session's life,
// and the app and web page read them (GET /api/sessions/{id}/supervisor-log) next to the read-only terminal. The
// lifecycle log (lifecycle.go) merges the lines of an operation's machines into that operation's log. On Destroy both
// go into the session's Storage Box archive (jarvis2/supervisor-log.jsonl), then off the volume.
//
// The lines are the machine's own words: the supervisor writes no secret into them (machine side), and the router
// shows them only to Deyao's login.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	supLogMaxLines = 500  // per push
	supLogMaxLine  = 2000 // bytes per line (clipped)
	supLogReadMax  = 2000 // lines per read
)

// supLogMaxFile: a session's file is cut to its newer half past this (a var: tests shrink it)
var supLogMaxFile int64 = 20 << 20

type SupLine struct {
	Seq     int64  `json:"seq"`
	At      string `json:"at"`
	Machine string `json:"machine"`
	Text    string `json:"text"`
}

type supLogs struct {
	mu   sync.Mutex
	next map[string]int64 // session → the next seq (read from its file on first use)
}

func (r *Router) supLogPath(session string) string {
	return filepath.Join(r.cfg.DataDir, "supervisor-log", logFileName(session)+".jsonl")
}

// safeName: a session id as a file name (ids are [a-z0-9-]; anything else is replaced)
func logFileName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			b[i] = '_'
		}
	}
	if len(b) == 0 {
		return "_"
	}
	return string(b)
}

// readSupLog: every line of a session's file, in order
func readSupLog(p string) []SupLine {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []SupLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var l SupLine
		if json.Unmarshal(sc.Bytes(), &l) == nil {
			out = append(out, l)
		}
	}
	return out
}

// appendSupLog: lines of one machine onto its session's file, numbered; cut to the newer half past supLogMaxFile
func (r *Router) appendSupLog(session, machine string, lines []SupLine) error {
	r.sup.mu.Lock()
	defer r.sup.mu.Unlock()
	if r.lc.dropped(session) {
		return nil
	}
	p := r.supLogPath(session)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	next, ok := r.sup.next[session]
	if !ok {
		next = 1
		if all := readSupLog(p); len(all) > 0 {
			next = all[len(all)-1].Seq + 1
		}
	}
	var buf bytes.Buffer
	for _, l := range lines {
		l.Seq, l.Machine = next, machine
		next++
		b, _ := json.Marshal(l)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(buf.Bytes())
	f.Close()
	if err != nil {
		return err
	}
	r.sup.next[session] = next
	if fi, err := os.Stat(p); err == nil && fi.Size() > supLogMaxFile {
		all := readSupLog(p)
		keep := all[len(all)/2:]
		note := SupLine{Seq: keep[0].Seq - 1 /* a dropped line's: the seqs stay in order */, At: time.Now().UTC().Format(time.RFC3339Nano), Machine: "",
			Text: fmt.Sprintf("[router] the supervisor log passed %d MB: its %d oldest lines were dropped", supLogMaxFile>>20, len(all)-len(keep))}
		var out bytes.Buffer
		for _, l := range append([]SupLine{note}, keep...) {
			b, _ := json.Marshal(l)
			out.Write(b)
			out.WriteByte('\n')
		}
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, out.Bytes(), 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, p)
	}
	return nil
}

// supLogLines: a session's lines after seq after (at most limit), and the seq to ask after next
func (r *Router) supLogLines(session string, after int64, limit int) ([]SupLine, int64) {
	r.sup.mu.Lock()
	all := readSupLog(r.supLogPath(session))
	r.sup.mu.Unlock()
	out := []SupLine{}
	next := after
	for _, l := range all {
		if l.Seq <= after {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, l)
		next = l.Seq
	}
	return out, next
}

// dropSupLog: the session is gone (a record now, its archive holds the log)
func (r *Router) dropSupLog(session string) {
	r.sup.mu.Lock()
	defer r.sup.mu.Unlock()
	os.Remove(r.supLogPath(session))
	delete(r.sup.next, session)
}

func (r *Router) registerSupervisorLog(app appRoute, m machineRoute) {
	m("POST /m/supervisor-log", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Lines []struct {
				At   string `json:"at"`
				Text string `json:"text"`
			} `json:"lines"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "not JSON: " + err.Error()})
			return
		}
		if len(in.Lines) > supLogMaxLines {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("at most %d lines per push", supLogMaxLines)})
			return
		}
		var session string
		r.st.Do(func(d *persisted) { session = d.Machines[machine] })
		if session == "" {
			writeJSON(w, 404, map[string]string{"error": "this machine belongs to no session"})
			return
		}
		lines := make([]SupLine, 0, len(in.Lines))
		now := time.Now().UTC()
		for _, l := range in.Lines {
			at, err := time.Parse(time.RFC3339Nano, l.At)
			if err != nil || at.After(now.Add(time.Minute)) || at.Before(now.Add(-24*time.Hour)) {
				at = now // a machine clock off by a lot: the router's time
			}
			text := l.Text
			if len(text) > supLogMaxLine {
				text = text[:supLogMaxLine] + "…"
			}
			lines = append(lines, SupLine{At: at.UTC().Format(time.RFC3339Nano), Text: text})
		}
		if err := r.appendSupLog(session, machine, lines); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("GET /api/sessions/{id}/supervisor-log", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		found, machine := false, ""
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[id]; s != nil {
				found, machine = true, s.MachineID
			}
		})
		if !found {
			writeJSON(w, 404, map[string]string{"error": "no session " + id})
			return
		}
		after, _ := strconv.ParseInt(req.URL.Query().Get("after"), 10, 64)
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		if limit <= 0 || limit > supLogReadMax {
			limit = supLogReadMax
		}
		lines, next := r.supLogLines(id, after, limit)
		writeJSON(w, 200, map[string]any{"lines": lines, "next": next, "machine": machine})
	})
}
