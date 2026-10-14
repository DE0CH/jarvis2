package main

// The guard's records (~/.jarvis2-guard.json, in snapshotPaths): what needs memory across the session's life, carried
// from machine to machine in the snapshot whose hash the kill's source names.
//
//   - once: every once:<id> condition already used (a grant with a used id is refused);
//   - the session's own texts: its wakeups, crons and watches (the prompt stays here; the router only schedules them
//     and later says "X is due" / "X fired"), its lease notes (by device) and its Inbox filings (by filing id), with
//     what was already delivered of each.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const recordsFile = ".jarvis2-guard.json"

type wakeupText struct {
	Name      string `json:"name"`
	Prompt    string `json:"prompt"`
	Delivered string `json:"delivered,omitempty"`
}

type cronText struct {
	Name         string `json:"name"`
	Prompt       string `json:"prompt"`
	EverySeconds int64  `json:"everySeconds"`
	Until        int64  `json:"until,omitempty"` // unix ms, 0 = none (as the session armed it)
	LastRun      int    `json:"lastRun"`
	LastAt       int64  `json:"lastAt"` // unix seconds
}

type watchText struct {
	Name       string `json:"name"`
	Script     string `json:"script"`
	Prompt     string `json:"prompt"`
	FailPrompt string `json:"failPrompt,omitempty"`
	Delivered  string `json:"delivered,omitempty"`
}

type filing struct {
	Path string          `json:"path"` // e.g. /api/requests/add-store
	Body json.RawMessage `json:"body"`
	Told map[string]bool `json:"told,omitempty"` // item index → its outcome was delivered
}

type recordsData struct {
	Once    map[string]string     `json:"once"`
	Wakeups map[string]wakeupText `json:"wakeups"`
	Crons   map[string]cronText   `json:"crons"`
	Watches map[string]watchText  `json:"watches"`
	Leases  map[string]string     `json:"leases"`
	Filings map[string]filing     `json:"filings"`
}

// records: the file, read and written whole under one lock (one process, the guard, writes it)
type records struct {
	mu   sync.Mutex
	path string
}

func newRecords(home string) *records { return &records{path: filepath.Join(home, recordsFile)} }

func (r *records) load() recordsData {
	d := recordsData{}
	if b, err := os.ReadFile(r.path); err == nil {
		json.Unmarshal(b, &d)
	}
	if d.Once == nil {
		d.Once = map[string]string{}
	}
	if d.Wakeups == nil {
		d.Wakeups = map[string]wakeupText{}
	}
	if d.Crons == nil {
		d.Crons = map[string]cronText{}
	}
	if d.Watches == nil {
		d.Watches = map[string]watchText{}
	}
	if d.Leases == nil {
		d.Leases = map[string]string{}
	}
	if d.Filings == nil {
		d.Filings = map[string]filing{}
	}
	return d
}

func (r *records) save(d recordsData) error {
	b, _ := json.Marshal(d)
	return writeAtomic(r.path, b)
}

// update: fn changes the records (an error leaves them as they were)
func (r *records) update(fn func(*recordsData) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.load()
	if err := fn(&d); err != nil {
		return err
	}
	return r.save(d)
}

func (r *records) read() recordsData {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.load()
}

func (r *records) onceUsed(id string) bool {
	_, ok := r.read().Once[id]
	return ok
}

// useOnce: records every id, or refuses (recording none) when one was already used
func (r *records) useOnce(ids []string, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	return r.update(func(d *recordsData) error {
		for _, id := range ids {
			if _, ok := d.Once[id]; ok {
				return fmt.Errorf("once:%s was already used", id)
			}
		}
		for _, id := range ids {
			d.Once[id] = now.UTC().Format(time.RFC3339)
		}
		return nil
	})
}
