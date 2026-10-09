package main

// The router's own records, in one JSON file on the box's volume (written atomically). Nothing here is
// trusted by anyone else: the certs are core-signed and the snapshots machine-signed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Session struct {
	ID             string     `json:"id"`        // stable: the first machine's id
	MachineID      string     `json:"machineId"` // "" while paused
	State          string     `json:"state"`
	Error          string     `json:"error,omitempty"`
	Created        time.Time  `json:"created"`
	PausedAt       *time.Time `json:"pausedAt,omitempty"`
	Label          string     `json:"label"`
	Prompt         string     `json:"-"`
	Model          string     `json:"model"`
	PermissionMode string     `json:"permissionMode"`
	Size           string     `json:"size"`
	Harness        string     `json:"harness"`
	Stores         []string   `json:"stores"`
	Repos          string     `json:"repos"`
	Image          string     `json:"image"` // what the current line runs (ref@digest), pinned on resume
	Cert           *Doc       `json:"-"`     // the line's latest succession cert
	RequestID      string     `json:"createRequestId,omitempty"`
	Title          string     `json:"aiTitle,omitempty"`
	Status         string     `json:"status,omitempty"`
	UserTitle      string     `json:"userTitle,omitempty"`      // Deyao's own rename (the transcript's custom title): beats Label
	DiscordChannel string     `json:"discordChannel,omitempty"` // the session's channel (discord.go), LOBSTER_CHANNEL on the machine
	Live           *Liveness  `json:"live,omitempty"`           // reported status, auto-pause/one-shot settings (autopilot.go)
}

type Approval struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"` // new-session | resume-upgrade | add-store
	Created   time.Time         `json:"created"`
	Session   string            `json:"session"`
	Machine   string            `json:"machine"`
	Label     string            `json:"label"`
	Challenge *Doc              `json:"challenge"`
	BurnCert  *Doc              `json:"burnCert,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

type Record struct {
	Session
	DestroyedAt time.Time `json:"destroyedAt"`
}

// Started: what the core reported at start (the machine's keys authenticate its requests here)
type Started struct {
	ID            string `json:"id"`
	Image         string `json:"image"`
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
}

type persisted struct {
	Sessions  map[string]*Session     `json:"sessions"`
	Approvals map[string]*Approval    `json:"approvals"`
	Records   []*Record               `json:"records"`
	Started   map[string]*Started     `json:"started"`
	Certs     map[string]*Doc         `json:"certs"`    // machine id → its latest succession cert
	Machines  map[string]string       `json:"machines"` // machine id → session id
	SessCerts map[string]*Doc         `json:"sessionCerts"`
	Grants    map[string]*StoredGrant `json:"grants"` // id → a phone-signed grant or standing rule (grants.go)
}

type State struct {
	mu   sync.Mutex
	dir  string
	data persisted
}

func LoadState(dir string) (*State, error) {
	if err := os.MkdirAll(filepath.Join(dir, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	s := &State{dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, err
		}
	}
	d := &s.data
	if d.Sessions == nil {
		d.Sessions = map[string]*Session{}
	}
	if d.Approvals == nil {
		d.Approvals = map[string]*Approval{}
	}
	if d.Started == nil {
		d.Started = map[string]*Started{}
	}
	if d.Certs == nil {
		d.Certs = map[string]*Doc{}
	}
	if d.Machines == nil {
		d.Machines = map[string]string{}
	}
	if d.SessCerts == nil {
		d.SessCerts = map[string]*Doc{}
	}
	if d.Grants == nil {
		d.Grants = map[string]*StoredGrant{}
	}
	for id, c := range d.SessCerts {
		if s := d.Sessions[id]; s != nil {
			s.Cert = c
		}
	}
	return s, nil
}

// Do runs fn under the lock and saves afterwards
func (s *State) Do(fn func(d *persisted)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
	s.save()
}

func (s *State) save() {
	d := &s.data
	d.SessCerts = map[string]*Doc{}
	for id, ss := range d.Sessions {
		if ss.Cert != nil {
			d.SessCerts[id] = ss.Cert
		}
	}
	b, _ := json.MarshalIndent(d, "", " ")
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, filepath.Join(s.dir, "state.json"))
	}
}

func (s *State) snapshotPath(machine string) string {
	return filepath.Join(s.dir, "snapshots", machine+".tar.gz")
}
