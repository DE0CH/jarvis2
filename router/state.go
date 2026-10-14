package main

// The router's own records, in one JSON file on the box's volume (written atomically). Nothing here is
// trusted by anyone else: the kernel's documents are signed by their parts (docstore.go keeps them by ID) and the
// snapshots by their machines.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

type Session struct {
	ID             string       `json:"id"`        // stable: "s" + 16 hex, the settings' `session`
	MachineID      string       `json:"machineId"` // "" while paused
	State          string       `json:"state"`
	Error          string       `json:"error,omitempty"`
	Created        time.Time    `json:"created"`
	PausedAt       *time.Time   `json:"pausedAt,omitempty"`
	Label          string       `json:"label"`
	Prompt         string       `json:"-"`
	Model          string       `json:"model"`
	PermissionMode string       `json:"permissionMode"`
	Size           string       `json:"size"`
	Harness        string       `json:"harness"`
	Stores         []string     `json:"stores"`
	Repos          string       `json:"repos"`
	Content        []string     `json:"content,omitempty"` // content.go: the content stores the line gets (signed in its config)
	Image          string       `json:"image"`             // the current source's image (ref@digest)
	Chain          *Chain       `json:"chain,omitempty"`   // chain.go: where the session's chain is, its grants
	RequestID      string       `json:"createRequestId,omitempty"`
	Title          string       `json:"aiTitle,omitempty"`
	Status         string       `json:"status,omitempty"`
	UserTitle      string       `json:"userTitle,omitempty"`      // Deyao's own rename (the transcript's custom title): beats Label
	AppTitle       string       `json:"serverTitle,omitempty"`    // the Claude app's own title (machine report; Jarvis 1's serverTitle): beats all
	LiveSync       *LiveSync    `json:"liveSync,omitempty"`       // livesync.go: the transcripts the machine last copied out
	DiscordChannel string       `json:"discordChannel,omitempty"` // the session's channel (discord.go), LOBSTER_CHANNEL on the machine
	Live           *Liveness    `json:"live,omitempty"`           // reported status, auto-pause/one-shot settings (autopilot.go)
	ArchiveDir     string       `json:"archiveDir,omitempty"`     // archive.go: fixed by the destroy that archives it
	RestoreFrom    string       `json:"restoreFrom,omitempty"`    // restore.go: the record this session restores
	ImportFrom     string       `json:"importFrom,omitempty"`     // jarvis1import.go: the paused Jarvis 1 session this line imports
	StartSnapshot  string       `json:"startSnapshot,omitempty"`  // the snapshot the first source names (a restore's, an import's manifest)
	Ops            *SessionOps  `json:"ops,omitempty"`            // sessionops.go: API proxy, env patch, rollback, attachments
	Booted         string       `json:"booted,omitempty"`         // the machine that has reported status: it got past boot (lastSnapshot)
	Waiting        string       `json:"waiting,omitempty"`        // what a pause or destroy is waiting on, in plain words (the app shows it)
	LockedStore    string       `json:"lockedStore,omitempty"`    // a store the machine's last pull named as locked
	Commands       []CommandRun `json:"commands,omitempty"`       // addons.go: the approved commands' results, newest last
	taskConfig     *TaskConfig  // a task line's instance + parameters while its first draft is made (not kept)
}

type Approval struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"` // new-session | resume-upgrade | terminal | command | add-store
	Created time.Time `json:"created"`
	Session string    `json:"session"`
	Machine string    `json:"machine,omitempty"` // an add-on: the running machine it is for
	Label   string    `json:"label"`
	// Drafts: the succession certs the phone signs, in order, each with its log-notary challenge (chain.go)
	Drafts  []Draft           `json:"drafts"`
	Options map[string]string `json:"options,omitempty"`
	// an add-on's facts (the phone reads them from the drafts; these are the router's own record)
	Until  *time.Time     `json:"until,omitempty"`
	Cmd    string         `json:"cmd,omitempty"`
	Once   string         `json:"once,omitempty"`
	Store  string         `json:"store,omitempty"`
	Source *kernel.Object `json:"source,omitempty"` // resume-upgrade: the source its draft makes
	// inbox.go: who asked for it (from the caller's credential) and the call it made, and the caller's own words
	Origin      *Origin `json:"origin,omitempty"`
	Explanation string  `json:"explanation,omitempty"`
	// ImageSig: CI's signature over "jarvis2-session-image <image>" for the image the draft names, when that is a
	// CI build (SESSION_IMAGE_SIG / the signatures file, made by images.yml with the key of keys/ci.pub): the phone checks it
	ImageSig string `json:"imageSig,omitempty"`
	// batches.go: the batch it was filed in (reviewed with the batch's others under one Face ID)
	Batch string `json:"batch,omitempty"`
}

type Record struct {
	Session
	DestroyedAt  time.Time     `json:"destroyedAt"`
	Archive      *ArchiveInfo  `json:"archive,omitempty"`      // archive.go
	ArchiveError string        `json:"archiveError,omitempty"` // a forced destroy whose archive failed
	Restored     []RestoreMark `json:"restored,omitempty"`
}

// Started: a machine's keys as its spawn cert names them (its signing key authenticates its requests here)
type Started struct {
	ID            string `json:"id"`
	Image         string `json:"image"`
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
	Spawn         string `json:"spawn"` // its notarized spawn cert's ID (docstore.go)
	// the machine's last snapshot as it uploaded it: the sha256 and its signature over it (POST /m/snapshot)
	Snapshot    string `json:"snapshot,omitempty"`
	SnapshotSig string `json:"snapshotSig,omitempty"`
}

type persisted struct {
	Sessions  map[string]*Session  `json:"sessions"`
	Approvals map[string]*Approval `json:"approvals"`
	Records   []*Record            `json:"records"`
	Started   map[string]*Started  `json:"started"`             // machine id → its keys (from its spawn cert)
	Machines  map[string]string    `json:"machines"`            // machine id → session id
	RootGrant string               `json:"rootGrant,omitempty"` // docstore.go: root's ⊤ on the sink (its ID)

	Schedules   map[string]*Schedule     `json:"schedules,omitempty"`   // session id → wakeups, crons, watches (schedule.go)
	Budget      *BudgetState             `json:"budget,omitempty"`      // budget.go: this month's Fly spend estimate
	BBBudget    *BBBudgetState           `json:"bbBudget,omitempty"`    // bbbudget.go: this month's Browserbase DM flags
	Devices     map[string]*Device       `json:"devices,omitempty"`     // devices.go: Deyao's paired OpenClaw/Paseo apps
	Uploads     map[string]*Upload       `json:"uploads,omitempty"`     // uploads.go: first-prompt attachments staged on the volume
	Tasks       *TaskState               `json:"tasks,omitempty"`       // tasks.go: task instances (session lines), runs, daily schedules
	Inbox       map[string]*InboxRequest `json:"inbox,omitempty"`       // inbox.go: requests waiting for the phone
	Batches     map[string]*Batch        `json:"batches,omitempty"`     // batches.go: requests and approvals filed together, one review
	CallResults map[string]*CallResult   `json:"callResults,omitempty"` // apicalls.go: approved/denied API calls, for their caller
	Leases      *LeaseState              `json:"leases,omitempty"`      // leases.go: shared-device leases (holder + queue per device)
	Outcomes    map[string][]*Outcome    `json:"outcomes,omitempty"`    // outcomes.go: session id → decisions on its Inbox filings, until delivered
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
	if d.Inbox == nil {
		d.Inbox = map[string]*InboxRequest{}
	}
	if d.Approvals == nil {
		d.Approvals = map[string]*Approval{}
	}
	if d.Batches == nil {
		d.Batches = map[string]*Batch{}
	}
	if d.Started == nil {
		d.Started = map[string]*Started{}
	}
	if d.Machines == nil {
		d.Machines = map[string]string{}
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
	b, _ := json.MarshalIndent(&s.data, "", " ")
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, filepath.Join(s.dir, "state.json"))
	}
}

// snapshotPath: a snapshot (or a Jarvis 1 import manifest) by its sha256 — what a source's `snapshot` names
func (s *State) snapshotPath(sha string) string {
	return filepath.Join(s.dir, "snapshots", sha)
}
