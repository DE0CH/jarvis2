package main

// Workers: how many subagents and background jobs the session's Claude Code harness has running now, for the
// session's card (router/registry.go Workers, docs/DECISIONS.md "Workers").
//
// Claude Code documents no live list of its tasks, so the count comes from its documented hooks
// (code.claude.com/docs/en/hooks): boot installs `jarvis2-machine workers-hook` in ~/.claude/settings.json for
// SessionStart, SubagentStart, SubagentStop, Stop and PostToolUse (Bash|Monitor|Agent), and the hook keeps one
// small file per conversation in ~/.claude/jarvis2-workers/ (not in the snapshot):
//   - Stop and SubagentStop carry `background_tasks`, the harness's own list of what is in flight (types
//     shell, subagent, monitor, workflow, teammate, …): each one replaces the file's list. A SubagentStop's list
//     still names the agent that is stopping, so that one is left out.
//   - between two of those, SubagentStart adds the agent (a foreground subagent never appears in the list, so
//     it stays until its own SubagentStop or the turn's Stop), and a PostToolUse whose result has a
//     backgroundTaskId (a background Bash, a Monitor) adds that job until the next list.
//   - SessionStart (startup, resume) empties the file: a restarted host has nothing running.
// The status report (status.go) prints the files; the router picks the host conversation's. Only ids and types
// are kept, never a command or a description. The hook never fails the harness: any error exits 0 silently.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const workersHookCmd = "/usr/local/bin/jarvis2-machine workers-hook"

var workersDirRel = filepath.Join(".claude", "jarvis2-workers")

// workerHookEvents: the hook events the count needs (with PostToolUse's matcher)
var workerHookEvents = []struct{ event, matcher string }{
	{"SessionStart", ""}, {"SubagentStart", ""}, {"SubagentStop", ""}, {"Stop", ""}, {"PostToolUse", "Bash|Monitor|Agent"},
}

// workerFile: one conversation's file; Subagents and Jobs are what the router reads
type workerFile struct {
	SessionID string            `json:"workersOf"`
	At        int64             `json:"at"` // ms, the last change
	Subagents int               `json:"subagents"`
	Jobs      map[string]int    `json:"jobs"`   // every other in-flight task by the harness's type label
	Listed    map[string]string `json:"listed"` // id → type, from the last background_tasks
	Added     map[string]string `json:"added"`  // id → type, seen since it ("subagent-fg" until known as background)
}

type hookInput struct {
	SessionID string `json:"session_id"`
	Event     string `json:"hook_event_name"`
	Source    string `json:"source"`
	AgentID   string `json:"agent_id"`
	AgentType string `json:"agent_type"`
	ToolName  string `json:"tool_name"`
	Tasks     *[]struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Status string `json:"status"`
	} `json:"background_tasks"`
	Response json.RawMessage `json:"tool_response"`
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

// workersHook: the hook command (stdin = the event's JSON). Always exits 0 with no output.
func workersHook() {
	defer func() { recover() }()
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		return
	}
	home, _ := os.UserHomeDir()
	applyWorkerEvent(filepath.Join(home, workersDirRel), b, time.Now())
}

func applyWorkerEvent(dir string, raw []byte, now time.Time) {
	var in hookInput
	if json.Unmarshal(raw, &in) != nil || !safeID.MatchString(in.SessionID) {
		return
	}
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX) != nil {
		return
	}
	path := filepath.Join(dir, in.SessionID+".json")
	var f workerFile
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &f)
	}
	if f.Listed == nil {
		f.Listed = map[string]string{}
	}
	if f.Added == nil {
		f.Added = map[string]string{}
	}
	switch in.Event {
	case "SessionStart":
		if in.Source != "startup" && in.Source != "resume" {
			return
		}
		f.Listed, f.Added = map[string]string{}, map[string]string{}
	case "SubagentStart":
		if in.AgentType == "" || !safeID.MatchString(in.AgentID) { // the harness's own internal agents
			return
		}
		if _, ok := f.Listed[in.AgentID]; !ok {
			f.Added[in.AgentID] = "subagent-fg"
		}
	case "PostToolUse":
		var r struct {
			IsAsync bool   `json:"isAsync"`
			AgentID string `json:"agentId"`
			TaskID  string `json:"backgroundTaskId"`
		}
		if json.Unmarshal(in.Response, &r) != nil {
			return
		}
		switch {
		case in.ToolName == "Agent" && r.IsAsync && f.Added[r.AgentID] == "subagent-fg":
			f.Added[r.AgentID] = "subagent" // a background one: the next list says when it ends
		case r.TaskID != "" && safeID.MatchString(r.TaskID):
			if _, ok := f.Listed[r.TaskID]; !ok {
				f.Added[r.TaskID] = map[string]string{"Bash": "shell", "Monitor": "monitor"}[in.ToolName]
				if f.Added[r.TaskID] == "" {
					f.Added[r.TaskID] = "other"
				}
			}
		default:
			return
		}
	case "SubagentStop", "Stop":
		if in.Event == "SubagentStop" {
			delete(f.Added, in.AgentID)
		}
		if in.Tasks == nil { // no registry reachable: keep what we had
			break
		}
		f.Listed = map[string]string{}
		for _, t := range *in.Tasks {
			if t.ID == "" || t.ID == in.AgentID || (t.Status != "" && t.Status != "running" && t.Status != "pending") {
				continue
			}
			f.Listed[t.ID] = t.Type
		}
		for id, ty := range f.Added { // background ones the list no longer names have ended
			if _, ok := f.Listed[id]; ok || ty != "subagent-fg" || in.Event == "Stop" {
				delete(f.Added, id) // and at the turn's end no foreground subagent is left
			}
		}
	default:
		return
	}
	f.SessionID, f.At = in.SessionID, now.UnixMilli()
	f.Subagents, f.Jobs = 0, map[string]int{}
	all := map[string]string{}
	for id, ty := range f.Listed {
		all[id] = ty
	}
	for id, ty := range f.Added {
		all[id] = ty
	}
	for _, ty := range all {
		switch ty {
		case "subagent", "subagent-fg":
			f.Subagents++
		case "":
			f.Jobs["other"]++
		default:
			f.Jobs[ty]++
		}
	}
	b, _ := json.Marshal(f)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, path)
	}
}

// installWorkerHooks: the hook entries in ~/.claude/settings.json (boot, before the harness starts), replacing
// any earlier copy of ours and keeping everything else in the file
func installWorkerHooks(home string) error {
	os.RemoveAll(filepath.Join(home, workersDirRel)) // a new machine: nothing is running yet
	p := filepath.Join(home, ".claude", "settings.json")
	s := map[string]any{}
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &s); err != nil {
			return err // never overwrite a file we can't read
		}
	}
	hooks, _ := s["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	for _, e := range workerHookEvents {
		var keep []any
		groups, _ := hooks[e.event].([]any)
		for _, g := range groups {
			if !isWorkersGroup(g) {
				keep = append(keep, g)
			}
		}
		g := map[string]any{"hooks": []any{map[string]any{"type": "command", "command": workersHookCmd, "timeout": 10}}}
		if e.matcher != "" {
			g["matcher"] = e.matcher
		}
		hooks[e.event] = append(keep, g)
	}
	s["hooks"] = hooks
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(p), 0o755)
	return os.WriteFile(p, b, 0o600)
}

func isWorkersGroup(g any) bool {
	m, _ := g.(map[string]any)
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		if hm, _ := h.(map[string]any); hm != nil && hm["command"] == workersHookCmd {
			return true
		}
	}
	return false
}
