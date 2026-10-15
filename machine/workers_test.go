package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readWorkers(t *testing.T, dir, sid string) workerFile {
	t.Helper()
	var f workerFile
	b, err := os.ReadFile(filepath.Join(dir, sid+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// the event order Claude Code 2.1.300 sent for: a background Bash, a background subagent, a foreground subagent
// (recorded with a logging hook, 2026-10-15)
func TestWorkersHookSequence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "w")
	now := time.Now()
	ev := func(s string) { applyWorkerEvent(dir, []byte(s), now) }
	want := func(step string, sub int, jobs map[string]int) {
		t.Helper()
		f := readWorkers(t, dir, "s1")
		if f.Subagents != sub || len(f.Jobs) != len(jobs) {
			t.Fatalf("%s: %d subagents, jobs %v; want %d, %v", step, f.Subagents, f.Jobs, sub, jobs)
		}
		for k, n := range jobs {
			if f.Jobs[k] != n {
				t.Fatalf("%s: jobs %v, want %v", step, f.Jobs, jobs)
			}
		}
	}
	ev(`{"session_id":"s1","hook_event_name":"SessionStart","source":"startup"}`)
	want("start", 0, nil)
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"abg","agent_type":"general-purpose"}`)
	want("bg agent started", 1, nil)
	ev(`{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Agent","tool_response":{"isAsync":true,"status":"async_launched","agentId":"abg"}}`)
	ev(`{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"","backgroundTaskId":"b1"}}`)
	want("bash", 1, map[string]int{"shell": 1})
	ev(`{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"x"}}`) // foreground: nothing
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"afg","agent_type":"Explore"}`)
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"internal","agent_type":""}`) // prompt suggestion
	want("fg agent", 2, map[string]int{"shell": 1})
	// the foreground agent stops: the list names the other two (and never a foreground agent)
	ev(`{"session_id":"s1","hook_event_name":"SubagentStop","agent_id":"afg","agent_type":"Explore","background_tasks":[{"id":"abg","type":"subagent","status":"running"},{"id":"b1","type":"shell","status":"running"}]}`)
	want("fg stopped", 1, map[string]int{"shell": 1})
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"afg2","agent_type":"Explore"}`)
	// the background agent stops after the shell ended: its own entry is still listed as running
	ev(`{"session_id":"s1","hook_event_name":"SubagentStop","agent_id":"abg","agent_type":"general-purpose","background_tasks":[{"id":"abg","type":"subagent","status":"running"},{"id":"m1","type":"monitor","status":"running"}]}`)
	want("bg stopped", 1, map[string]int{"monitor": 1}) // afg2 (foreground) stays
	ev(`{"session_id":"s1","hook_event_name":"Stop","background_tasks":[{"id":"w1","type":"workflow","status":"running"},{"id":"x","type":"shell","status":"completed"}]}`)
	want("turn end", 0, map[string]int{"workflow": 1})
	ev(`{"session_id":"s1","hook_event_name":"Stop"}`) // no registry: unchanged
	want("no list", 0, map[string]int{"workflow": 1})
	ev(`{"session_id":"s1","hook_event_name":"SessionStart","source":"compact"}`)
	want("compact", 0, map[string]int{"workflow": 1})
	ev(`{"session_id":"s1","hook_event_name":"SessionStart","source":"resume"}`)
	want("restart", 0, nil)
	ev(`{"session_id":"../x","hook_event_name":"Stop","background_tasks":[]}`)
	if _, err := os.Stat(filepath.Join(dir, "../x.json")); err == nil {
		t.Fatal("unsafe session id written")
	}
	ev(`not json`)
}

func TestInstallWorkerHooks(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".claude", "settings.json")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(`{"remoteControlAtStartup":true,"hooks":{"Stop":[{"hooks":[{"type":"command","command":"mine"}]}]}}`), 0o644)
	os.MkdirAll(filepath.Join(home, workersDirRel), 0o700)
	os.WriteFile(filepath.Join(home, workersDirRel, "old.json"), []byte(`{}`), 0o600)
	for i := 0; i < 2; i++ { // idempotent
		if err := installWorkerHooks(home); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, workersDirRel, "old.json")); err == nil {
		t.Fatal("an earlier machine's counts survived boot")
	}
	var s struct {
		RC    bool                        `json:"remoteControlAtStartup"`
		Hooks map[string][]map[string]any `json:"hooks"`
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if !s.RC || len(s.Hooks["Stop"]) != 2 || len(s.Hooks["SubagentStart"]) != 1 || s.Hooks["PostToolUse"][0]["matcher"] != "Bash|Monitor|Agent" {
		t.Fatalf("settings %s", b)
	}
	os.WriteFile(p, []byte(`{broken`), 0o644)
	if installWorkerHooks(home) == nil {
		t.Fatal("overwrote an unreadable settings file")
	}
}
