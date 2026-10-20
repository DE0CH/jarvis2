package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A session raised to bypass in place keeps a cert that says auto: Jarvis's own messages must go in the class claude
// really runs in, or Claude Code holds them as a mode mismatch (2026-10-20). Decided as harness-claude.sh decides.
func TestLiveModeFollowsTheInPlaceSwitch(t *testing.T) {
	old := claudeHome
	claudeHome = t.TempDir()
	defer func() { claudeHome = old }()
	auto, bypass := Cert{}, Cert{}
	bypass.Options.PermissionMode = "bypass"
	if liveMode(auto) != "auto" || liveMode(bypass) != "bypass" {
		t.Fatal("without the in-place file the cert decides")
	}
	p := filepath.Join(claudeHome, modeFile)
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("bypass\n"), 0o644)
	if liveMode(auto) != "bypass" {
		t.Fatal("raised in place to bypass, sent as auto")
	}
	os.WriteFile(p, []byte("auto\n"), 0o644)
	if liveMode(bypass) != "auto" {
		t.Fatal("lowered in place to auto, sent as bypass")
	}
	os.WriteFile(p, []byte("nonsense"), 0o644)
	if liveMode(bypass) != "auto" {
		t.Fatal("harness-claude.sh runs anything but bypass as auto")
	}
}
