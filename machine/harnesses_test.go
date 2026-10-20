package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Claude Code · Paseo (proxyLogin): after an account switch the token's account is checked and proven as for the
// claude harness, but nothing is typed into the terminal pane (it shows `paseo logs`, there is no Remote Control)
func TestAfterSwitchProxyLoginTypesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	os.MkdirAll(home(t)+"/.claude/sessions", 0o700)
	quietAfterSwitch(t)
	oldHarness := certHarness
	certHarness = func() string { return "paseo-claude" }
	t.Cleanup(func() { certHarness = oldHarness })
	b, _ := json.Marshal(map[string]any{"status": "busy", "pid": os.Getpid(), "bridgeSessionId": "paseo:s1"}) // the status shim
	os.WriteFile(home(t)+"/.claude/sessions/paseo.json", b, 0o600)
	os.WriteFile(home(t)+"/.claude.json", []byte(acct2Record), 0o600)
	typed := []string{}
	sendKeys = func(a ...string) error { typed = append(typed, strings.Join(a, " ")); return nil }
	paneText = func() string { return "signed-in claude.ai account or " + rcChangedText }

	done := make(chan struct{})
	go func() { afterSwitch(routerLogin{Credentials: pairJSON(4000), Account: acct2Record}, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("afterSwitch hung")
	}
	if b, err := os.ReadFile(accountProof()); err != nil || !strings.Contains(string(b), `"acct-2"`) {
		t.Fatalf("proof: %v %s", err, b)
	}
	if len(typed) != 0 {
		t.Fatalf("typed into the pane: %q", typed)
	}
}

func TestHarnessKinds(t *testing.T) {
	for h, want := range map[string][3]bool{
		"": {false, true, false}, "claude": {false, true, false}, "opencode": {true, false, false},
		"openclaw": {true, false, false}, "paseo-claude": {true, true, true},
	} {
		if got := [3]bool{viaHarnessSend(h), runsClaudeCode(h), proxyLogin(h)}; got != want {
			t.Errorf("%q: %v, want %v", h, got, want)
		}
	}
}
