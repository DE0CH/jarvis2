package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func pairJSON(exp int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"a%d","refreshToken":"r%d","expiresAt":%d}}`, exp, exp, exp)
}

// a new session's Claude login comes from Jarvis 1 at boot, with the store's token: no grant, no router
func TestSessionClaudeLoginAtBoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var gotID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get("CF-Access-Client-Id")
		json.NewEncoder(w).Encode(map[string]any{"credentials": pairJSON(2000), "account": `{"oauthAccount":{"emailAddress":"x"}}`, "expiresAt": 2000})
	}))
	defer srv.Close()
	oldURL, oldStart := jarvis1Credentials, startCredsSync
	defer func() { jarvis1Credentials, startCredsSync = oldURL, oldStart }()
	jarvis1Credentials = srv.URL
	started := false
	startCredsSync = func(id, sec string) { started = id == "cid" && sec == "csec" }

	if acct := sessionClaudeLogin(map[string]string{}); acct != "" || started {
		t.Fatal("no claude store: nothing to do")
	}
	acct := sessionClaudeLogin(map[string]string{"JARVIS1_CREDENTIALS_ID": "cid", "JARVIS1_CREDENTIALS_SECRET": "csec"})
	if gotID != "cid" || !started || !strings.Contains(acct, "oauthAccount") {
		t.Fatalf("id %q started %v account %q", gotID, started, acct)
	}
	b, err := os.ReadFile(credsPath())
	if err != nil || expiresAt(b) != 2000 {
		t.Fatalf("credentials file: %v %s", err, b)
	}
	if fi, _ := os.Stat(credsPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// a resumed pair that expires later is kept
	os.WriteFile(credsPath(), []byte(pairJSON(3000)), 0o600)
	sessionClaudeLogin(map[string]string{"JARVIS1_CREDENTIALS_ID": "cid", "JARVIS1_CREDENTIALS_SECRET": "csec"})
	if b, _ := os.ReadFile(credsPath()); expiresAt(b) != 3000 {
		t.Fatalf("a later pair was replaced: %s", b)
	}
}

func TestTakeIfLater(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if took, err := takeIfLater([]byte(`{}`)); took || err == nil {
		t.Fatal("a pair without expiresAt is refused")
	}
	if took, _ := takeIfLater([]byte(pairJSON(10))); !took {
		t.Fatal("no file: taken")
	}
	if took, _ := takeIfLater([]byte(pairJSON(10))); took {
		t.Fatal("same expiry: kept")
	}
	if took, _ := takeIfLater([]byte(pairJSON(11))); !took {
		t.Fatal("later: taken")
	}
}
