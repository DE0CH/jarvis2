package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signIn: an account's sign-in through the app routes, as Deyao does it (start → the page → paste code#state)
func signIn(t *testing.T, r *Router, startPath, startBody string) (int, map[string]any) {
	t.Helper()
	code, out := appDo(t, r, "POST", startPath, startBody)
	if code != 200 {
		return code, out
	}
	u, _ := url.Parse(out["url"].(string))
	store := out["store"].(string)
	return appDo(t, r, "POST", "/api/claude-accounts/"+store+"/code", `{"code":"abc#`+u.Query().Get("state")+`"}`)
}

// Add, Re-login, Make default, Remove (DECISIONS 185)
func TestClaudeAccountsManage(t *testing.T) {
	f := newFakeAnthropic(t)
	r := newTestRouter(t)
	if code, out := appDo(t, r, "GET", "/api/claude-accounts", ""); code != 200 || out["default"] != "" || len(out["accounts"].([]any)) != 0 {
		t.Fatal(code, out)
	}
	if code, _ := appDo(t, r, "POST", "/api/claude-accounts", `{"name":"Bad Name!"}`); code != 400 {
		t.Fatal("a name that can't be a store name was taken")
	}
	// the first account: signed in, and the default
	code, out := signIn(t, r, "/api/claude-accounts", `{"name":"main"}`)
	if code != 200 || out["store"] != "claude-main" || out["email"] != "acct-1@example.com" {
		t.Fatal(code, out)
	}
	if code, _ := appDo(t, r, "POST", "/api/claude-accounts", `{"name":"claude-main"}`); code != 400 {
		t.Fatal("the same name twice")
	}
	// a second account: the same Claude account again is refused, another one is taken
	if code, out := signIn(t, r, "/api/claude-accounts", `{"name":"work"}`); code != 400 || !strings.Contains(out["error"].(string), "already claude-main") {
		t.Fatal("the same Claude account in two slots", code, out)
	}
	f.accounts["new"] = "acct-2"
	if code, out := signIn(t, r, "/api/claude-accounts/claude-work/login", ""); code != 200 || out["email"] != "acct-2@example.com" {
		t.Fatal(code, out)
	}
	// a Re-login into an account must be that account
	f.accounts["new"] = "acct-3"
	if code, out := signIn(t, r, "/api/claude-accounts/claude-work/login", ""); code != 400 || !strings.Contains(out["error"].(string), "another Claude account") {
		t.Fatal("a Re-login switched an account's Claude account", code, out)
	}
	_, out = appDo(t, r, "GET", "/api/claude-accounts", "")
	rows := out["accounts"].([]any)
	if out["default"] != "claude-main" || len(rows) != 2 || rows[1].(map[string]any)["store"] != "claude-work" ||
		rows[1].(map[string]any)["email"] != "acct-2@example.com" || rows[0].(map[string]any)["default"] != true ||
		strings.Contains(jsonString(out), "at-new") {
		t.Fatal(out)
	}
	// usage per account
	if code, out := appDo(t, r, "GET", "/api/claude-accounts/claude-work/usage", ""); code != 200 || out["store"] != "claude-work" || len(out["limits"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	// Remove: refused for the default and while a session uses it
	if code, _ := appDo(t, r, "DELETE", "/api/claude-accounts/claude-main", ""); code != 409 {
		t.Fatal("removed the default account")
	}
	addSession(r, "s1", "paused", "", false)
	r.st.Do(func(d *persisted) { d.Sessions["s1"].ClaudeAccount = "claude-work" })
	if code, out := appDo(t, r, "DELETE", "/api/claude-accounts/claude-work", ""); code != 409 || !strings.Contains(out["error"].(string), "s1") {
		t.Fatal("removed an account a session uses", code, out)
	}
	r.st.Do(func(d *persisted) { delete(d.Sessions, "s1") })
	if code, _ := appDo(t, r, "POST", "/api/claude-accounts/claude-work/default", ""); code != 200 || r.accounts().defaultStore() != "claude-work" {
		t.Fatal("make default")
	}
	if code, _ := appDo(t, r, "DELETE", "/api/claude-accounts/claude-main", ""); code != 200 || r.accounts().hub("claude-main") != nil {
		t.Fatal("remove")
	}
	if _, err := os.Stat(filepath.Join(r.cfg.DataDir, "claude-accounts", "claude-main.json")); !os.IsNotExist(err) {
		t.Fatal("a removed account's pair stayed on the volume")
	}
	// the routes of the one shared login act on the default account
	if code, out := appDo(t, r, "GET", "/api/claude-login", ""); code != 200 || out["store"] != "claude-work" {
		t.Fatal(code, out)
	}
	// a router restart reads the accounts back
	r2 := NewRouter(Config{NoAccess: true, DataDir: r.cfg.DataDir}, r.st, nil, Policy{})
	if h := r2.accounts().hub("claude-work"); h == nil || accountUUID(h.current().Account) != "acct-2" || r2.accounts().defaultStore() != "claude-work" {
		t.Fatal("not read back")
	}
}

// the clean cut: the one shared login becomes the account claude-<email name>, and the sessions holding the old
// store `claude` use it
func TestClaudeAccountsMigrateSharedLogin(t *testing.T) {
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(8 * time.Hour).UnixMilli()
	old, _ := json.Marshal(loginFile{Credentials: pairOf("a", exp), Account: `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"chendeyao.uk@gmail.com"}}`})
	os.WriteFile(filepath.Join(st.dir, "claude-login.json"), old, 0o600)
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Harness: "claude", Stores: []string{"claude", "default"}}
		d.Sessions["s2"] = &Session{ID: "s2", State: "paused", Harness: "opencode", Stores: []string{"openrouter"}}
		d.Records = append(d.Records, &Record{Session: Session{ID: "s0", Harness: "claude", Stores: []string{"claude"}}})
		d.Machines["m1"] = "s1"
	})
	r := NewRouter(Config{NoAccess: true, DataDir: st.dir}, st, nil, Policy{})
	a := r.accounts()
	h := a.hub("claude-chendeyao-uk")
	if h == nil || h.current().ExpiresAt != exp || a.defaultStore() != "claude-chendeyao-uk" || a.jarvis1Hub() != h {
		t.Fatalf("%+v %s", h, a.defaultStore())
	}
	r.st.Do(func(d *persisted) {
		if d.Sessions["s1"].ClaudeAccount != "claude-chendeyao-uk" || d.Sessions["s2"].ClaudeAccount != "" || d.Records[0].ClaudeAccount != "claude-chendeyao-uk" {
			t.Fatalf("%+v %+v %+v", d.Sessions["s1"], d.Sessions["s2"], d.Records[0])
		}
	})
	if _, err := os.Stat(filepath.Join(st.dir, "claude-login.json")); !os.IsNotExist(err) {
		t.Fatal("the old file is still there: the next start would migrate again")
	}
	// the running session's machine keeps its pair coming
	m := newTestMachine(r, "m1")
	if code, out := m.do(t, r.MachineHandler(), "GET", "/m/claude-login?have=0", ""); code != 200 || !strings.Contains(out["credentials"].(string), "at-a") {
		t.Fatal(code, out)
	}
}

func TestSlugAndStoreNames(t *testing.T) {
	for in, want := range map[string]string{"chendeyao.uk@gmail.com": "chendeyao-uk", "A_B..c@x": "a-b-c", "@x": ""} {
		if got := slugFromEmail(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"work": "claude-work", "claude-work": "claude-work", "Work": "claude-work", "": "", "a--b": "", "claude-": "", "x y": ""} {
		if got := accountStoreName(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// a new session gets the account it names, else the default; a harness without one gets none; the old store is refused
func TestNewSessionClaudeAccount(t *testing.T) {
	newFakeAnthropic(t)
	rg := newRig(t)
	r := rg.r
	r.policy = Policy{Harnesses: map[string]HarnessPolicy{"claude": {Stores: []string{"tunnel"}, ClaudeAccount: true}, "opencode": {Stores: []string{"openrouter"}}}}
	acct := func(id string) (s string) {
		r.st.Do(func(d *persisted) { s = d.Sessions[id].ClaudeAccount })
		return
	}
	// no account at all (a new box): it starts logged out
	if id, err := r.CreateSession(NewSession{Label: "x", Harness: "claude"}); err != nil || acct(id) != "" {
		t.Fatal("a Claude session with no account at all", err)
	}
	r.accounts().add("main")
	r.accounts().add("work")
	id, err := r.CreateSession(NewSession{Label: "x", Harness: "claude"})
	if err != nil || acct(id) != "claude-main" {
		t.Fatal(err, acct(id))
	}
	id, err = r.CreateSession(NewSession{Label: "y", Harness: "claude", Account: "work"})
	if err != nil || acct(id) != "claude-work" {
		t.Fatal(err, acct(id))
	}
	if _, err := r.CreateSession(NewSession{Label: "z", Harness: "claude", Account: "nope"}); err == nil {
		t.Fatal("an unknown account was taken")
	}
	if _, err := r.CreateSession(NewSession{Label: "z", Harness: "claude", Stores: []string{"claude"}}); err == nil || !strings.Contains(err.Error(), "store claude is gone") {
		t.Fatal("the old store was taken", err)
	}
	id, err = r.CreateSession(NewSession{Label: "o", Harness: "opencode"})
	if err != nil || acct(id) != "" {
		t.Fatal(err, acct(id))
	}
	if _, err := r.CreateSession(NewSession{Label: "o", Harness: "opencode", Account: "work"}); err == nil {
		t.Fatal("an account for a harness that takes none")
	}
	// the app's, the web page's and jarvis2-request's body names it as "account"
	var ns NewSession
	json.Unmarshal([]byte(`{"label":"w","harness":"claude","account":"claude-work"}`), &ns)
	if id, err = r.CreateSession(ns); err != nil || acct(id) != "claude-work" {
		t.Fatal(err, acct(id))
	}
	// every made session's approval is filed in the background: let them land before the temp dir goes
	waitFor(t, "the approvals", func() bool {
		n := 0
		r.st.Do(func(d *persisted) { n = len(d.Approvals) })
		return n >= 5
	})
}
