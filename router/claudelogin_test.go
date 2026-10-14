package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func pairOf(tag string, exp int64) string {
	return fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"at-%s","refreshToken":"rt-%s","expiresAt":%d,"scopes":["user:inference","user:profile"],"subscriptionType":"max"}}`, tag, tag, exp)
}

// fakeAnthropic: the token, profile and usage endpoints. Each access token "at-<tag>" belongs to the account
// named by accounts[tag] (default "acct-1"); a refresh of "rt-<tag>" answers "at-<tag>'".
type fakeAnthropic struct {
	srv       *httptest.Server
	mu        sync.Mutex
	refreshes []map[string]any
	exchanges []map[string]any
	reject    bool
	accounts  map[string]string
	onRefresh func()
}

func newFakeAnthropic(t *testing.T) *fakeAnthropic {
	f := &fakeAnthropic{accounts: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/token":
			var b map[string]any
			json.NewDecoder(req.Body).Decode(&b)
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.reject {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token not found or invalid"}`))
				return
			}
			switch b["grant_type"] {
			case "refresh_token":
				f.refreshes = append(f.refreshes, b)
				if f.onRefresh != nil {
					f.onRefresh()
				}
				tag := strings.TrimPrefix(b["refresh_token"].(string), "rt-") + "'"
				json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + tag, "refresh_token": "rt-" + tag, "expires_in": 28800, "scope": "user:inference user:profile"})
			case "authorization_code":
				f.exchanges = append(f.exchanges, b)
				json.NewEncoder(w).Encode(map[string]any{"access_token": "at-new", "refresh_token": "rt-new", "expires_in": 28800, "scope": "user:inference user:profile user:sessions:claude_code"})
			}
		case "/profile":
			tag := strings.TrimPrefix(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), "at-")
			f.mu.Lock()
			acct := f.accounts[strings.TrimRight(tag, "'")]
			f.mu.Unlock()
			if acct == "" {
				acct = "acct-1"
			}
			json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"uuid": acct, "email": acct + "@example.com", "display_name": "D"},
				"organization": map[string]any{"uuid": "org-1", "organization_type": "claude_max", "rate_limit_tier": "default_claude_max_20x"}})
		case "/usage":
			if req.Header.Get("Authorization") == "" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"limits":[{"kind":"session","group":"g","percent":12,"severity":"ok","resets_at":"2026-10-13T05:00:00Z","is_active":true,"scope":{"model":{"id":"m","display_name":"Opus"}}}],"extra_usage":{"is_enabled":false,"disabled_reason":"off"}}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	saved := []string{oauthTokenURL, oauthProfileURL, oauthUsageURL}
	oauthTokenURL, oauthProfileURL, oauthUsageURL = f.srv.URL+"/token", f.srv.URL+"/profile", f.srv.URL+"/usage"
	t.Cleanup(func() { oauthTokenURL, oauthProfileURL, oauthUsageURL = saved[0], saved[1], saved[2] })
	return f
}

const acct1 = `{"oauthAccount":{"accountUuid":"acct-1","emailAddress":"acct-1@example.com"}}`

func ownRouter(t *testing.T) (*Router, *loginHub) {
	r := newTestRouter(t)
	return r, r.loginHub()
}

func TestLoginOfferNewerWinsAndAccount(t *testing.T) {
	f := newFakeAnthropic(t)
	_, h := ownRouter(t)
	now := time.Now().UnixMilli()
	if ok, err := h.offer(pairOf("a", now+1000), acct1, "seed", true, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := h.offer(pairOf("b", now+500), "", "push", false, false); ok || err != errNotNewer {
		t.Fatal("an older pair must not replace a newer one", ok, err)
	}
	f.accounts["c"] = "acct-2"
	if ok, err := h.offer(pairOf("c", now+2000), "", "push", false, false); ok || err != errOtherAcct {
		t.Fatal("another account's pair must be refused", ok, err)
	}
	if ok, err := h.offer(pairOf("d", now+3000), "", "push", false, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if cur := h.current(); cur.ExpiresAt != now+3000 || accountUUID(cur.Account) != "acct-1" {
		t.Fatalf("%+v", cur)
	}
	// on the volume, 0600, and read back by a new hub (a router restart)
	fi, err := os.Stat(h.path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, fi)
	}
	h2 := newLoginHub(strings.TrimSuffix(h.path, "/claude-login.json"))
	if c := h2.current(); c.ExpiresAt != now+3000 {
		t.Fatalf("%+v", c)
	}
	if h.offer("{}", "", "push", false, false); h.current().ExpiresAt != now+3000 {
		t.Fatal("a malformed pair changed the store")
	}
}

// the lessons/74 protocol: participants lock before the refresh, the refresh waits for them, then all get the pair
func TestLoginRefreshProtocol(t *testing.T) {
	f := newFakeAnthropic(t)
	_, h := ownRouter(t)
	exp := time.Now().Add(10 * time.Minute).UnixMilli() // inside the margin: due
	h.offer(pairOf("a", exp), acct1, "seed", true, false)

	ctx := context.Background()
	// two participants, each seen (polling with have = the current expiry)
	for _, who := range []string{"m:1", "jarvis1"} {
		if a := h.poll(ctx, who, exp, 0, 0); a.Credentials != "" || a.Preparing {
			t.Fatalf("%s: nothing new yet: %+v", who, a)
		}
	}
	var locked atomic.Int32
	f.onRefresh = func() {
		if locked.Load() != 2 {
			t.Errorf("refreshed with %d of 2 participants locked", locked.Load())
		}
	}
	var wg sync.WaitGroup
	got := make([]loginAnswer, 2)
	for i, who := range []string{"m:1", "jarvis1"} {
		wg.Add(1)
		go func(i int, who string) {
			defer wg.Done()
			a := h.poll(ctx, who, exp, 0, 30*time.Second) // waits for the prepare
			if !a.Preparing {
				t.Errorf("%s: expected a prepare: %+v", who, a)
				return
			}
			locked.Add(1)                                         // the participant took its CLI lock
			got[i] = h.poll(ctx, who, exp, a.Gen, 30*time.Second) // acknowledges and waits for the pair
		}(i, who)
	}
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	ok, err := h.refresh(false)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the refresh waited out the ack timeout although both acknowledged")
	}
	wg.Wait()
	for i, a := range got {
		if !strings.Contains(a.Credentials, "at-a'") || a.Preparing || a.ExpiresAt <= exp {
			t.Fatalf("participant %d: %+v", i, a)
		}
	}
	if len(f.refreshes) != 1 || f.refreshes[0]["refresh_token"] != "rt-a" || f.refreshes[0]["scope"] != "user:inference user:profile" {
		t.Fatalf("%v", f.refreshes)
	}
	// not due again
	if ok, _ := h.refresh(false); ok {
		t.Fatal("refreshed a fresh pair")
	}
}

// a refused refresh: participants are told to release; the dead login is DMed once, not retried
func TestLoginRefreshRejected(t *testing.T) {
	f := newFakeAnthropic(t)
	_, h := ownRouter(t)
	var dms atomic.Int32
	h.dm = func(string) { dms.Add(1) }
	exp := time.Now().Add(time.Minute).UnixMilli()
	h.offer(pairOf("a", exp), acct1, "seed", true, false)
	h.poll(context.Background(), "m:1", exp, 0, 0)
	f.reject = true
	done := make(chan loginAnswer)
	go func() {
		a := h.poll(context.Background(), "m:1", exp, 0, 10*time.Second)
		done <- h.poll(context.Background(), "m:1", exp, a.Gen, 10*time.Second)
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := h.refresh(false); err == nil {
		t.Fatal("expected the refusal")
	}
	if a := <-done; a.Preparing || a.Credentials != "" {
		t.Fatalf("the participant must be told to release: %+v", a)
	}
	// it answers at once while the participant still says it holds a lock (ack != 0, not preparing)
	if a := h.poll(context.Background(), "m:1", exp, 1, 10*time.Second); a.Preparing {
		t.Fatalf("%+v", a)
	}
	n := len(f.refreshes)
	if _, err := h.refresh(false); err == nil || len(f.refreshes) != n {
		t.Fatal("a refused grant must not be retried", err)
	}
	time.Sleep(20 * time.Millisecond)
	if dms.Load() != 1 {
		t.Fatalf("%d DMs", dms.Load())
	}
	if st := h.status(); st["needLogin"] != true || st["rejected"] != true {
		t.Fatalf("%v", st)
	}
	// a newer pair (a Re-login, a push) clears it
	h.offer(pairOf("b", time.Now().Add(8*time.Hour).UnixMilli()), "", "relogin", true, true)
	if st := h.status(); st["needLogin"] == true {
		t.Fatalf("%v", st)
	}
}

func TestLoginRelogin(t *testing.T) {
	f := newFakeAnthropic(t)
	r, h := ownRouter(t)
	code, out := appDo(t, r, "POST", "/api/claude-login/start", "")
	if code != 200 {
		t.Fatal(code, out)
	}
	u, _ := url.Parse(out["url"].(string))
	q := u.Query()
	if u.Host != "claude.com" || q.Get("client_id") != oauthClientID || q.Get("redirect_uri") != oauthRedirectURL || q.Get("code_challenge_method") != "S256" ||
		q.Get("scope") != strings.Join(oauthScopes, " ") || q.Get("state") == "" || q.Get("code") != "true" {
		t.Fatalf("%s", u)
	}
	if code, _ := appDo(t, r, "POST", "/api/claude-login/code", `{"code":"abc#wrong"}`); code != 400 {
		t.Fatal("another sign-in's state must be refused")
	}
	code, out = appDo(t, r, "POST", "/api/claude-login/code", `{"code":"abc#`+q.Get("state")+`"}`)
	if code != 200 || out["email"] != "acct-1@example.com" {
		t.Fatal(code, out)
	}
	x := f.exchanges[0]
	if x["code"] != "abc" || x["redirect_uri"] != oauthRedirectURL || x["code_verifier"] == "" || x["state"] != q.Get("state") {
		t.Fatalf("%v", x)
	}
	cur := h.current()
	var d struct {
		O map[string]any `json:"claudeAiOauth"`
	}
	json.Unmarshal([]byte(cur.Credentials), &d)
	if d.O["accessToken"] != "at-new" || d.O["subscriptionType"] != "max" || d.O["rateLimitTier"] != "default_claude_max_20x" || accountUUID(cur.Account) != "acct-1" {
		t.Fatalf("%v %s", d.O, cur.Account)
	}
	if code, _ := appDo(t, r, "POST", "/api/claude-login/code", `{"code":"abc#`+q.Get("state")+`"}`); code != 400 {
		t.Fatal("a code is used once")
	}
	// status and usage, with no secret in either
	code, st := appDo(t, r, "GET", "/api/claude-login", "")
	if code != 200 || st["email"] != "acct-1@example.com" || strings.Contains(fmt.Sprint(st), "at-new") {
		t.Fatal(code, st)
	}
	code, us := appDo(t, r, "GET", "/api/usage", "")
	if code != 200 || len(us["limits"].([]any)) != 1 || us["limits"].([]any)[0].(map[string]any)["model"] != "Opus" {
		t.Fatal(code, us)
	}
}

// the Claude login is the store claude: every change of the pair is written there (writer router, with its backup),
// the machines whose grant names store:claude are told to pull, and the next pull serves it
func TestLoginGoesIntoTheStoreClaude(t *testing.T) {
	newFakeAnthropic(t)
	g := newKRig(t)
	g.setUpSecrets()
	g.writeKey("claude", "CLAUDE_CREDENTIALS", "old")
	g.unlock("claude")
	sid, m := g.newSession()
	m.boot()
	_, other := g.newSession("default")
	other.boot()
	g.r.Narrow(sessionOfMachine(g.r, other.id), []string{"default"}) // other: no store claude
	other.commands()
	m.commands()
	h := g.r.loginHub()
	exp := time.Now().Add(8 * time.Hour).UnixMilli()
	if ok, err := h.offer(pairOf("a", exp), acct1, "seed", true, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	waitFor(t, "the pull", func() bool {
		a := m.commands()
		return len(a.Commands) == 1 && a.Commands[0] == "pull"
	})
	if a := other.commands(); len(a.Commands) != 0 {
		t.Fatalf("a machine without store:claude was told: %+v", a)
	}
	vals, _ := m.pull()
	if !strings.Contains(vals["claude"]["CLAUDE_CREDENTIALS"], "at-a") || accountUUID(vals["claude"]["CLAUDE_ACCOUNT"]) != "acct-1" {
		t.Fatalf("pulled %v", vals["claude"])
	}
	g.backups.mu.Lock()
	_, backed := g.backups.puts["/jarvis2-backup-de0ch/keys/claude/CLAUDE_CREDENTIALS.json"]
	g.backups.mu.Unlock()
	if !backed {
		t.Fatal("no backup of the login")
	}
	// the refresh handshake: claude-prepare:<gen> to the holder, its ack, then the refresh and another pull
	go func() {
		for i := 0; i < 400; i++ {
			for _, w := range m.commands().Commands {
				if gen, ok := strings.CutPrefix(w, "claude-prepare:"); ok {
					m.json("POST", "/m/claude-ack", map[string]string{"gen": gen}, nil)
					return
				}
			}
		}
	}()
	start := time.Now()
	if ok, err := h.refresh(true); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the refresh waited out the ack timeout")
	}
	waitFor(t, "the refreshed pair in the store", func() bool {
		vals, _ := m.pull()
		return strings.Contains(vals["claude"]["CLAUDE_CREDENTIALS"], "at-a'")
	})
	// the machine's own refreshed pair: newer, same account → stored (and written into the store)
	b, _ := json.Marshal(map[string]string{"credentials": pairOf("b", exp+time.Hour.Milliseconds())})
	var out map[string]any
	if code := m.json("POST", "/m/claude-push", json.RawMessage(b), &out); code != 200 || out["stored"] != true {
		t.Fatal(code, out)
	}
	// a machine whose grant doesn't name store:claude: refused
	if code := other.json("POST", "/m/claude-push", json.RawMessage(b), nil); code != 403 {
		t.Fatal(code)
	}
	if code := other.json("POST", "/m/claude-ack", map[string]string{"gen": "1"}, nil); code != 403 {
		t.Fatal(code)
	}
	// the old polls are gone
	if code, _, _ := m.call("GET", "/m/claude-login", nil); code != 404 && code != 405 {
		t.Fatal(code)
	}
	_ = sid
}

func sessionOfMachine(r *Router, machine string) string {
	sid, _ := r.machineSession(machine)
	return sid
}

// the peer route (Jarvis 1): the same poll; a Re-login pushed from Jarvis 1 may switch the account
func TestLoginPeer(t *testing.T) {
	f := newFakeAnthropic(t)
	r, h := ownRouter(t)
	exp := time.Now().Add(8 * time.Hour).UnixMilli()
	h.offer(pairOf("a", exp), acct1, "seed", true, false)
	code, out := appDo(t, r, "GET", "/peer/claude-login?have=0", "")
	if code != 200 || !strings.Contains(out["credentials"].(string), "at-a") {
		t.Fatal(code, out)
	}
	f.accounts["z"] = "acct-2"
	b, _ := json.Marshal(map[string]any{"credentials": pairOf("z", exp+10), "account": `{"oauthAccount":{"accountUuid":"acct-2"}}`})
	if code, _ := appDo(t, r, "POST", "/peer/claude-login", string(b)); code != 403 {
		t.Fatal("a plain push of another account must be refused")
	}
	b, _ = json.Marshal(map[string]any{"credentials": pairOf("z", exp-10), "account": `{"oauthAccount":{"accountUuid":"acct-2"}}`, "relogin": true})
	if code, out := appDo(t, r, "POST", "/peer/claude-login", string(b)); code != 200 || out["stored"] != true || accountUUID(h.current().Account) != "acct-2" {
		t.Fatal("a Re-login through Jarvis 1 wins", code, out)
	}
	// the setup status is the setup session's (signed): a router with Access refuses anyone else
	r2 := NewRouter(Config{DataDir: t.TempDir(), AppAUD: "a", SetupAUD: "s"}, r.st, r.k, Policy{})
	if code, _ := appDo(t, r2, "GET", "/setup/claude-login", ""); code != 403 {
		t.Fatal(code)
	}
	if code, _ := appDo(t, r2, "GET", "/peer/claude-login", ""); code != 503 && code != 403 {
		t.Fatal(code)
	}
}
