package main

// Claude accounts (Deyao, 2026-10-15: "there should be multiple claude key stores, one per account, so I can choose
// which account a session starts with and the session uses it (refreshed automatically), and I can manage the accounts
// in the dashboard"; DECISIONS 181). Each account is a Claude key store of the router's own, named `claude-<name>`:
// its OAuth pair and account record (claude-accounts/<store>.json on the volume, 0600, one loginHub each,
// claudelogin.go), refreshed by this router alone. They are the router's, not the core's: the pair rotates every 8
// hours with nobody there (DECISIONS 115), and the core's stores take keys only from the setup session or a session.
//
//   - A session's account is chosen when it is made (New session in the app and web page, `jarvis2-request
//     new-session --account`, a task instance, a restore) and kept for the session's life (Session.ClaudeAccount): a
//     resume keeps it, a running session never switches. Harnesses that need one (policy/stores.json
//     `claudeAccount`: claude, openclaw) and prompt tasks get the default account when none is named. Trusted as the
//     router's word, like the pair itself (Deyao, 2026-10-15: no machine-side account check).
//   - The default account (claude-accounts/accounts.json) is what New session pre-picks; Deyao sets it.
//   - Remove is refused while any session (running, paused, waiting for approval, failed) uses the account, and for
//     the default account. A broken login gets no automatic action: the dashboard shows each account's state and
//     Deyao re-logs it in.
//   - The clean cut from the one shared login (`claude` in the core): at the first start of this code the router's
//     claude-login.json becomes the account claude-<the email's name> (the default and Jarvis 1's), and every session
//     whose cert names the old store `claude` gets that account. New sessions no longer get the core's `claude`.
//
// Routes (the app and web page; GET /setup/claude-accounts for the setup session):
//
//	GET    /api/claude-accounts                    {default, accounts: [status + {name, default, sessions}]}
//	POST   /api/claude-accounts {name}             a new account: {store, url} — the sign-in page; then …/code
//	POST   /api/claude-accounts/{store}/login      Re-login: {url}
//	POST   /api/claude-accounts/{store}/code       {code: "code#state"} → {ok, email, expiresAt}
//	POST   /api/claude-accounts/{store}/refresh    refresh now
//	POST   /api/claude-accounts/{store}/default    make it the default
//	DELETE /api/claude-accounts/{store}            remove (409 while a session uses it, or it is the default)
//	GET    /api/claude-accounts/{store}/usage      its usage quota (?refresh=1)
//
// The routes of the one shared login (/api/claude-login, …/refresh, …/start, …/code, /api/usage) act on the default
// account, for app builds from before accounts.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// the core's store of the one shared login before accounts (sessions from before the cut still hold it)
const legacyClaudeStore = "claude"

var accountStoreRE = regexp.MustCompile(`^claude-[a-z0-9]+(-[a-z0-9]+)*$`)

// accountStoreName: "work" or "claude-work" → "claude-work"; "" when it can't be one
func accountStoreName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "claude-") {
		n = "claude-" + n
	}
	if len(n) > 48 || !accountStoreRE.MatchString(n) {
		return ""
	}
	return n
}

// slugFromEmail: "chendeyao.uk@gmail.com" → "chendeyao-uk"
func slugFromEmail(email string) string {
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	var b strings.Builder
	dash := false
	for _, c := range local {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

type accountsDoc struct {
	Default string `json:"default"`
	Jarvis1 string `json:"jarvis1,omitempty"` // the account Jarvis 1 follows (the one the shared login became)
}

type claudeAccounts struct {
	r    *Router
	dir  string
	mu   sync.Mutex
	hubs map[string]*loginHub
	doc  accountsDoc
}

// accounts: the router's Claude accounts (loaded, and the one shared login migrated, on first use)
func (r *Router) accounts() *claudeAccounts {
	r.loginOnce.Do(func() {
		dir := r.cfg.DataDir
		if dir == "" {
			dir = os.TempDir()
		}
		a := &claudeAccounts{r: r, dir: filepath.Join(dir, "claude-accounts"), hubs: map[string]*loginHub{}}
		a.load(dir)
		r.claude = a
	})
	return r.claude
}

func (a *claudeAccounts) docPath() string { return filepath.Join(a.dir, "accounts.json") }

func (a *claudeAccounts) newHub(store string) *loginHub {
	h := newLoginHub(filepath.Join(a.dir, store+".json"), store)
	h.dm = a.r.DM
	h.check = func(uuid string) error { return a.checkRelogin(store, uuid) }
	return h
}

func (a *claudeAccounts) load(dataDir string) {
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		log.Printf("[accounts] %s: %v", a.dir, err)
	}
	if b, err := os.ReadFile(a.docPath()); err == nil {
		json.Unmarshal(b, &a.doc)
	}
	files, _ := filepath.Glob(filepath.Join(a.dir, "claude-*.json"))
	for _, f := range files {
		store := strings.TrimSuffix(filepath.Base(f), ".json")
		if accountStoreRE.MatchString(store) {
			a.hubs[store] = a.newHub(store)
		}
	}
	a.migrate(dataDir)
}

// migrate: the clean cut from the one shared login (claude-login.json) to accounts, once
func (a *claudeAccounts) migrate(dataDir string) {
	old := filepath.Join(dataDir, "claude-login.json")
	b, err := os.ReadFile(old)
	if err != nil {
		return
	}
	var f loginFile
	if json.Unmarshal(b, &f) != nil {
		log.Printf("[accounts] %s unreadable: not migrated", old)
		return
	}
	store := accountStoreName(slugFromEmail(accountEmail(f.Account)))
	if store == "" {
		store = "claude-main"
	}
	if a.hubs[store] == nil {
		f.Pending = nil
		nb, _ := json.MarshalIndent(f, "", " ")
		if err := writeFile0600(filepath.Join(a.dir, store+".json"), nb); err != nil {
			log.Printf("[accounts] migrating %s: %v", old, err)
			return
		}
		a.hubs[store] = a.newHub(store)
	}
	if a.doc.Default == "" {
		a.doc.Default = store
	}
	if a.doc.Jarvis1 == "" {
		a.doc.Jarvis1 = store
	}
	if err := a.saveDoc(); err != nil {
		log.Printf("[accounts] %v", err)
		return
	}
	n := 0
	a.r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.ClaudeAccount == "" && containsStr(s.Stores, legacyClaudeStore) {
				s.ClaudeAccount = store
				n++
			}
		}
		for _, rec := range d.Records {
			if rec.ClaudeAccount == "" && containsStr(rec.Stores, legacyClaudeStore) {
				rec.ClaudeAccount = store
			}
		}
	})
	if err := os.Rename(old, old+".migrated"); err != nil {
		log.Printf("[accounts] %v", err)
	}
	log.Printf("[accounts] the shared Claude login became the account %s (default); %d sessions holding the store claude use it", store, n)
}

func containsStr(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func writeFile0600(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *claudeAccounts) saveDoc() error {
	b, _ := json.MarshalIndent(a.doc, "", " ")
	return writeFile0600(a.docPath(), b)
}

// hub: the account's hub; nil = no such account
func (a *claudeAccounts) hub(store string) *loginHub {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hubs[store]
}

// all: every account's hub, by name
func (a *claudeAccounts) all() []*loginHub {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*loginHub, 0, len(a.hubs))
	for _, h := range a.hubs {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].store < out[j].store })
	return out
}

func (a *claudeAccounts) defaultStore() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hubs[a.doc.Default] == nil {
		return ""
	}
	return a.doc.Default
}

func (a *claudeAccounts) defaultHub() *loginHub { return a.hub(a.defaultStore()) }

// jarvis1Hub: the account Jarvis 1 follows: the one the shared login became, else the default
func (a *claudeAccounts) jarvis1Hub() *loginHub {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.doc.Jarvis1 != "" {
		return a.hubs[a.doc.Jarvis1]
	}
	return a.hubs[a.doc.Default]
}

// resolve: the account a new session gets — the one named, else the default; "" with no error when it needs none,
// or when there is no account at all
func (a *claudeAccounts) resolve(named string, needs bool) (string, error) {
	if named == "" {
		if !needs {
			return "", nil
		}
		// no account at all (a new box before its first sign-in): the session starts logged out, as before accounts
		return a.defaultStore(), nil
	}
	store := accountStoreName(named)
	if store == "" || a.hub(store) == nil {
		return "", fmt.Errorf("no Claude account %q (Settings → Claude accounts lists them)", named)
	}
	if !needs {
		return "", fmt.Errorf("this session's harness takes no Claude account")
	}
	return store, nil
}

// checkRelogin: a sign-in into store must be its own account (once it has one) and no other account's
func (a *claudeAccounts) checkRelogin(store, uuid string) error {
	if uuid == "" {
		return nil // the profile wasn't readable: nothing to check against
	}
	for _, h := range a.all() {
		u := accountUUID(h.current().Account)
		switch {
		case h.store == store && u != "" && u != uuid:
			return fmt.Errorf("that sign-in is another Claude account than %s's (%s): sign in as %s, or add it as a new account", store, accountEmail(h.current().Account), accountEmail(h.current().Account))
		case h.store != store && u == uuid:
			return fmt.Errorf("that Claude account is already %s", h.store)
		}
	}
	return nil
}

// users: the sessions (not destroyed) that use store
func (r *Router) accountUsers(store string) []string {
	var out []string
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.ClaudeAccount == store {
				out = append(out, s.ID)
			}
		}
	})
	sort.Strings(out)
	return out
}

func (a *claudeAccounts) add(name string) (*loginHub, error) {
	store := accountStoreName(name)
	if store == "" {
		return nil, errors.New("name: lowercase letters, digits and single dashes (it becomes claude-<name>)")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hubs[store] != nil {
		return nil, fmt.Errorf("%s exists already: Re-login it instead", store)
	}
	h := a.newHub(store)
	if err := h.save(); err != nil { // the slot exists from here on, signed in or not
		return nil, err
	}
	a.hubs[store] = h
	if a.doc.Default == "" || a.hubs[a.doc.Default] == nil {
		a.doc.Default = store
		a.saveDoc()
	}
	log.Printf("[accounts] %s added", store)
	return h, nil
}

func (a *claudeAccounts) setDefault(store string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hubs[store] == nil {
		return fmt.Errorf("no Claude account %s", store)
	}
	a.doc.Default = store
	return a.saveDoc()
}

type accountConflict struct{ msg string }

func (e *accountConflict) Error() string { return e.msg }

func (a *claudeAccounts) remove(store string) error {
	if users := a.r.accountUsers(store); len(users) > 0 {
		return &accountConflict{fmt.Sprintf("%s is used by %d session(s) (%s): destroy them first", store, len(users), strings.Join(users, ", "))}
	}
	h := a.hub(store)
	if h == nil {
		return fmt.Errorf("no Claude account %s", store)
	}
	h.refreshMu.Lock() // not while its refresh or a sign-in is out (taken before a.mu: finishLogin's check takes a.mu)
	defer h.refreshMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.doc.Default == store {
		return &accountConflict{store + " is the default account: make another one the default first"}
	}
	if err := os.Remove(h.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(a.hubs, store)
	if a.doc.Jarvis1 == store {
		a.doc.Jarvis1 = ""
		a.saveDoc()
	}
	log.Printf("[accounts] %s removed", store)
	return nil
}

// list: every account's status (no secrets), with its name, whether it is the default and the sessions using it
func (a *claudeAccounts) list() map[string]any {
	def := a.defaultStore()
	rows := []map[string]any{}
	for _, h := range a.all() {
		st := h.status()
		st["name"] = strings.TrimPrefix(h.store, "claude-")
		st["default"] = h.store == def
		users := a.r.accountUsers(h.store)
		if users == nil {
			users = []string{}
		}
		st["sessions"] = users
		rows = append(rows, st)
	}
	return map[string]any{"default": def, "accounts": rows}
}

func loginErrStatus(err error) int {
	var c *accountConflict
	switch {
	case errors.As(err, &c):
		return 409
	case errors.Is(err, errNoPair):
		return 409
	}
	return 400
}

func (r *Router) registerClaudeAccounts(app appRoute, public publicRoute) {
	a := r.accounts()
	withHub := func(fn func(w http.ResponseWriter, req *http.Request, h *loginHub)) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			h := a.hub(req.PathValue("store"))
			if h == nil {
				writeJSON(w, 404, map[string]string{"error": "no Claude account " + req.PathValue("store")})
				return
			}
			fn(w, req, h)
		}
	}
	// the default account, for the routes that took no account (app builds from before accounts)
	withDefault := func(fn func(w http.ResponseWriter, req *http.Request, h *loginHub)) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			h := a.defaultHub()
			if h == nil {
				writeJSON(w, 409, map[string]any{"error": "no Claude account yet: add one in Settings → Claude accounts", "needLogin": true})
				return
			}
			fn(w, req, h)
		}
	}
	refresh := func(w http.ResponseWriter, req *http.Request, h *loginHub) {
		ok, err := h.refresh(true)
		if err != nil {
			status := 502
			if errors.Is(err, errNoPair) {
				status = 409
			}
			writeJSON(w, status, map[string]any{"error": err.Error(), "needLogin": errors.Is(err, errNoPair) || strings.Contains(err.Error(), "Re-login")})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "refreshed": ok, "expiresAt": h.current().ExpiresAt})
	}
	start := func(w http.ResponseWriter, req *http.Request, h *loginHub) {
		u, err := h.startLogin()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"url": u, "store": h.store})
	}
	code := func(w http.ResponseWriter, req *http.Request, h *loginHub) {
		var b struct {
			Code string `json:"code"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&b)
		email, err := h.finishLogin(b.Code)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		cur := h.current()
		go r.resumeStuckLogins()
		writeJSON(w, 200, map[string]any{"ok": true, "store": h.store, "email": email, "expiresAt": cur.ExpiresAt})
	}
	usage := func(w http.ResponseWriter, req *http.Request, h *loginHub) {
		status, body := h.usageQuota(req.URL.Query().Get("refresh") == "1")
		body["store"] = h.store
		writeJSON(w, status, body)
	}

	app("GET /api/claude-accounts", func(w http.ResponseWriter, req *http.Request) { writeJSON(w, 200, a.list()) })
	app("POST /api/claude-accounts", func(w http.ResponseWriter, req *http.Request) {
		var b struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&b); err != nil {
			writeJSON(w, 400, map[string]string{"error": "body must be {name}"})
			return
		}
		h, err := a.add(b.Name)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		start(w, req, h)
	})
	app("POST /api/claude-accounts/{store}/login", withHub(start))
	app("POST /api/claude-accounts/{store}/code", withHub(code))
	app("POST /api/claude-accounts/{store}/refresh", withHub(refresh))
	app("GET /api/claude-accounts/{store}/usage", withHub(usage))
	app("POST /api/claude-accounts/{store}/default", withHub(func(w http.ResponseWriter, req *http.Request, h *loginHub) {
		if err := a.setDefault(h.store); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "default": h.store})
	}))
	app("DELETE /api/claude-accounts/{store}", withHub(func(w http.ResponseWriter, req *http.Request, h *loginHub) {
		if err := a.remove(h.store); err != nil {
			writeJSON(w, loginErrStatus(err), map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))

	app("GET /api/claude-login", withDefault(func(w http.ResponseWriter, req *http.Request, h *loginHub) { writeJSON(w, 200, h.status()) }))
	app("POST /api/claude-login/refresh", withDefault(refresh))
	app("POST /api/claude-login/start", withDefault(start))
	app("POST /api/claude-login/code", withDefault(code))
	app("GET /api/usage", withDefault(usage))

	// ---- the setup session: the status ----
	setupSigned := func(fn func(w http.ResponseWriter, req *http.Request)) http.Handler {
		return r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req)
		})
	}
	public("GET /setup/claude-accounts", setupSigned(func(w http.ResponseWriter, req *http.Request) { writeJSON(w, 200, a.list()) }))
	public("GET /setup/claude-login", setupSigned(func(w http.ResponseWriter, req *http.Request) {
		if h := a.defaultHub(); h != nil {
			writeJSON(w, 200, h.status())
			return
		}
		writeJSON(w, 409, map[string]any{"error": "no Claude account yet", "needLogin": true})
	}))
}
