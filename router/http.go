package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ke *KernelError
	if errors.As(err, &ke) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ke.Status)
		w.Write(ke.Body) // the part's signed error, unchanged
		return
	}
	status := 400
	switch {
	case errors.Is(err, errPartDown):
		writeJSON(w, 503, map[string]any{"error": err.Error(), "kernelDown": true})
		return
	case errors.Is(err, errDraining):
		status = 503 // drain.go: "router updating, try again shortly", shown as is
	case errors.Is(err, errBusy):
		status = 409
	case errors.Is(err, errNoShell):
		writeJSON(w, 403, map[string]any{"error": err.Error(), "needsTerminal": true})
		return
	}
	var b *badRequest
	var f *forbidden
	switch {
	case errors.As(err, &b):
		status = 400
	case errors.As(err, &f):
		status = 403
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// MachineHandler: /m only, for the listener that only Fly's private network reaches
func (r *Router) MachineHandler() http.Handler {
	r.handlers()
	return r.machineMux
}

// Handler: the public listener behind cloudflared — the app, the web page and setup
func (r *Router) Handler() http.Handler {
	r.handlers()
	return r.publicMux
}

func (r *Router) handlers() {
	r.muxOnce.Do(r.buildHandlers)
}

// secretsRelays: secrets' endpoints the app calls through the router, unchanged (the phone checks every answer)
var secretsRelays = []string{"state", "stores", "stores/create", "stores/mark-sensitive", "unlock/begin", "lock", "unlocked", "store-key",
	"stores/versions"}

func (r *Router) buildHandlers() {
	mux, mmux := http.NewServeMux(), http.NewServeMux()
	r.publicMux, r.machineMux = mux, mmux
	r.appPatterns = map[string]bool{}
	app := func(pattern string, fn http.HandlerFunc) {
		r.appPatterns[pattern] = true
		mux.Handle(pattern, r.requireDeyao(fn))
	}
	m := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte)) {
		mmux.Handle(pattern, r.requireMachine(fn))
	}
	// setup: the setup session's Access token AND its key's signature (checked here, by the router: secrets' store
	// calls are open, the router decides who uses them)
	setup := func(pattern, method, part, path string) {
		mux.Handle(pattern, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			if method == "GET" {
				b = nil
			}
			r.relay(w, part, method, path, b)
		}))
	}
	r.registerFeatures(app, m, mux.Handle)
	r.registerStoreDocs(app, m, mux) // storedocs.go: every store's keys, what they are for, and writing one key
	r.registerRestore(app, mux)      // storerestore.go: a store's versions and putting one back (phone-signed)
	r.registerActions(m)             // actions.go: each session's actions, on its machine key
	r.registerDocs(app)              // docstore.go: kernel documents by ID, chains, the root grant
	r.registerMachineAPI(m, mmux)    // machineapi.go: the guard's boot, grant, commands, answers, pull, snapshot
	// the router's own health, for an operator with no way into the box: secret NAMES present, image, parts up
	mux.Handle("GET /setup/status", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), nil); err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		present := []string{}
		for _, k := range []string{"LOBSTER_TOKEN", "STORAGEBOX_HOST", "STORAGEBOX_USER", "STORAGEBOX_PASSWORD", "FLY_READ_TOKEN",
			"JARVIS2_TUNNEL_KEY",
			"GITHUB_READ_TOKEN", "BACKUP_READ_ACCESS_KEY", "BACKUP_READ_SECRET_KEY", "FLY_ORG_READ_TOKENS",
			"FLY_PERSONAL_READ_TOKEN", "BROWSERBASE_API_KEY", "CF_DEVICE_TOKENS_API"} {
			if os.Getenv(k) != "" {
				present = append(present, k)
			}
		}
		parts := map[string]bool{}
		for role, key := range r.k.Roster() {
			parts[role] = key != ""
		}
		// what the repo picker's token sees, as counts only
		gh := map[string]any{}
		if repos, _, err := r.GitHubRepos(false); err != nil {
			gh["error"] = err.Error()
		} else {
			priv := 0
			for _, x := range repos {
				if x.Private {
					priv++
				}
			}
			gh["total"], gh["private"] = len(repos), priv
		}
		flyOrgs := []map[string]any{}
		ownMs, _ := listFlyMachines()
		orgs, _ := r.flyOrgsOverview(ownMs, time.Now())
		for _, o := range orgs {
			apps, machines := []string{}, 0
			for _, a := range o.Apps {
				apps = append(apps, a.App)
				machines += len(a.Machines)
			}
			flyOrgs = append(flyOrgs, map[string]any{"org": o.Org, "via": o.Via, "error": o.Error, "apps": apps, "machines": machines,
				"attention": flyAttentionCount([]flyOrgView{o})})
		}
		_, rootErr := r.rootGrant()
		writeJSON(w, 200, map[string]any{"secrets": present, "sessionImage": r.cfg.SessionImage, "kernel": parts, "rootGrant": rootErr == nil,
			"version": os.Getenv("VERSION"), "githubRepos": gh, "flyOrgs": flyOrgs})
	}))
	setup("GET /setup/identity", "GET", "secrets", "/identity")
	setup("POST /setup/stores", "POST", "secrets", "/stores")
	setup("POST /setup/stores/create", "POST", "secrets", "/stores/create")
	setup("POST /setup/stores/mark-sensitive", "POST", "secrets", "/stores/mark-sensitive")
	// the spawner's Fly token, sealed to the spawner
	setup("POST /setup/fly-token", "POST", "spawner", "/fly-token")

	// ---- setting secrets up: Reset and Recover (the app, with the master key) --------------------------------------
	app("GET /api/secrets/identity", func(w http.ResponseWriter, req *http.Request) { r.relay(w, "secrets", "GET", "/identity", nil) })
	app("GET /api/kernel/identities", func(w http.ResponseWriter, req *http.Request) {
		out := map[string]any{}
		for role := range kernelParts {
			if id, err := r.k.Identity(role); err == nil {
				out[role] = id
			} else {
				out[role] = nil
			}
		}
		writeJSON(w, 200, out)
	})
	// claim and wipe come only from the app's own device login (the cf-access-token header the shell sends)
	deviceOnly := func(req *http.Request, w http.ResponseWriter) bool {
		if !r.cfg.NoAccess && req.Header.Get("cf-access-token") == "" {
			writeJSON(w, 403, map[string]string{"error": "only the iPhone app sets secrets up"})
			return false
		}
		return true
	}
	// the claim also carries the app's device-key countersignature (deviceKey, deviceSig over the statement): secrets
	// ignores it; the router keeps it for the setup session (claimdevice.go). Right after a claim the router writes the
	// Claude login into the store claude (claudelogin.go).
	app("POST /api/secrets/claim", func(w http.ResponseWriter, req *http.Request) {
		if !deviceOnly(req, w) {
			return
		}
		b, _ := io.ReadAll(io.LimitReader(req.Body, 16<<20))
		r.keepClaimDevice(b)
		var in map[string]json.RawMessage
		json.Unmarshal(b, &in)
		fwd, _ := json.Marshal(map[string]json.RawMessage{"statement": in["statement"], "masterSig": in["masterSig"], "bundle": in["bundle"]})
		status, out, err := r.k.Raw("secrets", "POST", "/claim", fwd)
		if err != nil {
			writeJSON(w, 503, map[string]any{"error": err.Error(), "kernelDown": true})
			return
		}
		if status == 200 {
			r.keepSecretsCert(b) // claimdevice.go: the master's signature on this secrets, kept by the router
			go r.publishLogin("claim")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(out)
	})
	app("POST /api/secrets/wipe", func(w http.ResponseWriter, req *http.Request) {
		if !deviceOnly(req, w) {
			return
		}
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		r.relay(w, "secrets", "POST", "/wipe", b)
	})
	mux.Handle("GET /setup/secrets-cert", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), nil); err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		b := r.secretsCert()
		if b == nil {
			writeJSON(w, 404, map[string]string{"error": "no claim kept for the running secrets (empty, or claimed elsewhere)"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	mux.Handle("GET /setup/claim-device", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, r.claimDevices())
	}))
	r.registerBackups(app)
	app("GET /api/policy", func(w http.ResponseWriter, req *http.Request) { writeJSON(w, 200, r.policy) })

	// ---- sign-in -----------------------------------------------------------------------------------
	app("GET /api/auth/start", func(w http.ResponseWriter, req *http.Request) {
		redirect := req.URL.Query().Get("redirect")
		if !strings.HasPrefix(redirect, "jarvis2://") {
			writeJSON(w, 400, map[string]string{"error": "only jarvis2:// redirects"})
			return
		}
		tok := req.Header.Get("Cf-Access-Jwt-Assertion")
		if tok == "" {
			tok = req.Header.Get("cf-access-token")
		}
		http.Redirect(w, req, redirect+"#token="+url.QueryEscape(tok), http.StatusFound)
	})

	// ---- state ---------------------------------------------------------------------------------------
	app("GET /api/state", func(w http.ResponseWriter, req *http.Request) {
		id, err := r.k.Identity("secrets")
		secretsInfo := map[string]any{"up": err == nil}
		if err == nil {
			secretsInfo["signingKey"], secretsInfo["agreementKey"] = id.SigningKey, id.AgreementKey
		}
		_, rootErr := r.rootGrant()
		var sessions []map[string]any
		var approvals []*Approval
		r.st.Do(func(d *persisted) {
			for _, s := range d.Sessions {
				sessions = append(sessions, sessionView(s, d))
			}
			for _, a := range d.Approvals {
				approvals = append(approvals, a)
			}
		})
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i]["created"].(time.Time).After(sessions[j]["created"].(time.Time))
		})
		sort.Slice(approvals, func(i, j int) bool { return approvals[i].Created.Before(approvals[j].Created) })
		out := map[string]any{"sessions": orEmpty(sessions), "approvals": orEmptyA(approvals), "secrets": secretsInfo, "rootGrant": rootErr == nil}
		for _, h := range stateHooks {
			h(r, out)
		}
		writeJSON(w, 200, out)
	})
	app("GET /api/sizes", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]any{"sizes": []map[string]string{
			{"id": "small", "label": "2×shared · 2 GB"}, {"id": "medium", "label": "4×shared · 4 GB"}, {"id": "large", "label": "8×shared · 8 GB"}}})
	})
	app("GET /api/records", func(w http.ResponseWriter, req *http.Request) {
		var recs []*Record
		r.st.Do(func(d *persisted) { recs = append(recs, d.Records...) })
		if recs == nil {
			recs = []*Record{}
		}
		writeJSON(w, 200, map[string]any{"records": recs})
	})

	// ---- the terminal (terminal.go): a shell command under a terminal add-on (addons.go) -------------------------
	app("POST /api/sessions/{id}/exec", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Cmd     string `json:"cmd"`
			Timeout int    `json:"timeout"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in)
		res, err := r.Shell(req.PathValue("id"), in.Cmd, time.Duration(max(5, min(in.Timeout, 600)))*time.Second)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, res)
	})
	app("GET /api/sessions/{id}/terminal", func(w http.ResponseWriter, req *http.Request) {
		snap, err := r.TermSnapshot(req.PathValue("id"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, snap)
	})
	r.registerTermPage(app) // termpage.go: the terminal as a web page (the iPhone app shows it in a web view)
	app("POST /api/sessions/{id}/terminal", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Text       string   `json:"text"`
			Keys       []string `json:"keys"`
			Cols, Rows int
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		var err error
		if in.Cols > 0 {
			err = r.TermResize(req.PathValue("id"), in.Cols, in.Rows)
		} else {
			err = r.TermInput(req.PathValue("id"), in.Text, in.Keys)
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ---- sessions ------------------------------------------------------------------------------------
	app("POST /api/sessions", func(w http.ResponseWriter, req *http.Request) {
		var in NewSession
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil {
			writeErr(w, fmt.Errorf("bad JSON: %v", err))
			return
		}
		if in.RequestID == "" {
			in.RequestID = randID()
		}
		args := map[string]any{"label": in.Label, "harness": in.Harness, "stores": in.Stores, "model": in.Model, "permissionMode": in.PermissionMode, "size": in.Size}
		if in.Repos != "" {
			args["repos"] = in.Repos
		}
		if len(in.Content) > 0 {
			args["content"] = in.Content
		}
		if in.Prompt != "" {
			args["prompt"] = fmt.Sprintf("(%d characters)", len([]rune(in.Prompt)))
		}
		in.Origin = &Origin{Caller: appCaller(req), Call: APICall{Method: "POST", Path: "/api/sessions", Args: args}}
		id, err := r.CreateSession(in)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"id": id, "requestId": in.RequestID})
	})
	app("POST /api/sessions/{id}/pause", func(w http.ResponseWriter, req *http.Request) {
		if err := r.Pause(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/resume", func(w http.ResponseWriter, req *http.Request) {
		var in ResumeIn
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		prompt, err := cleanResumePrompt(in.Prompt)
		if err != nil {
			writeErr(w, err)
			return
		}
		in.Prompt, in.Rollback = prompt, ""
		r.noteOrigin(req.PathValue("id"), Origin{Caller: appCaller(req), Call: APICall{Method: "POST", Path: req.URL.Path, Args: map[string]any{"upgrade": in.Upgrade}}})
		if err := r.Resume(req.PathValue("id"), in); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/destroy", func(w http.ResponseWriter, req *http.Request) {
		if err := r.DestroyWith(req.PathValue("id"), req.URL.Query().Get("force") == "1"); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// narrowing in place: the main grant moved along the identity edge to fewer stores (addons.go)
	app("POST /api/sessions/{id}/narrow", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Stores []string `json:"stores"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		kept, err := r.Narrow(req.PathValue("id"), in.Stores)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "stores": kept})
	})

	// ---- approvals -----------------------------------------------------------------------------------
	app("GET /api/approvals", func(w http.ResponseWriter, req *http.Request) {
		var out []*Approval
		r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				out = append(out, a)
			}
		})
		sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
		writeJSON(w, 200, map[string]any{"approvals": orEmptyA(out)})
	})
	app("POST /api/approvals/{id}/respond", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Signatures []string `json:"signatures"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		sid, err := r.Respond(req.PathValue("id"), in.Signatures)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "session": sid})
	})
	app("POST /api/approvals/{id}/reject", func(w http.ResponseWriter, req *http.Request) {
		if err := r.Reject(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ---- secrets, relayed unchanged ---------------------------------------------------------------------
	for _, p := range secretsRelays {
		path := "/" + p
		app("POST /api/secrets"+path, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			r.relay(w, "secrets", "POST", path, b)
		})
	}
	// an unlock of a store: every running machine whose grant names it pulls again
	app("POST /api/secrets/unlock/finish", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		status, out, err := r.k.Raw("secrets", "POST", "/unlock/finish", b)
		if err != nil {
			writeJSON(w, 503, map[string]any{"error": err.Error(), "kernelDown": true})
			return
		}
		if status == 200 {
			var d kernel.SignedDoc
			var u struct {
				Kind  string `json:"kind"`
				Store string `json:"store"`
			}
			if json.Unmarshal(out, &d) == nil && payloadOf(d, &u) == nil && u.Kind == "unlocked" && u.Store != "" {
				r.pullHolders(u.Store)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(out)
	})

	// an API path no route serves is a 404, not the web page
	mux.Handle("GET /api/", r.requireDeyao(func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 404, map[string]string{"error": "no such API: " + req.Method + " " + req.URL.Path})
	}))

	// ---- the web page ------------------------------------------------------------------------------------
	web := http.FileServer(http.Dir(r.cfg.WebDir))
	mux.Handle("GET /", r.requireDeyao(func(w http.ResponseWriter, req *http.Request) {
		p := filepath.Join(r.cfg.WebDir, filepath.Clean("/"+req.URL.Path))
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			if _, err := os.Stat(p + ".html"); err == nil {
				req.URL.Path += ".html"
			} else if _, err := os.Stat(filepath.Join(p, "index.html")); err != nil {
				req.URL.Path = "/" // a client-side route
			}
		}
		web.ServeHTTP(w, req)
	}))
}

// relay: one call to a kernel part, its answer unchanged
func (r *Router) relay(w http.ResponseWriter, part, method, path string, body []byte) {
	status, b, err := r.k.Raw(part, method, path, body)
	if err != nil {
		// the part isn't reachable (its pod is restarting, e.g. after a wipe): a state, not a fault — the app waits
		// and shows it as a plain note (kernelDown)
		log.Printf("%s %s %s: %v", part, method, path, err)
		writeJSON(w, 503, map[string]any{"error": err.Error(), "kernelDown": true})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

// checkSetupSig: a setup call is signed by the setup key over "<METHOD> <path> <unix time> <sha256hex body>",
// within two minutes, each signature once
func (r *Router) checkSetupSig(method, path, t, sig string, body []byte) error {
	if r.cfg.NoAccess && r.cfg.SetupKey == "" {
		return nil // CI without a setup key
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return fmt.Errorf("setup signature required")
	}
	if d := time.Since(time.Unix(ts, 0)); d > 2*time.Minute || d < -2*time.Minute {
		return fmt.Errorf("X-Setup-Time too far off")
	}
	sum := sha256.Sum256(body)
	msg := fmt.Sprintf("%s %s %d %s", method, path, ts, hex.EncodeToString(sum[:]))
	if r.cfg.SetupKey == "" || !verifyP256(r.cfg.SetupKey, []byte(msg), sig) {
		return fmt.Errorf("bad setup signature")
	}
	r.setupMu.Lock()
	defer r.setupMu.Unlock()
	for k, at := range r.setupSeen {
		if time.Since(at) > 5*time.Minute {
			delete(r.setupSeen, k)
		}
	}
	if _, ok := r.setupSeen[sig]; ok {
		return fmt.Errorf("setup signature already used")
	}
	r.setupSeen[sig] = time.Now()
	return nil
}

func sessionView(s *Session, d *persisted) map[string]any {
	guest := map[string]string{"small": "2×shared · 2 GB", "medium": "4×shared · 4 GB", "large": "8×shared · 8 GB"}[s.Size]
	name := s.Label
	if name == "" {
		name = s.Title
	}
	v := map[string]any{
		"serverTitle": s.AppTitle, "userTitle": s.UserTitle, "title": sessionTitle(*s), "liveSync": s.LiveSync,
		"id": s.ID, "machineId": nullIfEmpty(s.MachineID), "released": s.MachineID == "" && s.State == "paused",
		"name": name, "state": s.State, "status": s.Status, "error": s.Error, "created": s.Created, "region": "",
		"environment": strings.Join(s.Stores, ","), "stores": s.Stores, "content": orEmptyS(s.Content), "harness": s.Harness, "label": s.Label, "aiTitle": s.Title,
		"model": s.Model, "permissionMode": s.PermissionMode, "guest": guest, "size": s.Size, "pausedAt": s.PausedAt,
		"image": s.Image, "createRequestId": s.RequestID, "repos": s.Repos, "discordChannel": s.DiscordChannel,
		"waiting": s.Waiting, "lockedStore": s.LockedStore, "commands": orEmptyC(s.Commands), "addOns": addOnsView(s),
	}
	liveView(s, v)
	scheduleView(d, s.ID, v)
	opsView(s, v)
	return v
}

func orEmptyC(c []CommandRun) []CommandRun {
	if c == nil {
		return []CommandRun{}
	}
	return c
}

// addOnsView: the add-ons in force on the running machine (kind, until; the documents are in the chain)
func addOnsView(s *Session) []map[string]any {
	out := []map[string]any{}
	if s.Chain == nil || s.MachineID == "" {
		return out
	}
	for _, a := range s.Chain.active(time.Now()) {
		out = append(out, map[string]any{"id": a.ID, "kind": a.Kind, "until": a.Until})
	}
	return out
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orEmpty(s []map[string]any) []map[string]any {
	if s == nil {
		return []map[string]any{}
	}
	return s
}

func orEmptyA(s []*Approval) []*Approval {
	if s == nil {
		return []*Approval{}
	}
	return s
}

// ---- Cloudflare Access: the router checks the JWT itself too ---------------------------------------------

func (r *Router) requireDeyao(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.cfg.NoAccess {
			tok := req.Header.Get("Cf-Access-Jwt-Assertion")
			claims, err := r.access().verify(tok, r.cfg.AppAUD)
			if err != nil || !strings.EqualFold(claims.Email, r.cfg.AllowedEmail) {
				writeJSON(w, 403, map[string]string{"error": "Access login required"})
				return
			}
		}
		fn(w, req)
	})
}

// requireSetup: the setup session's Access service token (app jarvis2.deyaochen.com/setup); the router then
// checks the setup key's own signature, so this gate only keeps strangers away from the code
func (r *Router) requireSetup(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.cfg.NoAccess {
			if _, err := r.access().verify(req.Header.Get("Cf-Access-Jwt-Assertion"), r.cfg.SetupAUD); err != nil {
				writeJSON(w, 403, map[string]string{"error": "Access service token required"})
				return
			}
		}
		fn(w, req)
	})
}

// requireMachine: no Access here — this listener is reachable only over Fly's private network; every
// request must be signed by a machine the spawner started
func (r *Router) requireMachine(fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(io.LimitReader(req.Body, 4<<30))
		if err != nil {
			writeErr(w, err)
			return
		}
		machine, t, sig := req.Header.Get("X-Machine"), req.Header.Get("X-Time"), req.Header.Get("X-Sig")
		ts, _ := strconv.ParseInt(t, 10, 64)
		if d := time.Since(time.Unix(ts, 0)); d > 120*time.Second || d < -120*time.Second {
			writeJSON(w, 401, map[string]string{"error": "X-Time too far off"})
			return
		}
		var key string
		r.st.Do(func(d *persisted) {
			if s := d.Started[machine]; s != nil {
				key = s.SigningKey
			}
		})
		sum := sha256.Sum256(body)
		msg := req.Method + " " + req.URL.Path + " " + t + " " + hex.EncodeToString(sum[:])
		if key == "" || !verifyP256(key, []byte(msg), sig) {
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the spawner started"})
			return
		}
		fn(w, req, machine, body)
	})
}

// snapshotMax: the largest snapshot the router takes (the volume is the limit; a machine's disk is 16 GB)
const snapshotMax = 32 << 30

// requireMachineStream: requireMachine for a large body — streamed to a temp file on the volume while it is hashed,
// then the signature (over that hash) checked; fn gets the file's path and must move or remove it
func (r *Router) requireMachineStream(fn func(w http.ResponseWriter, req *http.Request, machine, tmp, sum string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		machine, t, sig := req.Header.Get("X-Machine"), req.Header.Get("X-Time"), req.Header.Get("X-Sig")
		ts, _ := strconv.ParseInt(t, 10, 64)
		if d := time.Since(time.Unix(ts, 0)); d > 120*time.Second || d < -120*time.Second {
			writeJSON(w, 401, map[string]string{"error": "X-Time too far off"})
			return
		}
		var key string
		r.st.Do(func(d *persisted) {
			if s := d.Started[machine]; s != nil {
				key = s.SigningKey
			}
		})
		if key == "" { // before reading a byte: only a machine the spawner started may write to the volume
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the spawner started"})
			return
		}
		f, err := os.CreateTemp(filepath.Dir(r.st.snapshotPath("x")), ".upload-*")
		if err != nil {
			writeErr(w, err)
			return
		}
		tmp := f.Name()
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(req.Body, snapshotMax+1))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil && n > snapshotMax {
			err = fmt.Errorf("body over %d bytes", int64(snapshotMax))
		}
		if err != nil {
			os.Remove(tmp)
			writeErr(w, err)
			return
		}
		sum := hex.EncodeToString(h.Sum(nil))
		msg := req.Method + " " + req.URL.Path + " " + t + " " + sum
		if !verifyP256(key, []byte(msg), sig) {
			os.Remove(tmp)
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the spawner started"})
			return
		}
		fn(w, req, machine, tmp, sum)
	})
}

func verifyP256(pubRaw string, payload []byte, sigB64 string) bool {
	b, err := base64.StdEncoding.DecodeString(pubRaw)
	if err != nil {
		return false
	}
	pk, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return false
	}
	der, _ := x509.MarshalPKIXPublicKey(pk)
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	ek, ok := k.(*ecdsa.PublicKey)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if !ok || err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(ek, h[:], sig)
}

type accessClaims struct {
	Aud        any    `json:"aud"`
	Email      string `json:"email"`
	CommonName string `json:"common_name"` // a service token's client id (no email)
	Exp        int64  `json:"exp"`
	Iss        string `json:"iss"`
}

type accessKeys struct {
	mu      sync.Mutex
	team    string
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

var accessCache = map[string]*accessKeys{}
var accessMu sync.Mutex

func (r *Router) access() *accessKeys {
	accessMu.Lock()
	defer accessMu.Unlock()
	a := accessCache[r.cfg.AccessTeam]
	if a == nil {
		a = &accessKeys{team: r.cfg.AccessTeam}
		accessCache[r.cfg.AccessTeam] = a
	}
	return a
}

func (a *accessKeys) key(kid string) (*rsa.PublicKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if k := a.keys[kid]; k != nil && time.Since(a.fetched) < time.Hour {
		return k, nil
	}
	resp, err := http.Get("https://" + a.team + "/cdn-cgi/access/certs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	a.keys, a.fetched = map[string]*rsa.PublicKey{}, time.Now()
	for _, k := range set.Keys {
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		a.keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if k := a.keys[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("unknown Access key")
}

func (a *accessKeys) verify(tok, aud string) (*accessClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("no Access token")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("bad token")
	}
	var h struct{ Alg, Kid string }
	json.Unmarshal(hb, &h)
	if h.Alg != "RS256" {
		return nil, errors.New("bad alg")
	}
	k, err := a.key(h.Kid)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("bad token signature")
	}
	var c accessClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	if time.Now().Unix() > c.Exp {
		return nil, errors.New("token expired")
	}
	if c.Iss != "https://"+a.team {
		return nil, errors.New("wrong issuer")
	}
	ok := false
	switch v := c.Aud.(type) {
	case string:
		ok = v == aud
	case []any:
		for _, x := range v {
			ok = ok || x == aud
		}
	}
	if !ok {
		return nil, errors.New("wrong audience")
	}
	return &c, nil
}
