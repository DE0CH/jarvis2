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
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var gn *GrantNeeded
	if errors.As(err, &gn) {
		writeJSON(w, 403, map[string]any{"error": err.Error(), "needsGrant": gn.Holder, "phoneGrant": gn.Phone})
		return
	}
	var ce *CoreError
	if errors.As(err, &ce) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ce.Status)
		w.Write(ce.Body) // the core's signed error, unchanged
		return
	}
	status := 400
	if errors.Is(err, errBusy) {
		status = 409
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

func (r *Router) buildHandlers() {
	mux, mmux := http.NewServeMux(), http.NewServeMux()
	r.publicMux, r.machineMux = mux, mmux
	app := func(pattern string, fn http.HandlerFunc) { mux.Handle(pattern, r.requireDeyao(fn)) }
	m := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte)) {
		mmux.Handle(pattern, r.requireMachine(fn))
	}
	// setup: the setup session's Access token AND its key's signature (checked here, by the router: the
	// core's store calls are open, the router decides who uses them)
	setup := func(pattern, method, corePath string) {
		mux.Handle(pattern, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			if method == "GET" {
				b = nil
			}
			r.relay(w, method, corePath, b)
		}))
	}
	r.registerFeatures(app, m, mux.Handle)
	// the router's own health, for an operator with no way into the box: secret NAMES present, image, core up
	mux.Handle("GET /setup/status", r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
		if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), nil); err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		present := []string{}
		for _, k := range []string{"LOBSTER_TOKEN", "STORAGEBOX_HOST", "STORAGEBOX_USER", "STORAGEBOX_PASSWORD", "FLY_READ_TOKEN",
			"JARVIS1_CREDENTIALS_ID", "JARVIS1_CREDENTIALS_SECRET", "JARVIS1_SERVICES_ID", "JARVIS1_SERVICES_SECRET", "JARVIS2_TUNNEL_KEY", "JARVIS2_REMOTES_CLIENT_ID",
			"GITHUB_READ_TOKEN"} {
			if os.Getenv(k) != "" {
				present = append(present, k)
			}
		}
		_, coreErr := r.core.Key()
		writeJSON(w, 200, map[string]any{"secrets": present, "sessionImage": r.cfg.SessionImage, "coreUp": coreErr == nil, "version": os.Getenv("VERSION")})
	}))
	setup("GET /setup/identity", "GET", "/identity")
	setup("GET /setup/core-cert", "GET", "/core-cert")
	setup("POST /setup/stores", "POST", "/stores")
	setup("POST /setup/stores/create", "POST", "/stores/create")
	setup("POST /setup/stores/write", "POST", "/stores/write")
	setup("POST /setup/stores/mark-sensitive", "POST", "/stores/mark-sensitive")
	// the backup bucket's read keys, sealed to the master key by the setup session (recoverykeys.go)
	r.registerRecoveryKeys(app, mux.Handle)

	// ---- recovery (the app, with the master key) and the core's identity --------------------------------
	app("GET /api/core/identity", func(w http.ResponseWriter, req *http.Request) { r.relay(w, "GET", "/identity", nil) })
	app("GET /api/core/core-cert", func(w http.ResponseWriter, req *http.Request) { r.relay(w, "GET", "/core-cert", nil) })
	app("POST /api/core/recover", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 16<<20))
		r.relay(w, "POST", "/recover", b)
	})
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
		key, err := r.core.Key()
		coreInfo := map[string]any{"up": err == nil}
		if err == nil {
			coreInfo["signingKey"], coreInfo["agreementKey"] = key["signingKey"], key["agreementKey"]
		}
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
		out := map[string]any{"sessions": orEmpty(sessions), "approvals": orEmptyA(approvals), "core": coreInfo}
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

	// ---- grants (grants.go) and the terminal (terminal.go) ----------------------------------------------
	app("GET /api/holders", func(w http.ResponseWriter, req *http.Request) {
		pub, err := r.HolderPublicKeys()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"holders": pub})
	})
	app("POST /api/sessions/{id}/grants/draft", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Holder  string    `json:"holder"`
			Kind    string    `json:"kind"`
			Minutes int       `json:"minutes"`
			Until   time.Time `json:"until"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		text, err := r.DraftGrant(req.PathValue("id"), in.Holder, in.Kind, in.Minutes, in.Until)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"text": text})
	})
	app("POST /api/sessions/{id}/grants", func(w http.ResponseWriter, req *http.Request) {
		var in Doc
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		g, err := r.AddGrant(req.PathValue("id"), &in)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, g)
	})
	// the line's latest core-signed succession cert: the phone's grant page reads the line, its own key and the
	// stores from it (the router can't forge it)
	app("GET /api/sessions/{id}/cert", func(w http.ResponseWriter, req *http.Request) {
		var c *Doc
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[req.PathValue("id")]; s != nil {
				c = s.Cert
			}
		})
		if c == nil {
			writeJSON(w, 404, map[string]string{"error": "the session has no certified machine yet"})
			return
		}
		writeJSON(w, 200, c)
	})
	app("GET /api/sessions/{id}/grants", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]any{"grants": r.Grants(req.PathValue("id"))})
	})
	app("DELETE /api/grants/{gid}", func(w http.ResponseWriter, req *http.Request) {
		r.ForgetGrant(req.PathValue("gid"))
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/exec", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Cmd     string `json:"cmd"`
			Timeout int    `json:"timeout"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in)
		res, err := r.Exec(req.PathValue("id"), "terminal", in.Cmd, time.Duration(max(5, min(in.Timeout, 600)))*time.Second)
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
		var in struct {
			Upgrade bool   `json:"upgrade"`
			Prompt  string `json:"prompt"` // delivered once the session is back (schedule.go)
			ResumeOptions
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		prompt, err := cleanResumePrompt(in.Prompt)
		if err == nil {
			err = r.applyResumeOptions(req.PathValue("id"), in.ResumeOptions) // sessionops.go: size, model, apiProxy
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		if err := r.Resume(req.PathValue("id"), in.Upgrade); err != nil {
			writeErr(w, err)
			return
		}
		if prompt != "" {
			r.SetResumePrompt(req.PathValue("id"), prompt)
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
			Signature string `json:"signature"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		cert, sid, err := r.Respond(req.PathValue("id"), in.Signature)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"answer": cert, "session": sid})
	})
	app("POST /api/approvals/{id}/reject", func(w http.ResponseWriter, req *http.Request) {
		if err := r.Reject(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ---- the core, relayed unchanged ------------------------------------------------------------------
	app("GET /api/core/key", func(w http.ResponseWriter, req *http.Request) { r.relay(w, "GET", "/key", nil) })
	for _, p := range []string{"stores", "stores/create", "stores/mark-sensitive", "stores/write", "unlock/begin", "unlock/finish", "lock", "unlocked", "log"} {
		path := "/" + p
		app("POST /api/core"+path, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			r.relay(w, "POST", path, b)
		})
	}

	// ---- machines --------------------------------------------------------------------------------------
	m("GET /m/cert", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		var cert, pred *Doc
		r.st.Do(func(d *persisted) {
			cert = d.Certs[machine]
			if cert != nil {
				var c struct {
					PredID string `json:"predecessorId"`
				}
				cert.Decode(&c)
				if c.PredID != "" && c.PredID != machine {
					pred = d.Certs[c.PredID]
				}
			}
		})
		if cert == nil {
			writeJSON(w, 404, map[string]string{"error": "no cert yet"})
			return
		}
		var coreCert json.RawMessage
		if st, b, err := r.core.Raw("GET", "/core-cert", nil); err == nil && st == 200 {
			coreCert = b
		}
		writeJSON(w, 200, map[string]any{"cert": cert, "predecessorCert": pred, "coreCert": coreCert})
	})
	m("GET /m/snapshot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		var pred string
		r.st.Do(func(d *persisted) {
			if cert := d.Certs[machine]; cert != nil {
				var c struct {
					PredID string `json:"predecessorId"`
				}
				cert.Decode(&c)
				pred = c.PredID
			}
		})
		if pred == "" {
			writeJSON(w, 404, map[string]string{"error": "no predecessor"})
			return
		}
		p := r.st.snapshotPath(pred)
		sig, err := os.ReadFile(p + ".sig")
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no snapshot"})
			return
		}
		w.Header().Set("X-Snapshot-Sig", strings.TrimSpace(string(sig)))
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeFile(w, req, p)
	})
	m("POST /m/snapshot", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		sig := req.Header.Get("X-Snapshot-Sig")
		if sig == "" {
			writeJSON(w, 400, map[string]string{"error": "X-Snapshot-Sig missing"})
			return
		}
		p := r.st.snapshotPath(machine)
		if err := os.WriteFile(p+".tmp", body, 0o600); err != nil {
			writeErr(w, err)
			return
		}
		os.Rename(p+".tmp", p)
		os.WriteFile(p+".sig", []byte(sig), 0o600)
		r.snapshotArrived(machine)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/pull-secrets", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var cert *Doc
		r.st.Do(func(d *persisted) { cert = d.Certs[machine] })
		if cert == nil {
			writeJSON(w, 404, map[string]string{"error": "no cert"})
			return
		}
		d, err := r.core.Call("/pull-secrets", map[string]any{"cert": cert})
		if err != nil {
			writeErr(w, err)
			return
		}
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine && s.State == "initialising" {
				s.State, s.Error = "started", ""
			}
		})
		writeJSON(w, 200, d)
	})
	m("GET /m/commands", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		q := r.queue(machine)
		r.cmdMu.Lock()
		eq := r.execQueue(machine)
		r.cmdMu.Unlock()
		select {
		case c := <-q:
			writeJSON(w, 200, map[string]any{"commands": []string{c}, "execs": []execItem{}})
		case e := <-eq:
			writeJSON(w, 200, map[string]any{"commands": []string{}, "execs": []execItem{e}})
		case <-time.After(50 * time.Second):
			writeJSON(w, 200, map[string]any{"commands": []string{}, "execs": []execItem{}})
		case <-req.Context().Done():
		}
	})
	m("POST /m/exec-result", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var res ExecResult
		json.Unmarshal(body, &res)
		r.execResult(res)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("GET /m/holders", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		pub, err := r.HolderPublicKeys()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, pub)
	})
	m("POST /m/add-store", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Store string `json:"store"`
		}
		json.Unmarshal(body, &in)
		if err := r.AddStore(machine, in.Store); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/downgrade", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Stores           []string `json:"stores"`
			NewEncryptionKey string   `json:"newEncryptionKey"`
			NewSigningKey    string   `json:"newSigningKey"`
		}
		json.Unmarshal(body, &in)
		ch, err := r.DowngradeBegin(machine, in.Stores, in.NewEncryptionKey, in.NewSigningKey)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"challenge": ch})
	})
	m("POST /m/downgrade/finish", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Challenge *Doc   `json:"challenge"`
			Signature string `json:"signature"`
		}
		json.Unmarshal(body, &in)
		cert, err := r.DowngradeFinish(machine, in.Challenge, in.Signature)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"cert": cert})
	})
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

func (r *Router) relay(w http.ResponseWriter, method, path string, body []byte) {
	status, b, err := r.core.Raw(method, path, body)
	if err != nil {
		// no core to talk to: before the first recovery (no master key yet) the core's pod isn't running at
		// all, so this is a state, not a fault — the app shows it as a plain note (coreDown)
		log.Printf("core %s %s: %v", method, path, err)
		writeJSON(w, 503, map[string]any{"error": "the core isn't running", "coreDown": true})
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
		"environment": strings.Join(s.Stores, ","), "stores": s.Stores, "harness": s.Harness, "label": s.Label, "aiTitle": s.Title,
		"model": s.Model, "permissionMode": s.PermissionMode, "guest": guest, "size": s.Size, "pausedAt": s.PausedAt,
		"image": s.Image, "createRequestId": s.RequestID, "repos": s.Repos, "discordChannel": s.DiscordChannel,
	}
	liveView(s, v)
	scheduleView(d, s.ID, v)
	opsView(s, v)
	return v
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

// requireSetup: the setup session's Access service token (app jarvis2.deyaochen.com/setup); the core then
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
// request must be signed by a machine the core started
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
			writeJSON(w, 401, map[string]string{"error": "not signed by a machine the core started"})
			return
		}
		fn(w, req, machine, body)
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
