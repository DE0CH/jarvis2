package main

// The session-facing API (Jarvis 1's `$JARVIS_URL/api/...` as its session scripts call it). In a Jarvis 2
// session JARVIS_URL points at the machine's local proxy (`jarvis2-machine agent`, machine/apiproxy.go), which
// signs each request with the machine key and sends it here as /m/api/<rest>. Any session id in the path must
// be the calling machine's own session.
//
// Served by the router: wakeups and crons (schedule.go), notify-idle (autopilot.go's switch), and the session
// retiring itself.
// Forwarded to Jarvis 1 (its own services, which Deyao lets Jarvis 2 sessions use "like Jarvis 1"): transcript
// search, the iCloud index, device leases, content stores and the shared Claude login, with the Access service
// token JARVIS1_SERVICES_ID/SECRET (the cf-tunnel Worker confines it to those paths) and the header
// X-Jarvis2-Session naming the calling session. The pull-secrets and changes calls never reach the router:
// the machine answers them itself (it holds its secrets and its repos).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// jarvis1Routes: the Jarvis 1 paths a Jarvis 2 session may reach (method + Go mux path under /api)
var jarvis1Routes = []string{
	"GET /api/search", "GET /api/search/context", "GET /api/search/status",
	"GET /api/icloud/search", "GET /api/icloud/file", "GET /api/icloud/status", "POST /api/icloud/relist",
	"GET /api/leases", "GET /api/leases/{name}",
	"POST /api/sessions/{id}/leases/{name}", "PUT /api/sessions/{id}/leases/{name}",
	"PATCH /api/sessions/{id}/leases/{name}", "DELETE /api/sessions/{id}/leases/{name}",
	"POST /api/sessions/{id}/leases/{name}/seen",
	"GET /api/sessions/{id}/content",
	"GET /api/sessions/{id}/content/{name}/file", "PUT /api/sessions/{id}/content/{name}/file",
	"DELETE /api/sessions/{id}/content/{name}/file",
	"GET /api/credentials", "POST /api/credentials",
}

var jarvis1Client = &http.Client{Timeout: 5 * time.Minute}

func (r *Router) registerSessionAPI(app appRoute, m machineRoute) {
	deliverHook = deliverPeer
	// auto-pause (autopilot.go) leaves a session running when a wakeup or cron fires within 10 minutes
	autoPauseVeto = func(r *Router, sid string) bool { return r.ScheduleDueWithin(sid, 10*time.Minute) }
	// ---- the app (Deyao) -------------------------------------------------------------------------------
	app("GET /api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request) { r.getWakeups(w, req.PathValue("id"), true) })
	app("GET /api/sessions/{id}/wakeups", func(w http.ResponseWriter, req *http.Request) { r.getWakeups(w, req.PathValue("id"), false) })
	for _, p := range []string{"POST /api/sessions/{id}/wakeup", "POST /api/sessions/{id}/wakeups"} {
		app(p, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			r.postWakeup(w, req.PathValue("id"), b)
		})
	}
	app("DELETE /api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request) {
		r.deleteWakeups(w, req.PathValue("id"), req.URL.Query().Get("name"), req.URL.Query().Get("all") == "1")
	})
	app("DELETE /api/sessions/{id}/wakeups/{name}", func(w http.ResponseWriter, req *http.Request) {
		r.deleteWakeups(w, req.PathValue("id"), req.PathValue("name"), false)
	})
	app("GET /api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request) { r.getCrons(w, req.PathValue("id")) })
	app("POST /api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		r.postCron(w, req.PathValue("id"), b)
	})
	app("DELETE /api/sessions/{id}/crons/{name}", func(w http.ResponseWriter, req *http.Request) {
		r.deleteCron(w, req.PathValue("id"), req.PathValue("name"))
	})

	// ---- the session itself (through its machine's local proxy) -------------------------------------------
	own := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, sid string, body []byte)) {
		m(pattern, func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if id := req.PathValue("id"); id != "" && id != sid {
				writeJSON(w, 403, map[string]string{"error": fmt.Sprintf("this machine is session %s, not %s", sid, id)})
				return
			}
			fn(w, req, sid, body)
		})
	}
	own("GET /m/api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) { r.getWakeups(w, sid, true) })
	own("GET /m/api/sessions/{id}/wakeups", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) { r.getWakeups(w, sid, false) })
	own("POST /m/api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) { r.postWakeup(w, sid, b) })
	own("POST /m/api/sessions/{id}/wakeups", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) { r.postWakeup(w, sid, b) })
	own("DELETE /m/api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.deleteWakeups(w, sid, req.URL.Query().Get("name"), req.URL.Query().Get("all") == "1")
	})
	own("DELETE /m/api/sessions/{id}/wakeups/{name}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.deleteWakeups(w, sid, req.PathValue("name"), false)
	})
	own("GET /m/api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) { r.getCrons(w, sid) })
	own("POST /m/api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) { r.postCron(w, sid, b) })
	own("DELETE /m/api/sessions/{id}/crons/{name}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.deleteCron(w, sid, req.PathValue("name"))
	})
	own("POST /m/api/sessions/{id}/notify-idle", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) { r.postNotifyIdle(w, sid, b) })
	// retire-session.sh: the session destroys itself, unless it still has a wakeup or cron to wait for
	own("DELETE /m/api/sessions/{id}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		if p := r.PendingSchedule(sid); len(p) > 0 {
			writeJSON(w, 409, map[string]any{"error": "the session still has pending " + strings.Join(p, ", ") + " — cancel them first, or let them fire", "pending": p})
			return
		}
		if err := r.Destroy(sid); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"started": true, "phase": "destroying"})
	})
	// watches run a script on Jarvis with the session's store secrets; Jarvis 2 doesn't (docs/PARITY.md)
	own("/m/api/sessions/{id}/watches", notInJarvis2("conditional wakeups (watches) aren't in Jarvis 2"))
	own("/m/api/sessions/{id}/watches/{name}", notInJarvis2("conditional wakeups (watches) aren't in Jarvis 2"))
	for _, p := range jarvis1Routes {
		own(strings.Replace(p, " /api/", " /m/api/", 1), r.forwardJarvis1)
	}
	own("/m/api/", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		writeJSON(w, 404, map[string]string{"error": fmt.Sprintf("Jarvis 2 doesn't serve %s %s", req.Method, strings.TrimPrefix(req.URL.Path, "/m"))})
	})
}

// the machine-side proxy's address (machine/apiproxy.go) and placeholders for the Access/session-token variables
// Jarvis 1's scripts insist on before calling; the proxy ignores them (a store's real values override these).
// Not for OpenCode/OpenClaw: their harness scripts take CF_ACCESS_* as "publish the web UI through the
// cf-tunnel" and would loop on a placeholder.
const machineAPIURL = "http://127.0.0.1:7171"

func init() {
	envHooks = append(envHooks, func(_ *Router, s *Session, e map[string]string) { sessionAPIEnv(e, s.Harness) })
}

func sessionAPIEnv(e map[string]string, harness string) {
	e["JARVIS_URL"] = machineAPIURL
	e["SESSION_API_TOKEN"] = "jarvis2-local-proxy"
	if !harnessSend[harness] {
		e["CF_ACCESS_CLIENT_ID"], e["CF_ACCESS_CLIENT_SECRET"] = "jarvis2-local-proxy", "jarvis2-local-proxy"
	}
}

// cleanResumePrompt: CRLF → LF, trimmed, at most resumePromptMax characters (multi-line kept)
func cleanResumePrompt(p string) (string, error) {
	p = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(p, "\r\n", "\n"), "\r", "\n"))
	if len([]rune(p)) > resumePromptMax {
		return "", fmt.Errorf("prompt longer than %d characters", resumePromptMax)
	}
	return p, nil
}

func notInJarvis2(msg string) func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
	return func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		writeJSON(w, 501, map[string]string{"error": msg})
	}
}

// machineSession: the session a machine currently runs (a paused or replaced machine has none)
func (r *Router) machineSession(machine string) (string, error) {
	var sid string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
			sid = s.ID
		}
	})
	if sid == "" {
		return "", errors.New("this machine isn't a running session")
	}
	return sid, nil
}

func scheduleErr(w http.ResponseWriter, err error) {
	var b *badRequest
	switch {
	case errors.As(err, &b):
		writeJSON(w, 400, map[string]string{"error": b.msg})
	case errors.Is(err, errNoSession):
		writeJSON(w, 404, map[string]string{"error": err.Error()})
	case strings.HasPrefix(err.Error(), "session is "):
		writeJSON(w, 409, map[string]string{"error": err.Error()})
	default:
		writeErr(w, err)
	}
}

func decodeBody(b []byte) (map[string]any, error) {
	m := map[string]any{}
	if len(strings.TrimSpace(string(b))) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, bad("bad JSON: %v", err)
	}
	return m, nil
}

// GET …/wakeup → {wakeup (the soonest, or null), wakeups}; GET …/wakeups → {wakeups}
func (r *Router) getWakeups(w http.ResponseWriter, sid string, single bool) {
	ws, err := r.ListWakeups(sid)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	views := []map[string]any{}
	for _, x := range ws {
		views = append(views, wakeupView(x))
	}
	if !single {
		writeJSON(w, 200, map[string]any{"wakeups": views})
		return
	}
	var first any
	if len(views) > 0 {
		first = views[0]
	}
	writeJSON(w, 200, map[string]any{"wakeup": first, "wakeups": views})
}

func (r *Router) postWakeup(w http.ResponseWriter, sid string, body []byte) {
	b, err := decodeBody(body)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	wu, err := normalizeWakeup(b, time.Now())
	if err == nil {
		err = r.ArmWakeup(sid, wu)
	}
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "wakeup": wakeupView(wu)})
}

func (r *Router) deleteWakeups(w http.ResponseWriter, sid, name string, all bool) {
	var names []string
	if !all {
		n, err := wakeupName(name)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		names = []string{n}
	}
	out, err := r.CancelWakeups(sid, names, all)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cancelled": out})
}

func (r *Router) getCrons(w http.ResponseWriter, sid string) {
	cs, err := r.ListCrons(sid)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	views := []map[string]any{}
	for _, c := range cs {
		views = append(views, cronView(c))
	}
	writeJSON(w, 200, map[string]any{"crons": views})
}

func (r *Router) postCron(w http.ResponseWriter, sid string, body []byte) {
	b, err := decodeBody(body)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	c, err := normalizeCron(b, time.Now())
	if err == nil {
		err = r.ArmCron(sid, c)
	}
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cron": cronView(c)})
}

func (r *Router) deleteCron(w http.ResponseWriter, sid, name string) {
	if !scheduleNameRE.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "bad cron name"})
		return
	}
	if err := r.CancelCron(sid, name); err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// postNotifyIdle: scripts/session-notify-idle.sh — the same switch as the app's (autopilot.go Liveness)
func (r *Router) postNotifyIdle(w http.ResponseWriter, sid string, body []byte) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	json.Unmarshal(body, &in)
	on := in.Enabled == nil || *in.Enabled
	found := false
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil {
			found = true
			if s.Live == nil {
				s.Live = &Liveness{}
			}
			s.Live.NotifyIdleOff = !on
		}
	})
	if !found {
		scheduleErr(w, errNoSession)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "notifyIdle": onOff(!on)})
}

// forwardJarvis1: the request to Jarvis 1 unchanged (path, query, body, content type) with the services token;
// nothing of the machine's own headers goes along
func (r *Router) forwardJarvis1(w http.ResponseWriter, req *http.Request, sid string, body []byte) {
	id, sec := os.Getenv("JARVIS1_SERVICES_ID"), os.Getenv("JARVIS1_SERVICES_SECRET")
	if id == "" || sec == "" {
		writeJSON(w, 503, map[string]string{"error": "the router has no JARVIS1_SERVICES_ID/SECRET: Jarvis 1's services aren't reachable"})
		return
	}
	base := strings.TrimSuffix(env("JARVIS1_URL", "https://jarvis.deyaochen.com"), "/")
	u := base + strings.TrimPrefix(req.URL.EscapedPath(), "/m")
	if req.URL.RawQuery != "" {
		u += "?" + req.URL.RawQuery
	}
	var rd io.Reader
	if len(body) > 0 {
		rd = strings.NewReader(string(body))
	}
	out, _ := http.NewRequestWithContext(req.Context(), req.Method, u, rd)
	out.Header.Set("CF-Access-Client-Id", id)
	out.Header.Set("CF-Access-Client-Secret", sec)
	out.Header.Set("User-Agent", "jarvis2-router/1") // Cloudflare 1010-blocks some default user agents
	out.Header.Set("X-Jarvis2-Session", sid)
	for _, h := range []string{"Content-Type", "Accept", "Range"} {
		if v := req.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	resp, err := jarvis1Client.Do(out)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "Jarvis 1 unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	for _, h := range []string{"Content-Type", "Content-Length", "Content-Range", "Content-Disposition"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[jarvis1] %s %s: %v", req.Method, u, err)
	}
}
