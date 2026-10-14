package main

// API-call requests (Deyao, 2026-10-13): a session's actions (actions.go) may ask for ANY app API call — one of the
// routes only Deyao's Access login reaches — to be run as Deyao. The request waits in the Inbox (kind "api-call")
// with its method, path and body; Deyao approves it from the app or the web page (no Face ID for the approval: a
// step that needs the core's signature, such as the terminal grant behind a switch to bypass, still asks for its own
// Face ID afterwards). The router then runs the call through its own public mux carrying the approver's own Access
// login (so the route's requireDeyao checks Deyao himself), and keeps the outcome for inboxTTL; the requesting
// session reads it back (GET /m/api/actions/requests/call/{id}).
//
// callRules classifies every app route (TestEveryAppRouteClassified fails on a new route left out):
//   callBody    the call may be requested and its status and response body go back to the session
//   callStatus  may be requested, but the response carries a credential, so only the status goes back
//   callNo      never requestable: the Inbox itself (a request can't approve or file another), or a call that can't be
//               run server-side or would hand out Deyao's own login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

const (
	requestKindCall = "api-call"
	callBodyMax     = 64 << 10 // a requested call's body, kept in the Inbox
	callResultMax   = 1 << 20  // a call's response kept for the session
)

type callRule int

const (
	callNo callRule = iota
	callBody
	callStatus
)

// CallResult: what an approved (or denied) API-call request came to, kept inboxTTL for its caller
type CallResult struct {
	ID          string    `json:"id"`
	Caller      Caller    `json:"caller"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	State       string    `json:"state"` // done | denied | failed
	Status      int       `json:"status,omitempty"`
	ContentType string    `json:"contentType,omitempty"`
	Body        string    `json:"body,omitempty"`
	Withheld    bool      `json:"withheld,omitempty"` // callStatus: the body carried a credential
	Error       string    `json:"error,omitempty"`
	ApprovedBy  string    `json:"approvedBy,omitempty"` // app | web
	At          time.Time `json:"at"`
}

// callIn: what POST /m/api/actions/requests/call takes. body is any JSON value (sent as application/json);
// bodyText a raw body with its contentType instead.
type callIn struct {
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Body        json.RawMessage `json:"body"`
	BodyText    string          `json:"bodyText"`
	ContentType string          `json:"contentType"`
	Explanation string          `json:"explanation"`
}

// callRoute: the app route a method + path (with its query) reaches, and its rule
func (r *Router) callRoute(method, target string) (string, callRule, error) {
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "", callNo, errors.New("path: an absolute path on the router, e.g. /api/sessions/ID/pause")
	}
	r.handlers()
	req := httptest.NewRequest(method, u.RequestURI(), nil)
	_, pattern := r.publicMux.Handler(req)
	if pattern == "" {
		return "", callNo, fmt.Errorf("no route %s %s", method, u.Path)
	}
	rule, known := callRules[pattern]
	if !r.appPatterns[pattern] || !known {
		return pattern, callNo, fmt.Errorf("%s is not an app API call", pattern)
	}
	if rule == callNo {
		return pattern, callNo, fmt.Errorf("%s can't be requested (%s)", pattern, callNoWhy(pattern))
	}
	return pattern, rule, nil
}

func callNoWhy(pattern string) string {
	if strings.Contains(pattern, "/api/requests") || strings.Contains(pattern, "/api/approvals") {
		return "the Inbox itself"
	}
	return "it would hand out Deyao's own login, or it can't run on the router"
}

// fileCall: an API-call request into the Inbox → {id, duplicate, expires}
func (r *Router) fileCall(w http.ResponseWriter, c Caller, path string, b []byte, filing string) {
	var in callIn
	if err := json.Unmarshal(b, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	in.Method = strings.ToUpper(strings.TrimSpace(in.Method))
	switch in.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		writeJSON(w, 400, map[string]string{"error": "method: GET, POST, PUT, PATCH or DELETE"})
		return
	}
	p := RequestParams{Method: in.Method, Path: strings.TrimSpace(in.Path)}
	switch {
	case len(in.Body) > 0 && string(in.Body) != "null" && in.BodyText != "":
		writeJSON(w, 400, map[string]string{"error": "body (JSON) or bodyText, not both"})
		return
	case len(in.Body) > 0 && string(in.Body) != "null":
		var compact bytes.Buffer
		if err := json.Compact(&compact, in.Body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "body: " + err.Error()})
			return
		}
		p.Body, p.ContentType = compact.String(), "application/json"
	case in.BodyText != "":
		p.Body, p.ContentType = in.BodyText, in.ContentType
		if p.ContentType == "" {
			p.ContentType = "text/plain"
		}
	}
	if len(p.Body) > callBodyMax {
		writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("body over %d KB", callBodyMax>>10)})
		return
	}
	pattern, _, err := r.callRoute(p.Method, p.Path)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	args := map[string]any{"method": p.Method, "path": p.Path, "route": pattern}
	if p.Body != "" {
		args["body"] = p.Body
	}
	q, dup, err := r.FileRequest(requestKindCall, p, in.Explanation, Origin{Caller: c, Call: APICall{Method: "POST", Path: path, Args: args}, Filing: filing})
	if err != nil {
		writeRequestErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": q.ID, "duplicate": dup, "expires": q.Expires})
}

// callerRunning: an actions caller's session still runs (its key is live)
func callerRunning(d *persisted, c Caller) bool {
	s := d.Sessions[c.Session]
	return s != nil && s.MachineID != "" && (s.State == "started" || s.State == "initialising")
}

// ApproveCall: Deyao's approval of an API-call request: the call runs now, as him (his Access login from the
// approving request), and its outcome is kept for the caller
func (r *Router) ApproveCall(id string, approver *http.Request) (*CallResult, error) {
	var q *InboxRequest
	var running bool
	r.st.Do(func(d *persisted) {
		pruneRequests(d, time.Now().UTC())
		if x := d.Inbox[id]; x != nil && x.Kind == requestKindCall {
			q = x
			running = callerRunning(d, x.Origin.Caller)
			delete(d.Inbox, id)
		}
	})
	if q == nil {
		return nil, errNoRequest
	}
	defer func() { // outcomes.go: the requesting session is told (its result stays readable for inboxTTL)
		r.st.Do(func(d *persisted) {
			x := d.CallResults[q.ID]
			if x == nil {
				return
			}
			if x.State == "done" {
				noteOutcome(d, &q.Origin, q.Kind, q.ID, outcomeApproved, x.Status)
			} else {
				noteOutcome(d, &q.Origin, q.Kind, q.ID, outcomeFailed, 0)
			}
		})
	}()
	res := &CallResult{ID: q.ID, Caller: q.Origin.Caller, Method: q.Params.Method, Path: q.Params.Path, ApprovedBy: appCaller(approver).Kind, At: time.Now().UTC()}
	if !running {
		res.State, res.Error = "failed", "the requesting session no longer runs"
		r.keepCallResult(res)
		return res, nil
	}
	pattern, rule, err := r.callRoute(q.Params.Method, q.Params.Path)
	if err != nil {
		res.State, res.Error = "failed", err.Error()
		r.keepCallResult(res)
		return res, nil
	}
	req := httptest.NewRequest(q.Params.Method, q.Params.Path, strings.NewReader(q.Params.Body)).
		WithContext(context.WithValue(approver.Context(), onBehalfKey{}, q.Origin.Caller))
	for _, h := range []string{"Cf-Access-Jwt-Assertion", "cf-access-token", "Cf-Access-Authenticated-User-Email"} {
		if v := approver.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if q.Params.ContentType != "" {
		req.Header.Set("Content-Type", q.Params.ContentType)
	}
	rec := httptest.NewRecorder()
	r.publicMux.ServeHTTP(rec, req)
	res.State, res.Status, res.ContentType = "done", rec.Code, rec.Header().Get("Content-Type")
	if rule == callStatus {
		res.Withheld = true
	} else {
		body := rec.Body.Bytes()
		if len(body) > callResultMax {
			body, res.Error = body[:callResultMax], fmt.Sprintf("response cut at %d KB", callResultMax>>10)
		}
		res.Body = string(body)
	}
	log.Printf("api-call %s: %s %s (%s) for %s, approved from the %s: %d", q.ID, q.Params.Method, q.Params.Path, pattern,
		q.Origin.Caller.Session, res.ApprovedBy, res.Status)
	r.keepCallResult(res)
	return res, nil
}

// onBehalfKey: the context value naming whose approved call the router is running (appCaller)
type onBehalfKey struct{}

var errNoRequest = errors.New("this request is gone (answered, denied or expired)")

func (r *Router) keepCallResult(res *CallResult) {
	r.st.Do(func(d *persisted) {
		pruneCallResults(d, time.Now().UTC())
		d.CallResults[res.ID] = res
	})
}

func pruneCallResults(d *persisted, now time.Time) {
	if d.CallResults == nil {
		d.CallResults = map[string]*CallResult{}
	}
	for id, x := range d.CallResults {
		if now.Sub(x.At) >= inboxTTL {
			delete(d.CallResults, id)
		}
	}
}

// serveCallResult: the caller's own request: pending while it waits, then its outcome
func (r *Router) serveCallResult(w http.ResponseWriter, c Caller, id string) {
	var out any
	r.st.Do(func(d *persisted) {
		now := time.Now().UTC()
		pruneRequests(d, now)
		pruneCallResults(d, now)
		if q := d.Inbox[id]; q != nil && q.Kind == requestKindCall && q.Origin.Caller == c {
			out = map[string]any{"id": id, "state": "pending", "expires": q.Expires}
		} else if x := d.CallResults[id]; x != nil && x.Caller == c {
			out = x
		}
	})
	if out == nil {
		writeJSON(w, 404, map[string]string{"error": "no such request of this session (expired, or its result is over " + inboxTTL.String() + " old)"})
		return
	}
	writeJSON(w, 200, out)
}

// callRules: every app route (the 2026-10-13 sweep). A new app route needs its line here (TestEveryAppRouteClassified).
var callRules = map[string]callRule{
	"GET /api/approvals":                        callNo,     // the Inbox
	"POST /api/approvals/{id}/reject":           callNo,     // the Inbox
	"POST /api/approvals/{id}/respond":          callNo,     // the Inbox
	"GET /api/auth/start":                       callNo,     // hands out Deyao's Access login (a jarvis2:// redirect carrying it)
	"GET /api/backups":                          callStatus, // every store's sealed backup
	"GET /api/claude-login":                     callBody,
	"POST /api/claude-login/code":               callBody,
	"POST /api/claude-login/refresh":            callBody,
	"POST /api/claude-login/start":              callStatus, // the OAuth sign-in URL with its state and PKCE challenge
	"GET /api/content":                          callBody,
	"POST /api/content":                         callBody,
	"DELETE /api/content/{name}":                callBody,
	"DELETE /api/content/{name}/file":           callBody,
	"GET /api/content/{name}/file":              callBody,
	"POST /api/content/{name}/file":             callBody,
	"GET /api/content/{name}/files":             callBody,
	"GET /api/devices":                          callBody,
	"GET /api/devices/pair":                     callNo, // mints a device service token: a login of its own
	"DELETE /api/devices/{id}":                  callBody,
	"GET /api/github/repos":                     callBody,
	"GET /api/icloud/file":                      callBody,
	"POST /api/icloud/relist":                   callBody,
	"POST /api/icloud/retry":                    callBody,
	"GET /api/icloud/search":                    callBody,
	"GET /api/icloud/status":                    callBody,
	"GET /api/jarvis1/paused":                   callBody,
	"GET /api/jarvis1/paused/{id}":              callBody,
	"POST /api/jarvis1/paused/{id}/import":      callBody,
	"POST /api/jarvis1/paused/{id}/prepare":     callBody,
	"GET /api/leases":                           callBody,
	"GET /api/leases/{name}":                    callBody,
	"POST /api/leases/{name}/force-return":      callBody,
	"POST /api/leases/{name}/hand-back":         callBody,
	"POST /api/leases/{name}/take-over":         callBody,
	"GET /api/machines":                         callBody,
	"POST /api/machines/{id}/destroy":           callBody,
	"GET /api/models":                           callBody,
	"GET /api/policy":                           callBody,
	"GET /api/records":                          callBody,
	"POST /api/records":                         callBody,
	"DELETE /api/records/{id}":                  callBody,
	"POST /api/records/{id}/restore":            callBody,
	"GET /api/records/{id}/tail":                callBody,
	"GET /api/remotes":                          callStatus, // every session's OpenClaw token / OpenCode pairing URL
	"GET /api/repos":                            callBody,
	"POST /api/repos/key/begin":                 callNo, // half of a deploy key the phone finishes with its signature
	"POST /api/repos/key/finish":                callNo, // needs the phone's signature and sealed share
	"GET /api/requests":                         callNo, // the Inbox
	"POST /api/requests/batch":                  callNo, // the Inbox
	"DELETE /api/requests/batches/{id}":         callNo, // the Inbox
	"GET /api/requests/batches/{id}":            callNo, // the Inbox
	"POST /api/requests/repo/add":               callNo, // the Inbox
	"POST /api/requests/repo/remove":            callNo, // the Inbox
	"POST /api/requests/restore":                callNo, // the Inbox
	"POST /api/requests/unlock":                 callNo, // the Inbox
	"DELETE /api/requests/{id}":                 callNo, // the Inbox
	"GET /api/requests/{id}":                    callNo, // the Inbox
	"POST /api/requests/{id}/approve":           callNo, // the Inbox
	"POST /api/requests/{id}/done":              callNo, // the Inbox
	"GET /api/search":                           callBody,
	"GET /api/search/context":                   callBody,
	"POST /api/search/reindex":                  callBody,
	"GET /api/search/status":                    callBody,
	"POST /api/sessions":                        callBody,
	"GET /api/sessions/{id}/attachments/{name}": callBody,
	"POST /api/sessions/{id}/auto-pause":        callBody,
	"GET /api/sessions/{id}/changes":            callBody,
	"GET /api/sessions/{id}/crons":              callBody,
	"POST /api/sessions/{id}/crons":             callBody,
	"DELETE /api/sessions/{id}/crons/{name}":    callBody,
	"POST /api/sessions/{id}/destroy":           callBody,
	"POST /api/sessions/{id}/exec":              callStatus, // another session's command output (its env, its files)
	"POST /api/sessions/{id}/notify-idle":       callBody,
	"POST /api/sessions/{id}/pause":             callBody,
	"GET /api/sessions/{id}/remote":             callStatus, // the OpenClaw gateway token / OpenCode pairing URL
	"POST /api/sessions/{id}/restart":           callBody,
	"POST /api/sessions/{id}/resume":            callBody,
	"POST /api/sessions/{id}/start":             callBody,
	"GET /api/sessions/{id}/tail":               callBody,
	"GET /api/sessions/{id}/terminal":           callStatus, // another session's screen
	"POST /api/sessions/{id}/terminal":          callBody,
	"POST /api/sessions/{id}/upgrade":           callBody,
	"DELETE /api/sessions/{id}/wakeup":          callBody,
	"GET /api/sessions/{id}/wakeup":             callBody,
	"POST /api/sessions/{id}/wakeup":            callBody,
	"GET /api/sessions/{id}/wakeups":            callBody,
	"POST /api/sessions/{id}/wakeups":           callBody,
	"DELETE /api/sessions/{id}/wakeups/{name}":  callBody,
	"GET /api/sessions/{id}/watches":            callBody,
	"POST /api/sessions/{id}/watches":           callNo, // only a session's own signed request arms a watch (always 400 here)
	"DELETE /api/sessions/{id}/watches/{name}":  callBody,
	"GET /api/sizes":                            callBody,
	"GET /api/state":                            callBody,
	"GET /api/stores":                           callBody,
	"PUT /api/stores/{store}/docs":              callBody, // explanations: no secret, no trust decision
	"POST /api/stores/restore/finish":           callNo,   // needs the phone's signature and sealed shares
	"GET /api/tasks":                            callBody,
	"POST /api/tasks/instances":                 callBody,
	"DELETE /api/tasks/instances/{id}":          callBody,
	"PUT /api/tasks/instances/{id}":             callBody,
	"POST /api/tasks/instances/{id}/approve":    callBody,
	"POST /api/tasks/instances/{id}/run":        callBody,
	"GET /api/tasks/instances/{id}/runs":        callBody,
	"GET /api/tasks/runs/{id}":                  callBody,
	"POST /api/tasks/runs/{id}/stop":            callBody,
	"POST /api/tasks/schedules":                 callBody,
	"DELETE /api/tasks/schedules/{id}":          callBody,
	"PUT /api/tasks/schedules/{id}":             callBody,
	"POST /api/uploads":                         callNo, // the app's attachment upload (raw file with its x-upload-* headers)
	"GET /api/usage":                            callBody,
	"GET /api/kernel/docs/{id}":                 callBody,
	"GET /api/kernel/identities":                callBody,
	"GET /api/kernel/notarized/{id}":            callBody,
	"GET /api/kernel/root-grant":                callBody,
	"PUT /api/kernel/root-grant":                callNo, // takes the root key's grant (the phone, at setup)
	"GET /api/kernel/roster":                    callBody,
	"GET /api/sessions/{id}/chain":              callBody,
	"POST /api/sessions/{id}/narrow":            callBody, // narrowing only: the main grant moved to fewer stores
	"POST /api/requests/add-store":              callNo,   // the Inbox
	"POST /api/requests/command":                callNo,   // the Inbox
	"POST /api/requests/terminal":               callNo,   // the Inbox
	"POST /api/secrets/claim":                   callNo,   // the iPhone app's Recover, signed by the master key
	"GET /api/secrets/identity":                 callBody,
	"POST /api/secrets/lock":                    callBody,
	"POST /api/secrets/state":                   callBody,
	"POST /api/secrets/store-key":               callBody,
	"POST /api/secrets/stores":                  callBody,
	"POST /api/secrets/stores/create":           callBody,
	"POST /api/secrets/stores/mark-sensitive":   callBody,
	"POST /api/secrets/stores/restore/begin":    callNo, // half of a restore the phone finishes with its signature and shares
	"POST /api/secrets/stores/versions":         callBody,
	"POST /api/secrets/unlock/begin":            callNo, // half of an unlock the phone finishes with its sealed share
	"POST /api/secrets/unlock/finish":           callNo, // needs the phone's sealed share
	"POST /api/secrets/unlocked":                callBody,
	"POST /api/secrets/wipe":                    callNo, // the iPhone app's Reset, signed by the master key
	"GET /term/{id}":                            callNo, // a terminal page for a browser
}
