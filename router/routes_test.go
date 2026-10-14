package main

// The API surface after the cut: every app route classified for API-call requests, the gone routes gone (holders,
// exec under holders, standing rules, the permission mode, the Claude login polls, carry, add-store and downgrade by
// self-succession, the old core's relays), and the app can't arm a wakeup, cron or watch.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// newTestRouter: a router with no kernel parts behind it (features that don't reach the kernel)
func newTestRouter(t *testing.T) *Router {
	t.Helper()
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return NewRouter(Config{NoAccess: true, DataDir: st.dir, WebDir: t.TempDir()}, st, &Kernel{URLs: map[string]string{}, HTTP: http.DefaultClient}, Policy{})
}

// the sweep: every app route is classified in callRules, and callRules names no route that no longer exists
func TestEveryAppRouteClassified(t *testing.T) {
	r := newTestRouter(t)
	r.handlers()
	missing, stale := []string{}, []string{}
	for p := range r.appPatterns {
		if _, ok := callRules[p]; !ok {
			missing = append(missing, p)
		}
	}
	for p := range callRules {
		if !r.appPatterns[p] {
			stale = append(stale, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("apicalls.go callRules: unclassified app routes %q; no longer app routes %q", missing, stale)
	}
	for p, rule := range callRules {
		if (strings.Contains(p, "/api/requests") || strings.Contains(p, "/api/approvals")) && rule != callNo {
			t.Fatalf("%s is the Inbox: callNo", p)
		}
	}
}

func TestGoneRoutes(t *testing.T) {
	g := newKRig(t)
	sid, m := g.newSession()
	m.boot()
	for _, p := range []string{
		"GET /api/holders", "POST /api/sessions/" + sid + "/grants/draft", "POST /api/sessions/" + sid + "/grants",
		"GET /api/sessions/" + sid + "/grants", "DELETE /api/grants/x", "GET /api/sessions/" + sid + "/cert",
		"POST /api/sessions/" + sid + "/permission-mode", "POST /api/sessions/" + sid + "/env", "POST /api/requests/grant",
		"GET /api/input-log", "POST /api/core/claim", "POST /api/core/unlock/begin", "GET /api/core/identity",
	} {
		method, path, _ := strings.Cut(p, " ")
		if code, _ := g.do(g.app, method, path, map[string]any{}); code != 404 && code != 405 {
			t.Errorf("%s answered %d", p, code)
		}
	}
	for _, p := range []string{
		"GET /m/cert", "POST /m/pull-secrets", "POST /m/exec-result", "GET /m/holders", "POST /m/delivery-result",
		"GET /m/claude-login", "POST /m/claude-login", "GET /m/api/credentials", "POST /m/api/credentials", "POST /m/add-store",
		"POST /m/downgrade", "POST /m/downgrade/finish", "GET /m/restore-cert", "GET /m/restore-snapshot", "GET /m/store-key",
		"GET /m/attachments",
	} {
		method, path, _ := strings.Cut(p, " ")
		if code, _, _ := m.call(method, path, []byte("{}")); code != 404 && code != 405 {
			t.Errorf("%s answered %d", p, code)
		}
	}
	// nothing from the old command channel: no execs, no deliveries, no refresh-secrets
	b, _ := json.Marshal(m.commands())
	for _, gone := range []string{"execs", "deliveries", "refresh-secrets"} {
		if strings.Contains(string(b), gone) {
			t.Fatalf("/m/commands carries %s: %s", gone, b)
		}
	}
}

// a machine's request must be signed by the key its spawn cert names
func TestUnsignedMachineRefused(t *testing.T) {
	g := newKRig(t)
	_, m := g.newSession()
	other := g.vm(m.id)
	other.sig, _ = newECDSA()
	if code, _, _ := other.call("GET", "/m/grant", nil); code != 401 {
		t.Fatalf("a request signed by another key: %d", code)
	}
}

func TestAppCantArmWakeups(t *testing.T) {
	g := newKRig(t)
	sid, m := g.newSession()
	m.boot()
	for _, p := range []string{"/api/sessions/" + sid + "/wakeup", "/api/sessions/" + sid + "/wakeups", "/api/sessions/" + sid + "/crons", "/api/sessions/" + sid + "/watches"} {
		code, out := g.do(g.app, "POST", p, map[string]any{"delaySeconds": 60, "prompt": "x", "name": "n", "script": "true"})
		if code != 400 {
			t.Errorf("%s: %d %s", p, code, out)
		}
	}
	// through the machine: the id, no text
	if code := m.json("POST", "/m/api/sessions/"+sid+"/wakeups", map[string]any{"delaySeconds": 60, "prompt": "text"}, nil); code != 400 {
		t.Fatalf("a wakeup with its text reached the router: %d", code)
	}
	if code := m.json("POST", "/m/api/sessions/"+sid+"/wakeups", map[string]any{"delaySeconds": 60, "id": "nothex"}, nil); code != 400 {
		t.Fatalf("a wakeup with a bad id: %d", code)
	}
	id := strings.Repeat("ab", 16)
	if code := m.json("POST", "/m/api/sessions/"+sid+"/wakeups", map[string]any{"delaySeconds": 60, "id": id, "name": "w"}, nil); code != 200 {
		t.Fatalf("a wakeup armed by the session: %d", code)
	}
	ws, _ := g.r.ListWakeups(sid)
	if len(ws) != 1 || ws[0].ID != id {
		t.Fatalf("%+v", ws)
	}
}
