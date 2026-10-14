package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// a session's actions ask for an app call; Deyao approves it; the call runs as him and the session reads the result
func TestAPICallRequest(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	addSession(r, "sR", "started", "mR", false)
	addSession(r, "sO", "started", "mO", false)
	m, o, mh := newTestMachine(r, "mR"), newTestMachine(r, "mO"), r.MachineHandler()

	// refused: the Inbox itself, no such route, a bad method, a full URL
	for _, body := range []string{
		`{"method": "POST", "path": "/api/requests/x/approve", "explanation": "x"}`,
		`{"method": "GET", "path": "/api/nothing-here", "explanation": "x"}`,
		`{"method": "TRACE", "path": "/api/sizes", "explanation": "x"}`,
		`{"method": "GET", "path": "https://evil.example/api/sizes", "explanation": "x"}`,
		`{"method": "GET", "path": "/api/sizes"}`,
	} {
		if code, out := m.do(t, mh, "POST", "/m/api/actions/requests/call", body); code != 400 {
			t.Fatalf("%s: %d %v", body, code, out)
		}
	}

	code, out := m.do(t, mh, "POST", "/m/api/actions/requests/call", `{"method": "post", "path": "/api/sessions/sO/auto-pause", "body": {"on": false}, "explanation": "keep sO up"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	it, ok := r.InboxItem(id)
	if !ok || it.Kind != requestKindCall || it.Params.Method != "POST" || it.Params.Path != "/api/sessions/sO/auto-pause" ||
		it.Params.Body != `{"on":false}` || it.CallerText != "the actions of session “label sR” (sR)" || it.Call.Args["route"] != "POST /api/sessions/{id}/auto-pause" {
		t.Fatalf("%+v", it)
	}
	if code, out := m.do(t, mh, "GET", "/m/api/actions/requests/call/"+id, ""); code != 200 || out["state"] != "pending" {
		t.Fatalf("%d %v", code, out)
	}
	// another session can't read it
	if code, _ := o.do(t, mh, "GET", "/m/api/actions/requests/call/"+id, ""); code != 404 {
		t.Fatalf("another session read it: %d", code)
	}
	// approved from the app: the call runs, the session reads its status and body
	if code, out := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", true); code != 200 || out["state"] != "done" || out["status"] != float64(200) {
		t.Fatalf("approve: %d %v", code, out)
	}
	if _, still := r.InboxItem(id); still {
		t.Fatal("an approved request stayed in the Inbox")
	}
	code, out = m.do(t, mh, "GET", "/m/api/actions/requests/call/"+id, "")
	if code != 200 || out["state"] != "done" || out["status"] != float64(200) || !strings.Contains(out["body"].(string), "off") || out["approvedBy"] != "app" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", true); code != 404 {
		t.Fatalf("approved twice: %d", code)
	}
	// denied: the session reads that
	_, out = m.do(t, mh, "POST", "/m/api/actions/requests/call", `{"method": "GET", "path": "/api/sizes", "explanation": "sizes"}`)
	id = out["id"].(string)
	if code, _ := inboxDo(t, r, "DELETE", "/api/requests/"+id, "", false); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	if code, out := m.do(t, mh, "GET", "/m/api/actions/requests/call/"+id, ""); code != 200 || out["state"] != "denied" {
		t.Fatalf("%d %v", code, out)
	}

	// a session that stops running: its pending calls leave the Inbox and an approval can't run them
	_, out = m.do(t, mh, "POST", "/m/api/actions/requests/call", `{"method": "GET", "path": "/api/sizes", "explanation": "sizes again"}`)
	id = out["id"].(string)
	r.st.Do(func(d *persisted) { d.Sessions["sR"].State = "pausing" })
	if _, still := r.InboxItem(id); still {
		t.Fatal("a pausing session's call stayed in the Inbox")
	}
	if code, _ := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", true); code != 404 {
		t.Fatalf("a pausing session's call was approved: %d", code)
	}
}

// what an approved call makes is its requester's: the route sees the session's actions as its caller
func TestReplayedCallKeepsItsCaller(t *testing.T) {
	c := Caller{Kind: "actions", Session: "sR"}
	req := httptest.NewRequest("POST", "/api/sessions", nil)
	req.Header.Set("cf-access-token", "x")
	if got := appCaller(req.WithContext(context.WithValue(req.Context(), onBehalfKey{}, c))); got != c {
		t.Fatalf("%+v", got)
	}
	if got := appCaller(req); got.Kind != "app" {
		t.Fatalf("%+v", got)
	}
}
