package main

// Adding to a running machine: a terminal, a command, a store (two phone-signed drafts each), the identity edge and the
// merge, the main grant back after `until`; narrowing in place; and the refusals at filing.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

func (g *krig) file(c Caller, intent string, body map[string]any) (int, map[string]any) {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	g.r.fileAddOnIntent(rec, "POST", "/api/requests/"+intent, intent, c, b, "")
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestTerminalAddOn(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	sid, m := g.newSession()
	m.boot()
	main := m.grant()
	if main.Allowed.Contains("shell") {
		t.Fatal("the main grant allows shell")
	}
	if _, err := g.r.Shell(sid, "true", time.Second); err != errNoShell {
		t.Fatalf("a shell without a terminal: %v", err)
	}
	code, out := g.file(Caller{Kind: "app"}, "terminal", map[string]any{"session": sid, "minutes": 5})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	a := g.approval(sid, "terminal")
	if len(a.Drafts) != 2 {
		t.Fatalf("%d drafts", len(a.Drafts))
	}
	var d1, d2 kernel.Succession
	json.Unmarshal([]byte(a.Drafts[0].Payload), &d1)
	json.Unmarshal([]byte(a.Drafts[1].Payload), &d2)
	if d1.Predecessor.ID != kernel.Sink || !d1.Allowed.Equal(kernel.Only("shell")) || d2.Predecessor.ID != d1.Successor.ID ||
		d2.Successor.ID != m.id || !d2.Allowed.Equal(kernel.Everything()) {
		t.Fatalf("drafts %+v %+v", d1, d2)
	}
	hasUntil := false
	for _, c := range d1.Conditions {
		hasUntil = hasUntil || strings.HasPrefix(c, "until:")
	}
	if !hasUntil {
		t.Fatalf("no until: %v", d1.Conditions)
	}
	if _, err := g.r.Respond(a.ID, g.sign("phone", a)); err != nil {
		t.Fatal(err)
	}
	// the machine gets the merged grant: its stores and shell, with the terminal's conditions
	ans := m.commands()
	if ans.Grant == nil {
		t.Fatal("no grant sent")
	}
	merged, err := kernel.OpenGrant(g.w.Roster, *ans.Grant, kernel.RoleMerger)
	if err != nil || !merged.Allowed.Contains("shell") || !merged.Allowed.Contains("store:claude") || !kernel.SameConditions(merged.Conditions, d1.Conditions) {
		t.Fatalf("merged %v %+v", err, merged)
	}
	// a shell command goes to the machine now
	go func() {
		for i := 0; i < 200; i++ {
			if a := m.commands(); len(a.Shell) > 0 {
				m.json("POST", "/m/shell-result", ShellResult{ID: a.Shell[0].ID, Code: 0, Stdout: "ok"}, nil)
				return
			}
		}
	}()
	res, err := g.r.Shell(sid, "echo ok", 5*time.Second)
	if err != nil || res.Stdout != "ok" {
		t.Fatalf("%v %+v", err, res)
	}
	// after until: the main grant again, untouched
	g.r.st.Do(func(d *persisted) { d.Sessions[sid].Chain.AddOns[0].Until = time.Now().Add(-time.Second) })
	g.r.refreshHeld(sid)
	ans = m.commands()
	if ans.Grant == nil || ans.Grant.ID() != g.session(sid).Chain.Main {
		t.Fatal("the main grant wasn't sent back")
	}
	if _, err := g.r.Shell(sid, "true", time.Second); err != errNoShell {
		t.Fatal("shell after the terminal ended")
	}
}

func TestTerminalRefusals(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	sid, m := g.newSession()
	m.boot()
	if code, _ := g.file(Caller{Kind: "app"}, "terminal", map[string]any{"session": sid, "minutes": 11}); code != 400 {
		t.Fatalf("an 11-minute terminal: %d", code)
	}
	if code, _ := g.file(Caller{Kind: "app"}, "terminal", map[string]any{"session": sid, "minutes": -1}); code != 400 {
		t.Fatalf("a negative terminal: %d", code)
	}
	// a session asks only for itself
	if code, _ := g.file(Caller{Kind: "session", Session: "sother"}, "terminal", map[string]any{"session": sid, "minutes": 5, "explanation": "x"}); code != 403 {
		t.Fatalf("another session's terminal: %d", code)
	}
	if code, _ := g.file(Caller{Kind: "app"}, "command", map[string]any{"session": sid}); code != 400 {
		t.Fatal("an empty command was filed")
	}
	if code, _ := g.file(Caller{Kind: "app"}, "terminal", map[string]any{"session": "snope", "minutes": 5}); code != 400 {
		t.Fatal("a terminal for no session was filed")
	}
	// the drafts can't be answered by another key, nor with too few signatures
	g.file(Caller{Kind: "app"}, "terminal", map[string]any{"session": sid, "minutes": 5})
	a := g.approval(sid, "terminal")
	if _, err := g.r.Respond(a.ID, g.sign("phone", a)[:1]); err == nil {
		t.Fatal("one signature for two drafts")
	}
	if _, err := g.r.Respond(a.ID, g.sign("identity", a)); err == nil {
		t.Fatal("drafts signed by the identity signer's key")
	}
}

func TestCommandAddOn(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	sid, m := g.newSession()
	m.boot()
	g.file(Caller{Kind: "app"}, "command", map[string]any{"session": sid, "cmd": "ls -la"})
	a := g.approval(sid, "command")
	var d1 kernel.Succession
	json.Unmarshal([]byte(a.Drafts[0].Payload), &d1)
	want := []string{"cmd:" + sha256Hex("ls -la"), "once:" + a.Once, "session:" + sid}
	for _, w := range want {
		found := false
		for _, c := range d1.Conditions {
			found = found || c == w
		}
		if !found {
			t.Fatalf("no %s in %v", w, d1.Conditions)
		}
	}
	if _, err := g.r.Respond(a.ID, g.sign("phone", a)); err != nil {
		t.Fatal(err)
	}
	// the merged grant and the command come together; the result is kept; then the main grant is back
	var cmd ShellCmd
	for i := 0; i < 200 && cmd.ID == ""; i++ {
		ans := m.commands()
		if len(ans.Shell) > 0 {
			cmd = ans.Shell[0]
		}
	}
	if cmd.Cmd != "ls -la" {
		t.Fatalf("command %+v", cmd)
	}
	m.json("POST", "/m/shell-result", ShellResult{ID: cmd.ID, Code: 3, Stdout: "out"}, nil)
	deadline := time.Now().Add(5 * time.Second)
	for len(g.session(sid).Commands) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	s := g.session(sid)
	if len(s.Commands) != 1 || s.Commands[0].Code != 3 || s.Commands[0].Stdout != "out" || s.Chain.Held != s.Chain.Main {
		t.Fatalf("%+v held=%s main=%s", s.Commands, s.Chain.Held, s.Chain.Main)
	}
}

func TestAddStoreAndNarrow(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	g.writeKey("extra", "K", "v")
	g.unlock("extra")
	sid, m := g.newSession()
	m.boot()
	if code, out := g.file(Caller{Kind: "session", Session: sid}, "add-store", map[string]any{"store": "extra", "explanation": "need it"}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	// a reserved store is refused at filing
	if code, _ := g.file(Caller{Kind: "app"}, "add-store", map[string]any{"session": sid, "store": "github-deploy-keys"}); code != 400 {
		t.Fatal("the deploy-key token store was filed")
	}
	a := g.approval(sid, "add-store")
	if _, err := g.r.Respond(a.ID, g.sign("phone", a)); err != nil {
		t.Fatal(err)
	}
	ans := m.commands()
	if ans.Grant == nil {
		t.Fatal("no new grant")
	}
	gr, _ := kernel.OpenGrant(g.w.Roster, *ans.Grant, kernel.RoleMerger)
	if !gr.Allowed.Contains("store:extra") || !gr.Allowed.Contains("store:claude") {
		t.Fatalf("%+v", gr)
	}
	if vals, _ := m.pull(); vals["extra"]["K"] != "v" {
		t.Fatalf("%v", vals)
	}
	if s := g.session(sid); !containsString(s.Stores, "extra") || s.Chain.Held != s.Chain.Main {
		t.Fatalf("%+v", s.Stores)
	}
	// narrowing: the identity edge to fewer stores
	if _, err := g.r.Narrow(sid, []string{"extra", "nope"}); err == nil {
		t.Fatal("kept a store the session doesn't hold")
	}
	if _, err := g.r.Narrow(sid, []string{"claude"}); err != nil {
		t.Fatal(err)
	}
	ans = m.commands()
	gr, err := kernel.OpenGrant(g.w.Roster, *ans.Grant, kernel.RoleMover)
	if err != nil || gr.Allowed.Contains("store:extra") || !gr.Allowed.Contains("store:claude") {
		t.Fatalf("%v %+v", err, gr)
	}
	if vals, _ := m.pull(); vals["extra"] != nil {
		t.Fatal("the dropped store is still served")
	}
}
