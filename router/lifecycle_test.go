package main

// A session's lifecycles against the kernel's real parts: new session (the phone signs the drafted (sink, source,
// P)), spawn, the machine's boot chain and grant, a pull, pause (kill into a fresh source with the snapshot), resume
// (spawn from it), a resume that changes the source (a new phone-made source; the paused one burned), destroy (burn).

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

func TestNewSessionToMachine(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	g.writeKey("claude", "CLAUDE_CREDENTIALS", "creds-1")
	g.unlock("claude")
	sid, err := g.r.CreateSession(NewSession{Label: "t", Prompt: "hello", Stores: []string{"default"}, PermissionMode: "bypass"})
	if err != nil {
		t.Fatal(err)
	}
	a := g.approval(sid, "new-session")
	// the draft is exactly (sink, source-x, P) by the phone, P = the session's stores on the condition of its id
	if len(a.Drafts) != 1 {
		t.Fatalf("%d drafts", len(a.Drafts))
	}
	var c kernel.Succession
	json.Unmarshal([]byte(a.Drafts[0].Payload), &c)
	if c.Signer != "phone" || c.Predecessor.ID != kernel.Sink || c.Successor.Kind() != kernel.KindSource || c.Successor.Image != testImage ||
		!c.Allowed.Equal(kernel.Only("store:claude", "store:default")) || len(c.Conditions) != 1 || c.Conditions[0] != "session:"+sid {
		t.Fatalf("draft %+v", c)
	}
	var st SessionSettings
	if err := json.Unmarshal([]byte(c.Successor.Settings), &st); err != nil || st.Session != sid || st.PermissionMode != "bypass" ||
		st.Prompt != "hello" || st.Harness != "claude" || st.V != 1 {
		t.Fatalf("settings %s %v", c.Successor.Settings, err)
	}
	// a signature by another key is refused by the notarizer; the approval stays
	if _, err := g.r.Respond(a.ID, g.sign("root", a)); err == nil {
		t.Fatal("a draft signed with the wrong key was notarized")
	}
	if _, err := g.r.Respond(a.ID, nil); err == nil {
		t.Fatal("an answer without signatures went through")
	}
	if _, err := g.r.Respond(a.ID, g.sign("phone", a)); err != nil {
		t.Fatal(err)
	}
	s := g.waitState(sid, "initialising")
	m := g.vm(s.MachineID)
	m.boot()
	gr := m.grant()
	if gr.Machine.ID != m.id || !gr.Pair().Leq(kernel.Pair{Allowed: kernel.Only("store:claude", "store:default"), Conditions: kernel.CanonConditions("session:" + sid)}) {
		t.Fatalf("grant %+v", gr)
	}
	vals, _ := m.pull()
	if vals["claude"]["CLAUDE_CREDENTIALS"] != "creds-1" {
		t.Fatalf("pulled %v", vals)
	}
	if g.session(sid).State != "started" {
		t.Fatal("not started after the pull")
	}
	// the chain is served to the app, every step resolvable
	code, out := g.do(g.app, "GET", "/api/sessions/"+sid+"/chain", nil)
	var cv ChainView
	json.Unmarshal(out, &cv)
	if code != 200 || len(cv.Steps) != 4 || cv.Held == nil || cv.Spawn == nil || cv.Origin == nil {
		t.Fatalf("chain %d %s", code, out)
	}
	for _, step := range cv.Steps {
		if (step.Kind == "cert" && step.Notarized == nil) || (step.Kind == "grant" && step.Grant == nil) {
			t.Fatalf("unresolved step %+v", step)
		}
	}
}

func TestPauseResumeDestroy(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	g.writeKey("claude", "CLAUDE_CREDENTIALS", "creds-1")
	g.unlock("claude")
	sid, m := g.newSession()
	m.boot()
	// pause: the router asks for the snapshot, the machine uploads it, the spawner kills into a source naming it
	done := make(chan string, 1)
	go func() {
		for i := 0; i < 200; i++ {
			if a := m.commands(); len(a.Commands) > 0 && a.Commands[0] == "snapshot" {
				done <- m.snapshot([]byte("the workspace"))
				return
			}
		}
		done <- ""
	}()
	if err := g.r.Pause(sid); err != nil {
		t.Fatal(err)
	}
	sum := <-done
	s := g.waitState(sid, "paused")
	if s.Chain.Source.Snapshot != sum || sum == "" || s.Chain.Machine != nil || s.MachineID != "" {
		t.Fatalf("paused chain %+v", s.Chain)
	}
	if g.fly.Machines[m.id].State != "destroyed" {
		t.Fatal("machine not destroyed")
	}
	main, _ := g.r.docs.Get(s.Chain.Main)
	if mg, _ := grantOf(main); mg.Machine.ID != s.Chain.Source.ID {
		t.Fatalf("the main grant isn't on the paused source: %+v", mg)
	}
	// the old machine has no session any more
	if code, _, _ := m.call("GET", "/m/grant", nil); code != 200 {
		t.Fatal(code)
	}
	if m.grantOrNil() != nil {
		t.Fatal("a paused session's old machine still gets a grant")
	}
	// resume: a spawn from the kill's source; the new machine gets the snapshot by its hash and its own grant
	if err := g.r.Resume(sid, ResumeIn{}); err != nil {
		t.Fatal(err)
	}
	s = g.waitState(sid, "initialising")
	m2 := g.vm(s.MachineID)
	if m2.id == m.id {
		t.Fatal("same machine")
	}
	m2.boot()
	code, body, _ := m2.call("GET", "/m/snapshot", nil)
	if code != 200 || string(body) != "the workspace" {
		t.Fatalf("snapshot %d %q", code, body)
	}
	if vals, _ := m2.pull(); vals["claude"]["CLAUDE_CREDENTIALS"] != "creds-1" {
		t.Fatal(vals)
	}
	// destroy: kill (nothing to snapshot within the wait), then the burn
	go func() {
		for i := 0; i < 200; i++ {
			if a := m2.commands(); len(a.Commands) > 0 {
				m2.snapshot([]byte("final"))
				return
			}
		}
	}()
	if err := g.r.Destroy(sid); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for g.session(sid).ID != "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if g.session(sid).ID != "" {
		t.Fatalf("not destroyed: %+v", g.session(sid))
	}
	rec := g.r.record(sid)
	if rec == nil || rec.Chain == nil {
		t.Fatal("no record")
	}
	last := rec.Chain.Steps[len(rec.Chain.Steps)-1]
	nc, _ := g.r.docs.Notarized(last.ID)
	burn, _ := successionOf(nc.Cert)
	if last.Kind != "cert" || burn.Signer != "gullible" || burn.Successor.ID != kernel.Sink || burn.Predecessor.ID != rec.Chain.Source.ID {
		t.Fatalf("the last step isn't the burn: %+v", burn)
	}
	// the burned source can't be spawned again: the notarizer refuses the spawn cert
	src, _ := g.r.notarized(rec.Chain.Origin)
	if mid, err := g.r.k.Spawn(src, "lhr", "small"); err == nil {
		cert, err := g.r.k.Init(mid)
		if err == nil {
			if _, err := g.r.k.NotarizeNew(cert); err == nil {
				t.Fatal("a burned source was continued")
			}
		}
	}
}

func (m *vmach) grantOrNil() *kernel.SignedDoc {
	var out struct {
		Grant *kernel.SignedDoc `json:"grant"`
	}
	m.json("GET", "/m/grant", nil, &out)
	return out.Grant
}

// a resume that changes the source (a prompt, a newer image) is a new phone-made source: the phone signs it, the paused
// source is burned, and the new source names the paused one's snapshot
func TestResumeWithAPromptIsANewPhoneSource(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	sid, m := g.newSession()
	m.boot()
	go func() {
		for i := 0; i < 200; i++ {
			if a := m.commands(); len(a.Commands) > 0 {
				m.snapshot([]byte("ws"))
				return
			}
		}
	}()
	g.r.Pause(sid)
	paused := g.waitState(sid, "paused")
	if err := g.r.Resume(sid, ResumeIn{Prompt: "carry on"}); err != nil {
		t.Fatal(err)
	}
	a := g.approval(sid, "resume-upgrade")
	var c kernel.Succession
	json.Unmarshal([]byte(a.Drafts[0].Payload), &c)
	var st SessionSettings
	json.Unmarshal([]byte(c.Successor.Settings), &st)
	if c.Predecessor.ID != kernel.Sink || c.Successor.Snapshot != paused.Chain.Source.Snapshot || st.Prompt != "carry on" {
		t.Fatalf("draft %+v %+v", c, st)
	}
	// denied: still paused on its source
	g.r.Reject(a.ID)
	if s := g.session(sid); s.State != "paused" || s.Chain.Source.ID != paused.Chain.Source.ID {
		t.Fatal(s.State)
	}
	g.r.Resume(sid, ResumeIn{Prompt: "carry on"})
	a = g.approval(sid, "resume-upgrade")
	if _, err := g.r.Respond(a.ID, g.sign("phone", a)); err != nil {
		t.Fatal(err)
	}
	s := g.waitState(sid, "initialising")
	g.vm(s.MachineID).boot()
	// the paused source was burned
	burned := false
	for _, step := range s.Chain.Steps {
		if nc, ok := g.r.docs.Notarized(step.ID); ok {
			if x, _ := successionOf(nc.Cert); x.Signer == "gullible" && x.Predecessor.ID == paused.Chain.Source.ID {
				burned = true
			}
		}
	}
	if !burned {
		t.Fatal("the paused source wasn't burned")
	}
}

// the permission mode is fixed for life: no route changes it, and a resume keeps the source's settings
func TestNoPermissionModeAPI(t *testing.T) {
	g := newKRig(t)
	for _, p := range []string{"/api/sessions/s1/permission-mode", "/api/sessions/s1/env"} {
		if code, _ := g.do(g.app, "POST", p, map[string]string{"mode": "bypass"}); code != 404 && code != 405 {
			t.Fatalf("%s answered %d", p, code)
		}
	}
}
