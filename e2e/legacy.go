package main

// E2E_ONLY=legacy (with E2E_CORE_REF = production's core before core continuity): a running and a paused session on
// that core (random keys), then the restart to this tree's core, Recovered with the master key's seed. The paused
// session is taken over at once, the running one at its pause; each resumes with its snapshot and, after one unlock
// the router asks for itself (the earlier core's carried secrets don't open), its secrets (router/legacy.go).

import (
	"crypto/ecdsa"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"time"
)

func legacyStep(p *phone, master *ecdsa.PrivateKey, phoneAgreement string, recovered map[string]map[string]string, id, m1, secret string) {
	step("legacy: a second session on the earlier core, paused; a marker in the running one's artifacts")
	s, b := call(router, "POST", "/api/sessions", map[string]any{"label": "e2e paused", "stores": []string{"e2e"}, "size": "small", "harness": "claude"}, nil)
	must(s, b, "create")
	a := waitApproval("new-session", "")
	unlock(p, "e2e", nonceOf(*a.Challenge))
	id2 := approve(p, a)
	waitState(id2, "started", 6*time.Minute)
	m2 := machineOf(id2)
	expectOnMachine(m2, "session-secret --names | grep -cx E2E_SECRET", "1")
	expectOnMachine(m2, "echo paused-"+secret+" > /home/claude/artifacts/e2e-marker && chown claude /home/claude/artifacts/e2e-marker && echo ok", "ok")
	must2(call(router, "POST", "/api/sessions/"+id2+"/pause", nil, nil))
	waitState(id2, "paused", 12*time.Minute)
	expectOnMachine(m1, "echo running-"+secret+" > /home/claude/artifacts/e2e-marker && chown claude /home/claude/artifacts/e2e-marker && echo ok", "ok")
	key := coreKey

	step("legacy: the release — the core restarts as this tree's core (empty)")
	out, err := exec.Command(os.Getenv("E2E_CORE_RESTART")).CombinedOutput()
	if err != nil {
		log.Fatalf("core restart: %v %s", err, out)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		var id coreIdentity
		if s, _ := call(router, "GET", "/api/core/identity", nil, &id); s == 200 && id.SigningKey != key && id.Continuity == 1 {
			var st struct{ Master string }
			json.Unmarshal([]byte(id.State.Payload), &st)
			if st.Master == "" {
				break
			}
		}
		if time.Now().After(deadline) {
			log.Fatal("no empty core from this tree after the restart")
		}
		time.Sleep(time.Second)
	}

	step("legacy: Deyao's Recover on the new app (the seed; the earlier core kept no line state)")
	if s, _ := call(router, "GET", "/api/core/line-state", nil, nil); s == 200 {
		log.Fatal("a line state from a core without one")
	}
	seededClaim(master, p, phoneAgreement, recovered, nil)

	resumeTakenOver := func(sid, want string) {
		must2(call(router, "POST", "/api/sessions/"+sid+"/resume", map[string]bool{"upgrade": false}, nil))
		deadline := time.Now().Add(8 * time.Minute)
		for session(sid)["lockedStore"] != "e2e" {
			if st := session(sid); st != nil && st["state"] == "failed" {
				log.Fatalf("%s failed: %v", sid, st["error"])
			}
			if time.Now().After(deadline) {
				dumpState()
				log.Fatalf("%s doesn't wait on store e2e", sid)
			}
			time.Sleep(3 * time.Second)
		}
		if q := waitRequestFor(sid, 30*time.Second); q == "" {
			log.Fatalf("the router asked for no unlock for %s", sid)
		}
		var cd Doc
		must2(call(router, "GET", "/api/sessions/"+sid+"/cert", nil, &cd))
		unlock(p, "e2e", nonceOf(cd))
		denyRequestsFor(sid)
		waitState(sid, "started", 4*time.Minute)
		m := machineOf(sid)
		expectOnMachine(m, "session-secret --names | grep -cx E2E_SECRET", "1")
		expectOnMachine(m, "cat /home/claude/artifacts/e2e-marker", want)
		expectNoUnlocks("after " + sid + "'s pull")
	}

	step("legacy: the paused session is taken over at once (not destroyed), and resumes with its snapshot and secrets")
	deadline = time.Now().Add(3 * time.Minute)
	for session(id2)["carryLost"] != true {
		if session(id2) == nil {
			log.Fatal("the paused session of the earlier core was destroyed")
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatal("the paused session wasn't taken over")
		}
		time.Sleep(3 * time.Second)
	}
	resumeTakenOver(id2, "paused-"+secret)

	step("legacy: the running session keeps running; it pauses (taken over at its kill) and resumes with its snapshot and secrets")
	if st := session(id); st == nil || st["state"] != "started" {
		log.Fatalf("the running session didn't keep running: %v", st)
	}
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	if session(id)["carryLost"] != true {
		dumpState()
		log.Fatal("the running session wasn't taken over at its pause")
	}
	resumeTakenOver(id, "running-"+secret)

	step("legacy: from now on a pause and resume carries its secrets as usual (no unlock)")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil))
	waitState(id, "started", 8*time.Minute)
	expectOnMachine(machineOf(id), "session-secret --names | grep -cx E2E_SECRET", "1")
	expectNoUnlocks("after the second resume")
	log.Printf("E2E PASSED (legacy: the earlier core's running and paused sessions went on under the new core)")
}
