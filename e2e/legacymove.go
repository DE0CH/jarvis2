package main

// E2E_ONLY=legacy-move (with E2E_CORE_REF = production's core before core continuity): the real box move, rehearsed.
// Router A runs on that core (random keys) with a running session and a paused one (a wakeup armed, due a few minutes
// later). Router B — the control box's — has its own core: this tree's, empty, no standby. The router moves (MOVE_AT;
// the WireGuard peer moves along); after it only B and its core serve. Then Deyao's seeded Recover on B; the corechange
// tick takes the paused session over at once (one unlock the router files: CarryLost), the running one at its pause;
// both resume, and the wakeup fires. What each session saw, with timings, is logged as RESULTS.

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

func legacyMoveStep(p *phone, master *ecdsa.PrivateKey, phoneAgreement string, recovered map[string]map[string]string, id, m1, secret string) {
	start := os.Getenv("E2E_ROUTER_B_START")
	routerA, routerB, coreB := router, os.Getenv("E2E_ROUTER_B"), os.Getenv("E2E_CORE_B")
	logA, logB := os.Getenv("E2E_ROUTER_LOG"), os.Getenv("E2E_ROUTER_B_LOG")
	if start == "" || routerB == "" || coreB == "" {
		log.Fatal("E2E_ONLY=legacy-move needs E2E_ROUTER_B_START, E2E_ROUTER_B and E2E_CORE_B (infra/e2e.sh sets them)")
	}
	t0 := time.Now()
	since := func() string { return time.Since(t0).Round(time.Second).String() }
	var events []string
	note := func(f string, a ...any) {
		e := fmt.Sprintf("T+%s  ", since()) + fmt.Sprintf(f, a...)
		events = append(events, e)
		log.Printf("   %s", e)
	}

	step("legacy-move: a second session on production's core, a wakeup armed by it (due in 6 min), paused")
	s, b := call(router, "POST", "/api/sessions", map[string]any{"label": "e2e paused", "stores": []string{"e2e"}, "size": "small", "harness": "claude"}, nil)
	must(s, b, "create")
	a := waitApproval("new-session", "")
	unlock(p, "e2e", nonceOf(*a.Challenge))
	id2 := approve(p, a)
	waitState(id2, "started", 6*time.Minute)
	m2 := machineOf(id2)
	expectOnMachine(m2, "grep -c E2E_SECRET /home/claude/.secrets", "1")
	expectOnMachine(m2, "echo paused-"+secret+" > /home/claude/artifacts/e2e-marker && chown claude /home/claude/artifacts/e2e-marker && echo ok", "ok")
	wakeAt := time.Now().Add(6 * time.Minute)
	expectOnMachine(m2, sessionAPI("POST", "/api/sessions/"+id2+"/wakeups", fmt.Sprintf(`{"prompt":"e2e legacy-move wake","at":%d,"name":"e2e-lm"}`, wakeAt.UnixMilli()))+" | grep -c '\"ok\":true'", "1")
	must2(call(router, "POST", "/api/sessions/"+id2+"/pause", nil, nil))
	waitState(id2, "paused", 12*time.Minute)
	note("%s paused on production's core (wakeup e2e-lm due at T+%s)", id2, wakeAt.Sub(t0).Round(time.Second))
	expectOnMachine(m1, "echo running-"+secret+" > /home/claude/artifacts/e2e-marker && chown claude /home/claude/artifacts/e2e-marker && echo ok", "ok")
	oldKey := coreKey
	bootBefore, _, _ := flyExec(m1, []string{"sh", "-c", "cat /proc/sys/kernel/random/boot_id; pgrep -f harness-claude | head -1"})

	moveAt := time.Now().Add(75 * time.Second).Truncate(time.Second)
	step("legacy-move: router B (its own core: this tree's, empty) is the candidate; MOVE_AT T+%s; the running machine probes", moveAt.Sub(t0).Round(time.Second))
	startProbe(m1, id, 150)
	if err := exec.Command(start, moveAt.UTC().Format(time.RFC3339)).Start(); err != nil {
		log.Fatalf("router B: %v", err)
	}
	waitLog(logB, "[move] candidate", time.Minute)
	gapLine := waitLog(logB, "[move] MOVED", 4*time.Minute)
	movedAt := time.Now()
	note("router moved: %s", gapLine[strings.Index(gapLine, "gap"):])
	if strings.Contains(readFile(logB), "FAILED") {
		log.Fatalf("the move failed: %s", grepLines(logB, "[move]"))
	}
	router = routerB // from here on the app talks to router B (the tunnel's connector moved)

	step("legacy-move: after the move only B's core answers (empty), through both routers' addresses")
	for _, base := range []string{routerB, routerA} {
		var idn coreIdentity
		must2(call(base, "GET", "/api/core/identity", nil, &idn))
		if idn.SigningKey == oldKey || !strings.Contains(idn.State.Payload, `"master":null`) && !strings.Contains(idn.State.Payload, `"master":""`) {
			log.Fatalf("%s answers a core that isn't B's empty one: %s %.200s", base, idn.SigningKey, idn.State.Payload)
		}
	}
	if st := session(id); st["state"] != "started" {
		log.Fatalf("the running session after the move: %v", st["state"])
	}
	if st := session(id2); st["state"] != "paused" {
		log.Fatalf("the paused session after the move: %v", st["state"])
	}
	note("both sessions on router B as before: %s started, %s paused", id, id2)

	step("legacy-move: Deyao's seeded Recover on B")
	seededClaim(master, p, phoneAgreement, recovered, nil)
	recoveredAt := time.Now()
	note("Recover done on B's core")

	step("legacy-move: the paused session is taken over at once (CarryLost)")
	for deadline := time.Now().Add(3 * time.Minute); session(id2)["carryLost"] != true; time.Sleep(time.Second) {
		if session(id2) == nil {
			log.Fatal("the paused session was destroyed")
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatal("the paused session wasn't taken over")
		}
	}
	note("%s taken over %s after the Recover", id2, time.Since(recoveredAt).Round(time.Second))

	step("legacy-move: the wakeup comes due and resumes the paused session; one unlock; it starts and the wakeup is delivered")
	for deadline := time.Now().Add(time.Until(wakeAt) + 8*time.Minute); session(id2)["lockedStore"] != "e2e"; time.Sleep(2 * time.Second) {
		if st := session(id2); st["state"] == "failed" {
			log.Fatalf("%s failed: %v", id2, st["error"])
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatalf("%s isn't resumed by its wakeup (waiting on store e2e)", id2)
		}
	}
	note("%s: its wakeup resumed it (%s after due); waits on one unlock of e2e", id2, time.Since(wakeAt).Round(time.Second))
	if q := waitRequestFor(id2, 30*time.Second); q == "" {
		log.Fatalf("the router asked for no unlock for %s", id2)
	}
	var cd Doc
	must2(call(router, "GET", "/api/sessions/"+id2+"/cert", nil, &cd))
	unlock(p, "e2e", nonceOf(cd))
	denyRequestsFor(id2)
	waitState(id2, "started", 6*time.Minute)
	note("%s started again (snapshot + secrets)", id2)
	m2 = machineOf(id2)
	expectOnMachine(m2, "grep -c E2E_SECRET /home/claude/.secrets", "1")
	expectOnMachine(m2, "cat /home/claude/artifacts/e2e-marker", "paused-"+secret)
	wakeupBug := false
	for deadline := time.Now().Add(5 * time.Minute); !strings.Contains(readFile(logB), `[wakeup] `+id2+` "e2e-lm" delivered`); time.Sleep(2 * time.Second) {
		if strings.Contains(readFile(logB), "this wakeup was already delivered") {
			// machine/deliver.go records a wakeup as delivered before the harness took it: a first try into a harness
			// still booting burns it (a machine bug, not the move's); noted, and the rehearsal goes on
			wakeupBug = true
			note("%s: wakeup e2e-lm NOT delivered: the machine refuses it as \"already delivered\" (%s)", id2, grepLines(logB, "e2e-lm"))
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("the wakeup was never delivered: %s", grepLines(logB, "e2e-lm"))
		}
	}
	if !wakeupBug {
		if n := strings.Count(readFile(logA)+readFile(logB), `[wakeup] `+id2+` "e2e-lm" delivered`); n != 1 {
			log.Fatalf("the wakeup was delivered %d times", n)
		}
		note("%s: wakeup e2e-lm delivered once, %s after it was due", id2, time.Since(wakeAt).Round(time.Second))
	}

	step("legacy-move: the running session kept running (same machine, boot, supervisor); it pauses (taken over at its kill) and resumes")
	if after, _, _ := flyExec(m1, []string{"sh", "-c", "cat /proc/sys/kernel/random/boot_id; pgrep -f harness-claude | head -1"}); after != bootBefore {
		log.Fatalf("the running session's machine restarted: %q → %q", bootBefore, after)
	}
	out, _, _ := flyExec(m1, []string{"cat", "/tmp/move-probe.log"})
	summary := probeSummary(out, moveAt)
	note("%s kept running across the move and the Recover; probes:\n%s", id, strings.TrimRight(summary, "\n"))
	probeFailed := strings.Contains(summary, "FAIL")
	t := time.Now()
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	if session(id)["carryLost"] != true {
		dumpState()
		log.Fatal("the running session wasn't taken over at its pause")
	}
	note("%s paused in %s, taken over at its kill", id, time.Since(t).Round(time.Second))
	t = time.Now()
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil))
	for deadline := time.Now().Add(8 * time.Minute); session(id)["lockedStore"] != "e2e"; time.Sleep(2 * time.Second) {
		if time.Now().After(deadline) {
			dumpState()
			log.Fatalf("%s doesn't wait on store e2e", id)
		}
	}
	if q := waitRequestFor(id, 30*time.Second); q == "" {
		log.Fatalf("the router asked for no unlock for %s", id)
	}
	must2(call(router, "GET", "/api/sessions/"+id+"/cert", nil, &cd))
	unlock(p, "e2e", nonceOf(cd))
	denyRequestsFor(id)
	waitState(id, "started", 6*time.Minute)
	expectOnMachine(machineOf(id), "cat /home/claude/artifacts/e2e-marker", "running-"+secret)
	expectOnMachine(machineOf(id), "grep -c E2E_SECRET /home/claude/.secrets", "1")
	note("%s resumed in %s (one unlock), snapshot and secrets back", id, time.Since(t).Round(time.Second))
	expectNoUnlocks("at the end")
	_ = movedAt
	log.Printf("RESULTS (legacy core + router move rehearsal):\n  %s", strings.Join(events, "\n  "))
	if probeFailed {
		log.Printf("RESULTS above: a probe call failed across the move")
	}
	if wakeupBug || probeFailed {
		log.Fatal("E2E FAILED (see RESULTS: the wakeup's machine bug and/or a probe call failed across the move)")
	}
	log.Printf("E2E PASSED (legacy-move)")
}
