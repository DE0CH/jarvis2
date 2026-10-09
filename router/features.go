package main

// Features outside the lifecycle (Jarvis 1 parity, docs/PARITY.md). Each lives in its own file, registers its
// routes in registerFeatures and its background loop in startFeatures, and reads its own settings from the
// environment (secrets come from k8s/secrets/router.enc.yaml via envFrom). They act on sessions only through
// the router's own flows and through grants (grants.go); none talks to the core directly.

import (
	"errors"
	"log"
	"net/http"
)

type (
	appRoute     func(pattern string, fn http.HandlerFunc)
	machineRoute func(pattern string, fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte))
)

// registerFeatures: called once from buildHandlers
func (r *Router) registerFeatures(app appRoute, m machineRoute) {
	r.registerAutopilot(app, m)
	r.registerSessionAPI(app, m) // sessionapi.go: sets deliverHook (peer.go); wakeups, crons, /m/api
	r.registerArchive(app, m)    // archive.go, restore.go (budget.go needs no routes: /api/state via stateHooks)
}

// startFeatures: called once from main after the router is built
func (r *Router) startFeatures() {
	r.startDiscord()
	r.startAutopilot()
	go r.scheduleLoop() // schedule.go: wakeups, crons, resume prompts
	go r.archiveLoop()  // archive.go: restore files tidied
	go r.budgetLoop()   // budget.go: the Fly budget cap
}

// stateHooks: add fields to GET /api/state
var stateHooks []func(r *Router, out map[string]any)

// DM: a message to Deyao's Discord DM (filled in by discord.go); without a bot token it only logs
var dmHook func(text string)

func (r *Router) DM(text string) {
	if dmHook != nil {
		dmHook(text)
		return
	}
	log.Printf("[dm] %s", text)
}

// Deliver: a message into the session's harness as a peer message (filled in by the scheduler feature); it
// runs through a grant, so it fails when the session hasn't allowed it
var deliverHook func(r *Router, session, from, text string) error

func (r *Router) Deliver(session, from, text string) error {
	if deliverHook == nil {
		return errNoDeliver
	}
	return deliverHook(r, session, from, text)
}

var errNoDeliver = errors.New("message delivery isn't built yet")

// envHooks: each adds to the env a machine starts with (start and resume; flows.go machineEnv). Not secret:
// the env is unsigned.
var envHooks []func(r *Router, s *Session, env map[string]string)

// onDestroy: each runs once a session's machine is killed and its line burned, before it becomes a record
// (flows.go Destroy), in order; they must not fail the destroy
var onDestroy []func(r *Router, s Session)
