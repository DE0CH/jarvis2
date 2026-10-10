package main

// Features outside the lifecycle (Jarvis 1 parity, docs/PARITY.md). Each lives in its own file, registers its
// routes in registerFeatures and its background loop in startFeatures, and reads its own settings from the
// environment (secrets come from k8s/secrets/router.enc.yaml via envFrom). They act on sessions only through
// the router's own flows and through grants (grants.go); none talks to the core directly.

import (
	"encoding/json"
	"errors"
	"log"
	"time"
	"net/http"
)

type (
	appRoute     func(pattern string, fn http.HandlerFunc)
	machineRoute func(pattern string, fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte))
	// publicRoute: a route on the public listener with the feature's own Access check (not requireDeyao)
	publicRoute func(pattern string, h http.Handler)
)

// registerFeatures: called once from buildHandlers
func (r *Router) registerFeatures(app appRoute, m machineRoute, public publicRoute) {
	r.registerAutopilot(app, m)
	r.registerHarnesses(app)         // harness.go: /api/models
	r.registerRemote(app, m, public) // remote.go: remote pages, /api/remotes, tunnel proofs
	r.registerSessionAPI(app, m)     // sessionapi.go: sets deliverHook (peer.go); wakeups, crons, /m/api
	r.registerArchive(app, m)        // archive.go, restore.go (budget.go needs no routes: /api/state via stateHooks)
	r.registerSessionOps(app, m)     // sessionops.go, uploads.go, repos.go
	r.registerTasks(app, m)          // tasks.go: task instances (one-shot session lines), runs, schedules
}

// startFeatures: called once from main after the router is built
func (r *Router) startFeatures() {
	r.startDiscord()
	r.startAutopilot()
	go r.scheduleLoop() // schedule.go: wakeups, crons, resume prompts
	go r.archiveLoop()  // archive.go: restore files tidied
	go r.budgetLoop()   // budget.go: the Fly budget cap
	go r.uploadsLoop()  // uploads.go: stale attachments
	go r.tasksLoop()    // tasks.go: daily schedules, runs, pausing finished task lines
	go r.resumeInterrupted()
}

// resumeInterrupted: a pause or destroy runs in a goroutine of the router that started it; a router restart (any
// rollout) ends that goroutine but not the session's state, which then sat at "destroying" or "pausing" for ever
// (a destroy waiting out a stuck machine's snapshot was cut off by a rollout, 2026-10-10). On start, each such
// session's pause or destroy runs again from the top: the kill force-destroys the machine whether it is running,
// stopped or gone, and the archive and burn follow.
func (r *Router) resumeInterrupted() {
	var destroying, pausing []string
	r.st.Do(func(d *persisted) {
		for id, s := range d.Sessions {
			switch s.State {
			case "destroying":
				destroying = append(destroying, id)
			case "pausing":
				pausing = append(pausing, id)
			}
		}
	})
	if len(destroying)+len(pausing) == 0 {
		return
	}
	// the kill needs a set-up core (its Fly token): after a box restart the core is empty until Deyao's Recover
	for i := 0; !r.coreSetUp(); i++ {
		if i == 0 {
			log.Printf("%d cut-off pause/destroy waiting for the core to be set up", len(destroying)+len(pausing))
		}
		time.Sleep(15 * time.Second)
	}
	for _, id := range destroying {
		log.Printf("session %s: its destroy was cut off by a router restart; destroying again", id)
		if err := r.destroy(id, destroyOpts{}); err != nil {
			log.Printf("session %s: destroy again: %v", id, err)
		}
	}
	for _, id := range pausing {
		log.Printf("session %s: its pause was cut off by a router restart; pausing again", id)
		if err := r.Pause(id); err != nil {
			log.Printf("session %s: pause again: %v", id, err)
			r.setState(id, "failed", "pause cut off by a router restart: "+err.Error())
		}
	}
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

// coreSetUp: the core answers and was set up (Reset or Recover): its state names a master key
func (r *Router) coreSetUp() bool {
	status, b, err := r.core.Raw("GET", "/identity", nil)
	if err != nil || status != 200 {
		return false
	}
	var id struct {
		State struct {
			Payload string `json:"payload"`
		} `json:"state"`
	}
	var st struct {
		Master string `json:"master"`
	}
	if json.Unmarshal(b, &id) != nil || json.Unmarshal([]byte(id.State.Payload), &st) != nil {
		return false
	}
	return st.Master != ""
}
