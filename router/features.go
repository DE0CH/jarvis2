package main

// Features outside the lifecycle (Jarvis 1 parity, docs/PARITY.md). Each lives in its own file, registers its
// routes in registerFeatures and its background loop in startFeatures, and reads its own settings from the
// environment (secrets come from k8s/secrets/router.enc.yaml via envFrom). They act on sessions only through the
// router's own flows, the command channel's content-free signals (commands.go) and, while Deyao has opened a terminal,
// shell commands under it (addons.go).

import (
	"log"
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
	r.registerMemory(app, m)                // memory.go
	r.registerHarnesses(app)                // harness.go: /api/models
	r.registerRemote(app, m, public)        // remote.go: remote pages, /api/remotes, tunnel proofs
	r.registerLeases(app, m, public)        // leases.go: shared-device leases (before sessionapi.go's /m/api/ catch-all)
	r.registerWatches(app, m)               // watches.go: conditional wakeups
	r.registerSessionAPI(app, m)            // sessionapi.go: wakeups, crons, /m/api
	r.registerJarvis1Import(app, m, public) // jarvis1import.go: paused Jarvis 1 sessions as new lines
	r.registerArchive(app, m)               // archive.go, restore.go (budget.go needs no routes: /api/state via stateHooks)
	r.registerSessionOps(app, m)            // sessionops.go, uploads.go, repos.go
	r.registerTasks(app, m)                 // tasks.go: task instances (one-shot session lines), runs, schedules
	r.registerInbox(app, m, public)         // inbox.go: requests waiting for the phone (the app's Inbox)
	r.registerOutcomes(m)                   // outcomes.go: a session reads what became of its requests
	r.registerMachines(app)                 // machines.go: every Fly machine of the app; Destroy for one with no session
	r.registerContent(app, m)               // content.go: content stores (Storage Box folders) for the app and the sessions
	r.registerClaudeLogin(app, m, public)   // claudelogin.go: the Claude login, its refresh, Re-login, the usage quota
	r.registerDevices(app, public)          // devices.go: pairing Deyao's OpenClaw/Paseo apps, /api/remotes, Start
}

// startFeatures: called once from main after the router is built
func (r *Router) startFeatures() {
	r.endCutOff() // drain.go: what a crash cut off becomes a failed or paused session, before any loop looks
	r.startDiscord()
	r.startAutopilot()
	go r.scheduleLoop() // schedule.go: wakeups, crons, resume prompts
	go r.leaseLoop()    // leases.go: expire silent holders, wake promoted ones
	go r.watchLoop()    // watches.go: run due checks on the watch runner, deliver met / given-up watches
	go r.archiveLoop()  // archive.go: restore files tidied
	go r.budgetLoop()   // budget.go: the Fly budget cap
	go r.bbBudgetLoop() // bbbudget.go: the Browserbase spend DM
	go r.uploadsLoop()  // uploads.go: stale attachments
	go r.inboxLoop()    // inbox.go: requests and approvals go after 10 min
	go r.outcomeLoop()  // outcomes.go: tell a session what became of its Inbox requests
	go r.tasksLoop()    // tasks.go: daily schedules, runs, pausing finished task lines
	go r.grantLoop()    // chain.go: an add-on's until passed → the machine holds its main grant again
	go r.loginLoop()    // claudelogin.go: refresh the Claude login, write it into the store claude
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

// onDestroy: each runs once a session's machine is killed and its source burned, before it becomes a record
// (flows.go Destroy), in order; they must not fail the destroy
var onDestroy []func(r *Router, s Session)
