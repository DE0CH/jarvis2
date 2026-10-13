package main

// The actions key (Deyao, 2026-10-13): one Access service token, jarvis2-actions, kept in the not-sensitive `default`
// store, for actions anyone holding it may take because none of them reaches a secret or a new input: list sessions
// and the Inbox, resume a paused session with no prompt (same image: approve_by_dead_machine), pause one, move a running one to the next size, destroy one (the app's Destroy), deny a
// request or approval, and file requests (a new session, an added store, a repo, a grant, an unlock), which only wait
// in Deyao's Inbox for his Face ID. A session can already message every other session, so this grants nothing an
// injected session couldn't already cause. Anything that needs Deyao's signature still does.

import (
	"io"
	"net/http"
	"os"
)

func (r *Router) registerActions(handle func(string, http.Handler)) {
	gate := r.requireClient(os.Getenv("ACCESS_ACTIONS_AUD"), os.Getenv("ACTIONS_CLIENT_ID"))
	caller := Caller{Kind: "actions"}
	act := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, b []byte)) {
		handle(pattern, gate(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
			fn(w, req, b)
		}))
	}
	act("GET /actions/sessions", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		out := []map[string]any{}
		r.st.Do(func(d *persisted) {
			for _, s := range d.Sessions {
				v := map[string]any{"id": s.ID, "machineId": s.MachineID, "state": s.State, "title": sessionTitle(*s), "error": s.Error}
				if l := s.Live; l != nil && l.Reg != nil {
					v["status"] = l.Reg.Status
				}
				if l := s.Live; l != nil && l.NeedsGrant != "" {
					v["needsGrant"] = l.NeedsGrant
				}
				out = append(out, v)
			}
		})
		writeJSON(w, 200, map[string]any{"sessions": out})
	})
	act("GET /actions/requests", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		writeJSON(w, 200, map[string]any{"requests": r.Inbox()})
	})
	// resume: same image, no prompt, no option changes, so the core answers approve_by_dead_machine and nothing
	// reaches the phone (a line whose permission mode differs from its cert still gets its approval in the Inbox)
	act("POST /actions/sessions/{id}/resume", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		id := req.PathValue("id")
		r.noteOrigin(id, Origin{Caller: caller, Call: APICall{Method: "POST", Path: req.URL.Path, Args: map[string]any{"upgrade": false}}})
		if err := r.Resume(id, false); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	act("POST /actions/sessions/{id}/pause", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		if err := r.Pause(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// upgrade: the next size up, as the app's Upgrade (memory.go): frees, snapshots, resumes on the bigger machine
	act("POST /actions/sessions/{id}/upgrade", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		out, err := r.Upgrade(req.PathValue("id"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
	// destroy (Deyao, 2026-10-13): exactly the app's Destroy, ?force=1 included (its "confirm lost work")
	act("POST /actions/sessions/{id}/destroy", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		if err := r.DestroyWith(req.PathValue("id"), req.URL.Query().Get("force") == "1"); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// deny: an Inbox request leaves; an approval is rejected as Deny in the app would (a new session disappears, a
	// resume stays paused)
	act("POST /actions/requests/{id}/deny", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		if err := r.DenyRequest(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	act("POST /actions/sessions", func(w http.ResponseWriter, req *http.Request, b []byte) {
		r.proposeSession(w, caller, "actions", b)
	})
	for intent := range intents {
		act("POST /actions/requests/"+intent, func(w http.ResponseWriter, req *http.Request, b []byte) {
			r.fileIntent(w, req.Method, req.URL.Path, intent, caller, b)
		})
	}
}
