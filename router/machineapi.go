package main

// The guard's router API (docs/API-grants.md): boot, the grant, the command channel and the machine's answers, the
// secrets pull and the snapshot. Every request is signed by the machine's key from its spawn cert (requireMachine).
// The router only carries: the guard checks every kernel document against the roster the spawner gave it.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// machineChain: the chain of the session this machine currently runs (nil when it runs none)
func (r *Router) machineChain(machine string) (string, *Chain) {
	var sid string
	var c *Chain
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine && s.Chain != nil {
			x := s.Chain.clone()
			sid, c = s.ID, &x
		}
	})
	return sid, c
}

// machineConfig: the values the router gives on its own (each a strict format the guard checks)
func (r *Router) machineConfig(machine string) (map[string]any, error) {
	sid, err := r.machineSession(machine)
	if err != nil {
		return nil, err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
		}
	})
	e := map[string]string{}
	for _, h := range configHooks {
		h(r, &s, e)
	}
	out := map[string]any{"discordChannel": e["discordChannel"], "taskRun": e["taskRun"], "taskTrigger": e["taskTrigger"]}
	if n, err := strconv.Atoi(e["liveSyncSeconds"]); err == nil {
		out["liveSyncSeconds"] = n
	}
	if p := tunnelProof(os.Getenv("JARVIS2_TUNNEL_KEY"), sid); p != "" {
		out["tunnelProof"] = p
	}
	return out, nil
}

// configHooks: each adds a value of GET /m/config (discordChannel, liveSyncSeconds, taskRun, taskTrigger)
var configHooks []func(r *Router, s *Session, out map[string]string)

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (r *Router) registerMachineAPI(m machineRoute, mmux *http.ServeMux) {
	m("GET /m/boot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		_, c := r.machineChain(machine)
		if c == nil || c.Spawn == "" || c.Origin == "" || c.Machine == nil || c.Machine.ID != machine {
			writeJSON(w, 404, map[string]string{"error": "no boot chain for this machine yet"})
			return
		}
		spawn, err1 := r.notarized(c.Spawn)
		origin, err2 := r.notarized(c.Origin)
		if err1 != nil || err2 != nil {
			writeJSON(w, 404, map[string]string{"error": "the boot chain isn't on the volume"})
			return
		}
		writeJSON(w, 200, map[string]any{"spawn": spawn, "source": origin})
	})
	m("GET /m/grant", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		_, c := r.machineChain(machine)
		var g *kernel.SignedDoc
		if c != nil && c.Held != "" {
			if d, ok := r.docs.Get(c.Held); ok {
				g = &d
			}
		}
		writeJSON(w, 200, map[string]any{"grant": g})
	})
	m("GET /m/config", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		out, err := r.machineConfig(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	})
	// the snapshot the machine's source names, by its sha256 (a pause's upload, a restore's archive, a Jarvis 1 import
	// manifest); the guard refuses any other bytes
	m("GET /m/snapshot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		_, c := r.machineChain(machine)
		if c == nil || !sha256RE.MatchString(c.Source.Snapshot) {
			writeJSON(w, 404, map[string]string{"error": "the source names no snapshot"})
			return
		}
		p := r.st.snapshotPath(c.Source.Snapshot)
		if _, err := os.Stat(p); err != nil {
			writeJSON(w, 404, map[string]string{"error": "no snapshot with that hash on the volume"})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, req, p)
	})
	// the final snapshot streams to the volume (a session's workspace can be several GB): hashed on the way, the
	// machine's request signature checked against that hash, then kept by its sha256 with the machine's own signature
	// over it (X-Snapshot-Sig), which the kill passes to the spawner
	mmux.Handle("POST /m/snapshot", r.requireMachineStream(func(w http.ResponseWriter, req *http.Request, machine, tmp, sum string) {
		if req.Header.Get("X-Snapshot-None") != "" {
			os.Remove(tmp)
			log.Printf("machine %s: nothing to snapshot (%s)", machine, req.Header.Get("X-Snapshot-None"))
			r.snapshotArrived(machine)
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
		sig := strings.TrimSpace(req.Header.Get("X-Snapshot-Sig"))
		if sig == "" {
			os.Remove(tmp)
			writeJSON(w, 400, map[string]string{"error": "X-Snapshot-Sig missing"})
			return
		}
		if err := os.Rename(tmp, r.st.snapshotPath(sum)); err != nil {
			os.Remove(tmp)
			writeErr(w, err)
			return
		}
		r.st.Do(func(d *persisted) {
			if st := d.Started[machine]; st != nil {
				st.Snapshot, st.SnapshotSig = sum, sig
			}
		})
		r.snapshotArrived(machine)
		writeJSON(w, 200, map[string]any{"ok": true, "sha256": sum})
	}))
	m("GET /m/commands", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		a := r.out(machine).next(commandsWait, req.Context().Done())
		writeJSON(w, 200, a)
	})
	m("POST /m/challenge", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Subject string `json:"subject"`
			About   string `json:"about"`
		}
		if json.Unmarshal(body, &in) != nil || !sha256RE.MatchString(in.Subject) || in.About == "" || len(in.About) > 32 {
			writeJSON(w, 400, map[string]string{"error": "subject: hex sha256; about: a word"})
			return
		}
		ch, err := r.k.Challenge(in.Subject, in.About)
		if err != nil {
			writeErr(w, err)
			return
		}
		r.docs.Put(ch)
		writeJSON(w, 200, ch)
	})
	m("POST /m/shell-result", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var res ShellResult
		json.Unmarshal(body, &res)
		r.out(machine).shellResult(res)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/due-result", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var res DueResult
		json.Unmarshal(body, &res)
		r.out(machine).dueResult(res)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/notice-result", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var res NoticeResult
		json.Unmarshal(body, &res)
		r.out(machine).noticeResult(res)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/secrets/pull", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Grant kernel.SignedDoc `json:"grant"`
		}
		if json.Unmarshal(body, &in) != nil || in.Grant.Payload == "" {
			writeJSON(w, 400, map[string]string{"error": "{grant}: the grant the machine holds"})
			return
		}
		g, err := grantOf(in.Grant)
		if err != nil || g.Machine.ID != machine {
			writeJSON(w, 403, map[string]string{"error": "a pull is with a grant on this machine"})
			return
		}
		d, err := r.k.Pull(in.Grant)
		if err != nil {
			writeErr(w, err)
			return
		}
		markPulled(machine) // a pause waits briefly for such a machine's boot to finish
		var a struct {
			Locked []string `json:"locked"`
		}
		payloadOf(d, &a)
		r.st.Do(func(p *persisted) {
			if s := p.Sessions[p.Machines[machine]]; s != nil && s.MachineID == machine {
				s.LockedStore = ""
				if len(a.Locked) > 0 {
					s.LockedStore = a.Locked[0]
				}
				if s.State == "initialising" {
					s.State, s.Error = "started", ""
				}
			}
		})
		writeJSON(w, 200, d)
	})
}

var commandsWait = 50 * time.Second

// machineSession: the session a machine currently runs (a paused or replaced machine has none)
func (r *Router) machineSession(machine string) (string, error) {
	var sid string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
			sid = s.ID
		}
	})
	if sid == "" {
		return "", errors.New("this machine isn't a running session")
	}
	return sid, nil
}
