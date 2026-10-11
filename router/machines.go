package main

// The Machines view (Deyao, 2026-10-11: "I should be able to see all machines"): every machine in the Fly app
// jarvis2-sessions, live from Fly with the router's read-only token (FLY_READ_TOKEN, as budget.go), each with
// the session it belongs to or none, and marked "test" when its JARVIS2_URL is not production's router.
//
// Destroying one goes through the core's kill, the same call a pause makes: the core alone holds a Fly token
// that can destroy, and its kill takes any machine of the app (Fly-confirmed). The router allows it only for a
// machine that belongs to no session: Fly lists it, the router never started it (no Started entry, no cert, no
// session mapping) and it is older than orphanMinAge, so a machine the core is still creating for a Start (not
// yet recorded) is never caught. A session machine is never acted on from this view; it is paused or destroyed
// as its session. The kill gives the router no power it didn't have (it kills session machines on every pause).

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// production's router address on the Fly private network (k8s/apps/router.yaml MACHINE_URL); any other
// JARVIS2_URL is a test router's (infra/e2e.sh, a rehearsal box)
const productionRouterHost = "jarvis2-box._peer.internal"

// a machine younger than this may be a Start in flight (the core creates it before the router records it)
const orphanMinAge = 15 * time.Minute

type flyMachineDetail struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	Region    string `json:"region"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Config    struct {
		Image string            `json:"image"`
		Env   map[string]string `json:"env"`
		Guest *flyGuest         `json:"guest"`
	} `json:"config"`
	ImageRef struct {
		Registry   string `json:"registry"`
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Digest     string `json:"digest"`
	} `json:"image_ref"`
}

type machineView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	Region    string `json:"region"`
	Size      string `json:"size"`  // small | medium | large when the guest is one of the sizes, else ""
	Guest     string `json:"guest"` // "4×shared · 4 GB"
	Image     string `json:"image"`
	Created   string `json:"created"`
	Updated   string `json:"updated"`
	SessionID string `json:"sessionId"` // "" = no session
	// the session's current machine (false: an earlier machine of it that Fly still lists)
	Current   bool   `json:"current"`
	RouterURL string `json:"routerUrl"` // the machine's JARVIS2_URL
	Test      bool   `json:"test"`      // JARVIS2_URL is not production's router
	// why Destroy isn't offered ("" = it is): belongs to a session, too new, …
	NoDestroy string `json:"noDestroy"`
}

// the sizes the router starts machines with (core/fly.go sizes)
func sizeOf(g *flyGuest) string {
	if g == nil || g.CPUKind != "shared" {
		return ""
	}
	switch {
	case g.CPUs == 2 && g.MemoryMB == 2048:
		return "small"
	case g.CPUs == 4 && g.MemoryMB == 4096:
		return "medium"
	case g.CPUs == 8 && g.MemoryMB == 8192:
		return "large"
	}
	return ""
}

func isTestRouter(u string) bool {
	if u == "" {
		return false
	}
	p, err := url.Parse(u)
	return err != nil || p.Hostname() != productionRouterHost
}

// machinesView: the list, newest first; pure (tests)
func (r *Router) machinesView(ms []flyMachineDetail, now time.Time) []machineView {
	out := []machineView{}
	r.st.Do(func(d *persisted) {
		for _, m := range ms {
			if m.State == "destroyed" {
				continue
			}
			v := machineView{ID: m.ID, Name: m.Name, State: m.State, Region: m.Region, Created: m.CreatedAt, Updated: m.UpdatedAt,
				Image: m.Config.Image, Size: sizeOf(m.Config.Guest), RouterURL: m.Config.Env["JARVIS2_URL"]}
			if v.Image == "" && m.ImageRef.Repository != "" {
				v.Image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + ":" + m.ImageRef.Tag
			}
			if g := m.Config.Guest; g != nil {
				v.Guest = fmt.Sprintf("%d×%s · %d GB", g.CPUs, g.CPUKind, int(math.Round(float64(g.MemoryMB)/1024)))
			}
			v.Test = isTestRouter(v.RouterURL)
			if sid, ok := d.Machines[m.ID]; ok {
				v.SessionID = sid
				if s := d.Sessions[sid]; s != nil && s.MachineID == m.ID {
					v.Current = true
				}
			}
			v.NoDestroy = orphanRefusal(d, m, now)
			out = append(out, v)
		}
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created > out[j].Created
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// orphanRefusal: why the machine may not be destroyed from the Machines view, or "" when it may. Called with
// the state held.
func orphanRefusal(d *persisted, m flyMachineDetail, now time.Time) string {
	if sid, ok := d.Machines[m.ID]; ok {
		return "it belongs to session " + sid + ": pause or destroy the session"
	}
	if d.Started[m.ID] != nil || d.Certs[m.ID] != nil {
		return "the router started it for a session"
	}
	if t, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil || now.Sub(t) < orphanMinAge {
		return fmt.Sprintf("it is less than %d minutes old and may be a session still starting", int(orphanMinAge.Minutes()))
	}
	return ""
}

// the router's Fly reader (read-only token); nil without FLY_READ_TOKEN
var machinesFly = func() *flyAPI {
	token := os.Getenv("FLY_READ_TOKEN")
	if token == "" {
		return nil
	}
	return &flyAPI{base: "https://api.machines.dev", app: sessionsApp, token: token, http: &http.Client{Timeout: 30 * time.Second}}
}

var listFlyMachines = func() ([]flyMachineDetail, error) {
	f := machinesFly()
	if f == nil {
		return nil, fmt.Errorf("FLY_READ_TOKEN not set")
	}
	var ms []flyMachineDetail
	return ms, f.get("/machines", &ms)
}

// the core's kill (flows.go makes the same call on a pause); swappable in tests
var orphanKill = func(r *Router, id string) error {
	_, err := r.core.Call("/kill", map[string]string{"machine": id})
	return err
}

// DestroyOrphan: destroy a machine that belongs to no session (re-checked against a fresh Fly list)
func (r *Router) DestroyOrphan(id string) error {
	ms, err := listFlyMachines()
	if err != nil {
		return fmt.Errorf("Fly: %v", err)
	}
	var m *flyMachineDetail
	for i := range ms {
		if ms[i].ID == id && ms[i].State != "destroyed" {
			m = &ms[i]
		}
	}
	if m == nil {
		return fmt.Errorf("no machine %s in %s", id, sessionsApp)
	}
	var why string
	r.st.Do(func(d *persisted) { why = orphanRefusal(d, *m, time.Now()) })
	if why != "" {
		return fmt.Errorf("%w: machine %s is not destroyed from here: %s", errBusy, id, why)
	}
	if err := orphanKill(r, id); err != nil {
		return err
	}
	log.Printf("machine %s (%s, router %s) destroyed from the Machines view: it belonged to no session", id, orDash(m.Name), orDash(m.Config.Env["JARVIS2_URL"]))
	return nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func (r *Router) registerMachines(app appRoute) {
	app("GET /api/machines", func(w http.ResponseWriter, req *http.Request) {
		ms, err := listFlyMachines()
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "Fly: " + err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"app": sessionsApp, "machines": r.machinesView(ms, time.Now()), "checkedAt": time.Now().UTC()})
	})
	app("POST /api/machines/{id}/destroy", func(w http.ResponseWriter, req *http.Request) {
		if err := r.DestroyOrphan(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": req.PathValue("id")})
	})
}
