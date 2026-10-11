package main

// Every Fly org on the Machines view (Deyao, 2026-10-11: "both list all machines so I can see a leak clearly"):
// besides jarvis2-sessions (machines.go: sessions, Destroy), every app in every org Deyao has, read-only, grouped
// org → app, each machine and volume with why it stands out (a possible leak), if it does.
//
// Where each org comes from:
//   - an org in FLY_ORG_READ_TOKENS ({"<org slug>": "<token>"}, router-secrets part `flyorgs`): Fly directly, with
//     that org's READ-ONLY token (`fly tokens create readonly`) — jarvis2-370 and kamyee. They can change nothing.
//   - org personal (Jarvis 1's): Jarvis 1's sanitized list (GET /api/fly/machines, the confined services token
//     JARVIS1_SERVICES_ID/SECRET). The router holds no token for personal on purpose: a Fly read token returns each
//     machine's whole config, and every Jarvis 1 session machine carries its secrets in its Fly env.
// A Fly read token also returns env for the orgs read directly; only the fields below leave this file.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// this router's own org (the one jarvis2-sessions lives in)
const ownFlyOrg = "jarvis2-370"

// the apps a Jarvis runs sessions in; a machine anywhere else is unexplained
var knownFlyApps = map[string]string{
	"de0ch-claude-sessions":   "Jarvis 1 sessions",
	"jarvis2-sessions":        "Jarvis 2 sessions",
	"kamyee-jarvis3-sessions": "KAMYEE's Jarvis 3 sessions",
}

// a machine still created/starting after this is stuck
const stuckAfter = 15 * time.Minute

type flyVolumeView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Region     string `json:"region"`
	SizeGB     int    `json:"sizeGb"`
	AttachedTo string `json:"attachedTo"`
	Created    string `json:"created"`
	Attention  string `json:"attention"`
}

type flyAppView struct {
	App      string          `json:"app"`
	Label    string          `json:"label"` // "Jarvis 2 sessions", or "" for an app no Jarvis uses
	Own      bool            `json:"own"`   // jarvis2-sessions: sessions and Destroy
	Status   string          `json:"status"`
	Machines []machineView   `json:"machines"`
	Volumes  []flyVolumeView `json:"volumes"`
	Error    string          `json:"error"`
}

type flyOrgView struct {
	Org       string       `json:"org"`
	Via       string       `json:"via"` // "fly" (read directly) or "Jarvis 1" (its relay)
	Error     string       `json:"error"`
	CheckedAt string       `json:"checkedAt"`
	Apps      []flyAppView `json:"apps"`
}

// attentionOf: why a machine stands out, or "". Both Jarvises destroy a machine on pause, so a stopped one is
// left over: it keeps its disk (billed) and counts toward the org's machine cap.
func attentionOf(state, created string, own bool, sessionID, app string, now time.Time) string {
	switch state {
	case "stopped", "suspended":
		return "Stopped: keeps its disk (billed) and counts toward Fly's machine cap"
	case "failed":
		return "Failed"
	case "created", "starting", "replacing":
		if t, err := time.Parse(time.RFC3339, created); err == nil && now.Sub(t) > stuckAfter {
			return fmt.Sprintf("Stuck in %q", state)
		}
	}
	if own && sessionID == "" {
		return "No session"
	}
	if !own && app != "" && knownFlyApps[app] == "" {
		return "In an app no Jarvis runs sessions in"
	}
	return ""
}

func volumeViewOf(v flyVolume) flyVolumeView {
	out := flyVolumeView{ID: v.ID, Name: v.Name, State: v.State, Region: v.Region, SizeGB: v.SizeGB, AttachedTo: v.AttachedMachineID, Created: v.CreatedAt}
	if v.AttachedMachineID == "" {
		out.Attention = "Not attached to a machine: billed for nothing"
	}
	return out
}

// otherMachineView: a machine of another app, read-only (no session, no Destroy); env never copied
func otherMachineView(m flyMachineDetail, app string, now time.Time) machineView {
	v := machineView{ID: m.ID, Name: m.Name, State: m.State, Region: m.Region, Created: m.CreatedAt, Updated: m.UpdatedAt,
		Image: m.Config.Image, NoDestroy: "it is not in " + sessionsApp + ": read-only here"}
	if v.Image == "" && m.ImageRef.Repository != "" {
		v.Image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + ":" + m.ImageRef.Tag
	}
	if g := m.Config.Guest; g != nil {
		v.Guest = guestText(g)
	}
	v.Attention = attentionOf(m.State, m.CreatedAt, false, "", app, now)
	return v
}

// flyOrgTokens: FLY_ORG_READ_TOKENS parsed; an unreadable value is an error shown on the page
func flyOrgTokens() (map[string]string, error) {
	raw := os.Getenv("FLY_ORG_READ_TOKENS")
	if raw == "" {
		return map[string]string{}, nil
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return map[string]string{}, fmt.Errorf("FLY_ORG_READ_TOKENS is not valid JSON")
	}
	return m, nil
}

var flyOrgHTTP = &http.Client{Timeout: 30 * time.Second}

// flyAPIBase: the Machines API (tests point it at a fake)
var flyAPIBase = "https://api.machines.dev"

func flyGet(token, path string, out any) error {
	req, _ := http.NewRequest("GET", flyAPIBase+path, nil)
	if !strings.HasPrefix(token, "FlyV1 ") && !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + token
	}
	req.Header.Set("Authorization", token)
	resp, err := flyOrgHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("Fly GET %s: HTTP %d %s", strings.SplitN(path, "?", 2)[0], resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// scanFlyOrg: one org read directly. ownApp (jarvis2-sessions, in the router's own org) is filled by the caller
// with machinesView's session-aware list.
func scanFlyOrg(org, token string, own func() ([]machineView, error), now time.Time) flyOrgView {
	o := flyOrgView{Org: org, Via: "fly", CheckedAt: now.UTC().Format(time.RFC3339), Apps: []flyAppView{}}
	var apps struct {
		Apps []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"apps"`
	}
	if err := flyGet(token, "/v1/apps?org_slug="+url.QueryEscape(org), &apps); err != nil {
		o.Error = err.Error()
		return o
	}
	out := make([]flyAppView, len(apps.Apps))
	var wg sync.WaitGroup
	for i, a := range apps.Apps {
		wg.Add(1)
		go func(i int, name, status string) {
			defer wg.Done()
			av := flyAppView{App: name, Label: knownFlyApps[name], Status: status, Machines: []machineView{}, Volumes: []flyVolumeView{}}
			if own != nil && org == ownFlyOrg && name == sessionsApp {
				av.Own = true
				ms, err := own()
				if err != nil {
					av.Error = err.Error()
				} else {
					av.Machines = ms
				}
			} else {
				var ms []flyMachineDetail
				if err := flyGet(token, "/v1/apps/"+url.PathEscape(name)+"/machines", &ms); err != nil {
					av.Error = err.Error()
				}
				for _, m := range ms {
					if m.State != "destroyed" {
						av.Machines = append(av.Machines, otherMachineView(m, name, now))
					}
				}
				sortMachineViews(av.Machines)
			}
			var vs []flyVolume
			if err := flyGet(token, "/v1/apps/"+url.PathEscape(name)+"/volumes", &vs); err != nil && av.Error == "" {
				av.Error = err.Error()
			}
			for _, v := range vs {
				if v.State != "destroyed" {
					av.Volumes = append(av.Volumes, volumeViewOf(v))
				}
			}
			out[i] = av
		}(i, a.Name, a.Status)
	}
	wg.Wait()
	sortApps(out)
	o.Apps = out
	return o
}

func sortMachineViews(ms []machineView) {
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].Created != ms[j].Created {
			return ms[i].Created > ms[j].Created
		}
		return ms[i].ID < ms[j].ID
	})
}

func sortApps(as []flyAppView) {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Own != as[j].Own {
			return as[i].Own
		}
		return as[i].App < as[j].App
	})
}

// jarvis1FlyURL: Jarvis 1's sanitized list of its own org
var jarvis1FlyURL = func() string {
	return strings.TrimSuffix(env("JARVIS1_URL", "https://jarvis.deyaochen.com"), "/") + "/api/fly/machines"
}

// jarvis1FlyOrgs: org personal from Jarvis 1's relay (via "Jarvis 1"). Without the services token, or when Jarvis 1
// doesn't answer, one org entry saying so (never silently nothing).
func jarvis1FlyOrgs(now time.Time) []flyOrgView {
	fail := func(msg string) []flyOrgView {
		return []flyOrgView{{Org: "personal", Via: "Jarvis 1", Error: msg, CheckedAt: now.UTC().Format(time.RFC3339), Apps: []flyAppView{}}}
	}
	id, sec := os.Getenv("JARVIS1_SERVICES_ID"), os.Getenv("JARVIS1_SERVICES_SECRET")
	if id == "" || sec == "" {
		return fail("the router has no JARVIS1_SERVICES_ID/SECRET: Jarvis 1's list isn't reachable")
	}
	req, _ := http.NewRequest("GET", jarvis1FlyURL(), nil)
	req.Header.Set("CF-Access-Client-Id", id)
	req.Header.Set("CF-Access-Client-Secret", sec)
	req.Header.Set("User-Agent", "jarvis2-router/1")
	resp, err := flyOrgHTTP.Do(req)
	if err != nil {
		return fail("Jarvis 1 unreachable: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fail(fmt.Sprintf("Jarvis 1: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b))))
	}
	var body struct {
		Orgs []struct {
			Org       string  `json:"org"`
			Error     *string `json:"error"`
			CheckedAt string  `json:"checkedAt"`
			Apps      []struct {
				App      string  `json:"app"`
				Label    string  `json:"label"`
				Status   string  `json:"status"`
				Error    *string `json:"error"`
				Machines []struct {
					ID, Name, State, Region, Size, Guest, Image, Created, Updated string
					SessionID                                                     *string `json:"sessionId"`
					Attention                                                     *string `json:"attention"`
				} `json:"machines"`
				Volumes []flyVolumeView `json:"volumes"`
			} `json:"apps"`
		} `json:"orgs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return fail("Jarvis 1: unreadable answer: " + err.Error())
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	out := []flyOrgView{}
	for _, o := range body.Orgs {
		ov := flyOrgView{Org: o.Org, Via: "Jarvis 1", Error: str(o.Error), CheckedAt: o.CheckedAt, Apps: []flyAppView{}}
		for _, a := range o.Apps {
			av := flyAppView{App: a.App, Label: a.Label, Status: a.Status, Error: str(a.Error), Machines: []machineView{}, Volumes: a.Volumes}
			if av.Volumes == nil {
				av.Volumes = []flyVolumeView{}
			}
			for _, m := range a.Machines {
				v := machineView{ID: m.ID, Name: m.Name, State: m.State, Region: m.Region, Size: m.Size, Guest: m.Guest, Image: m.Image,
					Created: m.Created, Updated: m.Updated, Attention: str(m.Attention), NoDestroy: "it is not in " + sessionsApp + ": read-only here"}
				if sid := str(m.SessionID); sid != "" {
					v.OtherSession = sid // a Jarvis 1 session's: shown, never linked
				}
				av.Machines = append(av.Machines, v)
			}
			ov.Apps = append(ov.Apps, av)
		}
		out = append(out, ov)
	}
	if len(out) == 0 {
		return fail("Jarvis 1 listed no org")
	}
	return out
}

// flyOrgsOverview: every org, the router's own first, then the read-only ones by name, then Jarvis 1's
// ownMs: jarvis2-sessions as the caller just listed it (FLY_READ_TOKEN)
func (r *Router) flyOrgsOverview(ownMs []flyMachineDetail, now time.Time) (orgs []flyOrgView, configErr string) {
	toks, err := flyOrgTokens()
	if err != nil {
		configErr = err.Error()
	}
	own := func() ([]machineView, error) { return r.machinesView(ownMs, now), nil }
	names := []string{}
	for org := range toks {
		if org != ownFlyOrg && org != "personal" {
			names = append(names, org)
		}
	}
	sort.Strings(names)
	results := make([]flyOrgView, len(names)+2)
	var wg sync.WaitGroup
	wg.Add(len(names) + 2)
	go func() {
		defer wg.Done()
		if t := toks[ownFlyOrg]; t != "" {
			results[0] = scanFlyOrg(ownFlyOrg, t, own, now)
			return
		}
		// no org token: the sessions app alone, with the app-scoped FLY_READ_TOKEN
		av := flyAppView{App: sessionsApp, Label: knownFlyApps[sessionsApp], Own: true, Machines: []machineView{}, Volumes: []flyVolumeView{}}
		if ms, err := own(); err != nil {
			av.Error = err.Error()
		} else {
			av.Machines = ms
		}
		results[0] = flyOrgView{Org: ownFlyOrg, Via: "fly", CheckedAt: now.UTC().Format(time.RFC3339), Apps: []flyAppView{av},
			Error: "no read-only token for the org in FLY_ORG_READ_TOKENS: only " + sessionsApp + " is listed"}
	}()
	for i, org := range names {
		go func(i int, org string) { defer wg.Done(); results[i+1] = scanFlyOrg(org, toks[org], nil, now) }(i, org)
	}
	var j1 []flyOrgView
	go func() { defer wg.Done(); j1 = jarvis1FlyOrgs(now) }()
	wg.Wait()
	orgs = append(results[:len(names)+1], j1...)
	return orgs, configErr
}

// flyAttentionCount: how many machines, volumes, apps and orgs stand out
func flyAttentionCount(orgs []flyOrgView) int {
	n := 0
	for _, o := range orgs {
		if o.Error != "" {
			n++
		}
		for _, a := range o.Apps {
			if a.Error != "" {
				n++
			}
			for _, m := range a.Machines {
				if m.Attention != "" {
					n++
				}
			}
			for _, v := range a.Volumes {
				if v.Attention != "" {
					n++
				}
			}
		}
	}
	return n
}
