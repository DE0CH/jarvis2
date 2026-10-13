package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// a fake Machines API: org → apps, app → machines (raw Fly JSON, env included) and volumes; records the tokens used
func fakeFlyOrgs(t *testing.T, orgTokens map[string]string, apps map[string][]string, machines map[string][]map[string]any, volumes map[string][]map[string]any) (*httptest.Server, *[]string) {
	seen := &[]string{}
	appOrg := map[string]string{}
	for org, as := range apps {
		for _, a := range as {
			appOrg[a] = org
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		*seen = append(*seen, req.URL.Path+" "+auth)
		org := req.URL.Query().Get("org_slug")
		if req.URL.Path == "/v1/apps" {
			if auth != "Bearer "+orgTokens[org] {
				w.WriteHeader(403)
				w.Write([]byte(`{"error":"unauthorized"}`))
				return
			}
			list := []map[string]string{}
			for _, a := range apps[org] {
				list = append(list, map[string]string{"name": a, "status": "deployed"})
			}
			json.NewEncoder(w).Encode(map[string]any{"apps": list})
			return
		}
		parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/apps/"), "/")
		if auth != "Bearer "+orgTokens[appOrg[parts[0]]] {
			w.WriteHeader(403)
			return
		}
		switch parts[1] {
		case "machines":
			json.NewEncoder(w).Encode(append([]map[string]any{}, machines[parts[0]]...))
		case "volumes":
			json.NewEncoder(w).Encode(append([]map[string]any{}, volumes[parts[0]]...))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func rawM(id, state, created string) map[string]any {
	return map[string]any{"id": id, "name": "n-" + id, "state": state, "region": "arn", "created_at": created,
		"config": map[string]any{"image": "img", "guest": map[string]any{"cpu_kind": "shared", "cpus": 2, "memory_mb": 2048},
			"env": map[string]string{"SECRET_THING": "TOPSECRET"}}}
}

func TestFlyOrgsOverviewEveryOrgReadOnly(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour).Format(time.RFC3339)
	srv, seen := fakeFlyOrgs(t, map[string]string{"jarvis2-370": "tok-j2", "kamyee": "tok-k", "personal": "tok-p"},
		map[string][]string{"jarvis2-370": {"jarvis2-sessions", "zz-stray"}, "kamyee": {"kamyee-jarvis3-sessions"}, "personal": {"de0ch-claude-sessions"}},
		map[string][]map[string]any{"zz-stray": {rawM("st1", "started", old)}, "kamyee-jarvis3-sessions": {rawM("k1", "stopped", old), rawM("k2", "started", old)},
			"de0ch-claude-sessions": {rawM("p1", "started", old), rawM("p2", "stopped", old)}},
		map[string][]map[string]any{"zz-stray": {{"id": "vol_1", "state": "created", "size_gb": 1, "created_at": old}}})
	oldBase := flyAPIBase
	defer func() { flyAPIBase = oldBase }()
	flyAPIBase = srv.URL
	t.Setenv("FLY_ORG_READ_TOKENS", `{"jarvis2-370":"tok-j2","kamyee":"tok-k"}`)
	t.Setenv("FLY_PERSONAL_READ_TOKEN", "tok-p")

	r := newTestRouter(t)
	addSession(r, "s1", "running", "m-cur", false)
	own := []flyMachineDetail{flyM("m-cur", "started", old, prodURL), flyM("m-orphan", "stopped", old, prodURL)}
	orgs, cerr := r.flyOrgsOverview(own, now)
	if cerr != "" {
		t.Fatal(cerr)
	}
	if len(orgs) != 3 || orgs[0].Org != "jarvis2-370" || orgs[1].Org != "kamyee" || orgs[2].Org != "personal" || orgs[2].Via != "fly" {
		t.Fatalf("orgs %+v", orgs)
	}
	j2 := orgs[0]
	if len(j2.Apps) != 2 || !j2.Apps[0].Own || j2.Apps[0].App != "jarvis2-sessions" || len(j2.Apps[0].Machines) != 2 {
		t.Fatalf("own org %+v", j2)
	}
	if m := j2.Apps[0].Machines[1]; m.ID != "m-orphan" && j2.Apps[0].Machines[0].ID != "m-orphan" {
		t.Fatalf("own machines %+v", j2.Apps[0].Machines)
	}
	stray := j2.Apps[1]
	if stray.Own || stray.Machines[0].Attention == "" || stray.Machines[0].NoDestroy == "" || stray.Volumes[0].Attention == "" {
		t.Fatalf("stray app %+v", stray)
	}
	k := orgs[1].Apps[0]
	att := map[string]string{}
	for _, m := range k.Machines {
		att[m.ID] = m.Attention
	}
	if !strings.HasPrefix(att["k1"], "Stopped") || att["k2"] != "" {
		t.Fatalf("kamyee %+v", att)
	}
	p := orgs[2].Apps[0]
	pa := map[string]string{}
	for _, m := range p.Machines {
		pa[m.ID] = m.Attention
	}
	if p.Own || p.Label != "Jarvis 1 sessions" || len(p.Machines) != 2 || pa["p1"] != "" || !strings.HasPrefix(pa["p2"], "Stopped") || p.Machines[0].NoDestroy == "" {
		t.Fatalf("personal %+v", p)
	}
	// own: m-orphan stopped (1) · stray machine + volume (2) · k1 (1) · p2 (1)
	if n := flyAttentionCount(orgs); n != 5 {
		t.Fatalf("attention %d", n)
	}
	b, _ := json.Marshal(orgs)
	if strings.Contains(string(b), "TOPSECRET") || strings.Contains(string(b), "SECRET_THING") {
		t.Fatal("a machine's env left the router")
	}
	// each org is read with its own token, and never with another org's
	for _, s := range *seen {
		if (strings.Contains(s, "kamyee-jarvis3-sessions") && !strings.HasSuffix(s, "tok-k")) ||
			(strings.Contains(s, "de0ch-claude-sessions") && !strings.HasSuffix(s, "tok-p")) {
			t.Fatalf("wrong token: %s", s)
		}
	}
}

func TestFlyOrgsOverviewFailuresAreShown(t *testing.T) {
	now := time.Now().UTC()
	srv, _ := fakeFlyOrgs(t, map[string]string{"kamyee": "right"}, map[string][]string{"kamyee": {}}, nil, nil)
	oldBase := flyAPIBase
	defer func() { flyAPIBase = oldBase }()
	flyAPIBase = srv.URL
	t.Setenv("FLY_ORG_READ_TOKENS", `{"kamyee":"wrong"}`)
	t.Setenv("FLY_PERSONAL_READ_TOKEN", "")
	r := newTestRouter(t)
	orgs, _ := r.flyOrgsOverview(nil, now)
	if len(orgs) != 3 {
		t.Fatalf("%+v", orgs)
	}
	if orgs[0].Error == "" || len(orgs[0].Apps) != 1 || !orgs[0].Apps[0].Own { // no own-org token: the sessions app alone, said so
		t.Fatalf("own %+v", orgs[0])
	}
	if !strings.Contains(orgs[1].Error, "403") {
		t.Fatalf("kamyee %+v", orgs[1])
	}
	if orgs[2].Org != "personal" || !strings.Contains(orgs[2].Error, "FLY_PERSONAL_READ_TOKEN") {
		t.Fatalf("personal %+v", orgs[2])
	}
	t.Setenv("FLY_ORG_READ_TOKENS", "{bad")
	if _, cerr := r.flyOrgsOverview(nil, now); !strings.Contains(cerr, "not valid JSON") {
		t.Fatal(cerr)
	}
}
