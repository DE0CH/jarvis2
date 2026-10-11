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
	srv, seen := fakeFlyOrgs(t, map[string]string{"jarvis2-370": "tok-j2", "kamyee": "tok-k"},
		map[string][]string{"jarvis2-370": {"jarvis2-sessions", "zz-stray"}, "kamyee": {"kamyee-jarvis3-sessions"}},
		map[string][]map[string]any{"zz-stray": {rawM("st1", "started", old)}, "kamyee-jarvis3-sessions": {rawM("k1", "stopped", old), rawM("k2", "started", old)}},
		map[string][]map[string]any{"zz-stray": {{"id": "vol_1", "state": "created", "size_gb": 1, "created_at": old}}})
	j1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("CF-Access-Client-Id") != "svc" || req.URL.Path != "/api/fly/machines" {
			w.WriteHeader(403)
			return
		}
		w.Write([]byte(`{"orgs":[{"org":"personal","error":null,"checkedAt":"x","apps":[{"app":"de0ch-claude-sessions","label":"Jarvis 1 sessions","status":"deployed","error":null,"volumes":[],
		  "machines":[{"id":"p1","name":"s-x","state":"started","region":"arn","size":"medium","guest":"4×shared · 4 GB","image":"i","created":"c","updated":"u","sessionId":"p1","attention":null},
		              {"id":"p2","name":"","state":"stopped","region":"arn","size":"","guest":"","image":"i","created":"c","updated":"u","sessionId":null,"attention":"Stopped: x"}]}]}]}`))
	}))
	defer j1.Close()
	oldBase, oldJ1 := flyAPIBase, jarvis1FlyURL
	defer func() { flyAPIBase, jarvis1FlyURL = oldBase, oldJ1 }()
	flyAPIBase = srv.URL
	jarvis1FlyURL = func() string { return j1.URL + "/api/fly/machines" }
	t.Setenv("FLY_ORG_READ_TOKENS", `{"jarvis2-370":"tok-j2","kamyee":"tok-k"}`)
	t.Setenv("JARVIS1_SERVICES_ID", "svc")
	t.Setenv("JARVIS1_SERVICES_SECRET", "sec")

	r := newTestRouter(t)
	addSession(r, "s1", "running", "m-cur", false)
	own := []flyMachineDetail{flyM("m-cur", "started", old, prodURL), flyM("m-orphan", "stopped", old, prodURL)}
	orgs, cerr := r.flyOrgsOverview(own, now)
	if cerr != "" {
		t.Fatal(cerr)
	}
	if len(orgs) != 3 || orgs[0].Org != "jarvis2-370" || orgs[1].Org != "kamyee" || orgs[2].Org != "personal" || orgs[2].Via != "Jarvis 1" {
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
	if p.Own || len(p.Machines) != 2 || p.Machines[0].OtherSession != "p1" || p.Machines[1].Attention == "" || p.Machines[0].NoDestroy == "" {
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
		if strings.Contains(s, "kamyee-jarvis3-sessions") && !strings.HasSuffix(s, "tok-k") {
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
	t.Setenv("JARVIS1_SERVICES_ID", "")
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
	if orgs[2].Org != "personal" || !strings.Contains(orgs[2].Error, "JARVIS1_SERVICES") {
		t.Fatalf("personal %+v", orgs[2])
	}
	t.Setenv("FLY_ORG_READ_TOKENS", "{bad")
	if _, cerr := r.flyOrgsOverview(nil, now); !strings.Contains(cerr, "not valid JSON") {
		t.Fatal(cerr)
	}
}
