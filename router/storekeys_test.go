package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// the core's signed list + the names the setup session recorded + a repo store's two derived names
func TestStoreKeysListed(t *testing.T) {
	r := newTestRouter(t)
	k := newTestKey()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/stores" {
			http.NotFound(w, req)
			return
		}
		writeJSON(w, 200, k.doc(map[string]any{"kind": "stores", "nonce": "n", "stores": []map[string]any{
			{"name": "default", "sensitive": false, "empty": false, "unlocked": true},
			{"name": "money", "sensitive": true, "empty": false, "unlocked": false},
			{"name": "fresh", "sensitive": false, "empty": true, "unlocked": false},
			{"name": "github-claude-env", "sensitive": false, "empty": false, "unlocked": false},
		}}))
	}))
	defer core.Close()
	r.core = &CoreClient{base: core.URL, http: http.DefaultClient}
	r.applyKeyAnswer(keyAnswer{Kind: "deploy-key-added", Repo: "DE0CH/claude-env"})

	// recorded through the setup route (NoAccess router without a setup key: no signature needed in tests)
	if code, out := appDo(t, r, "POST", "/setup/store-keys", `{"name":"default","keys":["OPENROUTER_API","EXA_API","EXA_API"]}`); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := appDo(t, r, "POST", "/setup/store-keys", `{"name":"default","keys":["bad name"]}`); code != 400 {
		t.Fatalf("a bad key name was taken: %d", code)
	}
	if err := r.RecordStoreKeys("gone", []string{"X"}); err != nil {
		t.Fatal(err)
	}

	byName := func(rows []any) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, x := range rows {
			m := x.(map[string]any)
			out[m["name"].(string)] = m
		}
		return out
	}
	check := func(code int, out map[string]any) {
		t.Helper()
		if code != 200 || out["signed"] == nil {
			t.Fatalf("%d %v", code, out)
		}
		s := byName(out["stores"].([]any))
		if len(s) != 4 || s["gone"] != nil {
			t.Fatalf("only the core's stores are listed: %v", s)
		}
		if !reflect.DeepEqual(s["default"]["keys"], []any{"EXA_API", "OPENROUTER_API"}) || s["default"]["keysFrom"] != "setup" || s["default"]["unlocked"] != true {
			t.Fatalf("default: %v", s["default"])
		}
		if s["money"]["keys"] != nil || s["money"]["keysFrom"] != "" || s["money"]["sensitive"] != true {
			t.Fatalf("money (no names recorded): %v", s["money"])
		}
		if !reflect.DeepEqual(s["fresh"]["keys"], []any{}) || s["fresh"]["keysFrom"] != "empty" {
			t.Fatalf("fresh: %v", s["fresh"])
		}
		if !reflect.DeepEqual(s["github-claude-env"]["keys"], []any{"GITHUB_DEPLOY_KEY_DE0CH_CLAUDE_ENV", "GITHUB_DEPLOY_REPO_DE0CH_CLAUDE_ENV"}) || s["github-claude-env"]["keysFrom"] != "deploy-key" {
			t.Fatalf("repo store: %v", s["github-claude-env"])
		}
	}
	check(appDo(t, r, "GET", "/api/stores", ""))
	check(appDo(t, r, "GET", "/setup/stores/keys", ""))
	// every session sees every store, not only its own
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	check(m.do(t, r.MachineHandler(), "GET", "/m/stores", ""))

	// null forgets
	if code, _ := appDo(t, r, "POST", "/setup/store-keys", `{"name":"default","keys":null}`); code != 200 {
		t.Fatal(code)
	}
	if _, ok := r.readStoreKeys()["default"]; ok {
		t.Fatal("not forgotten")
	}
}
