package main

// Stores: a session writes one key (sealed three ways on its machine; backup first, then secrets, then `pull` to the
// machines whose grant names the store, and the next pull serves it), the list names who wrote each key, and nothing
// is written without its backup.

import (
	"encoding/json"
	"testing"
)

// machineWrite: what the guard sends (machine/putkey.go keyWriteRequest), sealed here with the router's own helper
func (g *krig) machineWrite(m *vmach, store, key, value, explanation string) (int, map[string]any) {
	g.t.Helper()
	tg, err := g.r.sealTargets()
	if err != nil {
		g.t.Fatal(err)
	}
	in, err := sealKeyWrite(tg, store, key, []byte(value), explanation)
	if err != nil {
		g.t.Fatal(err)
	}
	b, _ := json.Marshal(in)
	var out map[string]any
	code := m.json("POST", "/m/stores/"+store+"/keys/"+key, json.RawMessage(b), &out)
	return code, out
}

func TestASessionWritesAKey(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	g.writeKey("work", "OLD", "1")
	g.unlock("work")
	sid, m := g.newSession("work")
	m.boot()
	_, other := g.newSession()
	other.boot()
	m.commands()
	other.commands()
	// what a writer seals to: secrets' signed state, store key and agreement key
	var keys map[string]json.RawMessage
	if code := m.json("GET", "/m/store-keys", nil, &keys); code != 200 || keys["state"] == nil || keys["storeKey"] == nil || keys["agreementKey"] == nil {
		t.Fatalf("%d %v", code, keys)
	}
	// a new key name needs its explanation
	if code, _ := g.machineWrite(m, "work", "NEW", "v", ""); code != 400 {
		t.Fatalf("no explanation: %d", code)
	}
	code, out := g.machineWrite(m, "work", "NEW", "secret-v", "what NEW is for")
	if code != 200 || out["receipt"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	if p, _ := out["pulled"].([]any); len(p) != 1 || p[0] != sid {
		t.Fatalf("pulled %v", out["pulled"])
	}
	if a := m.commands(); len(a.Commands) != 1 || a.Commands[0] != "pull" {
		t.Fatalf("the holder wasn't told to pull: %+v", a)
	}
	if a := other.commands(); len(a.Commands) != 0 {
		t.Fatalf("a machine without the store was told: %+v", a)
	}
	if vals, _ := m.pull(); vals["work"]["NEW"] != "secret-v" || vals["work"]["OLD"] != "1" {
		t.Fatalf("%v", vals)
	}
	// the list: the key, its explanation, written by this machine's session
	rows, _, err := g.r.StoreList()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		for _, k := range row.KeyInfo {
			if row.Name == "work" && k.Name == "NEW" {
				found = k.Explanation == "what NEW is for" && k.Writer != nil && k.Writer.By == "machine" && k.Writer.Machine == m.id && k.Writer.Session == sid
			}
		}
	}
	if !found {
		t.Fatalf("%+v", rows)
	}
	// reserved stores: never
	for _, st := range []string{"core", "github-deploy-keys"} {
		if code, _ := g.machineWrite(m, st, "K", "v", "x"); code != 403 {
			t.Fatalf("%s: %d", st, code)
		}
	}
}

func TestNoKeyWithoutItsBackup(t *testing.T) {
	g := newKRig(t)
	g.setUpSecrets()
	_, m := g.newSession()
	m.boot()
	t.Setenv("BACKUP_READ_ACCESS_KEY", "")
	if code, out := g.machineWrite(m, "work", "K", "v", "x"); code == 200 {
		t.Fatalf("written without a backup: %v", out)
	}
}
