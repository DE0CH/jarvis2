package main

// Store key names (Deyao, 2026-10-11: "the names of the keys should be visible through the api"). A session that
// needs one more store (`jarvis2 add-store <name>`) must know which store holds the key it wants, so every store's
// KEY NAMES (never a value) are listed to the app, the web page, every session and the setup session.
//
// Where the names come from: the core can't say (a locked store is ciphertext to it), and it needn't (Deyao,
// 2026-10-11: names are fine from data we own, protected by TLS and the push path). The router keeps them in its
// own data volume (store-keys.json), written by the setup session's signed `POST /setup/store-keys` — which
// `infra/setup.py write` sends with every store it writes (and `infra/setup.py keys` on its own, to record names
// without writing values). A repo's store (`github-<repo>`, made by the core on Deyao's Face ID) holds two keys
// whose names follow from the repo (core/deploykeys.go), so those come from the repo list. The store list itself
// (names, sensitivity, empty, unlocked) is the core's signed list, passed on as `signed` for anyone who checks it.
//
//	GET /api/stores, GET /m/stores, GET /setup/stores/keys → {stores: [{name, sensitive, empty, unlocked, keys,
//	    keysFrom, keysAt}], signed}
//	POST /setup/store-keys {name, keys: [...] | null} → {ok}   (null forgets the store's names)

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// StoreKeys: one store's recorded key names
type StoreKeys struct {
	Keys []string `json:"keys"`
	At   string   `json:"at"`
}

// StoreRow: one store as listed
type StoreRow struct {
	Name      string   `json:"name"`
	Sensitive bool     `json:"sensitive"`
	Empty     bool     `json:"empty"`
	Unlocked  bool     `json:"unlocked"`
	Keys      []string `json:"keys"`     // null: not known
	KeysFrom  string   `json:"keysFrom"` // setup | deploy-key | empty | "" (not known)
	KeysAt    string   `json:"keysAt,omitempty"`
}

var keyNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

var storeKeysMu sync.Mutex

func (r *Router) storeKeysPath() string { return filepath.Join(r.cfg.DataDir, "store-keys.json") }

func (r *Router) readStoreKeys() map[string]StoreKeys {
	m := map[string]StoreKeys{}
	if b, err := os.ReadFile(r.storeKeysPath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

// RecordStoreKeys: the names a store holds (nil forgets them)
func (r *Router) RecordStoreKeys(name string, keys []string) error {
	if !storeNameOK(name) {
		return fmt.Errorf("bad store name %q", name)
	}
	var clean []string
	if keys != nil {
		if len(keys) > 1000 {
			return fmt.Errorf("too many keys")
		}
		seen := map[string]bool{}
		clean = []string{}
		for _, k := range keys {
			if !keyNameRE.MatchString(k) {
				return fmt.Errorf("bad key name %q", k)
			}
			if !seen[k] {
				seen[k] = true
				clean = append(clean, k)
			}
		}
		sort.Strings(clean)
	}
	storeKeysMu.Lock()
	defer storeKeysMu.Unlock()
	m := r.readStoreKeys()
	if clean == nil {
		delete(m, name)
	} else {
		m[name] = StoreKeys{Keys: clean, At: time.Now().UTC().Format(time.RFC3339)}
	}
	b, _ := json.MarshalIndent(m, "", " ")
	tmp := r.storeKeysPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.storeKeysPath())
}

func storeNameOK(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// envSlug: the core's EnvSlug (core/deploykeys.go) — OWNER_NAME, upper case, anything outside [A-Z0-9] as "_"
func envSlug(repo string) string {
	b := []byte(strings.ToUpper(repo))
	for i, ch := range b {
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

// StoreList: the core's signed list with each store's key names
func (r *Router) StoreList() ([]StoreRow, *Doc, error) {
	d, err := r.core.Call("/stores", map[string]string{"nonce": "store-keys-" + randID()})
	if err != nil {
		return nil, nil, err
	}
	var list struct {
		Kind   string     `json:"kind"`
		Stores []StoreRow `json:"stores"`
	}
	if err := d.Decode(&list); err != nil || list.Kind != "stores" {
		return nil, nil, fmt.Errorf("the core's store list isn't readable")
	}
	storeKeysMu.Lock()
	recorded := r.readStoreKeys()
	storeKeysMu.Unlock()
	repoKeys := map[string][]string{}
	for _, e := range r.Repos() {
		s := envSlug(e.Repo)
		repoKeys[e.Store] = []string{"GITHUB_DEPLOY_KEY_" + s, "GITHUB_DEPLOY_REPO_" + s}
	}
	rows := make([]StoreRow, 0, len(list.Stores))
	for _, s := range list.Stores {
		row := StoreRow{Name: s.Name, Sensitive: s.Sensitive, Empty: s.Empty, Unlocked: s.Unlocked}
		if k, ok := repoKeys[s.Name]; ok && !s.Empty {
			row.Keys, row.KeysFrom = k, "deploy-key"
		} else if s.Empty {
			row.Keys, row.KeysFrom = []string{}, "empty"
		} else if k, ok := recorded[s.Name]; ok {
			row.Keys, row.KeysFrom, row.KeysAt = k.Keys, "setup", k.At
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, d, nil
}

func (r *Router) serveStoreList(w http.ResponseWriter) {
	rows, d, err := r.StoreList()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"stores": rows, "signed": d})
}

func (r *Router) registerStoreKeys(app appRoute, m machineRoute, mux *http.ServeMux) {
	app("GET /api/stores", func(w http.ResponseWriter, req *http.Request) { r.serveStoreList(w) })
	// every session may see every store's names (not only its own): it needs them to know which store to ask for
	m("GET /m/stores", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) { r.serveStoreList(w) })
	setup := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, body []byte)) {
		mux.Handle(pattern, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		}))
	}
	setup("GET /setup/stores/keys", func(w http.ResponseWriter, req *http.Request, _ []byte) { r.serveStoreList(w) })
	setup("POST /setup/store-keys", func(w http.ResponseWriter, req *http.Request, b []byte) {
		var in struct {
			Name string   `json:"name"`
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			writeErr(w, fmt.Errorf("bad JSON: %v", err))
			return
		}
		if err := r.RecordStoreKeys(in.Name, in.Keys); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
