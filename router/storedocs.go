package main

// Stores, their keys and what each key is for (Deyao, 2026-10-11: "the names of the keys should be visible through the
// api"; 2026-10-13: the explanation of each key is surfaced on the web and iPhone portal, and writing one key by name
// is allowed without overwriting the store).
//
// Key names and who wrote each key come from secrets' signed store list (a store is a set of keys,
// core/kernel/secrets/keys.go). What a store and each key are for is the router's own record (store-docs.json on its
// data volume): not a secret and not part of any trust decision, written by whoever writes a key (a new key name needs
// its explanation), by the setup session (`POST /setup/store-docs`) and by Deyao in the app. Every key's backup carries
// its explanation too, so a Recover brings them back.
//
// Writing a key (no approval: Deyao, 2026-10-13, "any session with a valid machine key … writing a key is perfectly
// safe (has backup, so can't overwrite, and also can't read)"; DESIGN "Layers": writing secrets is protected only by
// the router): the writer seals the value to the store key P + K, to the master key for its backup, and to secrets'
// agreement key (`live`, so the next pull serves it at once). The router writes the backup first (keys/<store>/<key>.json
// in the versioned bucket), then the key into secrets, records the explanation, and sends `pull` to every running
// machine whose grant names the store.
//
//	GET /api/stores, GET /m/stores, GET /setup/stores/keys → {stores: [StoreRow], signed}
//	GET /m/store-keys, GET /setup/store-keys → {state, storeKey, agreementKey}: what a writer seals to (secrets'
//	    signed state naming the master key and the phone, its signed store key for that phone, its agreement key)
//	POST /m/stores/{store}/keys/{key}      a session writes or deletes one key (writer "machine", its id)
//	POST /setup/stores/{store}/keys/{key}  the same as the setup session (writer "setup", the setup key's signature)
//	POST /setup/store-docs, PUT /api/stores/{store}/docs {about?, keys: {KEY: text}} → {ok}

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// KeyWriter: who wrote a key, as secrets recorded it, with the session the router knows that machine as
type KeyWriter struct {
	By           string `json:"by"`
	Machine      string `json:"machine,omitempty"`
	Session      string `json:"session,omitempty"`
	SessionLabel string `json:"sessionLabel,omitempty"`
}

// KeyRow: one key as listed (never a value)
type KeyRow struct {
	Name        string     `json:"name"`
	Explanation string     `json:"explanation"`
	At          string     `json:"at,omitempty"`
	Writer      *KeyWriter `json:"writer,omitempty"`
}

// StoreRow: one store as listed
type StoreRow struct {
	Name      string `json:"name"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Unlocked  bool   `json:"unlocked"`
	About     string `json:"about"`
	Version   string `json:"version,omitempty"`
	// Keys: the key names, the shape every session image reads; KeyInfo: the same keys with what each is for and who
	// wrote it
	Keys    []string `json:"keys"`
	KeyInfo []KeyRow `json:"keyInfo"`
}

// StoreDoc: what a store and its keys are for
type StoreDoc struct {
	About string            `json:"about,omitempty"`
	Keys  map[string]string `json:"keys,omitempty"`
}

var keyNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

const docMax = 2000 // characters of one explanation

var storeDocsMu sync.Mutex

func (r *Router) storeDocsPath() string { return filepath.Join(r.cfg.DataDir, "store-docs.json") }

func (r *Router) readStoreDocs() map[string]StoreDoc {
	m := map[string]StoreDoc{}
	if b, err := os.ReadFile(r.storeDocsPath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

// cleanDoc: an explanation as plain text (cleanExplanation's rules, longer)
func cleanDoc(s string) (string, error) {
	s = strings.ReplaceAll(s, "\n", " ")
	out, err := plainLines(s)
	if err != nil {
		return "", err
	}
	if n := len([]rune(out)); n > docMax {
		return "", fmt.Errorf("explanation longer than %d characters (%d)", docMax, n)
	}
	return out, nil
}

// SetStoreDocs: a store's about text (nil = unchanged) and explanations of its keys ("" removes one)
func (r *Router) SetStoreDocs(store string, about *string, keys map[string]string) error {
	if !storeNameOK(store) {
		return fmt.Errorf("bad store name %q", store)
	}
	clean := map[string]string{}
	for k, v := range keys {
		if !keyNameRE.MatchString(k) {
			return fmt.Errorf("bad key name %q", k)
		}
		c, err := cleanDoc(v)
		if err != nil {
			return fmt.Errorf("%s: %v", k, err)
		}
		clean[k] = c
	}
	var ab string
	if about != nil {
		var err error
		if ab, err = cleanDoc(*about); err != nil {
			return fmt.Errorf("about: %v", err)
		}
	}
	storeDocsMu.Lock()
	defer storeDocsMu.Unlock()
	m := r.readStoreDocs()
	d := m[store]
	if d.Keys == nil {
		d.Keys = map[string]string{}
	}
	if about != nil {
		d.About = ab
	}
	for k, v := range clean {
		if v == "" {
			delete(d.Keys, k)
		} else {
			d.Keys[k] = v
		}
	}
	m[store] = d
	b, _ := json.MarshalIndent(m, "", " ")
	tmp := r.storeDocsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.storeDocsPath())
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

// envSlug: secrets' EnvSlug (core/kernel/secrets/deploykeys.go) — OWNER_NAME, upper case, anything outside [A-Z0-9] as "_"
func envSlug(repo string) string {
	b := []byte(strings.ToUpper(repo))
	for i, ch := range b {
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

// secretsStoreRow: one row of secrets' signed list
type secretsStoreRow struct {
	Name      string `json:"name"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Unlocked  bool   `json:"unlocked"`
	Version   string `json:"version"`
	Keys      []struct {
		Name   string     `json:"name"`
		At     string     `json:"at"`
		Writer *KeyWriter `json:"writer"`
	} `json:"keys"`
}

// StoreList: secrets' signed list with each store's keys, who wrote them and what they are for
func (r *Router) StoreList() ([]StoreRow, *Doc, error) {
	d, err := r.k.SecretsDoc("/stores", map[string]string{"nonce": "store-keys-" + randID()})
	if err != nil {
		return nil, nil, err
	}
	var list struct {
		Kind   string            `json:"kind"`
		Stores []secretsStoreRow `json:"stores"`
	}
	if err := payloadOf(d, &list); err != nil || list.Kind != "stores" {
		return nil, nil, fmt.Errorf("secrets' store list isn't readable")
	}
	storeDocsMu.Lock()
	docs := r.readStoreDocs()
	storeDocsMu.Unlock()
	owners := map[string][2]string{} // machine → session id, label
	r.st.Do(func(p *persisted) {
		for m, sid := range p.Machines {
			label := ""
			if s := p.Sessions[sid]; s != nil {
				label = sessionTitle(*s)
			} else {
				for _, rec := range p.Records {
					if rec.ID == sid {
						label = sessionTitle(rec.Session)
					}
				}
			}
			owners[m] = [2]string{sid, label}
		}
	})
	rows := make([]StoreRow, 0, len(list.Stores))
	for _, s := range list.Stores {
		doc := docs[s.Name]
		row := StoreRow{Name: s.Name, Sensitive: s.Sensitive, Empty: s.Empty, Unlocked: s.Unlocked, About: doc.About, Version: s.Version,
			Keys: []string{}, KeyInfo: []KeyRow{}}
		for _, k := range s.Keys {
			kr := KeyRow{Name: k.Name, Explanation: doc.Keys[k.Name], At: k.At, Writer: k.Writer}
			if w := kr.Writer; w != nil && w.Machine != "" {
				w.Session, w.SessionLabel = owners[w.Machine][0], owners[w.Machine][1]
			}
			row.Keys, row.KeyInfo = append(row.Keys, k.Name), append(row.KeyInfo, kr)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, docOf(d), nil
}

func (r *Router) serveStoreList(w http.ResponseWriter) {
	rows, d, err := r.StoreList()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"stores": rows, "signed": d})
}

// storeKeys: what a writer seals to — secrets' signed state (the master key, the phone), its signed store key for that
// phone, and its agreement key (the writer checks P + K = the store key)
func (r *Router) storeKeys() (map[string]any, error) {
	state, err := r.k.SecretsDoc("/state", map[string]string{})
	if err != nil {
		return nil, err
	}
	var st struct {
		Master string `json:"master"`
		Phone  *struct {
			AgreementKey string `json:"agreementKey"`
		} `json:"phone"`
	}
	if payloadOf(state, &st) != nil || st.Master == "" || st.Phone == nil || st.Phone.AgreementKey == "" {
		return nil, errors.New("secrets isn't set up (no master key or phone in its signed state)")
	}
	sk, err := r.k.SecretsDoc("/store-key", map[string]string{"phone": st.Phone.AgreementKey})
	if err != nil {
		return nil, err
	}
	id, err := r.k.Identity("secrets")
	if err != nil {
		return nil, err
	}
	return map[string]any{"state": state, "storeKey": sk, "agreementKey": id.AgreementKey}, nil
}

// keyWriteIn: a writer's request (docs/API-grants.md POST /m/stores/{store}/keys/{key})
type keyWriteIn struct {
	Delete  bool `json:"delete"`
	Wrapped *struct {
		E       string `json:"e"`
		Wrapped string `json:"wrapped"`
	} `json:"wrapped"`
	Data         string         `json:"data"`
	Live         *kernel.Sealed `json:"live"`
	BackupSha256 string         `json:"backupSha256"`
	Backup       *struct {
		E    string `json:"e"`
		Data string `json:"data"`
	} `json:"backup"`
	Sig         string `json:"sig"`        // setup: the setup key's signature over secrets.WriterText
	WriterText  string `json:"writerText"` // informational
	Explanation string `json:"explanation"`
}

// backupSha: what WriterText names for a key's backup — sha256 of its sealed parts
func backupSha(e, data string) string {
	h := sha256.Sum256([]byte(e + "\n" + data))
	return hex.EncodeToString(h[:])
}

func wrappedE(in keyWriteIn) string {
	if in.Wrapped == nil {
		return ""
	}
	return in.Wrapped.E
}

func dataSha(data string) string {
	if data == "" {
		return ""
	}
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// WriteKey: one key written by a session's machine (writer "machine"), the setup session (writer "setup") or the
// router itself (writer "router": the Claude login, claudelogin.go). The backup first, then secrets, then `pull` to
// the machines whose grant names the store.
func (r *Router) WriteKey(writer, machine, store, key string, in keyWriteIn) (map[string]any, error) {
	if !storeNameOK(store) || !keyNameRE.MatchString(key) {
		return nil, &badRequest{"store: lower-case letters, digits and -; key: letters, digits and _"}
	}
	// the reserved store never; the deploy-key token store only by the setup session (secrets refuses others there too)
	if store == flyStore || (store == deployKeyTokenStore && writer != "setup") {
		return nil, &forbidden{fmt.Sprintf("store %s isn't written this way", store)}
	}
	expl, err := cleanDoc(in.Explanation)
	if err != nil {
		return nil, &badRequest{err.Error()}
	}
	storeDocsMu.Lock()
	documented := r.readStoreDocs()[store].Keys[key] != ""
	storeDocsMu.Unlock()
	if !in.Delete && expl == "" && !documented {
		return nil, &badRequest{fmt.Sprintf("%s has no explanation yet: say what the key is for (explanation)", key)}
	}
	if writer == "setup" && in.Sig == "" {
		return nil, &badRequest{"sig: the setup key's signature over secrets' WriterText"}
	}
	var sealed any
	if !in.Delete {
		if in.Wrapped == nil || in.Data == "" || in.Live == nil || in.Backup == nil || in.Backup.E == "" || in.Backup.Data == "" {
			return nil, &badRequest{"a write carries wrapped, data, live and its backup (sealed to the master key)"}
		}
		if in.BackupSha256 != backupSha(in.Backup.E, in.Backup.Data) {
			return nil, &badRequest{"backupSha256 isn't the backup's"}
		}
		sealed = in.Backup
	} else if in.BackupSha256 != "" {
		return nil, &badRequest{"a delete has no backup"}
	}
	fwd := map[string]any{"store": store, "key": key, "delete": in.Delete, "data": in.Data, "backupSha256": in.BackupSha256, "writer": writer}
	if in.Wrapped != nil {
		fwd["wrapped"] = in.Wrapped
	}
	if in.Live != nil {
		fwd["live"] = in.Live
	}
	switch writer {
	case "setup":
		fwd["sig"] = in.Sig
	case "machine":
		var ok bool
		r.st.Do(func(d *persisted) {
			s := d.Sessions[d.Machines[machine]]
			ok = s != nil && s.MachineID == machine && s.State == "started"
		})
		if !ok {
			return nil, &forbidden{"only a running session writes a key"}
		}
		fwd["machine"] = machine
	}
	id, err := r.k.Identity("secrets")
	if err != nil {
		return nil, fmt.Errorf("secrets' identity isn't readable: %v", err)
	}
	// the backup first: a key never reaches secrets without one (Deyao: "has backup, so can't overwrite")
	b := backupBucketFromEnv()
	if b == nil {
		return nil, errors.New("the router has no backup credential (BACKUP_READ_ACCESS_KEY): no key is written without its backup")
	}
	ident, _ := json.Marshal(id)
	obj := map[string]any{"kind": "key-backup", "store": store, "key": key, "deleted": in.Delete, "sealed": sealed,
		"backupSha256": in.BackupSha256, "e": wrappedE(in), "dataSha256": dataSha(in.Data),
		"writer": map[string]any{"by": writer, "sig": in.Sig, "machine": machine}, "secrets": json.RawMessage(ident),
		"explanation": expl, "at": time.Now().UTC().Format(time.RFC3339)}
	raw, _ := json.Marshal(obj)
	if err := b.put("keys/"+store+"/"+key+".json", raw); err != nil {
		return nil, fmt.Errorf("the backup wasn't written, so the key wasn't either: %v", err)
	}
	receipt, err := r.k.SecretsDoc("/stores/write-key", fwd)
	if err != nil {
		return nil, err
	}
	if expl != "" {
		if err := r.SetStoreDocs(store, nil, map[string]string{key: expl}); err != nil {
			log.Printf("store %s: the explanation of %s wasn't kept: %v", store, key, err)
		}
	}
	pulled := r.pullHolders(store)
	return map[string]any{"ok": true, "receipt": receipt, "pulled": pulled}, nil
}

// ---- routes -------------------------------------------------------------------------------------------------

func writeWriteErr(w http.ResponseWriter, err error) {
	var ke *KernelError
	if errors.As(err, &ke) {
		writeJSON(w, ke.Status, map[string]string{"error": ke.Msg})
		return
	}
	writeRequestErr(w, err)
}

func (r *Router) registerStoreDocs(app appRoute, m machineRoute, mux *http.ServeMux) {
	app("GET /api/stores", func(w http.ResponseWriter, req *http.Request) { r.serveStoreList(w) })
	app("PUT /api/stores/{store}/docs", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			About *string           `json:"about"`
			Keys  map[string]string `json:"keys"`
		}
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		if err := r.SetStoreDocs(req.PathValue("store"), in.About, in.Keys); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// every session may see every store's names (not only its own): it needs them to know which store to ask for
	m("GET /m/stores", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) { r.serveStoreList(w) })
	m("GET /m/store-keys", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		out, err := r.storeKeys()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	m("POST /m/stores/{store}/keys/{key}", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in keyWriteIn
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		in.Sig = ""
		out, err := r.WriteKey("machine", machine, req.PathValue("store"), req.PathValue("key"), in)
		if err != nil {
			writeWriteErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
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
	setup("GET /setup/store-keys", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		out, err := r.storeKeys()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	setup("POST /setup/stores/{store}/keys/{key}", func(w http.ResponseWriter, req *http.Request, b []byte) {
		var in keyWriteIn
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		out, err := r.WriteKey("setup", "", req.PathValue("store"), req.PathValue("key"), in)
		if err != nil {
			writeWriteErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	setup("POST /setup/store-docs", func(w http.ResponseWriter, req *http.Request, b []byte) {
		var in struct {
			Store string            `json:"store"`
			About *string           `json:"about"`
			Keys  map[string]string `json:"keys"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		if err := r.SetStoreDocs(in.Store, in.About, in.Keys); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
