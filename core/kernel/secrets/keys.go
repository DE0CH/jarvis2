package secrets

// A store is a set of keys, each sealed on its own (carried over from core/keys.go). Each key's value is under its own
// data key (the store's and the key's names as associated data), and that data key is wrapped to the combined key
// P + K (phone + secrets) — the public store key, so anyone can write a key and nobody but the phone and secrets
// together can read one. Writing a key replaces that key only.
//
// write_key is open: writing secrets is protected only by the router (DESIGN "Layers"); secrets checks no writer. It
// records who the writer says it is, which unlock_begin shows the phone before it gives its share:
//   - setup: with the setup key's signature over WriterText, passed on (the phone checks it against keys/setup.pub);
//   - router / machine: the router's word (a machine id for a session's write), recorded as given;
//   - core: secrets' own (a Recover's bundle, a deploy key).
//
// Any written key is served on the next pull, whoever wrote it (DESIGN "Secrets"): a write carries the value a second
// time, sealed to secrets' own agreement key (live). If the store is unlocked, secrets opens it and replaces that key
// in the unlocked values; otherwise it drops it (the next unlock opens the wrapped key). It never stores live.

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// KeyEntry: one key of a store
type KeyEntry struct {
	Store   string     `json:"store"`
	Key     string     `json:"key"`
	Wrapped WrappedKey `json:"wrapped"` // the data key, to phone + secrets
	Data    string     `json:"data"`    // AES-GCM(value) under the data key, KeyAAD(store, key) as associated data
	// set by secrets from the write, never taken from a bundle
	Writer       *EntryWriter `json:"writer,omitempty"`
	At           string       `json:"at,omitempty"`
	BackupSha256 string       `json:"backupSha256,omitempty"`
}

// EntryWriter: who wrote a key (see the file comment)
type EntryWriter struct {
	By      string `json:"by"`                // "setup" | "router" | "machine" | "core"
	Sig     string `json:"sig,omitempty"`     // setup: its signature over WriterText (the phone checks it)
	Machine string `json:"machine,omitempty"` // machine: the session machine, as the router says
}

// KeyAAD: a key's value is bound to its store and its name
func KeyAAD(store, key string) []byte { return []byte(store + "\n" + key) }

// WriterText: what a setup writer signs — the store, the key, its E and the sha256 of its data ("" and "" for a
// delete), and the sha256 of the key's backup ("" when it has none)
func WriterText(store, key, e, data, backupSha256 string) string {
	sum := ""
	if data != "" {
		sum = kernel.SHA256Hex(data)
	}
	return "jarvis2-store-key\n" + store + "\n" + key + "\n" + e + "\n" + sum + "\n" + backupSha256
}

// LiveInfo: what a write's live copy is sealed under (to secrets' agreement key): bound to the store and the key
func LiveInfo(store, key string) string { return "jarvis2/live-key\n" + store + "\n" + key }

var (
	keyNameRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	machineIDRE = regexp.MustCompile(`^[0-9a-z]{1,32}$`)
	hex64RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// storeVersion: one store's contents as a hash (each key's name, E and data hash)
func storeVersion(keys map[string]*KeyEntry) string {
	h := sha256.New()
	for _, k := range sortedKeys(keys) {
		h.Write([]byte(k + "\t" + keys[k].Wrapped.E + "\t" + kernel.SHA256Hex(keys[k].Data) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// validEntry: a key as a writer or a bundle brings it (callers set Writer and At)
func validEntry(x *KeyEntry, store string) bool {
	return x != nil && x.Store == store && keyNameRE.MatchString(x.Key) && x.Wrapped.E != "" && x.Wrapped.Wrapped != "" && x.Data != ""
}

// WriteKeyInput: write_key's input. Delete: the key goes (no wrapped/data/live). Writer "setup" brings Sig; "machine"
// brings Machine; "router" neither.
type WriteKeyInput struct {
	Store        string         `json:"store"`
	Key          string         `json:"key"`
	Delete       bool           `json:"delete"`
	Wrapped      WrappedKey     `json:"wrapped"`
	Data         string         `json:"data"`
	Live         *kernel.Sealed `json:"live"`
	BackupSha256 string         `json:"backupSha256"`
	Writer       string         `json:"writer"`
	Sig          string         `json:"sig"`
	Machine      string         `json:"machine"`
}

// WriteKey: one key written (or deleted). The first key of a store that doesn't exist makes it (sensitive, as every
// store create_store didn't make). The deploy-key stores take only setup writes (their keys otherwise come from a
// phone-approved deploy-key call); the core store is never written.
func (c *Secrets) WriteKey(in WriteKeyInput) (kernel.SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return kernel.SignedDoc{}, kernel.Fail(409, "secrets isn't set up yet")
	}
	keys, exists := c.stores[in.Store]
	if !storeName(in.Store) || in.Store == ReservedStore {
		return kernel.SignedDoc{}, kernel.Fail(400, "store: %q isn't one a key is written to", in.Store)
	}
	if !keyNameRE.MatchString(in.Key) {
		return kernel.SignedDoc{}, kernel.Fail(400, "key: letters, digits and _, not starting with a digit")
	}
	if in.BackupSha256 != "" && !hex64RE.MatchString(in.BackupSha256) {
		return kernel.SignedDoc{}, kernel.Fail(400, "backupSha256: hex sha256")
	}
	e, live := "", ""
	if in.Delete {
		if _, ok := keys[in.Key]; !ok {
			return kernel.SignedDoc{}, kernel.Fail(404, "store %s has no key %s", in.Store, in.Key)
		}
		in.Wrapped, in.Data = WrappedKey{}, ""
	} else {
		x := &KeyEntry{Store: in.Store, Key: in.Key, Wrapped: in.Wrapped, Data: in.Data}
		if !validEntry(x, in.Store) {
			return kernel.SignedDoc{}, kernel.Fail(400, "not a sealed key: wrapped {e, wrapped} and data")
		}
		if in.Live == nil {
			return kernel.SignedDoc{}, kernel.Fail(400, "live: the value sealed to secrets' agreement key (served on the next pull)")
		}
		v, err := kernel.OpenSealed(c.agreement, *in.Live, LiveInfo(in.Store, in.Key))
		if err != nil {
			return kernel.SignedDoc{}, kernel.Fail(400, "live isn't sealed to secrets for %s/%s", in.Store, in.Key)
		}
		e, live = in.Wrapped.E, string(v)
	}
	var w EntryWriter
	switch in.Writer {
	case "setup":
		if in.Sig == "" {
			return kernel.SignedDoc{}, kernel.Fail(400, "a setup write carries the setup key's signature")
		}
		w = EntryWriter{By: "setup", Sig: in.Sig}
	case "router":
		w = EntryWriter{By: "router"}
	case "machine":
		if !machineIDRE.MatchString(in.Machine) {
			return kernel.SignedDoc{}, kernel.Fail(400, "machine: a Fly machine id")
		}
		w = EntryWriter{By: "machine", Machine: in.Machine}
	default:
		return kernel.SignedDoc{}, kernel.Fail(400, "writer: setup, router or machine")
	}
	if w.By != "setup" && (in.Store == DeployKeyTokenStore || c.repoOwner[in.Store] != "") {
		return kernel.SignedDoc{}, kernel.Fail(403, "store %s's keys come only from a phone-approved deploy-key call", in.Store)
	}
	now := c.now().UTC().Format(time.RFC3339)
	if !exists {
		keys = map[string]*KeyEntry{}
		c.stores[in.Store] = keys
	}
	if in.Delete {
		delete(keys, in.Key)
	} else {
		keys[in.Key] = &KeyEntry{Store: in.Store, Key: in.Key, Wrapped: in.Wrapped, Data: in.Data, Writer: &w, At: now, BackupSha256: in.BackupSha256}
	}
	if u := c.unlocked[in.Store]; u != nil { // served on the next pull
		if in.Delete {
			delete(u.values, in.Key)
		} else {
			u.values[in.Key] = live
		}
	}
	if in.Delete {
		c.noteWritten(in.Store, in.Key, nil)
	} else {
		c.noteWritten(in.Store, in.Key, &live)
	}
	c.record(in.Store, VersionCause{Kind: map[bool]string{true: "delete", false: "write"}[in.Delete], Key: in.Key, Writer: &w})
	c.logf("store %s: key %s %s by %s %s", in.Store, in.Key, map[bool]string{true: "deleted", false: "written"}[in.Delete], w.By, w.Machine)
	sum := ""
	if in.Data != "" {
		sum = kernel.SHA256Hex(in.Data)
	}
	return kernel.Sign(c.signer, map[string]any{"kind": "key-written", "store": in.Store, "key": in.Key, "deleted": in.Delete, "e": e,
		"dataSha256": sum, "backupSha256": in.BackupSha256, "writer": w, "at": now,
		"sensitive": !c.notSensitive[in.Store], "version": storeVersion(keys), "live": c.unlocked[in.Store] != nil})
}

// keyRows: a store's keys as the signed store list shows them (names and writers, never values)
type keyRow struct {
	Name   string       `json:"name"`
	At     string       `json:"at"`
	Writer *EntryWriter `json:"writer"`
}

func keyRows(keys map[string]*KeyEntry) []keyRow {
	out := make([]keyRow, 0, len(keys))
	for _, k := range sortedKeys(keys) {
		w := keys[k].Writer
		if w != nil && w.By == "setup" {
			w = &EntryWriter{By: "setup"} // the list doesn't carry signatures (unlock_begin does)
		}
		out = append(out, keyRow{k, keys[k].At, w})
	}
	return out
}

// openEntry: one key's value, with the phone's share x(p·E) and secrets' k
func (c *Secrets) openEntry(x *KeyEntry, phoneShareX []byte) (string, error) {
	dk, err := UnwrapWithShares(x.Wrapped, phoneShareX, c.agreement)
	if err != nil {
		return "", err
	}
	data, _ := b64.DecodeString(x.Data)
	plain, err := kernel.GCMOpen(dk, data, KeyAAD(x.Store, x.Key))
	if err != nil {
		return "", kernel.Fail(403, "key %s of %s doesn't decrypt (a wrong or altered entry)", x.Key, x.Store)
	}
	return string(plain), nil
}

// entryWriter: unlock_begin's writer field for a key
func entryWriter(x *KeyEntry) *EntryWriter {
	if x.Writer == nil {
		return &EntryWriter{By: "core"}
	}
	return x.Writer
}

// copyEntries: a snapshot of a store's keys (an unlock opens exactly what it began with)
func copyEntries(keys map[string]*KeyEntry) map[string]KeyEntry {
	out := make(map[string]KeyEntry, len(keys))
	for k, x := range keys {
		out[k] = *x
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
