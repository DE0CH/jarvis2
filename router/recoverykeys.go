package main

// The backup bucket's read keys on their way to the iPhone (docs/DESIGN.md "Recovery", docs/API.md
// "Recovery kit"). The setup session seals them to the master public key and signs the document with the
// setup key (infra/setup.py recovery-keys); the router only keeps the blob on its volume and hands it to the
// app, which checks the setup key's signature (keys/setup.pub from GitHub) and opens it with the master key.
// The router can't read the keys and can't change them unnoticed: at most it can withhold the blob or serve
// an older one (the app then finds the keys don't read the bucket).

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// RecoveryKeys is the stored blob, exactly as the setup session sent it: doc = the JSON text
// {"kind":"recovery-keys","bucket","credential","sealed":{e,data},"at"}, sig = the setup key's ECDSA over doc
type RecoveryKeys struct {
	Doc string `json:"doc"`
	Sig string `json:"sig"`
}

func (r *Router) recoveryKeysPath() string { return filepath.Join(r.cfg.DataDir, "recovery-keys.json") }

// checkRecoveryKeys: a well-formed document of the right kind, signed by the setup key (when the router has
// one: CI without a setup key skips the signature, as checkSetupSig does)
func (r *Router) checkRecoveryKeys(k RecoveryKeys) error {
	var d struct {
		Kind   string            `json:"kind"`
		Sealed map[string]string `json:"sealed"`
	}
	if json.Unmarshal([]byte(k.Doc), &d) != nil || d.Kind != "recovery-keys" || d.Sealed["e"] == "" || d.Sealed["data"] == "" {
		return errors.New("not a recovery-keys document")
	}
	if r.cfg.SetupKey != "" && !verifyP256(r.cfg.SetupKey, []byte(k.Doc), k.Sig) {
		return errors.New("the document isn't signed by the setup key")
	}
	if r.cfg.SetupKey == "" && !(r.cfg.NoAccess) {
		return errors.New("no setup key configured")
	}
	return nil
}

func (r *Router) SaveRecoveryKeys(k RecoveryKeys) error {
	if err := r.checkRecoveryKeys(k); err != nil {
		return err
	}
	b, _ := json.Marshal(k)
	tmp := r.recoveryKeysPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.recoveryKeysPath())
}

// LoadRecoveryKeys: nil when the setup session hasn't sent any
func (r *Router) LoadRecoveryKeys() *RecoveryKeys {
	b, err := os.ReadFile(r.recoveryKeysPath())
	if err != nil {
		return nil
	}
	var k RecoveryKeys
	if json.Unmarshal(b, &k) != nil || k.Doc == "" {
		return nil
	}
	return &k
}

func (r *Router) registerRecoveryKeys(app func(string, http.HandlerFunc), handle func(string, http.Handler)) {
	signedSetup := func(fn func(w http.ResponseWriter, req *http.Request, body []byte)) http.Handler {
		return r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 64<<10))
			var sigBody []byte
			if req.Method != "GET" {
				sigBody = b
			}
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), sigBody); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		})
	}
	serve := func(w http.ResponseWriter) {
		k := r.LoadRecoveryKeys()
		if k == nil {
			writeJSON(w, 404, map[string]any{"error": "no recovery keys yet", "missing": true})
			return
		}
		writeJSON(w, 200, k)
	}
	handle("POST /setup/recovery-keys", signedSetup(func(w http.ResponseWriter, req *http.Request, body []byte) {
		var k RecoveryKeys
		if err := json.Unmarshal(body, &k); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad body"})
			return
		}
		if err := r.SaveRecoveryKeys(k); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	handle("GET /setup/recovery-keys", signedSetup(func(w http.ResponseWriter, req *http.Request, _ []byte) { serve(w) }))
	app("GET /api/recovery-keys", func(w http.ResponseWriter, req *http.Request) { serve(w) })
}
