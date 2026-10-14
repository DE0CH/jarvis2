package main

// The app's device-key countersignature on a claim (R1 audit 2026-10-11: claim is first-come, so a router or box
// that claims an emptied secrets with its own master key must not get the setup session's writes). The app sends,
// with POST /api/secrets/claim, deviceKey (its long-lived Secure Enclave key, kept across Reset and Recover) and
// deviceSig over the exact claim statement. Secrets never sees them; the router keeps the last few here and serves
// them to the setup session (GET /setup/claim-device), which checks the signature itself against the device key it
// pinned (infra/setup.py). The router can only withhold one, never make one.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type ClaimDevice struct {
	Statement string `json:"statement"`
	DeviceKey string `json:"deviceKey"`
	DeviceSig string `json:"deviceSig"`
}

var claimDeviceMu sync.Mutex

func (r *Router) claimDevicePath() string { return filepath.Join(r.cfg.DataDir, "claim-device.json") }

func (r *Router) claimDevices() []ClaimDevice {
	claimDeviceMu.Lock()
	defer claimDeviceMu.Unlock()
	out := []ClaimDevice{}
	if b, err := os.ReadFile(r.claimDevicePath()); err == nil {
		json.Unmarshal(b, &out)
	}
	return out
}

// keepClaimDevice: the countersignature in a claim body, if any (the newest 10 kept)
func (r *Router) keepClaimDevice(body []byte) {
	var in ClaimDevice
	if json.Unmarshal(body, &in) != nil || in.Statement == "" || in.DeviceKey == "" || in.DeviceSig == "" ||
		len(in.Statement) > 8<<10 || len(in.DeviceKey) > 200 || len(in.DeviceSig) > 200 {
		return
	}
	list := r.claimDevices()
	claimDeviceMu.Lock()
	defer claimDeviceMu.Unlock()
	list = append([]ClaimDevice{in}, list...)
	if len(list) > 10 {
		list = list[:10]
	}
	b, _ := json.Marshal(list)
	os.WriteFile(r.claimDevicePath(), b, 0o600)
}

// ---- the master's signature on secrets (kept here, not in secrets) -------------------------------------------------
//
// A claim secrets accepted is the master key's signature over a statement naming secrets' keys: it verifies on its
// own, so who stores it doesn't matter. The router keeps the newest few (by secrets' signing key) and serves the
// running secrets' to the setup session (GET /setup/secrets-cert).

type MasterCert struct {
	Statement string `json:"statement"`
	MasterSig string `json:"masterSig"`
}

func (r *Router) secretsCertsPath() string { return filepath.Join(r.cfg.DataDir, "secrets-certs.json") }

// keepSecretsCert: a claim body secrets answered 200
func (r *Router) keepSecretsCert(body []byte) {
	var in MasterCert
	if json.Unmarshal(body, &in) != nil || in.Statement == "" || in.MasterSig == "" || len(in.Statement) > 8<<10 {
		return
	}
	claimDeviceMu.Lock()
	defer claimDeviceMu.Unlock()
	list := []MasterCert{}
	if b, err := os.ReadFile(r.secretsCertsPath()); err == nil {
		json.Unmarshal(b, &list)
	}
	list = append([]MasterCert{in}, list...)
	if len(list) > 10 {
		list = list[:10]
	}
	b, _ := json.Marshal(list)
	os.WriteFile(r.secretsCertsPath(), b, 0o600)
}

// secretsCert: the kept claim naming the running secrets (by its signing key from /identity); nil when none
func (r *Router) secretsCert() []byte {
	id, err := r.k.Identity("secrets")
	if err != nil {
		return nil
	}
	claimDeviceMu.Lock()
	list := []MasterCert{}
	if b, err := os.ReadFile(r.secretsCertsPath()); err == nil {
		json.Unmarshal(b, &list)
	}
	claimDeviceMu.Unlock()
	for _, mc := range list {
		var st struct {
			Core struct {
				SigningKey string `json:"signingKey"`
			} `json:"core"`
		}
		if json.Unmarshal([]byte(mc.Statement), &st) == nil && st.Core.SigningKey == id.SigningKey {
			b, _ := json.Marshal(mc)
			return b
		}
	}
	return nil
}
