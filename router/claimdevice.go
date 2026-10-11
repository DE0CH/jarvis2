package main

// The app's device-key countersignature on a claim (R1 audit 2026-10-11: claim is first-come, so a router or box
// that claims an emptied core with its own master key must not get the setup session's writes). The app sends,
// with POST /api/core/claim, deviceKey (its long-lived Secure Enclave key, kept across Reset and Recover) and
// deviceSig over the exact claim statement. The core ignores both; the router keeps the last few here and serves
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
