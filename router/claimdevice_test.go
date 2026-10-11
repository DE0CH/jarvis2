package main

import "testing"

func TestTheClaimsDeviceSignatureIsKeptForTheSetupSession(t *testing.T) {
	r := &Router{cfg: Config{DataDir: t.TempDir()}}
	r.keepClaimDevice([]byte(`{"statement":"{\"kind\":\"claim\"}","masterSig":"m","deviceKey":"k","deviceSig":"s"}`))
	r.keepClaimDevice([]byte(`{"statement":"x"}`)) // no countersignature: nothing kept
	got := r.claimDevices()
	if len(got) != 1 || got[0].DeviceKey != "k" || got[0].Statement != `{"kind":"claim"}` {
		t.Fatalf("got %v", got)
	}
}
