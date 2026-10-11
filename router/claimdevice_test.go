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

// R1 audit: an approval for the current CI build carries CI's signature; one for any other image carries none
func TestOnlyTheCIBuildCarriesItsSignature(t *testing.T) {
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &Router{cfg: Config{SessionImage: "ghcr.io/de0ch/jarvis2-session:sha-1@sha256:aa", SessionImageSig: "c2ln"}, st: st}
	ch := func(img string) *Doc { return &Doc{Payload: `{"kind":"challenge","request":{"image":"` + img + `"}}`} }
	a := &Approval{Challenge: ch("ghcr.io/de0ch/jarvis2-session:sha-1@sha256:aa"), Origin: &Origin{}}
	r.addApproval(a)
	b := &Approval{Challenge: ch("ghcr.io/de0ch/jarvis2-session:x@sha256:bb"), Origin: &Origin{}}
	r.addApproval(b)
	if a.ImageSig != "c2ln" || b.ImageSig != "" {
		t.Fatalf("got %q and %q", a.ImageSig, b.ImageSig)
	}
}
