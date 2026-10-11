package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A grant the phone signs for a feature the machine turned away is used at the next tick: the back-off from the
// refusal and the callout go (2026-10-11: the 10-minute back-off outlasted a 10-minute grant, so "Allow" looked
// like it did nothing)
func TestAddGrantClearsTheRefusalBackoff(t *testing.T) {
	r := newTestRouter(t)
	phone, _ := ecdh.P256().GenerateKey(rand.Reader)
	phonePub := base64.StdEncoding.EncodeToString(phone.PublicKey().Bytes())
	cert, _ := json.Marshal(map[string]any{"line": "LsA", "phone": phonePub})
	r.st.Do(func(d *persisted) {
		d.Sessions["sA"] = &Session{ID: "sA", State: "started", MachineID: "mA", Harness: "claude", Cert: &Doc{Payload: string(cert)}}
		d.Machines["mA"] = "sA"
	})
	r.st.Do(func(d *persisted) { d.Sessions["sA"].Live = &Liveness{} })
	r.noteRefusal("sA", "login", errors.New("the machine refused or failed: no grant"))
	now := time.Now()
	r.st.Do(func(d *persisted) {
		if l := d.Sessions["sA"].Live; l.NeedsGrant != "login" || l.mayExec("login", now) {
			t.Fatalf("the refusal isn't recorded: %+v", l)
		}
	})
	pub, err := r.HolderPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	text, _ := json.Marshal(map[string]any{"kind": "grant", "holder": pub["login"], "session": "LsA", "scope": "shell",
		"issued": now.UTC().Format(time.RFC3339), "expires": now.Add(10 * time.Minute).UTC().Format(time.RFC3339)})
	sig, _ := signP256(phone, text)
	if _, err := r.AddGrant("sA", &Doc{Payload: string(text), Sig: sig}); err != nil {
		t.Fatal(err)
	}
	r.st.Do(func(d *persisted) {
		if l := d.Sessions["sA"].Live; l.NeedsGrant != "" || !l.mayExec("login", now) {
			t.Fatalf("the grant left the back-off in place: %+v", l)
		}
	})
}
