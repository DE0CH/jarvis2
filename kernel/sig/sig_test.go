package sig

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSignVerifyOpen(t *testing.T) {
	s, _ := NewSigner()
	d, err := s.SignJSON(map[string]string{"kind": "x"})
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Kind string `json:"kind"`
	}
	if err := d.Open(s.PublicKey(), &v); err != nil || v.Kind != "x" {
		t.Fatal(err, v)
	}
	var w struct{}
	if d.Open(s.PublicKey(), &w) == nil {
		t.Fatal("an unknown field was accepted")
	}
	o, _ := NewSigner()
	if d.Open(o.PublicKey(), &v) == nil {
		t.Fatal("another key's signature was accepted")
	}
	d.Payload = `{"kind":"y"}`
	if d.Open(s.PublicKey(), &v) == nil {
		t.Fatal("a changed payload was accepted")
	}
}

func TestSealOpen(t *testing.T) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, err := SealTo(B64.EncodeToString(k.PublicKey().Bytes()), []byte("v"), "i")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := OpenSealed(k, s, "i"); err != nil || string(b) != "v" {
		t.Fatal(err)
	}
	if _, err := OpenSealed(k, s, "other"); err == nil {
		t.Fatal("opened under another info")
	}
}

func TestIdentity(t *testing.T) {
	box, _ := NewSigner()
	c, err := NewComponent("notary", box)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckIdentity(c.Identity, "notary", box.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if CheckIdentity(c.Identity, "spawner", box.PublicKey()) == nil {
		t.Fatal("one role's identity passed as another's")
	}
	other, _ := NewSigner()
	if CheckIdentity(c.Identity, "notary", other.PublicKey()) == nil {
		t.Fatal("another box key")
	}
}
