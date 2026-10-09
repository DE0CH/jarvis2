package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type tkey struct{ k *ecdh.PrivateKey }

func newKey() tkey         { k, _ := ecdh.P256().GenerateKey(rand.Reader); return tkey{k} }
func (t tkey) pub() string { return b64.EncodeToString(t.k.PublicKey().Bytes()) }
func (t tkey) doc(v any) *SignedDoc {
	b, _ := json.Marshal(v)
	s, _ := sign(t.k, b)
	return &SignedDoc{string(b), s}
}
func (t tkey) req(r ExecRequest) Exec {
	b, _ := json.Marshal(r)
	s, _ := sign(t.k, b)
	return Exec{Request: string(b), Sig: s}
}

func TestGrants(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	phone, holder, other := newKey(), newKey(), newKey()
	cert := Cert{Phone: phone.pub(), Line: "m1"}
	currentCert = func() (Cert, error) { return cert, nil }
	now := time.Now()
	n := 0
	req := func(k tkey, session string) Exec {
		n++
		return k.req(ExecRequest{ID: string(rune('a' + n)), Session: session, Holder: holder.pub(), Cmd: "true", Timeout: 5, At: now.Unix()})
	}
	grant := func(kind string, d time.Duration) *SignedDoc {
		g := Grant{Kind: kind, Holder: holder.pub(), Session: "m1", Scope: "shell", Issued: now.UTC().Format(time.RFC3339)}
		if kind == "grant" {
			g.Expires = now.Add(d).UTC().Format(time.RFC3339)
		} else {
			g.Until = now.Add(d).UTC().Format(time.RFC3339)
		}
		return phone.doc(g)
	}
	ok := func(name string, e Exec, want bool) {
		t.Helper()
		_, err := authorise(e, now)
		if (err == nil) != want {
			t.Fatalf("%s: err=%v, want allowed=%v", name, err, want)
		}
	}
	e := req(holder, "m1")
	ok("no grant, no allow list", e, false)
	e = req(holder, "m1")
	e.Grant = grant("grant", 10*time.Minute)
	ok("phone grant", e, true)
	ok("the same request again", e, false)
	e = req(holder, "m1")
	e.Grant = grant("grant", 20*time.Minute)
	ok("grant over 10 minutes", e, false)
	e = req(holder, "m1")
	e.Grant = grant("grant", -time.Minute)
	ok("expired grant", e, false)
	e = req(holder, "m2")
	e.Grant = grant("grant", 5*time.Minute)
	ok("another line", e, false)
	e = req(other, "m1") // signed by a key other than the holder it names
	e.Grant = grant("grant", 5*time.Minute)
	ok("not the holder's signature", e, false)
	e = req(holder, "m1")
	e.Grant = other.doc(Grant{Kind: "grant", Holder: holder.pub(), Session: "m1", Scope: "shell", Issued: now.UTC().Format(time.RFC3339), Expires: now.Add(time.Minute).UTC().Format(time.RFC3339)})
	ok("grant not signed by the phone", e, false)
	e = req(holder, "m1")
	e.Grant = grant("rule", 30*24*time.Hour)
	ok("standing rule", e, true)
	home, _ := os.UserHomeDir()
	b, _ := json.Marshal([]allowEntry{{Holder: holder.pub(), Name: "scheduler", Until: now.Add(time.Hour).UTC().Format(time.RFC3339)}})
	os.WriteFile(filepath.Join(home, allowFile), b, 0o600)
	ok("own allow list", req(holder, "m1"), true)

	cert.Sensitive = true
	ok("allow list on a sensitive session", req(holder, "m1"), false)
	e = req(holder, "m1")
	e.Grant = grant("rule", time.Hour)
	ok("rule on a sensitive session", e, false)
	e = req(holder, "m1")
	e.Grant = grant("grant", 5*time.Minute)
	ok("phone grant on a sensitive session", e, true)
}
