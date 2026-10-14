package main

// Helpers for the feature tests that don't need the kernel: a session put straight into the state, and a machine whose
// key the router knows (as its spawn cert would name it), signing its requests as the guard does.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// addSession: a session in a state, on a machine ("" = none); sensitive is kept for the old call sites (no meaning now)
func addSession(r *Router, id, state, machine string, _ bool) {
	r.st.Do(func(d *persisted) {
		s := &Session{ID: id, State: state, MachineID: machine, Label: "label " + id, Harness: "claude", Chain: &Chain{Steps: []ChainStep{}}}
		if machine != "" {
			s.Chain.Machine = &kernel.Object{ID: machine}
			d.Machines[machine] = id
		}
		d.Sessions[id] = s
	})
}

func signP256(k *ecdh.PrivateKey, payload []byte) (string, error) {
	e, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), k.Bytes())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(payload)
	s, err := ecdsa.SignASN1(rand.Reader, e, h[:])
	return base64.StdEncoding.EncodeToString(s), err
}

type testMachine struct {
	id  string
	key *ecdh.PrivateKey
}

func newTestMachine(r *Router, id string) testMachine {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	r.st.Do(func(d *persisted) {
		d.Started[id] = &Started{ID: id, SigningKey: base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())}
	})
	return testMachine{id, k}
}

// do: a request to the machines' listener, signed as the machine signs it (decoded path, no query)
func (m testMachine) do(t *testing.T, h http.Handler, method, target, body string) (int, map[string]any) {
	t.Helper()
	return m.doH(t, h, method, target, body, nil)
}

func (m testMachine) doH(t *testing.T, h http.Handler, method, target, body string, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256([]byte(body))
	sig, _ := signP256(m.key, []byte(method+" "+req.URL.Path+" "+ts+" "+hex.EncodeToString(sum[:])))
	req.Header.Set("X-Machine", m.id)
	req.Header.Set("X-Time", ts)
	req.Header.Set("X-Sig", sig)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// holdStores: the session's machine holds a grant naming these stores (a document the router keeps; nothing checks
// its signature in these tests)
func holdStores(r *Router, sid string, extra ...string) {
	g := kernel.Grant{Kind: "grant", By: "mover", Allowed: kernel.Only(extra...), Conditions: kernel.Conditions{}, From: []string{}}
	b, _ := json.Marshal(g)
	id := r.docs.Put(kernel.SignedDoc{Payload: string(b), Sig: "test"})
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Chain != nil {
			s.Chain.Main, s.Chain.Held = id, id
		}
	})
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func appDo(t *testing.T, r *Router, method, target, body string, hdr ...string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }
