package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func p256Key(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := k.PublicKey.ECDH()
	return k, base64.StdEncoding.EncodeToString(pk.Bytes())
}

func sign(t *testing.T, k *ecdsa.PrivateKey, msg []byte) string {
	t.Helper()
	sum := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestRecoveryKeysStoredAndServed(t *testing.T) {
	setup, setupPub := p256Key(t)
	other, _ := p256Key(t)
	st, err := LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := NewRouter(Config{NoAccess: true, DataDir: st.dir, WebDir: t.TempDir(), SetupKey: setupPub}, st, nil, Policy{})
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	call := func(method, path string, body []byte, key *ecdsa.PrivateKey) (int, map[string]any) {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sum := sha256.Sum256(body)
		if key != nil {
			req.Header.Set("X-Setup-Time", ts)
			req.Header.Set("X-Setup-Sig", sign(t, key, []byte(fmt.Sprintf("%s %s %s %s", method, path, ts, hex.EncodeToString(sum[:])))))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	if s, b := call("GET", "/api/recovery-keys", nil, nil); s != 404 || b["missing"] != true {
		t.Fatalf("before any: %d %v", s, b)
	}
	doc := `{"kind":"recovery-keys","bucket":"b","credential":"c","sealed":{"e":"AAAA","data":"BBBB"},"at":1}`
	good, _ := json.Marshal(RecoveryKeys{Doc: doc, Sig: sign(t, setup, []byte(doc))})

	// the setup call itself must be signed by the setup key
	if s, _ := call("POST", "/setup/recovery-keys", good, nil); s != 401 {
		t.Fatalf("unsigned setup call: %d", s)
	}
	if s, _ := call("POST", "/setup/recovery-keys", good, other); s != 401 {
		t.Fatalf("setup call signed by another key: %d", s)
	}
	// the document must be signed by the setup key too
	forged, _ := json.Marshal(RecoveryKeys{Doc: doc, Sig: sign(t, other, []byte(doc))})
	if s, _ := call("POST", "/setup/recovery-keys", forged, setup); s != 400 {
		t.Fatalf("document signed by another key: %d", s)
	}
	wrongKind := `{"kind":"store-backup","sealed":{"e":"AAAA","data":"BBBB"}}`
	wk, _ := json.Marshal(RecoveryKeys{Doc: wrongKind, Sig: sign(t, setup, []byte(wrongKind))})
	if s, _ := call("POST", "/setup/recovery-keys", wk, setup); s != 400 {
		t.Fatalf("another kind of document: %d", s)
	}
	if s, b := call("POST", "/setup/recovery-keys", good, setup); s != 200 || b["ok"] != true {
		t.Fatalf("store: %d %v", s, b)
	}
	// the app gets exactly what was sent
	s, b := call("GET", "/api/recovery-keys", nil, nil)
	if s != 200 || b["doc"] != doc || !verifyP256(setupPub, []byte(b["doc"].(string)), b["sig"].(string)) {
		t.Fatalf("served: %d %v", s, b)
	}
	if s, b := call("GET", "/setup/recovery-keys", nil, setup); s != 200 || b["doc"] != doc {
		t.Fatalf("setup read-back: %d %v", s, b)
	}
	// kept across a router restart (the volume)
	r2 := NewRouter(Config{NoAccess: true, DataDir: st.dir, WebDir: t.TempDir(), SetupKey: setupPub}, st, nil, Policy{})
	if k := r2.LoadRecoveryKeys(); k == nil || k.Doc != doc {
		t.Fatalf("after restart: %v", k)
	}
}
