package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// a fake Cloudflare API: Access service tokens only, with the scoped token
func fakeCF(t *testing.T) (*httptest.Server, *sync.Map) {
	tokens := &sync.Map{}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer cf-scoped" {
			w.WriteHeader(403)
			w.Write([]byte(`{"success":false,"errors":[{"code":10000}]}`))
			return
		}
		base := "/accounts/" + cfAccount + "/access/service_tokens"
		switch {
		case req.Method == "POST" && req.URL.Path == base:
			var in map[string]string
			json.NewDecoder(req.Body).Decode(&in)
			n++
			id := "tok" + string(rune('0'+n))
			tokens.Store(id, in["name"])
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": id, "client_id": id + ".access", "client_secret": "secret-" + id}})
		case req.Method == "DELETE" && strings.HasPrefix(req.URL.Path, base+"/"):
			id := strings.TrimPrefix(req.URL.Path, base+"/")
			if _, ok := tokens.LoadAndDelete(id); !ok {
				w.WriteHeader(404)
				w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"not found"}]}`))
				return
			}
			w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	old := cfAPIBase
	cfAPIBase = srv.URL
	t.Cleanup(func() { cfAPIBase = old })
	return srv, tokens
}

func TestPairListAdmitRevokeDevices(t *testing.T) {
	_, tokens := fakeCF(t)
	t.Setenv("CF_DEVICE_TOKENS_API", "cf-scoped")
	r := newTestRouter(t)
	r.cfg.AllowedEmail = "chendeyao000@gmail.com"
	h := r.Handler()
	pair := func(app, state string) *url.URL {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/devices/pair?state="+state+"&name=Deyao%27s+iPhone&model=iPhone18,3&app="+app, nil))
		if w.Code != 302 {
			t.Fatalf("pair: %d %s", w.Code, w.Body.String())
		}
		u, _ := url.Parse(w.Header().Get("Location"))
		return u
	}
	u := pair("paseo", "abcdefghijklmnop")
	q := u.Query()
	if u.Scheme != "paseo-de0ch" || u.Host != "paired" || q.Get("state") != "abcdefghijklmnop" || q.Get("clientId") != "tok1.access" ||
		q.Get("clientSecret") != "secret-tok1" || q.Get("id") == "" {
		t.Fatalf("answer %s", u)
	}
	if name, _ := tokens.Load("tok1"); name != "jarvis2-device paseo Deyao's iPhone" {
		t.Fatalf("token name %v", name)
	}
	// a second pairing within 30 s: refused through the scheme, no token minted
	u2 := pair("openclaw", "abcdefghijklmnopq")
	if u2.Scheme != "openclaw-de0ch" || u2.Query().Get("status") != "429" || u2.Query().Get("clientSecret") != "" {
		t.Fatalf("second: %s", u2)
	}
	if _, ok := tokens.Load("tok2"); ok {
		t.Fatal("a token for a refused pairing")
	}
	// bad requests
	for _, target := range []string{"/api/devices/pair?state=short&app=paseo", "/api/devices/pair?state=abcdefghijklmnop&app=jarvis"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 400 {
			t.Fatalf("%s: %d", target, w.Code)
		}
	}
	// the list shows no token ids or secrets
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/devices", nil))
	if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, `"app":"paseo"`) || strings.Contains(b, "tok1") || strings.Contains(b, "secret") {
		t.Fatalf("list: %d %s", w.Code, b)
	}
	// who /api/remotes admits: Deyao, a paired device's token, nobody else
	now := time.Now()
	if !r.admitClaims(&accessClaims{Email: "ChenDeyao000@gmail.com"}, now) || r.admitClaims(&accessClaims{Email: "x@y.z"}, now) ||
		!r.admitClaims(&accessClaims{CommonName: "tok1.access"}, now) || r.admitClaims(&accessClaims{CommonName: "other.access"}, now) ||
		r.admitClaims(&accessClaims{}, now) {
		t.Fatal("admit")
	}
	// revoke: the token goes at Cloudflare, the device from the list, and its token is no longer admitted
	id := q.Get("id")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/devices/"+id, nil))
	if w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if _, ok := tokens.Load("tok1"); ok || r.admitClaims(&accessClaims{CommonName: "tok1.access"}, now) {
		t.Fatal("revoked token still there")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/devices/"+id, nil))
	if w.Code != 200 {
		t.Fatalf("revoke twice: %d", w.Code)
	}
	// Start of a session that doesn't exist
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/sessions/snope/start", nil))
	if w.Code == 202 {
		t.Fatalf("start of nothing: %d", w.Code)
	}
}

func TestPairWithoutCloudflareToken(t *testing.T) {
	t.Setenv("CF_DEVICE_TOKENS_API", "")
	r := newTestRouter(t)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/devices/pair?state=abcdefghijklmnop&app=openclaw", nil))
	u, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || !strings.Contains(u.Query().Get("error"), "CF_DEVICE_TOKENS_API") || u.Query().Get("status") != "500" {
		b, _ := io.ReadAll(w.Body)
		t.Fatalf("%d %s %s", w.Code, u, b)
	}
}
