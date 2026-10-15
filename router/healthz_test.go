package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /healthz refuses without the probe's Access service token (no audience configured = 503, never open)
func TestHealthzNeedsItsAccessApp(t *testing.T) {
	r := &Router{cfg: Config{}}
	mux := http.NewServeMux()
	r.registerHealthz(mux.Handle)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 503 {
		t.Fatalf("no ACCESS_HEALTH_AUD: want 503, got %d %s", rec.Code, rec.Body)
	}
	t.Setenv("ACCESS_HEALTH_AUD", "aud")
	t.Setenv("HEALTH_CLIENT_ID", "id.access")
	mux = http.NewServeMux()
	r.registerHealthz(mux.Handle)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 403 {
		t.Fatalf("no Access JWT: want 403, got %d %s", rec.Code, rec.Body)
	}
}
