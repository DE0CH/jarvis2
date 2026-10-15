package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A store still locked after the wait doesn't stop the machine: the pull says so (errStoresLocked) and prepare starts
// the harness without secrets; any other failure still stops it.
func TestALockedStoreIsReportedApartFromOtherPullFailures(t *testing.T) {
	pullTries, pullWait = 2, time.Millisecond
	defer func() { pullTries, pullWait = 300, 2*time.Second }()
	key := newKey()
	for status, locked := range map[int]bool{423: true, 409: false, 500: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"store gmail is locked"}`))
		}))
		c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
		_, err := pullSecrets(c, "core", "m1")
		srv.Close()
		if err == nil || errors.Is(err, errStoresLocked) != locked {
			t.Fatalf("HTTP %d: %v", status, err)
		}
	}
}
