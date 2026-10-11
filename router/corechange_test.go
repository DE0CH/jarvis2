package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// swapCore: a core whose identity can change (a restart: a new key)
type swapCore struct {
	mu sync.Mutex
	fc *fakeCore
}

func (s *swapCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	fc := s.fc
	s.mu.Unlock()
	fc.ServeHTTP(w, req)
}

func TestANewCoreDestroysTheEarlierCoresPausedSessions(t *testing.T) {
	t.Setenv("RECORDS_OFF", "1")
	r := newTestRouter(t)
	sc := &swapCore{fc: &fakeCore{key: newTestKey()}}
	srv := httptest.NewServer(sc)
	t.Cleanup(srv.Close)
	r.core = &CoreClient{base: srv.URL, http: http.DefaultClient}
	addSession(r, "s1", "paused", "", false)
	addSession(r, "s2", "started", "m2", false)
	r.saveCarry("m1", "blob")
	r.st.Do(func(d *persisted) { d.Machines["m1"] = "s1" })

	r.coreChangeTick() // first sight: these are the running core's
	r.coreChangeTick()
	if n := sessions(r); n != 2 {
		t.Fatalf("the same core destroyed sessions: %d left", n)
	}

	sc.mu.Lock()
	sc.fc = &fakeCore{key: newTestKey()} // a restart: a new core
	sc.mu.Unlock()
	r.coreChangeTick()
	waitFor(t, "s1 destroyed", func() bool { return sessions(r) == 1 })
	if r.readCarry("m1") != "" {
		t.Fatal("the carried secrets outlived the session")
	}
	var rec bool
	r.st.Do(func(d *persisted) { rec = len(d.Records) == 1 && d.Records[0].ID == "s1"; _ = d })
	if !rec {
		t.Fatal("no record in Previous")
	}
	// the running one goes once it is paused; a session the new core certified stays
	addSession(r, "s3", "paused", "", false)
	r.coreChangeTick()
	r.st.Do(func(d *persisted) { d.Sessions["s2"].State = "paused" })
	r.coreChangeTick()
	waitFor(t, "s2 destroyed", func() bool { return sessions(r) == 1 })
	r.st.Do(func(d *persisted) {
		if d.Sessions["s3"] == nil {
			t.Fatal("the new core's own session was destroyed")
		}
	})

	// an unreachable or unsigned identity decides nothing
	sc.mu.Lock()
	sc.fc = &fakeCore{key: key{}}
	sc.mu.Unlock()
	srv.Close()
	r.coreChangeTick()
	if sessions(r) != 1 {
		t.Fatal("an unreachable core destroyed a session")
	}
}

func sessions(r *Router) int {
	n := 0
	r.st.Do(func(d *persisted) { n = len(d.Sessions) })
	return n
}
