package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// splitCore: a core whose start is one Fly create and whose init and kill answer 409 until Fly is ready (R2); with
// old=true it answers like the core from before R2 (start waits and returns "started", kill waits)
type splitCore struct {
	key              key
	old              bool
	initWait, killWt int
	initFail         bool
	limit            int // /start answers Fly's machine-limit refusal this many times first
	mu               sync.Mutex
	calls            []string
	bodies           map[string]map[string]any
}

func (c *splitCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var b map[string]any
	json.NewDecoder(req.Body).Decode(&b)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, req.URL.Path)
	c.bodies[req.URL.Path] = b
	started := map[string]any{"kind": "started", "machine": map[string]string{"id": "m7", "requested": "img", "image": "img"}}
	switch req.URL.Path {
	case "/start":
		if c.limit > 0 {
			c.limit--
			writeJSON(w, 502, c.key.doc(map[string]string{"kind": "error", "error": "fly create: 422 Your organization has reached its machine limit. Please contact billing@fly.io"}))
			return
		}
		if c.old {
			writeJSON(w, 200, c.key.doc(started))
			return
		}
		writeJSON(w, 200, c.key.doc(map[string]string{"kind": "created", "id": "m7", "image": "img"}))
	case "/init":
		if c.initFail {
			writeJSON(w, 409, c.key.doc(map[string]string{"kind": "error", "error": "machine m7 isn't one this core created and hasn't initialised"}))
			return
		}
		if c.initWait > 0 {
			c.initWait--
			writeJSON(w, 409, c.key.doc(map[string]string{"kind": "error", "error": "machine m7 is starting, not started"}))
			return
		}
		writeJSON(w, 200, c.key.doc(started))
	case "/kill":
		if c.killWt > 0 {
			c.killWt--
			writeJSON(w, 409, c.key.doc(map[string]string{"kind": "error", "error": "machine m7 is destroying, not destroyed yet"}))
			return
		}
		writeJSON(w, 200, c.key.doc(map[string]string{"kind": "killed", "id": "m7"}))
	default:
		writeJSON(w, 404, map[string]string{"error": "no"})
	}
}

func (c *splitCore) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, p := range c.calls {
		if p == path {
			n++
		}
	}
	return n
}

func splitRouter(t *testing.T, c *splitCore) *Router {
	r := newTestRouter(t)
	s := httptest.NewServer(c)
	t.Cleanup(s.Close)
	r.core = &CoreClient{base: s.URL, http: http.DefaultClient}
	initStep, killStep = time.Millisecond, time.Millisecond
	return r
}

func TestStartRetriesInitUntilTheMachineIsUp(t *testing.T) {
	c := &splitCore{key: newTestKey(), initWait: 3, bodies: map[string]map[string]any{}}
	r := splitRouter(t, c)
	d, err := r.startMachine("img", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var st struct{ Kind string }
	d.Decode(&st)
	if st.Kind != "started" || c.count("/init") != 4 || c.count("/kill") != 0 {
		t.Fatalf("%v %v", st, c.calls)
	}
	if b := c.bodies["/start"]; b["size"] != "medium" || b["env"] != nil {
		t.Fatalf("start body %v (size defaults in the router; no env)", b)
	}
}

func TestStartKillsAMachineThatNeverComesUp(t *testing.T) {
	c := &splitCore{key: newTestKey(), initFail: true, killWt: 2, bodies: map[string]map[string]any{}}
	r := splitRouter(t, c)
	if _, err := r.startMachine("img", "small", 0); err == nil {
		t.Fatal("started")
	}
	if c.count("/init") != 1 || c.count("/kill") != 3 { // a permanent refusal isn't retried; the kill is, until destroyed
		t.Fatalf("%v", c.calls)
	}
	c.initFail, c.initWait = false, 1<<30
	initMax = 20 * time.Millisecond
	defer func() { initMax = 12 * time.Minute }()
	if _, err := r.startMachine("img", "small", 0); err == nil {
		t.Fatal("started")
	}
	if c.calls[len(c.calls)-1] != "/kill" {
		t.Fatalf("a machine that never came up wasn't killed: %v", c.calls)
	}
}

func TestStartWithACoreFromBeforeR2(t *testing.T) {
	c := &splitCore{key: newTestKey(), old: true, bodies: map[string]map[string]any{}}
	r := splitRouter(t, c)
	d, err := r.startMachine("img", "large", 0)
	if err != nil || c.count("/init") != 0 {
		t.Fatalf("%v %v", err, c.calls)
	}
	var st struct{ Kind string }
	d.Decode(&st)
	if st.Kind != "started" {
		t.Fatal(st)
	}
	if _, err := r.killUntilDestroyed(map[string]any{"machine": "m7"}); err != nil || c.count("/kill") != 1 {
		t.Fatalf("%v %v", err, c.calls)
	}
}

func TestStartWaitsOutFlysMachineLimit(t *testing.T) {
	c := &splitCore{key: newTestKey(), limit: 2, bodies: map[string]map[string]any{}}
	r := splitRouter(t, c)
	machineLimitStep = time.Millisecond
	defer func() { machineLimitStep = time.Minute }()
	if _, err := r.startMachine("img", "", 0); err != nil {
		t.Fatal(err)
	}
	if c.count("/start") != 3 {
		t.Fatalf("%v", c.calls)
	}
	c.limit = 1 << 30
	machineLimitWait = 5 * time.Millisecond
	defer func() { machineLimitWait = 3 * time.Hour }()
	if _, err := r.startMachine("img", "", 0); err == nil || !flyMachineLimit(err) {
		t.Fatalf("gave up without the limit's error: %v", err)
	}
}
