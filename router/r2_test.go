package main

// R2 (the core as small as it can be): what the core answers beside a cert — its input-log entry and the line's
// carry rebound — is kept by the router; the core keeps no log for reading and has no /carry/forward.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTheRouterKeepsWhatComesBesideACert(t *testing.T) {
	ck := newTestKey()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/certify":
			d := ck.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m1", "machine": map[string]string{"id": "m2"}})
			writeJSON(w, 200, map[string]any{"payload": d.Payload, "sig": d.Sig,
				"entry": ck.doc(map[string]any{"kind": "input", "seq": 0, "input": "cert", "machine": "m2"}), "carry": "BLOB-M2"})
		case "/attest":
			writeJSON(w, 200, ck.doc(map[string]any{"kind": "input", "seq": 1, "input": "wakeup", "machine": "m2"}))
		default: // no /input-log, no /carry/forward
			writeJSON(w, 404, map[string]string{"error": "no such route"})
		}
	}))
	defer core.Close()
	r := newTestRouter(t)
	r.core = &CoreClient{base: core.URL, http: http.DefaultClient}
	keptLogProbe.Lock()
	keptLogProbe.at = time.Time{}
	keptLogProbe.Unlock()
	t.Cleanup(func() { keptLogProbe.Lock(); keptLogProbe.at = time.Time{}; keptLogProbe.Unlock() })
	r.saveCarry("m1", "BLOB-M1")

	cert, ans, err := r.core.CallAnswer("/certify", map[string]any{"carry": r.readCarry("m1")})
	if err != nil || ans.Entry == nil || ans.Carry != "BLOB-M2" || strings.Contains(cert.Payload, "BLOB") {
		t.Fatalf("%v %+v", err, ans)
	}
	r.logInputs(ans.Entry)
	r.carryAfter("m1", "m2", cert, ans)
	if r.readCarry("m2") != "BLOB-M2" || r.readCarry("m1") != "" {
		t.Fatal("the rebound carry wasn't kept for the successor (or the predecessor's stayed)")
	}
	a, _ := r.core.Call("/attest", map[string]string{})
	r.logInputs(a)
	b, _ := os.ReadFile(r.inputLogPath())
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `\"input\":\"cert\"`) || !strings.Contains(lines[1], `\"input\":\"wakeup\"`) {
		t.Fatalf("input log %q", lines)
	}
}
