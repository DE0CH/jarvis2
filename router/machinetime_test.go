package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// slowBody: a body that takes d to arrive (a large upload over a slow link)
type slowBody struct {
	r io.Reader
	d time.Duration
}

func (s *slowBody) Read(b []byte) (int, error) {
	if s.d > 0 {
		time.Sleep(s.d)
		s.d = 0
	}
	return s.r.Read(b)
}

// the machine's X-Time is checked as the request arrives, not after its body (2026-10-21: the YYC session's 20 MB
// live transcript took over 2 min to arrive and every sync was refused "X-Time too far off")
func TestASlowBodyIsNotRefusedAsTooOld(t *testing.T) {
	rg := newRig(t)
	runningM2(rg, false)
	defer func(d time.Duration) { machineTimeSkew = d }(machineTimeSkew)
	machineTimeSkew = 2 * time.Second
	m := testMachine{"m2", rg.mkey.k}
	send := func(at time.Time, delay time.Duration) int {
		body := `{"phase":"uploading","done":1,"total":2,"sent":1,"elapsedMs":1}`
		req := httptest.NewRequest("POST", "/m/snapshot-progress", &slowBody{strings.NewReader(body), delay})
		ts := strconv.FormatInt(at.Unix(), 10)
		sum := sha256.Sum256([]byte(body))
		sig, _ := signP256(m.key, []byte("POST /m/snapshot-progress "+ts+" "+hex.EncodeToString(sum[:])))
		req.Header.Set("X-Machine", m.id)
		req.Header.Set("X-Time", ts)
		req.Header.Set("X-Sig", sig)
		w := httptest.NewRecorder()
		rg.r.MachineHandler().ServeHTTP(w, req)
		return w.Code
	}
	if code := send(time.Now(), 4*time.Second); code != 200 {
		t.Fatalf("a slow body: %d", code)
	}
	if code := send(time.Now().Add(-10*time.Second), 0); code != 401 {
		t.Fatalf("a stale X-Time: %d", code)
	}
}
