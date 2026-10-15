package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A rollout in miniature (leader.go): clients hit the new pod (a standby proxying to the leader) and the old pod;
// the old leader hands over; the standby takes the lock and serves. No request fails, and after the handover every
// answer comes from the new leader, including what still reaches the old pod.
func TestLeaderHandoverNoFailedRequests(t *testing.T) {
	dir := t.TempDir()
	lockA, err := openLeaderLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !lockA.tryLock() {
		t.Fatal("first router must lead")
	}
	lockB, _ := openLeaderLock(dir) // a second open file: flock sees another holder
	if lockB.tryLock() {
		t.Fatal("standby must not lead while the leader holds the lock")
	}

	serve := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			io.WriteString(w, name+":"+r.Method+":"+string(b))
		})
	}
	pubA, pubB := &swapHandler{}, &swapHandler{}
	pubA.set(serve("A"))
	srvA, srvB := httptest.NewServer(pubA), httptest.NewServer(pubB)
	defer srvA.Close()
	defer srvB.Close()
	lockA.setAddr(srvA.URL)
	pubB.set(newLeaderProxy(lockB, srvB.URL, pubB))

	// B waits for the lock like main() does
	led := make(chan struct{})
	go func() {
		if err := lockB.lock(); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(150 * time.Millisecond) // loading state.json and starting the router
		pubB.set(serve("B"))
		lockB.setAddr(srvB.URL)
		close(led)
	}()

	var fails, total atomic.Int64
	var mu sync.Mutex
	seen := map[string]int{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			base := srvB.URL
			if i%2 == 1 {
				base = srvA.URL // cloudflared's kept-alive connection to the old pod
			}
			for {
				select {
				case <-stop:
					return
				default:
				}
				method, body := "GET", ""
				if i%4 == 3 {
					method, body = "POST", "x"
				}
				req, _ := http.NewRequest(method, base+"/api/thing", strings.NewReader(body))
				res, err := http.DefaultClient.Do(req)
				total.Add(1)
				if err != nil || res.StatusCode != 200 {
					fails.Add(1)
					if err == nil {
						b, _ := io.ReadAll(res.Body)
						t.Logf("%s %s -> %d %s", method, base, res.StatusCode, b)
						res.Body.Close()
					} else {
						t.Logf("%s %s -> %v", method, base, err)
					}
					continue
				}
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if want := method + ":" + body; !strings.HasSuffix(string(b), want) {
					t.Errorf("body %q, want suffix %q", b, want)
				}
				mu.Lock()
				seen[string(b[:1])]++
				mu.Unlock()
			}
		}(i)
	}
	time.Sleep(300 * time.Millisecond)
	// the old leader's handover (leadership.handOver without WireGuard), state frozen
	st := &State{dir: dir}
	(&leadership{lock: lockA, self: srvA.URL, handler: pubA}).handOver(st)
	<-led
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	before := seen["B"]
	mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d of %d requests failed across the handover", fails.Load(), total.Load())
	}
	if seen["A"] == 0 || seen["B"] <= before {
		t.Fatalf("answers: %v (want A before and B after the handover)", seen)
	}
	if a := lockB.leaderAddr(); a != srvB.URL {
		t.Fatalf("leader address %q, want %q", a, srvB.URL)
	}
	t.Logf("%d requests across the handover, none failed; answers %v", total.Load(), seen)
}
