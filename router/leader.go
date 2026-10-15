package main

// Gapless rollouts (Deyao, 2026-10-15: "deploy" means zero downtime). The router's state is one process's memory
// (state.json on the volume is its copy), so exactly ONE router process may own it: the LEADER. A rollout starts the
// new pod next to the old one (RollingUpdate, maxUnavailable 0, k8s/apps/router.yaml); the handover is an flock on
// the shared volume (both pods are on the box's one node, so they share the file and its lock):
//
//   1. The new pod can't take the lock: it is a STANDBY. It listens at once and is ready, and it reverse-proxies
//      every request (the app, the web page, setup, WebSockets, long polls) to the leader, whose address the leader
//      writes next to the lock (POD_IP, the downward API). It runs nothing else: no loops, no WireGuard.
//   2. k8s takes the old pod out of the Service and sends SIGTERM. The old leader drains (drain.go): its running
//      lifecycle actions finish while it keeps serving, directly and through the standby.
//   3. The old leader stops its WireGuard peer, clears the address, freezes its state (holds the state lock, so no
//      loop of the old process acts on what is no longer its state) and releases the lock; from then on it proxies
//      what still reaches it to the new leader, and exits a few seconds later.
//   4. The standby takes the lock, loads state.json (the old leader's last save), starts the loops and its WireGuard
//      peer, writes its address and switches its listener from proxying to serving.
//
// A request that arrives between 3 and 4 waits in the proxy for the new address (that window is the time to load
// state.json and start the router: well under a second), so no request sees a refused connection. What still waits:
// a NEW lifecycle action (start, pause, resume, destroy, restart, upgrade) asked for while the old leader drains gets
// 503 "router updating, try again shortly" as before — such an action runs in the leader's memory against its state
// and can't be handed to another process half way (and is never saved and redone, Deyao 2026-10-13); the machines'
// WireGuard path (/m) moves to the new peer at step 4, so a machine's request in flight at that moment is retried by
// the machine.

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// leaderLock: the flock on <dir>/router.leader and the leader's address in <dir>/router.leader.addr
type leaderLock struct {
	f    *os.File
	addr string // the file with the leader's base URL
}

func openLeaderLock(dir string) (*leaderLock, error) {
	f, err := os.OpenFile(dir+"/router.leader", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &leaderLock{f: f, addr: dir + "/router.leader.addr"}, nil
}

// tryLock: true when this process is the leader now
func (l *leaderLock) tryLock() bool {
	return syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

// lock blocks until this process is the leader
func (l *leaderLock) lock() error {
	for {
		err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX)
		if err == nil || !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

func (l *leaderLock) unlock() { syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) }

func (l *leaderLock) setAddr(a string) {
	tmp := l.addr + ".tmp"
	if os.WriteFile(tmp, []byte(a), 0o600) == nil {
		os.Rename(tmp, l.addr)
	}
}

func (l *leaderLock) leaderAddr() string {
	b, _ := os.ReadFile(l.addr)
	return strings.TrimSpace(string(b))
}

// swapHandler: the public listener's handler, switched from proxying to serving (or back) without a restart
type swapHandler struct{ h atomic.Value }

func (s *swapHandler) set(h http.Handler)    { s.h.Store(&h) }
func (s *swapHandler) current() http.Handler { return *s.h.Load().(*http.Handler) }
func (s *swapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*s.h.Load().(*http.Handler)).ServeHTTP(w, r)
}

// leaderProxy forwards to whoever leads, waiting (up to wait) while no leader has written its address yet, or while
// the address is this process's own (it just handed over). A GET that fails to reach the leader (it exited in that
// instant) waits for the next address and is tried again.
type leaderProxy struct {
	lock  *leaderLock
	self  string
	local *swapHandler // this pod's listener: once it leads, a request still waiting here is served locally
	wait  time.Duration
	tr    http.RoundTripper
	fixed func() string // move.go: a router that moved, or a move's candidate: always this address, not the lock's
}

func newLeaderProxy(l *leaderLock, self string, local *swapHandler) *leaderProxy {
	return &leaderProxy{lock: l, self: self, local: local, wait: 60 * time.Second, tr: &http.Transport{
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 32,
	}}
}

// target: the leader's address, or "" when this pod itself leads now (serve locally)
func (p *leaderProxy) target(ctx context.Context, not string) (string, error) {
	deadline := time.Now().Add(p.wait)
	for {
		var a string
		if p.fixed != nil {
			a = p.fixed()
		} else {
			a = p.lock.leaderAddr()
		}
		if a != "" && a == p.self && p.local != nil && p.local.current() != http.Handler(p) {
			return "", nil
		}
		if a != "" && a != p.self && a != not {
			return a, nil
		}
		if time.Now().After(deadline) {
			return "", errors.New("no router leader")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (p *leaderProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	retriable := r.Method == http.MethodGet || r.Method == http.MethodHead
	failed := ""
	for attempt := 0; ; attempt++ {
		a, err := p.target(r.Context(), failed)
		if err != nil {
			http.Error(w, `{"error":"router updating, try again shortly"}`, http.StatusServiceUnavailable)
			return
		}
		if a == "" {
			p.local.ServeHTTP(w, r)
			return
		}
		u, _ := url.Parse(a)
		var dialErr error
		rp := &httputil.ReverseProxy{
			Rewrite:       func(pr *httputil.ProxyRequest) { pr.SetURL(u); pr.Out.Host = pr.In.Host; pr.SetXForwarded() },
			Transport:     p.tr,
			FlushInterval: -1, // long polls and streams pass through as they come
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				var op *net.OpError
				if errors.As(err, &op) && op.Op == "dial" {
					dialErr = err // nothing was sent: safe to send again to the next leader
					return
				}
				log.Printf("[standby] proxy to %s: %v", a, err)
				w.WriteHeader(http.StatusBadGateway)
			},
		}
		rp.ServeHTTP(w, r)
		if dialErr == nil {
			return
		}
		if (!retriable && r.ContentLength != 0) || attempt >= 3 {
			http.Error(w, `{"error":"router updating, try again shortly"}`, http.StatusServiceUnavailable)
			return
		}
		failed = a
	}
}

// leadership: the leader's side of the handover
type leadership struct {
	lock     *leaderLock
	self     string
	handler  *swapHandler
	mu       sync.Mutex
	stopWG   func()
	quiesce  func() // wg.go: no new machine connection opens here (a handover begins)
	released bool
}

// handOver ends this process's leadership (after the drain): WireGuard down, address cleared, state frozen, lock
// released, and what still reaches this pod proxied to the next leader.
func (ld *leadership) handOver(st *State) {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	if ld.released {
		return
	}
	ld.released = true
	if ld.stopWG != nil {
		ld.stopWG()
	}
	ld.handler.set(newLeaderProxy(ld.lock, ld.self, nil))
	st.mu.Lock() // never unlocked: this process's loops must not act on state it no longer owns
	ld.lock.setAddr("")
	ld.lock.unlock()
	log.Printf("[leader] handed over: lock released, proxying to the next leader")
}

// selfURL: this pod's address for the standby's proxy (POD_IP from the downward API; the public port)
func selfURL(addr string) string {
	ip := os.Getenv("POD_IP")
	if ip == "" {
		ip = "127.0.0.1"
	}
	port := "8080"
	if i := strings.LastIndex(addr, ":"); i >= 0 && addr[i+1:] != "" {
		port = addr[i+1:]
	}
	return "http://" + net.JoinHostPort(ip, port)
}
