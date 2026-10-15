package main

// What a handover does to the requests and deliveries in flight (Deyao, 2026-10-15: a move or a rollout must not
// make a running session wait longer than the handover's gap, nor drop or repeat a wakeup). Both handovers — a
// rollout's (leader.go) and a box move's (move.go) — freeze this process's state; before that:
//
//  1. Deliveries stop (stopDeliveries): no new wakeup, cron, watch, lease or outcome delivery begins here (the caller
//     sees errSkip: its next tick, in the next leader, tries again), and the ones in flight finish, so what they changed
//     (a wakeup cleared, a cron advanced) is in the state the next leader loads. No delivery is lost or made twice.
//  2. Requests in flight end (freezeRequests): every request still inside a handler of this process has its context
//     cancelled. A long poll ends at once: the machine's /m/commands answers "nothing" (it polls again at once, through
//     the new connection), the Claude login's answers what it has. A GET that ended without an answer is handed to the
//     next leader (the fallback proxy, which waits for it); anything else gets 503 "router moving" with
//     Connection: close, which the app and the machine retry. Every answer from then on closes its connection, so no
//     client keeps a pooled connection to a process that no longer serves.
//  3. The machines' listener shuts down gracefully (wg.go): the idle connections are closed with a FIN that still
//     reaches the machines before the WireGuard device goes, so a machine's next call dials anew — and that dial waits
//     in TCP's SYN retries until the next leader's peer answers, instead of failing on a dead pooled connection.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type moveGate struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	frozen     bool
	reqs       int           // gated requests in flight
	deliveries int           // deliveries in flight
	stopped    bool          // no new delivery begins
	changed    chan struct{} // closed and replaced whenever reqs or deliveries drop
	fallback   http.Handler
}

func (g *moveGate) init() {
	if g.ctx == nil {
		g.ctx, g.cancel = context.WithCancel(context.Background())
		g.changed = make(chan struct{})
	}
}

func (g *moveGate) notify() {
	close(g.changed)
	g.changed = make(chan struct{})
}

// waitZero: until count() is 0 or max passed; true = 0
func (g *moveGate) waitZero(count func() int, max time.Duration) bool {
	deadline := time.After(max)
	for {
		g.mu.Lock()
		g.init()
		n, ch := count(), g.changed
		g.mu.Unlock()
		if n == 0 {
			return true
		}
		select {
		case <-ch:
		case <-deadline:
			return false
		}
	}
}

// ---- deliveries -------------------------------------------------------------------------------------------------

// beginDelivery: a delivery to a machine starts here; errSkip once deliveries stopped (the next leader makes it)
func (r *Router) beginDelivery() (func(), error) {
	g := &r.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	g.init()
	if g.stopped {
		return nil, fmt.Errorf("%w: the router is handing over", errSkip)
	}
	g.deliveries++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.deliveries--
			g.notify()
			g.mu.Unlock()
		})
	}, nil
}

// stopDeliveries: no new delivery begins; waits (at most max) for the ones in flight
func (r *Router) stopDeliveries(max time.Duration) {
	g := &r.gate
	g.mu.Lock()
	g.init()
	g.stopped = true
	n := g.deliveries
	g.mu.Unlock()
	if n > 0 {
		log.Printf("[handover] waiting for %d deliveries in flight", n)
	}
	if !g.waitZero(func() int { return g.deliveries }, max) {
		log.Printf("[handover] deliveries still in flight after %s: handing over anyway", max)
	}
}

func (r *Router) resumeDeliveries() {
	g := &r.gate
	g.mu.Lock()
	g.stopped = false
	g.mu.Unlock()
}

// ---- requests ---------------------------------------------------------------------------------------------------

// freezeRequests: every request in flight is ended (see the top); GETs that end unanswered go to fallback. Waits (at
// most max) for the handlers to return, so none of them is still inside when the state freezes.
func (r *Router) freezeRequests(fallback http.Handler, max time.Duration) {
	g := &r.gate
	g.mu.Lock()
	g.init()
	g.frozen, g.fallback = true, fallback
	n := g.reqs
	g.cancel()
	g.mu.Unlock()
	if !g.waitZero(func() int { return g.reqs }, max) {
		g.mu.Lock()
		log.Printf("[handover] %d of %d requests still inside a handler after %s", g.reqs, n, max)
		g.mu.Unlock()
		return
	}
	if n > 0 {
		log.Printf("[handover] %d requests in flight ended", n)
	}
}

// thawRequests: an aborted move serves again
func (r *Router) thawRequests() {
	g := &r.gate
	g.mu.Lock()
	g.ctx, g.cancel = context.WithCancel(context.Background())
	g.frozen, g.fallback = false, nil
	g.mu.Unlock()
}

// handingOver: the channel that closes when this process's requests are ended (long polls select on it)
func (r *Router) handingOver() <-chan struct{} {
	g := &r.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	g.init()
	return g.ctx.Done()
}

func (r *Router) frozenNow() bool {
	g := &r.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.frozen
}

// gated: every request of the public and the machines' listener passes here
func (r *Router) gated(h http.Handler) http.Handler {
	g := &r.gate
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		g.mu.Lock()
		g.init()
		fctx, frozen := g.ctx, g.frozen
		g.reqs++
		g.mu.Unlock()
		left := false
		leave := func() {
			if !left {
				left = true
				g.mu.Lock()
				g.reqs--
				g.notify()
				g.mu.Unlock()
			}
		}
		defer leave()
		tw := &gateWriter{ResponseWriter: w, r: r}
		if !frozen {
			ctx, cancel := context.WithCancel(req.Context())
			stop := context.AfterFunc(fctx, cancel)
			h.ServeHTTP(tw, req.WithContext(ctx))
			stop()
			cancel()
			if tw.wrote || fctx.Err() == nil {
				return
			}
		}
		// ended by the handover with no answer
		leave()
		g.mu.Lock()
		fb := g.fallback
		g.mu.Unlock()
		if fb != nil && (req.Method == http.MethodGet || req.Method == http.MethodHead) && req.Context().Err() == nil {
			fb.ServeHTTP(w, req)
			return
		}
		w.Header().Set("Connection", "close")
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "router moving, try again shortly", "retry": true})
	})
}

// gateWriter: knows whether the handler answered; every answer after the freeze closes its connection
type gateWriter struct {
	http.ResponseWriter
	r     *Router
	wrote bool
}

func (w *gateWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		if w.r.frozenNow() {
			w.ResponseWriter.Header().Set("Connection", "close")
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gateWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gateWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if !w.wrote {
			w.WriteHeader(http.StatusOK)
		}
		f.Flush()
	}
}

func (w *gateWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
