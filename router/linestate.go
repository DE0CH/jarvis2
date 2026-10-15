package main

// The core's line state (core/continuity.go, docs/DESIGN.md "Core continuity"): a core set up with the seed from the
// master key seals what it must remember about lines (newest certs, killed/used, spent approvals, the input log's head,
// the deploy-key stores) after every call that changes it, and names the newest number in every answer
// (X-Line-Seq). The router keeps the newest one: on its volume at once (line-state.json, before the call's answer goes
// on), and in the backup bucket at most every few minutes and when it drains (keys/_jarvis2/line-state.json, for a
// router or box that comes back without its volume). At a Recover the app reads it (GET /api/core/line-state), checks
// it and hands it back to the new core in the claim bundle. The router can't read or forge it (sealed and signed by
// the core); it can withhold it (the lines then end, as before continuity) or serve an older one, which the app refuses
// below the newest number it has seen itself.

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	lineSeqHeader    = "X-Line-Seq"
	lineStateObject  = "keys/_jarvis2/line-state.json" // the bucket's copy (the router may only add versions under keys/)
	lineBucketPeriod = 5 * time.Minute
)

// LineStateDoc: as the core answers GET /line-state
type LineStateDoc struct {
	Head   Doc    `json:"head"`
	Sealed string `json:"sealed"`
}

// keptLineState: what the router keeps — the core's doc and the core key that signed its head
type keptLineState struct {
	Core string       `json:"core"`
	Seq  int          `json:"seq"`
	Doc  LineStateDoc `json:"doc"`
	At   time.Time    `json:"at"`
}

type lineKeeper struct {
	mu         sync.Mutex
	path       string
	kept       *keptLineState
	bucketSeq  int
	bucketAt   time.Time
	bucket     func() *backupBucket
	fetch      func() (int, []byte, error) // GET /line-state, raw
	coreKey    func() string               // the core's signing key (its identity)
	bucketBusy bool
}

func (r *Router) lineStatePath() string { return filepath.Join(r.cfg.DataDir, "line-state.json") }

// lineKeeperFor: the router's keeper, wired to its core client
func newLineKeeper(path string, c *CoreClient) *lineKeeper {
	k := &lineKeeper{path: path, bucket: backupBucketFromEnv}
	k.fetch = func() (int, []byte, error) { return c.rawNoHook("GET", "/line-state", nil) }
	k.coreKey = func() string {
		st, b, err := c.rawNoHook("GET", "/identity", nil)
		if err != nil || st != 200 {
			return ""
		}
		var id struct {
			SigningKey string `json:"signingKey"`
		}
		json.Unmarshal(b, &id)
		return id.SigningKey
	}
	if b, err := os.ReadFile(path); err == nil {
		var x keptLineState
		if json.Unmarshal(b, &x) == nil && x.Core != "" {
			k.kept = &x
		}
	}
	return k
}

// seen: an answer named seq n — fetch and keep the core's line state when it isn't the kept one (a newer one, or
// another core's after a Reset). Synchronous, so the answer that moved it goes on only once it is kept.
func (k *lineKeeper) seen(n int) {
	if n <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kept != nil && k.kept.Seq == n {
		return // already kept (a lower number is another core, or one Recovered from an older state: the running core's word goes)
	}
	st, b, err := k.fetch()
	if err != nil || st != 200 {
		log.Printf("line state %d: GET /line-state: %d %v", n, st, err)
		return
	}
	var d LineStateDoc
	var h struct {
		Kind string `json:"kind"`
		Seq  int    `json:"seq"`
	}
	if json.Unmarshal(b, &d) != nil || d.Head.Decode(&h) != nil || h.Kind != "line-state-head" {
		log.Printf("line state %d: not a line state", n)
		return
	}
	key := k.coreKey()
	if key == "" || !verifyP256(key, []byte(d.Head.Payload), d.Head.Sig) {
		log.Printf("line state %d: its head isn't signed by the running core", h.Seq)
		return
	}
	if k.kept != nil && k.kept.Core == key && k.kept.Seq == h.Seq {
		return
	}
	x := &keptLineState{Core: key, Seq: h.Seq, Doc: d, At: time.Now().UTC()}
	raw, _ := json.Marshal(x)
	tmp := k.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil || os.Rename(tmp, k.path) != nil {
		log.Printf("line state %d: can't write %s", h.Seq, k.path)
		return
	}
	k.kept = x
	if time.Since(k.bucketAt) >= lineBucketPeriod && !k.bucketBusy {
		k.bucketBusy = true
		go k.toBucket()
	}
}

// toBucket: the kept state into the bucket (a new version; never deletes one)
func (k *lineKeeper) toBucket() {
	k.mu.Lock()
	x := k.kept
	k.mu.Unlock()
	defer func() { k.mu.Lock(); k.bucketBusy = false; k.mu.Unlock() }()
	if x == nil || x.Seq == k.bucketSeq {
		return
	}
	b := k.bucket()
	if b == nil {
		return
	}
	raw, _ := json.Marshal(x)
	if err := b.put(lineStateObject, raw); err != nil {
		log.Printf("line state %d: bucket: %v", x.Seq, err)
		return
	}
	k.mu.Lock()
	k.bucketSeq, k.bucketAt = x.Seq, time.Now()
	k.mu.Unlock()
}

// flush: the newest into the bucket now (the router's drain)
func (k *lineKeeper) flush() {
	k.mu.Lock()
	busy := k.bucketBusy
	k.bucketBusy = true
	k.mu.Unlock()
	if !busy {
		k.toBucket()
	}
}

// current: the kept state; without one (a router that lost its volume), the bucket's copy
func (k *lineKeeper) current() *keptLineState {
	k.mu.Lock()
	x := k.kept
	k.mu.Unlock()
	if x != nil {
		return x
	}
	b := k.bucket()
	if b == nil {
		return nil
	}
	raw, err := b.get(lineStateObject, nil)
	if err != nil {
		return nil
	}
	var y keptLineState
	if json.Unmarshal(raw, &y) != nil || y.Core == "" {
		return nil
	}
	return &y
}

func (r *Router) registerLineState(app func(string, http.HandlerFunc)) {
	// the app's Recover: the newest line state the router holds (the app checks the head against the derived key and
	// against the newest number it has seen; the router's word decides nothing)
	app("GET /api/core/line-state", func(w http.ResponseWriter, req *http.Request) {
		x := r.lines.current()
		if x == nil {
			writeJSON(w, 404, map[string]string{"error": "the router keeps no line state"})
			return
		}
		w.Header().Set(lineSeqHeader, strconv.Itoa(x.Seq))
		writeJSON(w, 200, x.Doc)
	})
}

// isLineStateObject: the router's own object under keys/, which isn't a key backup (backups.go leaves it out)
func isLineStateObject(key string) bool { return strings.HasPrefix(key, "keys/_jarvis2/") }
