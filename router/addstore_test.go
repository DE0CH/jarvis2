package main

// Two add-stores pending for one running session, both approved (2026-10-13: identity and yyc for one session; the
// session ended with only the store answered last). Whatever order and timing the phone answers in, the session ends
// with both stores — with a core that answers every add-store onto the newest cert, and, with the production core that
// doesn't, by filing the stale one again rather than storing an answer that drops a store.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
)

// addStoreCore: a core's add-store rules. held = the production core of 2026-10-13 (sha-06ab2452f8ad, before R1):
// no newest cert at all, so it answers any add-store challenge from the cert it was made from and ignores current
type addStoreCore struct {
	mu       sync.Mutex
	held     bool
	latest   map[string]string // machine → newest cert nonce
	answered map[string]bool
	n        int
}

type fakeCert struct {
	Kind    string            `json:"kind"`
	Nonce   string            `json:"nonce"`
	Stores  []string          `json:"stores"`
	Machine map[string]string `json:"machine"`
	Options map[string]string `json:"options"`
}

func (c *addStoreCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	var in struct {
		Predecessor *Doc     `json:"predecessor"`
		Machine     string   `json:"machine"`
		Stores      []string `json:"stores"`
		Challenge   *Doc     `json:"challenge"`
		Current     *Doc     `json:"current"`
	}
	json.Unmarshal(b, &in)
	c.mu.Lock()
	defer c.mu.Unlock()
	doc := func(v any) {
		p, _ := json.Marshal(v)
		json.NewEncoder(w).Encode(map[string]string{"payload": string(p), "sig": "s"})
	}
	refuse := func(msg string) {
		w.WriteHeader(409)
		doc(map[string]string{"error": msg})
	}
	switch req.URL.Path {
	case "/succession":
		var pc fakeCert
		in.Predecessor.Decode(&pc)
		if !c.held && c.latest[in.Machine] != pc.Nonce {
			refuse("the predecessor cert isn't the newest")
			return
		}
		added := ""
		for _, s := range in.Stores {
			if !containsString(pc.Stores, s) {
				added = s
			}
		}
		c.n++
		doc(map[string]any{"kind": "challenge", "nonce": "ch" + string(rune('0'+c.n)), "request": map[string]any{
			"predecessor": in.Predecessor, "machine": map[string]string{"id": in.Machine}, "stores": in.Stores, "addedStore": added}})
	case "/approve/by-phone":
		var ch struct {
			Nonce   string
			Request struct {
				Predecessor *Doc
				Machine     map[string]string
				Stores      []string
				AddedStore  string
			}
		}
		in.Challenge.Decode(&ch)
		var pc fakeCert
		ch.Request.Predecessor.Decode(&pc)
		m := ch.Request.Machine["id"]
		if c.answered[ch.Nonce] {
			refuse("this challenge was already answered")
			return
		}
		stores := ch.Request.Stores
		if !c.held { // core addOnto: always the newest cert the router sends, plus the added store
			var cur fakeCert
			if in.Current == nil || in.Current.Decode(&cur) != nil || c.latest[m] != cur.Nonce {
				refuse("current isn't the newest cert")
				return
			}
			if containsString(cur.Stores, ch.Request.AddedStore) {
				refuse("already holds the store")
				return
			}
			stores = sortedSet(append(append([]string{}, cur.Stores...), ch.Request.AddedStore))
		}
		c.answered[ch.Nonce], c.latest[m] = true, ch.Nonce
		doc(fakeCert{Kind: "succession-cert", Nonce: ch.Nonce, Stores: stores, Machine: map[string]string{"id": m}, Options: map[string]string{"permissionMode": "auto"}})
	default:
		http.NotFound(w, req)
	}
}

func addStoreRouter(t *testing.T, held bool) *Router {
	r := newTestRouter(t)
	cc := &addStoreCore{held: held, latest: map[string]string{"m1": "c0"}, answered: map[string]bool{}}
	s := httptest.NewServer(cc)
	t.Cleanup(s.Close)
	r.core = &CoreClient{base: s.URL, http: http.DefaultClient}
	p, _ := json.Marshal(fakeCert{Kind: "succession-cert", Nonce: "c0", Stores: []string{"default"}, Machine: map[string]string{"id": "m1"}, Options: map[string]string{"permissionMode": "auto"}})
	r.st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Harness: "claude", Cert: &Doc{Payload: string(p)}, Stores: []string{"default"}}
		d.Machines["m1"] = "s1"
	})
	return r
}

// fileTwo: identity and yyc asked for, both pending before either is answered → their approval ids
func fileTwo(t *testing.T, r *Router) map[string]string {
	t.Helper()
	for _, s := range []string{"identity", "yyc"} {
		if err := r.AddStoreFrom("m1", s, Origin{Caller: Caller{Kind: "session", Session: "s1"}}, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	ids := map[string]string{}
	r.st.Do(func(d *persisted) {
		for id, a := range d.Approvals {
			ids[a.Options["store"]] = id
		}
	})
	if len(ids) != 2 {
		t.Fatalf("filed %v", ids)
	}
	return ids
}

func sessionStores(r *Router) []string {
	var out []string
	r.st.Do(func(d *persisted) {
		var c fakeCert
		d.Sessions["s1"].Cert.Decode(&c)
		if !equalSets(c.Stores, d.Sessions["s1"].Stores) {
			out = []string{"cert and session disagree"}
			return
		}
		out = append([]string{}, d.Sessions["s1"].Stores...)
	})
	sort.Strings(out)
	return out
}

func equalSets(a, b []string) bool { return containsAll(a, b) && containsAll(b, a) }

func TestTwoPendingAddStoresBothApprovedEndInTheSession(t *testing.T) {
	want := []string{"default", "identity", "yyc"}
	for _, order := range [][2]string{{"yyc", "identity"}, {"identity", "yyc"}} {
		r := addStoreRouter(t, false)
		ids := fileTwo(t, r)
		for _, s := range order {
			if _, _, err := r.Respond(ids[s], "sig"); err != nil {
				t.Fatalf("%v: %s: %v", order, s, err)
			}
		}
		if got := sessionStores(r); !equalSets(got, want) {
			t.Fatalf("%v: the session ends with %v", order, got)
		}
	}
	// both answered at the same moment
	r := addStoreRouter(t, false)
	ids := fileTwo(t, r)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if _, _, err := r.Respond(id, "sig"); err != nil {
				t.Error(err)
			}
		}(id)
	}
	wg.Wait()
	if got := sessionStores(r); !equalSets(got, want) {
		t.Fatalf("concurrent: the session ends with %v", got)
	}
}

// The held core answers the stale one from the cert it was made from: the router doesn't store that answer, files
// the approval again from the newest cert, and the next answer ends with both.
func TestAStaleAnswerFromTheHeldCoreDropsNoStore(t *testing.T) {
	r := addStoreRouter(t, true)
	ids := fileTwo(t, r)
	if _, _, err := r.Respond(ids["yyc"], "sig"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Respond(ids["identity"], "sig"); err == nil {
		t.Fatal("a stale answer was taken")
	}
	if got := sessionStores(r); !equalSets(got, []string{"default", "yyc"}) {
		t.Fatalf("the stale answer dropped a store: %v", got)
	}
	if _, _, err := r.Respond(ids["identity"], "sig"); err != nil {
		t.Fatal(err)
	}
	if got := sessionStores(r); !equalSets(got, []string{"default", "identity", "yyc"}) {
		t.Fatalf("the session ends with %v", got)
	}
}
