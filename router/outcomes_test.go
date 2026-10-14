package main

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureOutcomes: request-outcome notices the outcome tick sends, instead of a machine
func captureOutcomes(t *testing.T, fail func(Notice) error) (*[]Notice, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	got := []Notice{}
	old := deliverOutcomeHook
	deliverOutcomeHook = func(r *Router, sid string, n Notice) error {
		mu.Lock()
		defer mu.Unlock()
		if fail != nil {
			if err := fail(n); err != nil {
				return err
			}
		}
		got = append(got, n)
		return nil
	}
	t.Cleanup(func() { outcomeWG.Wait(); deliverOutcomeHook = old })
	return &got, &mu
}

func tickOutcomes(r *Router) {
	r.outcomeTick()
	outcomeWG.Wait()
}

func outcomesOf(r *Router, sid string) []*Outcome {
	var out []*Outcome
	r.st.Do(func(d *persisted) { out = append(out, d.Outcomes[sid]...) })
	return out
}

var (
	filingA = strings.Repeat("a", 32)
	filingB = strings.Repeat("b", 32)
)

// A session's own request, denied: the session gets a notice naming its filing id, the item, the outcome word and the
// Inbox id, nothing else. A request the app filed tells no session; a filing without the guard's id tells nothing.
func TestADeniedRequestIsToldToTheSessionThatFiledIt(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	got, mu := captureOutcomes(t, nil)
	h := r.MachineHandler()
	code, out := m.doH(t, h, "POST", "/m/api/requests/unlock", `{"explanation": "need the store"}`, map[string]string{"X-Jarvis2-Filing": filingA})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	// no filing id (or a malformed one): nothing to tell
	m.doH(t, h, "POST", "/m/api/requests/repo/add", `{"repo": "DE0CH/x", "explanation": "x"}`, map[string]string{"X-Jarvis2-Filing": "nope"})
	if code, _ := inboxDo(t, r, "POST", "/api/requests/repo/add", `{"repo": "DE0CH/y"}`, true); code != 200 {
		t.Fatal(code)
	}
	for _, it := range r.Inbox() {
		if code, _ := inboxDo(t, r, "DELETE", "/api/requests/"+it.ID, "", true); code != 200 {
			t.Fatal(code)
		}
	}
	tickOutcomes(r)
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("%d notices: %+v", len(*got), *got)
	}
	n := (*got)[0]
	if n.Kind != "request-outcome" || n.Filing != filingA || len(n.Items) != 1 || n.Items[0] != (OutcomeItem{Item: 0, Outcome: "denied", Ref: id}) {
		t.Fatalf("%+v", n)
	}
	b, _ := json.Marshal(n)
	if strings.Contains(string(b), "need the store") {
		t.Fatalf("the router's words reached the notice: %s", b)
	}
	if o := outcomesOf(r, "sA"); len(o) != 1 || o[0].DeliveredAt == nil {
		t.Fatalf("not marked delivered: %+v", o)
	}
	*got = nil
	mu.Unlock()
	tickOutcomes(r)
	mu.Lock()
	if len(*got) != 0 {
		t.Fatalf("delivered again: %+v", *got)
	}
}

// lapsed requests and a lapsed add-on approval; a paused session is told only once it runs again
func TestLapsedOutcomesWaitForAPausedSession(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sa", "started", "mA", false)
	m := newTestMachine(r, "mA")
	got, mu := captureOutcomes(t, nil)
	code, out := m.doH(t, r.MachineHandler(), "POST", "/m/api/requests/repo/add", `{"repo": "DE0CH/yyc", "explanation": "push"}`,
		map[string]string{"X-Jarvis2-Filing": filingA})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	rid := out["id"].(string)
	r.addApproval(&Approval{Kind: "add-store", Session: "sa", Machine: "mA", Store: "gmail",
		Origin: &Origin{Caller: Caller{Kind: "session", Session: "sa"}, Filing: filingB}})
	r.st.Do(func(d *persisted) { d.Sessions["sa"].State = "paused" })
	later := time.Now().UTC().Add(11 * time.Minute)
	r.expireApprovals(later)
	r.st.Do(func(d *persisted) { pruneRequests(d, later) })
	tickOutcomes(r)
	mu.Lock()
	if len(*got) != 0 {
		t.Fatalf("delivered into a paused session: %+v", *got)
	}
	mu.Unlock()
	if o := outcomesOf(r, "sa"); len(o) != 2 {
		t.Fatalf("%+v", o)
	}
	r.st.Do(func(d *persisted) { d.Sessions["sa"].State = "started" })
	tickOutcomes(r)
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 2 {
		t.Fatalf("%d notices", len(*got))
	}
	seen := map[string]string{}
	for _, n := range *got {
		seen[n.Items[0].Ref] = n.Items[0].Outcome
	}
	if seen[rid] != "lapsed" || seen["sa"] != "lapsed" {
		t.Fatalf("%v", seen)
	}
}

// a batch's items are told together once all are decided (or after outcomeSettle)
func TestABatchIsToldTogether(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	got, mu := captureOutcomes(t, nil)
	code, out := m.doH(t, r.MachineHandler(), "POST", "/m/api/requests/batch", batchBody("two things",
		`{"intent": "repo/add", "repo": "DE0CH/a"}`, `{"intent": "unlock"}`), map[string]string{"X-Jarvis2-Filing": filingA})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	ids := []string{}
	for _, x := range out["items"].([]any) {
		ids = append(ids, x.(map[string]any)["id"].(string))
	}
	if code, _ := inboxDo(t, r, "POST", "/api/requests/"+ids[1]+"/done", "", true); code != 200 {
		t.Fatal(code)
	}
	tickOutcomes(r)
	mu.Lock()
	if len(*got) != 0 {
		t.Fatalf("told before the batch was decided: %+v", *got)
	}
	mu.Unlock()
	if err := r.DenyBatch(out["id"].(string)); err != nil {
		t.Fatal(err)
	}
	old := outcomeSettle
	outcomeSettle = 0 // the batch is gone after Deny: its count with it
	defer func() { outcomeSettle = old }()
	tickOutcomes(r)
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 || len((*got)[0].Items) != 2 || (*got)[0].Filing != filingA {
		t.Fatalf("%+v", *got)
	}
	o := (*got)[0].Items
	if o[0] != (OutcomeItem{Item: 0, Outcome: "denied", Ref: ids[0]}) || o[1] != (OutcomeItem{Item: 1, Outcome: "approved", Ref: ids[1]}) {
		t.Fatalf("%+v", o)
	}
}

// a machine that refuses the filing (it never kept it) is given up on at once; the session can still list its outcomes
func TestOutcomeDeliveryFailures(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	fail := errors.New("the machine refused or failed: request-outcome: no filing of this session has that id")
	got, mu := captureOutcomes(t, func(Notice) error { return fail })
	code, out := m.doH(t, r.MachineHandler(), "POST", "/m/api/requests/unlock", `{"explanation": "x"}`, map[string]string{"X-Jarvis2-Filing": filingA})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	r.DenyRequest(out["id"].(string))
	tickOutcomes(r)
	o := outcomesOf(r, "sA")
	if len(o) != 1 || o[0].DeliveredAt == nil || !strings.HasPrefix(o[0].Error, "not delivered") {
		t.Fatalf("%+v", o[0])
	}
	mu.Lock()
	if len(*got) != 0 {
		t.Fatal("recorded")
	}
	mu.Unlock()
	code, list := m.do(t, r.MachineHandler(), "GET", "/m/api/requests/outcomes", "")
	if code != 200 {
		t.Fatal(code)
	}
	b, _ := json.Marshal(list)
	if !strings.Contains(string(b), `"outcome":"denied"`) || !strings.Contains(string(b), `"kind":"unlock"`) {
		t.Fatalf("%s", b)
	}
}
