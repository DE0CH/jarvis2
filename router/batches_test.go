package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func batchBody(summary string, items ...string) string {
	return fmt.Sprintf(`{"summary": %q, "items": [%s]}`, summary, strings.Join(items, ","))
}

// a session files a batch of every kind it may ask for: one Inbox entry with the summary, every item carrying the
// batch's id and end; a single item can be denied on its own; Deny on the batch takes everything else
func TestBatchFromASession(t *testing.T) {
	rg, _ := newOpsRig(t)
	r := rg.r
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()

	body := batchBody("Set up the YYC work: two sessions, a repo, and an unlock.",
		`{"intent": "grant", "holder": "terminal", "minutes": 5}`,
		`{"intent": "repo/add", "repo": "DE0CH/yyc", "explanation": "the new work lives here"}`,
		`{"intent": "unlock", "explanation": "it waits on a store"}`,
		`{"intent": "new-session", "requestId": "n1", "label": "one", "prompt": "do one", "stores": ["default"]}`,
		`{"intent": "new-session", "requestId": "n2", "label": "two", "prompt": "do two"}`)
	code, out := m.do(t, h, "POST", "/m/api/requests/batch", body)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	bid := out["id"].(string)
	res := out["items"].([]any)
	if len(res) != 5 {
		t.Fatalf("%v", res)
	}
	for _, x := range res {
		if e := x.(map[string]any)["error"]; e != nil {
			t.Fatalf("an item failed: %v", x)
		}
	}
	waitFor(t, "the new sessions' approvals", func() bool {
		bs := r.InboxBatches(nil)
		return len(bs) == 1 && bs[0].Preparing == 0 && len(bs[0].Items) == 5
	})
	b := r.InboxBatches(nil)[0]
	if b.ID != bid || b.Summary != "Set up the YYC work: two sessions, a repo, and an unlock." || !strings.HasPrefix(b.CallerText, "session “label sA”") ||
		b.Call.Path != "/api/requests/batch" || b.Expires.Sub(b.Created) != inboxTTL {
		t.Fatalf("%+v", b)
	}
	// every item: in the batch, the batch's end, the call recorded with its intent; the list's order is the filing's
	items := map[string]InboxItem{}
	for _, it := range r.Inbox() {
		items[it.ID] = it
	}
	kinds := []string{}
	for _, id := range b.Items {
		it := items[id]
		kinds = append(kinds, it.Kind)
		if it.Batch != bid || it.Expires == nil || !it.Expires.Equal(b.Expires) || it.Call.Path != "/api/requests/batch" || it.Call.Args["intent"] == nil {
			t.Fatalf("%+v", it)
		}
	}
	if strings.Join(kinds, ",") != "grant,repo-key,unlock,new-session,new-session" {
		t.Fatalf("order %v", kinds)
	}
	// the batch as the app and the session read it
	if code, out := inboxDo(t, r, "GET", "/api/requests/batches/"+bid, "", true); code != 200 || len(out["items"].([]any)) != 5 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := m.do(t, h, "GET", "/m/api/requests", ""); code != 200 || len(out["batches"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	var unlock InboxItem
	for _, it := range items {
		if it.Kind == "unlock" {
			unlock = it
		}
	}
	if unlock.Open["kind"] != "unlock" || unlock.Open["options"].(map[string]any)["sessionId"] != "sA" || unlock.Explanation != "it waits on a store" {
		t.Fatalf("%+v", unlock)
	}
	// one item denied on its own: out of the batch, the rest stay
	if code, _ := inboxDo(t, r, "DELETE", "/api/requests/"+unlock.ID, "", true); code != 200 {
		t.Fatal(code)
	}
	if bs := r.InboxBatches(nil); len(bs) != 1 || len(bs[0].Items) != 4 {
		t.Fatalf("%+v", bs)
	}
	// Deny the batch: requests gone, the proposed sessions gone (their approvals rejected)
	if code, out := inboxDo(t, r, "DELETE", "/api/requests/batches/"+bid, "", true); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if len(r.Inbox()) != 0 || len(r.InboxBatches(nil)) != 0 {
		t.Fatalf("%+v %+v", r.Inbox(), r.InboxBatches(nil))
	}
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.State == "approval" {
				t.Fatalf("a proposed session is left: %+v", s)
			}
		}
	})
	if code, _ := inboxDo(t, r, "DELETE", "/api/requests/batches/"+bid, "", true); code != 404 {
		t.Fatal("denied twice")
	}
}

// nothing is filed when any item is bad; the summary is required; a batch has 1–20 items, none the same twice
func TestBatchChecksEveryItemFirst(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()
	ok := `{"intent": "repo/add", "repo": "DE0CH/a"}`
	for name, c := range map[string]struct {
		body string
		code int
	}{
		"another session's grant": {batchBody("s", ok, `{"intent": "grant", "session": "sB", "holder": "terminal"}`), 403},
		"a repo removed":          {batchBody("s", ok, `{"intent": "repo/remove", "repo": "DE0CH/a"}`), 403},
		"a Jarvis 1 import":       {batchBody("s", `{"intent": "jarvis1-import", "id": "x", "stores": ["default"]}`), 403},
		"no summary":              {batchBody("  ", ok), 400},
		"unknown intent":          {batchBody("s", `{"intent": "format-disk"}`), 400},
		"the same twice":          {batchBody("s", ok, `{"intent": "repo/add", "repo": "https://github.com/DE0CH/a"}`), 400},
		"empty":                   {batchBody("s"), 400},
		"too many":                {batchBody("s", strings.Repeat(ok+",", batchMaxItems)+ok), 400},
		"an attachment":           {batchBody("s", `{"intent": "new-session", "prompt": "p", "attachments": {"uploadId": "u"}}`), 400},
	} {
		if code, out := m.do(t, h, "POST", "/m/api/requests/batch", c.body); code != c.code {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		if len(r.Inbox()) != 0 {
			t.Fatalf("%s: something was filed: %+v", name, r.Inbox())
		}
	}
	// the setup session and the actions key file batches too; a standalone request already waiting joins
	q, _, err := r.FileRequest(requestKindRepo, RequestParams{Action: "add", Repo: "DE0CH/b"}, "why", Origin{Caller: Caller{Kind: "setup"}})
	if err != nil {
		t.Fatal(err)
	}
	code, out := inboxDo(t, r, "POST", "/setup/requests/batch", batchBody("two repos", `{"intent": "repo/add", "repo": "DE0CH/b"}`, `{"intent": "repo/remove", "repo": "DE0CH/c"}`), false)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if first := out["items"].([]any)[0].(map[string]any); first["id"] != q.ID || first["duplicate"] != true {
		t.Fatalf("%v", first)
	}
	if it, _ := r.InboxItem(q.ID); it.Batch != out["id"] {
		t.Fatalf("the waiting request didn't join: %+v", it)
	}
	if code, out := inboxDo(t, r, "POST", "/actions/requests/batch", batchBody("unlock", `{"intent": "unlock", "session": "sA"}`), false); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := inboxDo(t, r, "POST", "/actions/requests/batches/"+r.InboxBatches(&Caller{Kind: "actions"})[0].ID+"/deny", "", false); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
}

// a batch counts once toward the caller's limits: one of its 20 waiting requests, one of its 3 waiting proposals
func TestBatchLimits(t *testing.T) {
	rg, _ := newOpsRig(t)
	r := rg.r
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()
	items := []string{}
	for i := 0; i < batchMaxItems; i++ {
		items = append(items, fmt.Sprintf(`{"intent": "new-session", "requestId": "b%d", "prompt": "p%d"}`, i, i))
	}
	if code, out := m.do(t, h, "POST", "/m/api/requests/batch", batchBody("twenty", items...)); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	for i := 1; i <= 2; i++ {
		if code, out := m.do(t, h, "POST", "/m/api/sessions", fmt.Sprintf(`{"requestId":"s%d","prompt":"p","explanation":"e"}`, i)); code != 200 {
			t.Fatalf("proposal %d next to a batch: %d %v", i, code, out)
		}
	}
	waitFor(t, "approvals", func() bool {
		n := 0
		r.st.Do(func(d *persisted) { n = len(d.Approvals) })
		return n == batchMaxItems+2
	})
	if code, _ := m.do(t, h, "POST", "/m/api/sessions", `{"requestId":"s3","prompt":"p","explanation":"e"}`); code != 429 {
		t.Fatal("a fourth waiting proposal (a batch counts as one)")
	}
	if code, _ := m.do(t, h, "POST", "/m/api/requests/batch", batchBody("more", `{"intent": "new-session", "prompt": "p"}`)); code != 429 {
		t.Fatal("a batch proposing past the limit")
	}
	// requests: the batch is one of the caller's
	var reqs int
	r.st.Do(func(d *persisted) { reqs, _ = callerLoad(d, Caller{Kind: "session", Session: "sA"}) })
	if reqs != 1 {
		t.Fatalf("requests %d", reqs)
	}
}

// the whole batch goes after 10 minutes: its requests, its approvals (rejected), the batch itself
func TestBatchExpires(t *testing.T) {
	rg, _ := newOpsRig(t)
	r := rg.r
	addSession(r, "sA", "started", "mA", false)
	code, out := inboxDo(t, r, "POST", "/setup/requests/batch", batchBody("both",
		`{"intent": "unlock", "session": "sA"}`, `{"intent": "new-session", "prompt": "p", "label": "x"}`), false)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "approval", func() bool { bs := r.InboxBatches(nil); return len(bs) == 1 && len(bs[0].Items) == 2 })
	later := time.Now().UTC().Add(inboxTTL + time.Minute)
	r.expireApprovals(later)
	r.st.Do(func(d *persisted) {
		pruneRequests(d, later)
		pruneBatches(d, later)
		if len(d.Approvals) != 0 || len(d.Inbox) != 0 || len(d.Batches) != 0 {
			t.Fatalf("approvals %d inbox %d batches %d", len(d.Approvals), len(d.Inbox), len(d.Batches))
		}
	})
}
