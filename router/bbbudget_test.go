package main

import (
	"strings"
	"testing"
	"time"
)

func TestBBUsageAndOverage(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	ss := []bbSession{
		{CreatedAt: "2026-10-01T00:00:00Z", StartedAt: "2026-10-01T00:00:00Z", EndedAt: "2026-10-01T00:00:30Z", ProxyBytes: 400}, // 1 min, 1 MB
		{CreatedAt: "2026-10-02T00:00:00Z", StartedAt: "2026-10-02T00:00:00Z", Status: "COMPLETED", UpdatedAt: "2026-10-02T01:00:01Z"},
		{CreatedAt: "2026-10-20T11:00:00Z", Status: "RUNNING"},                                                  // up to now: 60 min
		{CreatedAt: "2026-09-30T23:59:00Z", StartedAt: "2026-09-30T23:59:00Z", EndedAt: "2026-10-01T05:00:00Z"}, // last month
	}
	u := bbCycleUsage(ss, "2026-10", now)
	if u.Count != 3 || u.Minutes != 1+61+60 || u.ProxyMB != 1 || u.ProxyBytes != 400 {
		t.Fatalf("%+v", u)
	}
	o := bbOverageOf(bbUsage{Minutes: 7000, ProxyMB: 1500, ProxyBytes: 2e9})
	if o.Time != 2 || o.ProxyMB != 6 || o.ProxyBytes != 20 || o.Total != 28 {
		t.Fatalf("%+v", o)
	}
	if c, w := bbThresholds(func(k string) string { return map[string]string{"BROWSERBASE_BUDGET_USD": "10"}[k] }); c != 10 || w != 8 {
		t.Fatal(c, w)
	}
	if c, _ := bbThresholds(func(string) string { return "" }); c != 0 {
		t.Fatal("on without a cap")
	}
}

func TestBBBudgetDMsOncePerMonth(t *testing.T) {
	r := newTestRouter(t)
	var dms []string
	old := budgetDM
	budgetDM = func(r *Router, text string) { dms = append(dms, text) }
	t.Cleanup(func() { budgetDM = old })
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	// 6,000 included minutes + 4,500 over = USD 9 → warn (8), then 5,500 over = USD 11 → cap (10)
	long := func(min int) []bbSession {
		start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		return []bbSession{{CreatedAt: start.Format(time.RFC3339), StartedAt: start.Format(time.RFC3339),
			EndedAt: start.Add(time.Duration(min) * time.Minute).Format(time.RFC3339)}}
	}
	r.bbBudgetTick(long(1000), now, 10, 8)
	r.bbBudgetTick(long(10500), now, 10, 8)
	r.bbBudgetTick(long(10600), now, 10, 8)
	r.bbBudgetTick(long(11500), now, 10, 8)
	r.bbBudgetTick(long(11600), now, 10, 8)
	if len(dms) != 2 || !strings.Contains(dms[0], "Browserbase spend: estimated overage USD 9.00 of the USD 10.00 cap") ||
		!strings.Contains(dms[1], "Browserbase spend cap reached: estimated overage USD 11.00") {
		t.Fatalf("%q", dms)
	}
	// a new month starts afresh
	r.bbBudgetTick(long(11600), now.AddDate(0, 1, 0), 10, 8)
	if len(dms) != 2 {
		t.Fatalf("a DM for a month with no usage: %q", dms)
	}
}
