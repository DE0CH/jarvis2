package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// Message approvals (messages.go): a session holding a sensitive store takes a delivery only when the phone signed that
// very message (its kind, the attested bytes' hash, the exact text) or a rule for its kind; a resume prompt needs it in
// every session
func TestMessageApprovals(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	phone, stranger := newKey(), newKey()
	cert := Cert{Phone: phone.pub(), Line: "L1", Sensitive: true}
	now := time.Now()
	ts := func(d time.Duration) string { return now.Add(d).UTC().Format(time.RFC3339) }
	d := Delivery{Kind: "nudge", Minutes: 30, Jobs: 2}
	text, attested, err := deliveryText(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(attested)
	h := hex.EncodeToString(sum[:])
	batch := func(k tkey, line string, items []MessageItem, exp time.Duration) *SignedDoc {
		return k.doc(MessageApproval{Kind: "messages", Session: line, Items: items, Issued: ts(0), Expires: ts(exp)})
	}
	item := MessageItem{ID: "mq1", Delivery: "nudge", Sha256: h, From: "Jarvis's watchdog", Text: text}
	check := func(a *SignedDoc, dl Delivery) (string, error) {
		dl.Approval = a
		return checkMessageApproval(cert, dl, attested, text, now)
	}

	// none: refused, saying what is needed
	if _, err := check(nil, d); !errors.Is(err, errNeedsApproval) || !strings.Contains(err.Error(), "sensitive store") {
		t.Fatalf("no approval: %v", err)
	}
	// the phone's batch naming it: taken, with the item to record
	ok := batch(phone, "L1", []MessageItem{{ID: "mq0", Delivery: "cron", Sha256: h, Text: text}, item}, time.Hour)
	if id, err := check(ok, d); err != nil || id != "mq1" {
		t.Fatalf("approved: %q %v", id, err)
	}
	// refused: another key, another line, expired, a window over an hour, other bytes, another kind
	for name, a := range map[string]*SignedDoc{
		"stranger":    batch(stranger, "L1", []MessageItem{item}, time.Hour),
		"other line":  batch(phone, "L2", []MessageItem{item}, time.Hour),
		"expired":     phone.doc(MessageApproval{Kind: "messages", Session: "L1", Items: []MessageItem{item}, Issued: ts(-2 * time.Hour), Expires: ts(-time.Hour)}),
		"too long":    batch(phone, "L1", []MessageItem{item}, 3*time.Hour),
		"other bytes": batch(phone, "L1", []MessageItem{{ID: "mq1", Delivery: "nudge", Sha256: strings.Repeat("0", 64), Text: text}}, time.Hour),
		"other kind":  batch(phone, "L1", []MessageItem{{ID: "mq1", Delivery: "continue", Sha256: h, Text: text}}, time.Hour),
		"a grant":     phone.doc(Grant{Kind: "grant", Session: "L1", Scope: "shell", Issued: ts(0), Expires: ts(time.Minute)}),
	} {
		if _, err := check(a, d); !errors.Is(err, errNeedsApproval) {
			t.Fatalf("%s: took it (%v)", name, err)
		}
	}
	// the right bytes but another text than this machine renders: refused, so the router can show Deyao this one
	if _, err := check(batch(phone, "L1", []MessageItem{{ID: "mq1", Delivery: "nudge", Sha256: h, Text: "something else"}}, time.Hour), d); !errors.Is(err, errTextDiffers) {
		t.Fatalf("other text: %v", err)
	}
	// once used, never again
	if err := recordApproved("mq1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := check(ok, d); !errors.Is(err, errNeedsApproval) || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("reused: %v", err)
	}

	// a rule for the kind: every nudge, until it ends; never another kind, never a peer message or resume prompt
	rule := func(k tkey, kind string, until time.Duration) *SignedDoc {
		return k.doc(MessageApproval{Kind: "message-rule", Session: "L1", Delivery: kind, Issued: ts(0), Until: ts(until)})
	}
	if id, err := check(rule(phone, "nudge", 24*time.Hour), d); err != nil || id != "" {
		t.Fatalf("rule: %q %v", id, err)
	}
	for name, a := range map[string]*SignedDoc{
		"ended":      rule(phone, "nudge", -time.Minute),
		"two years":  rule(phone, "nudge", 2*366*24*time.Hour),
		"other kind": rule(phone, "continue", time.Hour),
		"stranger":   rule(stranger, "nudge", time.Hour),
	} {
		if _, err := check(a, d); !errors.Is(err, errNeedsApproval) {
			t.Fatalf("rule %s: took it (%v)", name, err)
		}
	}
	if _, err := checkMessageApproval(cert, Delivery{Kind: "peer", Approval: rule(phone, "peer", time.Hour)}, attested, text, now); !errors.Is(err, errNeedsApproval) {
		t.Fatalf("a rule covered a peer message: %v", err)
	}

	// a session without a sensitive store takes it unapproved; a resume prompt never
	plain := Cert{Phone: phone.pub(), Line: "L1"}
	if _, err := checkMessageApproval(plain, d, attested, text, now); err != nil {
		t.Fatal(err)
	}
	rp := Delivery{Kind: "resume-prompt", Text: "  carry on with the report\r\n"}
	rt, ra, err := deliveryText(rp, nil)
	if err != nil || rt != "carry on with the report" || string(ra) != rt {
		t.Fatalf("resume prompt %q %v", rt, err)
	}
	if _, err := checkMessageApproval(plain, rp, ra, rt, now); !errors.Is(err, errNeedsApproval) {
		t.Fatalf("an unapproved resume prompt: %v", err)
	}
	rs := sha256.Sum256(ra)
	rp.Approval = phone.doc(MessageApproval{Kind: "messages", Session: "L1", Issued: ts(0), Expires: ts(time.Hour),
		Items: []MessageItem{{ID: "mq9", Delivery: "resume-prompt", Sha256: hex.EncodeToString(rs[:]), Text: rt}}})
	if id, err := checkMessageApproval(plain, rp, ra, rt, now); err != nil || id != "mq9" {
		t.Fatalf("approved resume prompt: %q %v", id, err)
	}
	if _, _, err := deliveryText(Delivery{Kind: "resume-prompt", Text: strings.Repeat("x", 4001)}, nil); err == nil {
		t.Fatal("took a resume prompt over 4000 characters")
	}
}

// the preview renders exactly the text a delivery would put in, and records nothing
func TestPreviewRendersWithoutTakingIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	old := currentCert
	currentCert = func() (Cert, error) { return Cert{Line: "L1", Sensitive: true}, nil }
	t.Cleanup(func() { currentCert = old })
	text, errText := previewDelivery(Delivery{Kind: "nudge", Minutes: 15, Jobs: 1})
	if errText != "" || !strings.HasPrefix(text, "Jarvis watchdog: this session has been idle for 15 min while 1 background job has") {
		t.Fatalf("%q %s", text, errText)
	}
	if _, errText := previewDelivery(Delivery{Kind: "wakeup"}); errText == "" {
		t.Fatal("previewed a wakeup with no signed request")
	}
	if len(readDelivered()) != 0 {
		t.Fatal("a preview recorded something")
	}
}

// a denied (or lapsed) message of the session's own wakeup, cron or watch comes back as an Inbox outcome of the request
// that armed it
func TestADeniedWakeupMessageIsAnOutcome(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mine := newKey()
	old := currentCert
	currentCert = func() (Cert, error) { return Cert{Line: "L1", Sensitive: true}, nil }
	t.Cleanup(func() { currentCert = old })
	for path, want := range map[string]string{
		"/m/api/sessions/s1/wakeup":  `DENIED: the message of this session's wakeup "ci"`,
		"/m/api/sessions/s1/crons":   `DENIED: a run's message of this session's recurring wakeup "ci"`,
		"/m/api/sessions/s1/watches": `DENIED: the message of this session's watch "ci"`,
	} {
		r := signedRequest(mine, "m1", "POST", path, []byte(`{"name":"ci","prompt":"check","script":"true"}`))
		s, _, err := deliveryText(Delivery{Kind: "request-outcome", Request: r, Outcomes: []OutcomeItem{{Outcome: "denied", Ref: "mq1"}}}, []string{mine.pub()})
		if err != nil || !strings.Contains(s, want) || !strings.Contains(s, "(Inbox mq1)") {
			t.Fatalf("%s: %q %v", path, s, err)
		}
	}
}
