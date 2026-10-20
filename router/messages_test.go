package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// msgRig: a router with a core that attests, one STARTED session s1 on machine `machine` whose cert names the phone
// key and (sensitive) a sensitive store, and a fake machine that answers each delivery with answer(d)
type msgRig struct {
	r     *Router
	phone *ecdh.PrivateKey
	mu    sync.Mutex
	got   []Delivery
	dms   *[]string
}

func newMsgRig(t *testing.T, machine string, sensitive bool, answer func(d Delivery) DeliveryResult) *msgRig {
	rg, _ := v2Rig(t)
	m := &msgRig{r: rg.r, dms: captureDM(t)}
	m.phone, _ = ecdh.P256().GenerateKey(rand.Reader)
	cert, _ := json.Marshal(map[string]any{"kind": "succession-cert", "line": "L1", "sensitive": sensitive,
		"phone": base64.StdEncoding.EncodeToString(m.phone.PublicKey().Bytes())})
	m.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Cert = "started", machine, &Doc{Payload: string(cert)}
		d.Machines[machine] = "s1"
	})
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case d := <-deliveryQueue(machine):
				m.mu.Lock()
				m.got = append(m.got, d)
				m.mu.Unlock()
				res := answer(d)
				res.ID = d.ID
				deliveries.Lock()
				ch := deliveries.results[d.ID]
				deliveries.Unlock()
				if ch != nil {
					ch <- res
				}
			}
		}
	}()
	t.Cleanup(func() { messageWG.Wait(); close(stop) })
	return m
}

func (m *msgRig) deliveries() []Delivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Delivery{}, m.got...)
}

func (m *msgRig) pending() []*PendingMessage {
	out := []*PendingMessage{}
	m.r.st.Do(func(d *persisted) {
		for _, pm := range d.Messages {
			x := *pm
			out = append(out, &x)
		}
	})
	return out
}

// sign: what the phone does with a draft
func (m *msgRig) sign(t *testing.T, text string) *Doc {
	sig, err := signP256(m.phone, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return &Doc{Payload: text, Sig: sig}
}

// previewOK: the machine renders the canned text the router would (its preview), and takes approved deliveries
func previewOK(d Delivery) DeliveryResult {
	if d.Preview {
		in, _, _ := attested(d)
		return DeliveryResult{OK: true, Text: string(in)}
	}
	return DeliveryResult{OK: true}
}

func TestAMessageIntoASensitiveSessionWaitsForDeyao(t *testing.T) {
	m := newMsgRig(t, "mmsg1", true, previewOK)
	// the watchdog's check-in: held (the caller sees it handed over), with the machine's own text
	if err := m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 20, Jobs: 2}, ""); err != nil {
		t.Fatal(err)
	}
	ps := m.pending()
	want := nudgeText(2, 20*time.Minute)
	if len(ps) != 1 || ps[0].Kind != "nudge" || ps[0].Text != want || ps[0].State != "pending" || !strings.Contains(ps[0].From, "watchdog") {
		t.Fatalf("held %+v", ps)
	}
	if ds := m.deliveries(); len(ds) != 1 || !ds[0].Preview || ds[0].Attest != nil {
		t.Fatalf("only a preview reached the machine: %+v", ds)
	}
	if len(*m.dms) != 1 || !strings.Contains((*m.dms)[0], "Watchdog check-in") {
		t.Fatalf("dm %q", *m.dms)
	}
	// it is in the Inbox, under its session, with the exact text and who asks
	var it *InboxItem
	for _, x := range m.r.Inbox() {
		if x.Kind == requestKindMsg {
			x := x
			it = &x
		}
	}
	if it == nil || it.Session != "s1" || it.Params.Text != want || it.CallerText != ps[0].From || it.Explanation != "Watchdog check-in" {
		t.Fatalf("inbox %+v", it)
	}
	// the next check-in replaces it (one DM per session while any waits)
	m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 35, Jobs: 2}, "")
	if ps2 := m.pending(); len(ps2) != 1 || ps2[0].ID == ps[0].ID || ps2[0].Text != nudgeText(2, 35*time.Minute) || len(*m.dms) != 1 {
		t.Fatalf("not replaced: %+v (dms %d)", ps2, len(*m.dms))
	}

	// Deliver: the phone signs the draft; the machine gets exactly that message with the signature, attested
	id := m.pending()[0].ID
	text, sid, line, err := m.r.DraftMessages([]string{id})
	if err != nil || sid != "s1" || line != "L1" {
		t.Fatal(err)
	}
	var a messageApproval
	json.Unmarshal([]byte(text), &a)
	sum := sha256.Sum256([]byte(nudgeText(2, 35*time.Minute)))
	if a.Kind != "messages" || a.Session != "L1" || len(a.Items) != 1 || a.Items[0].Sha256 != hex.EncodeToString(sum[:]) || a.Items[0].Text != nudgeText(2, 35*time.Minute) {
		t.Fatalf("draft %s", text)
	}
	stranger, _ := ecdh.P256().GenerateKey(rand.Reader)
	ssig, _ := signP256(stranger, []byte(text))
	if _, err := m.r.ApproveMessages(&Doc{Payload: text, Sig: ssig}); err == nil {
		t.Fatal("took another key's signature")
	}
	doc := m.sign(t, text)
	if ids, err := m.r.ApproveMessages(doc); err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	messageWG.Wait()
	ds := m.deliveries()
	last := ds[len(ds)-1]
	if last.Preview || last.Kind != "nudge" || last.Approval == nil || last.Approval.Payload != text || last.Attest == nil {
		t.Fatalf("delivered %+v", last)
	}
	if len(m.pending()) != 0 {
		t.Fatal("a delivered message stays")
	}
	if _, err := m.r.ApproveMessages(doc); err == nil {
		t.Fatal("the same approval twice")
	}
}

func TestAPausedSensitiveSessionIsntStartedToHoldAMessage(t *testing.T) {
	m := newMsgRig(t, "mmsg2", true, previewOK)
	m.r.st.Do(func(d *persisted) { d.Sessions["s1"].State, d.Sessions["s1"].MachineID = "paused", "" })
	body := []byte(`{"name":"ci","prompt":"check   the CI","delaySeconds":60}`)
	signed := &SignedRequest{Machine: "mmsg2", Method: "POST", Path: "/m/api/sessions/s1/wakeup", At: "1", Body: base64.StdEncoding.EncodeToString(body), Sig: "sg"}
	if err := m.r.deliverVouched("s1", Delivery{Kind: "wakeup", Request: signed}); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.r.sessionState("s1"); st != "paused" {
		t.Fatalf("started it: %s", st)
	}
	ps := m.pending()
	if len(ps) != 1 || ps[0].Text != `[scheduled wakeup "ci"] check the CI` || ps[0].Origin == nil || ps[0].Origin.Signed != signed {
		t.Fatalf("%+v", ps)
	}
	// Deny: nothing goes in; the session hears it as the outcome of the request that armed the wakeup
	if got := m.r.DenyMessages([]string{ps[0].ID}); len(got) != 1 {
		t.Fatal("not denied")
	}
	var oc []*Outcome
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["s1"] })
	if len(m.pending()) != 0 || len(oc) != 1 || oc[0].Outcome != outcomeDenied || oc[0].Ref != ps[0].ID || oc[0].Request != signed {
		t.Fatalf("outcomes %+v", oc)
	}
	if len(m.deliveries()) != 0 {
		t.Fatal("something reached the machine")
	}
}

func TestADeliveryIntoAPlainSessionIsntHeldButAResumePromptIs(t *testing.T) {
	m := newMsgRig(t, "mmsg3", false, previewOK)
	if err := m.r.DeliverCanned("s1", Delivery{Kind: "continue"}, ""); err != nil {
		t.Fatal(err)
	}
	if ds := m.deliveries(); len(ds) != 1 || ds[0].Preview || ds[0].Approval != nil || len(m.pending()) != 0 {
		t.Fatalf("%+v", ds)
	}
	if err := m.r.deliverVouched("s1", Delivery{Kind: "resume-prompt", Text: "carry on"}); err != nil {
		t.Fatal(err)
	}
	if ps := m.pending(); len(ps) != 1 || ps[0].Kind != "resume-prompt" || ps[0].Text != "carry on" || ruleText("resume-prompt") != "" {
		t.Fatalf("%+v", ps)
	}
}

func TestARuleDeliversItsKindAndOnlyThat(t *testing.T) {
	m := newMsgRig(t, "mmsg4", true, previewOK)
	m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 20, Jobs: 1}, "")
	m.r.DeliverCanned("s1", Delivery{Kind: "continue"}, "")
	if len(m.pending()) != 2 {
		t.Fatal(m.pending())
	}
	if _, err := m.r.DraftMessageRule("s1", "peer"); err == nil {
		t.Fatal("a rule for peer messages")
	}
	text, err := m.r.DraftMessageRule("s1", "nudge")
	if err != nil {
		t.Fatal(err)
	}
	rule, err := m.r.AddMessageRule("s1", m.sign(t, text))
	if err != nil || rule.Kind != "nudge" {
		t.Fatal(err)
	}
	messageWG.Wait()
	// the held check-in went in under the rule; "continue" still waits
	if ps := m.pending(); len(ps) != 1 || ps[0].Kind != "continue" {
		t.Fatalf("%+v", ps)
	}
	// the next check-in goes straight in under the rule
	n := len(m.deliveries())
	m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 40, Jobs: 1}, "")
	ds := m.deliveries()
	if len(ds) != n+1 || ds[n].Preview || ds[n].Approval == nil || ds[n].Approval.Payload != text {
		t.Fatalf("%+v", ds[n:])
	}
	var v map[string]any = map[string]any{}
	m.r.st.Do(func(d *persisted) { messagesView(d, "s1", v) })
	if v["pendingMessages"] != 1 || len(v["messageRules"].([]map[string]any)) != 1 {
		t.Fatalf("%v", v)
	}
	// removed: the router stops using it at once
	m.r.ForgetMessageRule(rule.ID)
	m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 55, Jobs: 1}, "")
	if ds := m.deliveries(); len(ds) != n+2 || !ds[n+1].Preview {
		t.Fatalf("delivered under a removed rule: %+v", ds[n+1:])
	}
}

func TestABatchOfMessagesUnderOneSignature(t *testing.T) {
	m := newMsgRig(t, "mmsg5", true, previewOK)
	m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 20, Jobs: 1}, "")
	m.r.DeliverCanned("s1", Delivery{Kind: "continue"}, "")
	ids := []string{}
	for _, pm := range m.pending() {
		ids = append(ids, pm.ID)
	}
	text, _, _, err := m.r.DraftMessages(ids)
	if err != nil {
		t.Fatal(err)
	}
	// a tampered item (another text than the one held) is refused
	bad := strings.Replace(text, `"continue"`, `"continue now"`, 1)
	if _, err := m.r.ApproveMessages(m.sign(t, bad)); err == nil {
		t.Fatal("took a changed text")
	}
	if got, err := m.r.ApproveMessages(m.sign(t, text)); err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	messageWG.Wait()
	sigs := map[string]bool{}
	for _, d := range m.deliveries() {
		if !d.Preview {
			sigs[d.Approval.Sig] = true
		}
	}
	if len(m.pending()) != 0 || len(sigs) != 1 {
		t.Fatalf("pending %d, signatures %d", len(m.pending()), len(sigs))
	}
	// one session at a time
	m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 30, Jobs: 1}, "")
	m.r.st.Do(func(d *persisted) {
		d.Messages["mqother"] = &PendingMessage{ID: "mqother", Session: "s2", Kind: "continue", State: "pending", Expires: time.Now().Add(time.Hour)}
	})
	if _, _, _, err := m.r.DraftMessages([]string{m.pending()[0].ID, "mqother"}); err == nil {
		t.Fatal("drafted two sessions' messages together")
	}
}

func TestMessagesLapseAndApprovalsRunOut(t *testing.T) {
	m := newMsgRig(t, "mmsg6", true, func(d Delivery) DeliveryResult {
		if d.Preview {
			in, _, _ := attested(d)
			return DeliveryResult{OK: true, Text: string(in)}
		}
		return DeliveryResult{Error: "target gone"} // the approved delivery fails
	})
	body := []byte(`{"name":"ci","prompt":"x","script":"true"}`)
	signed := &SignedRequest{Machine: "mmsg6", Method: "POST", Path: "/m/api/sessions/s1/watches", At: "1", Body: base64.StdEncoding.EncodeToString(body), Sig: "w"}
	m.r.st.Do(func(d *persisted) { d.Sessions["s1"].State = "paused" }) // rendered by the router's twin
	m.r.deliverVouched("s1", Delivery{Kind: "watch", Request: signed})
	m.r.st.Do(func(d *persisted) { d.Sessions["s1"].State = "started" })
	ps := m.pending()
	if len(ps) != 1 || ps[0].Text != `[watch "ci" met] x` || ps[0].Note == "" {
		t.Fatalf("%+v", ps)
	}
	// a day on, nobody answered: it lapses and the session hears so
	m.r.messageTickOnce(time.Now().Add(messageTTL + time.Minute))
	var oc []*Outcome
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["s1"] })
	if len(m.pending()) != 0 || len(oc) != 1 || oc[0].Outcome != outcomeLapsed {
		t.Fatalf("%+v", oc)
	}
	// approved but the machine fails it: failed, and the session hears so
	m.r.DeliverCanned("s1", Delivery{Kind: "continue"}, "")
	id := m.pending()[0].ID
	text, _, _, _ := m.r.DraftMessages([]string{id})
	m.r.ApproveMessages(m.sign(t, text))
	messageWG.Wait()
	if ps := m.pending(); len(ps) != 1 || ps[0].State != "failed" || !strings.Contains(ps[0].Error, "target gone") {
		t.Fatalf("%+v", ps)
	}
}

// the machine renders another text than the phone signed: it refuses with its own, and that one is held for Deyao
func TestATextTheMachineRendersDifferentlyIsHeldAgain(t *testing.T) {
	m := newMsgRig(t, "mmsg7", true, func(d Delivery) DeliveryResult {
		if d.Preview {
			return DeliveryResult{OK: true, Text: "continue"}
		}
		return DeliveryResult{Error: "message approval: the signed text isn't the text this machine renders", NeedsApproval: true, Text: "the machine's text"}
	})
	m.r.DeliverCanned("s1", Delivery{Kind: "continue"}, "")
	id := m.pending()[0].ID
	text, _, _, _ := m.r.DraftMessages([]string{id})
	if _, err := m.r.ApproveMessages(m.sign(t, text)); err != nil {
		t.Fatal(err)
	}
	messageWG.Wait()
	ps := m.pending()
	if len(ps) != 1 || ps[0].ID == id || ps[0].State != "pending" || ps[0].Text != "the machine's text" {
		t.Fatalf("%+v", ps)
	}
}

// a peer message into a session holding a sensitive store isn't a one-tap upward request: Deyao signs the message
func TestAPeerMessageIntoASensitiveSessionIsHeld(t *testing.T) {
	m := newMsgRig(t, "mmsg8", true, func(d Delivery) DeliveryResult {
		if d.Preview {
			return DeliveryResult{OK: true, Text: "[Message from another Jarvis 2 session] " + d.Peer.Text}
		}
		return DeliveryResult{OK: true}
	})
	addSession(m.r, "sfrom", "started", "mfrom", false)
	out, err := m.r.SendPeer("sfrom", "s1", "please run the report", &SignedRequest{Machine: "mfrom", Method: "POST", Path: "/m/api/requests/peer", Sig: "p"}, "POST", "/m/api/requests/peer")
	if err != nil || out["waiting"] != "message" {
		t.Fatal(out, err)
	}
	var ps []*PendingMessage
	for i := 0; i < 100 && len(ps) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		ps = m.pending()
	}
	if len(ps) != 1 || ps[0].Kind != "peer" || !ps[0].Delivery.Peer.Approved || ps[0].Origin == nil || ps[0].Origin.Caller.Session != "sfrom" {
		t.Fatalf("%+v", ps)
	}
	for _, q := range m.r.Inbox() {
		if q.Kind == requestKindPeer {
			t.Fatal("also filed as an upward peer request")
		}
	}
	m.r.DenyMessages([]string{ps[0].ID})
	var oc []*Outcome
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["sfrom"] })
	if len(oc) != 1 || oc[0].Outcome != outcomeDenied || oc[0].Kind != requestKindPeer {
		t.Fatalf("the sender wasn't told: %+v", oc)
	}
	if !errors.Is(handedOver(errAwaitingApproval), nil) {
		t.Fatal("held counts as handed over")
	}
}

// the router's twins render what machine/deliver.go deliveryText renders (its tests pin the same strings)
func TestMessageTextTwins(t *testing.T) {
	req := func(path, body string) *SignedRequest {
		return &SignedRequest{Method: "POST", Path: path, Body: base64.StdEncoding.EncodeToString([]byte(body))}
	}
	for d, want := range map[*Delivery]string{
		{Kind: "cron", Run: 3, Request: req("/m/api/sessions/s1/crons", `{"name":"daily","prompt":"report","everySeconds":86400}`)}: `[recurring wakeup "daily" — run 3] report`,
		{Kind: "wakeup", Request: req("/m/api/sessions/s1/wakeup", `{"prompt":"go  on"}`)}:                                          `go on`,
		{Kind: "watch-fail", Request: req("/m/api/sessions/s1/watches", `{"name":"ci","prompt":"x","failPrompt":"look"}`)}:          `[watch "ci" gave up] look`,
		{Kind: "upgraded", From: "medium", To: "large"}:                                                                             upgradedText("medium", "large"),
	} {
		if got, _, _, ok := messageText(*d); !ok || got != want {
			t.Fatalf("%s: %q", d.Kind, got)
		}
	}
}

// oldImageMachine: a machine on an image from before message approvals (2026-10-20, s6056456f64d9d2df): it knows no
// preview, so it takes the router's preview as a delivery and refuses it for want of the core's attestation; an
// attested delivery it takes (it checks no phone approval)
func oldImageMachine(d Delivery) DeliveryResult {
	if d.Attest == nil {
		return DeliveryResult{Error: "no core attestation (the input isn't in the core's log)"}
	}
	return DeliveryResult{OK: true}
}

// An upward peer message into a sensitive session whose machine can't preview was reported FAILED to its sender
// within 0.2 s, before Deyao ever saw it ("It was approved but carrying it out failed", the Paseo test session's two
// replies to "Jarvis 2 works", 2026-10-20). It is held with Jarvis's own rendering instead, and delivered once Deyao
// delivers it; the same for Jarvis's other messages into such a session.
func TestAMessageIntoAnOldImageMachineIsHeldWithJarvisText(t *testing.T) {
	m := newMsgRig(t, "mmsg9", true, oldImageMachine)
	addSession(m.r, "sfrom", "started", "mfrom", false)
	out, err := m.r.SendPeer("sfrom", "s1", "test step 2 could not run", &SignedRequest{Machine: "mfrom", Method: "POST", Path: "/m/api/requests/peer", Sig: "p"}, "POST", "/m/api/requests/peer")
	if err != nil || out["waiting"] != "message" {
		t.Fatal(out, err)
	}
	var ps []*PendingMessage
	for i := 0; i < 200 && len(ps) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		ps = m.pending()
	}
	var oc []*Outcome
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["sfrom"] })
	if len(oc) != 0 {
		t.Fatalf("the sender was told %s before Deyao saw the message", oc[0].Outcome)
	}
	if len(ps) != 1 || ps[0].Kind != "peer" || ps[0].State != "pending" || !strings.Contains(ps[0].Text, "test step 2 could not run") ||
		!strings.Contains(ps[0].Text, "relayed by Jarvis") || !strings.Contains(ps[0].Note, "before message approvals") {
		t.Fatalf("not held with Jarvis's text: %+v", ps)
	}
	text, _, _, err := m.r.DraftMessages([]string{ps[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.r.ApproveMessages(m.sign(t, text)); err != nil {
		t.Fatal(err)
	}
	messageWG.Wait()
	ds := m.deliveries()
	last := ds[len(ds)-1]
	if last.Preview || last.Kind != "peer" || last.Attest == nil || last.Peer == nil || !last.Peer.Approved {
		t.Fatalf("delivered %+v", last)
	}
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["sfrom"] })
	if len(oc) != 1 || oc[0].Outcome != outcomeApproved || len(m.pending()) != 0 {
		t.Fatalf("outcomes %+v, pending %+v", oc, m.pending())
	}

	// Jarvis's own kinds too: the watchdog's check-in is held with the router's twin of the text
	if err := m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 20, Jobs: 2}, ""); err != nil {
		t.Fatal(err)
	}
	if ps := m.pending(); len(ps) != 1 || ps[0].Kind != "nudge" || ps[0].Text != nudgeText(2, 20*time.Minute) {
		t.Fatalf("nudge %+v", ps)
	}
}
