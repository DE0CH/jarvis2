package main

// Message approvals (docs/DESIGN.md "Message approvals"; router/messages.go): a session holding a sensitive store takes
// an UPWARD peer message (words from a session holding less, or less permissive) only when Deyao's phone signed THAT
// message. A resume prompt (Deyao's own words, typed in the app) needs the phone's signature in every session: nothing
// else vouches for its bytes. Jarvis's own messages (Inbox outcomes, the watchdog, "continue", lease and upgrade notes),
// the session's own wakeups, crons and watches, and equal or downward peer messages go straight in (DECISIONS 210).
//
// What the phone signs (the key comes from this machine's core-signed cert, like a grant):
//
//   - {kind "messages", session <line>, items [{id, delivery, sha256, from, text}], issued, expires}: one Face ID for a
//     batch. The delivery is taken when one item names its kind, the sha256 of exactly the bytes the core attested,
//     and the very text this machine renders for it; the window is at most an hour (plus clock slack); each item id
//     is taken once (recorded in deliveredFile, which travels in the snapshot).
//   - {kind "message-rule", session <line>, delivery <kind>, issued, until}: every delivery of that one kind, until the
//     end (at most a year). Never for a peer message or a resume prompt: those are words from elsewhere.
//
// The router can only choose when to hand over what the phone signed; it can't change a byte of it.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	maxMessageWindow = time.Hour + 2*time.Minute        // a batch approval's issued → expires, with slack
	maxMessageRule   = 366*24*time.Hour + 2*time.Minute // a rule's issued → until
)

// MessageApproval: what the phone signs (router/messages.go drafts the same fields)
type MessageApproval struct {
	Kind     string        `json:"kind"` // messages | message-rule
	Session  string        `json:"session"`
	Items    []MessageItem `json:"items,omitempty"`
	Delivery string        `json:"delivery,omitempty"` // message-rule: the one kind
	Issued   string        `json:"issued"`
	Expires  string        `json:"expires,omitempty"` // messages
	Until    string        `json:"until,omitempty"`   // message-rule
}

type MessageItem struct {
	ID       string `json:"id"`
	Delivery string `json:"delivery"`
	Sha256   string `json:"sha256"`
	From     string `json:"from"`
	Text     string `json:"text"`
}

// unruleable: kinds no standing rule covers (their words come from another session, or from Deyao's app login)
var unruleable = map[string]bool{"peer": true, "resume-prompt": true}

// needsMessageApproval: this delivery must carry the phone's approval: a resume prompt in every session; in a session
// holding a sensitive store, an upward peer message (peer.go checks the direction against this machine's own cert).
// Jarvis's own messages and the session's own wakeups, crons and watches need none (DECISIONS 210): the core's
// attestation still vouches for every one
func needsMessageApproval(cert Cert, d Delivery) bool {
	switch d.Kind {
	case "resume-prompt":
		return true
	case "peer":
		return cert.Sensitive && d.Peer != nil && d.Peer.Direction == "upward"
	}
	return false
}

// errNeedsApproval: the machine's answer when a delivery came without (a valid) approval; the router files it for Deyao
var errNeedsApproval = errors.New("message approval needed")

// errTextDiffers: the phone signed another text than this machine renders (the router's preview was stale); the
// result carries this machine's text so the router can ask again
var errTextDiffers = errors.New("message approval: the signed text isn't the text this machine renders")

// checkMessageApproval: nil (and the item id to record once delivered, "" for a rule) when the phone approved exactly
// this delivery; text is what this machine would put into the harness, attested the bytes the core attested
func checkMessageApproval(cert Cert, d Delivery, attested []byte, text string, now time.Time) (string, error) {
	if !needsMessageApproval(cert, d) {
		return "", nil
	}
	why := "this session holds a sensitive store, so Deyao approves each message from a session holding less on the phone"
	if !cert.Sensitive {
		why = "a resume prompt is delivered only as the phone approved it"
	}
	if d.Approval == nil {
		return "", fmt.Errorf("%w: %s", errNeedsApproval, why)
	}
	var a MessageApproval
	if cert.Phone == "" || verifyDoc(cert.Phone, d.Approval, &a) != nil {
		return "", fmt.Errorf("%w: the approval isn't signed by the phone named in this machine's cert", errNeedsApproval)
	}
	if cert.Line == "" || a.Session != cert.Line {
		return "", fmt.Errorf("%w: the approval is for another session", errNeedsApproval)
	}
	iss, err := time.Parse(time.RFC3339, a.Issued)
	if err != nil || now.Before(iss.Add(-2*time.Minute)) {
		return "", fmt.Errorf("%w: the approval has no issue time, or one in the future", errNeedsApproval)
	}
	switch a.Kind {
	case "message-rule":
		u, err := time.Parse(time.RFC3339, a.Until)
		if err != nil || !now.Before(u) || u.Sub(iss) > maxMessageRule {
			return "", fmt.Errorf("%w: the rule has ended (or is longer than a year)", errNeedsApproval)
		}
		if a.Delivery != d.Kind || unruleable[d.Kind] {
			return "", fmt.Errorf("%w: the rule is for another kind of message (%s), and no rule covers a %s", errNeedsApproval, a.Delivery, d.Kind)
		}
		return "", nil
	case "messages":
		exp, err := time.Parse(time.RFC3339, a.Expires)
		if err != nil || !now.Before(exp) || exp.Sub(iss) > maxMessageWindow {
			return "", fmt.Errorf("%w: the approval has expired (it lasts an hour)", errNeedsApproval)
		}
		sum := sha256.Sum256(attested)
		h := hex.EncodeToString(sum[:])
		used := readDelivered()
		for _, it := range a.Items {
			if it.Delivery != d.Kind || it.Sha256 != h {
				continue
			}
			if it.ID == "" || used["message "+it.ID] != (delivered{}) {
				return "", fmt.Errorf("%w: this approval was already used", errNeedsApproval)
			}
			if it.Text != text {
				return "", errTextDiffers
			}
			return it.ID, nil
		}
		return "", fmt.Errorf("%w: the approval names other messages", errNeedsApproval)
	}
	return "", fmt.Errorf("%w: not an approval", errNeedsApproval)
}

// recordApproved: the item's approval is used up (deliveredFile, under deliveredMu)
func recordApproved(id string, now time.Time) error {
	if id == "" {
		return nil
	}
	deliveredMu.Lock()
	defer deliveredMu.Unlock()
	seen := readDelivered()
	seen["message "+id] = delivered{At: now.Unix()}
	b, _ := json.Marshal(seen)
	home, _ := os.UserHomeDir()
	return os.WriteFile(filepath.Join(home, deliveredFile), b, 0o600)
}
