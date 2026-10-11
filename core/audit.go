package main

// The input log (Deyao, 2026-10-11): every input a machine takes after it starts — a prompt, a wakeup/cron/watch
// prompt, a peer message, an attachment, a new cert — carries the core's signature over (machine, input hash, kind,
// origin), and the machine refuses an input without one. The core appends each to a hash chain: every entry names
// the hash of the one before. The core keeps only the head and the length: each entry leaves in the answer that made it
// (attest's answer; beside each cert), and the router persists them (append-only) so the log outlives a core restart,
// noting on its own where a new core's chain begins. The core only hashes, signs and appends: it
// never parses or judges an input — whether the input is vouched for (the cert, the machine's own key, the
// predecessor's signature, a trusted provider) is the machine's check.

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"
)

type AuditEntry struct {
	Kind    string `json:"kind"` // "input"
	Seq     int    `json:"seq"`
	Prev    string `json:"prev"` // sha256 of the previous entry's payload ("" = the first)
	At      string `json:"at"`
	Machine string `json:"machine"`
	Input   string `json:"input"`  // what it is: prompt, wakeup, cron, watch, peer, attachment, cert, continues…
	Origin  string `json:"origin"` // who vouches / where it came from (the caller's word, recorded as given)
	Sha256  string `json:"sha256"` // of the input's exact bytes
}

var auditWordRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._@/-]{0,127}$`)

// appendAudit: hash, sign, append (callers hold c.mu)
func (c *Core) appendAudit(machine, input, origin, sum string) (SignedDoc, error) {
	e := AuditEntry{Kind: "input", Seq: c.auditSeq, Prev: c.auditHead, At: c.now().UTC().Format(time.RFC3339Nano),
		Machine: machine, Input: input, Origin: origin, Sha256: sum}
	d, err := c.sign(e)
	if err != nil {
		return SignedDoc{}, err
	}
	h := sha256.Sum256([]byte(d.Payload))
	c.auditHead, c.auditSeq = hex.EncodeToString(h[:]), c.auditSeq+1
	return d, nil
}

// Attest: open (normally the router, before it hands an input to a machine). Signs what it is given; the machine
// checks the machine id, the kind and the hash against the input it holds.
func (c *Core) Attest(machine, input, origin, sum string) (SignedDoc, error) {
	if !auditWordRE.MatchString(machine) || !auditWordRE.MatchString(input) || !auditWordRE.MatchString(origin) || !hex64RE.MatchString(sum) {
		return SignedDoc{}, fail(400, "attest: machine, input and origin are words, sha256 is 64 hex")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendAudit(machine, input, origin, sum)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
