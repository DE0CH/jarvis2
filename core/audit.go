package main

// The input log (Deyao, 2026-10-11): every input a machine takes after it starts — a prompt, a wakeup/cron/watch
// prompt, a peer message, an attachment, a new cert — carries the core's signature over (machine, input hash, kind,
// origin), and the machine refuses an input without one. The core appends each to a hash chain: every entry names
// the hash of the one before, and the router persists the signed entries (append-only) so the log outlives a core
// restart; a new core continues from the persisted head (chain_from). The core only hashes, signs and appends: it
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

const auditKeep = 20000 // entries kept in memory for reading; the chain continues past it

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
	c.audit = append(c.audit, d)
	if len(c.audit) > auditKeep {
		c.audit = c.audit[len(c.audit)-auditKeep:]
	}
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

// ChainFrom: once, on a core whose log is still empty: its first entry names the persisted head of the log before
// it (an earlier core's), so the chain reads across restarts. The core can't check that head; it records it.
func (c *Core) ChainFrom(head string) (SignedDoc, error) {
	if !hex64RE.MatchString(head) {
		return SignedDoc{}, fail(400, "head: 64 hex")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.auditSeq != 0 {
		return SignedDoc{}, fail(409, "the log has entries: chain_from only starts an empty one")
	}
	return c.appendAudit("core", "continues", "router", head)
}

// AuditLog: the signed entries from seq `from` that are still in memory, and the head
func (c *Core) AuditLog(from int) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []SignedDoc{}
	first := c.auditSeq - len(c.audit)
	for i, d := range c.audit {
		if first+i >= from {
			out = append(out, d)
		}
	}
	head, _ := c.sign(map[string]any{"kind": "input-log-head", "seq": c.auditSeq, "head": c.auditHead})
	return map[string]any{"entries": out, "head": head}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
