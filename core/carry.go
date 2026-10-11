package main

// A session carries its secrets (Deyao, 2026-10-11: "after a session is started, there's no reason to keep the
// store unlocked in the core. So just lock it then"; for unattended resumes he chose "the session carries its
// secrets"). docs/DESIGN.md "Carried secrets".
//
// - Unlocks for one session: unlock_begin(store, for) names the nonce of the one challenge or cert it is for (the
//   Start's challenge, an add-store's challenge, a waiting session's cert). Only the cert with that nonce reads it,
//   its first pull that goes through locks it again, and an unused one lapses after scopedUnlockTTL. An unlock
//   with no "for" is a standing one (the Stores page): open to every cert naming the store until locked.
// - The carry blob: every pull that goes through also answers the values it sealed, per store, under the core's
//   carry key (AES-GCM, made when the core starts, never leaving it), bound to that machine. The router keeps it
//   with the machine's snapshot. A later pull of the same machine (add-store, downgrade) or of its certified
//   successor (a resume) reads its stores from it when no unlock is open to it; forward_carry rebinds it to the
//   successor as soon as that is certified, restricted to the successor's stores, so a successor that never pulls
//   doesn't break the chain. Nobody but this core can open or forge one: not the router, the Storage Box, a machine
//   or another core.
// - A new core (restart, Recover) has a new carry key: an earlier core's blobs don't open. Its paused lines can't
//   continue on it anyway (their certs are another core's, the killed/used sets are gone), so nothing is lost
//   that a carry key surviving would keep (DECISIONS).

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// scopedUnlockTTL: an unlock for one session that its cert hasn't pulled with by then lapses (a Start whose machine
// never came up, a denied approval). The machine retries a locked pull for 10 minutes.
const scopedUnlockTTL = 30 * time.Minute

const carryAAD = "jarvis2/carry"

// isNonce: a challenge or cert nonce (the core's HMAC, 64 hex)
func isNonce(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// expireScoped: drop the unlocks for one session that have lapsed (callers hold c.mu)
func (c *Core) expireScoped() {
	now := c.now()
	for name, u := range c.unlocked {
		for id, h := range u.ids {
			if h.For != "" && now.Sub(h.since) > scopedUnlockTTL {
				delete(u.ids, id)
				c.logf("unlock %s of %s for %s lapsed unused", id, name, h.For[:12])
			}
		}
		if len(u.ids) == 0 {
			delete(c.unlocked, name)
		}
	}
}

// standing: the store has an unlock open to every session (callers hold c.mu)
func (c *Core) standing(name string) bool {
	if u := c.unlocked[name]; u != nil {
		for _, h := range u.ids {
			if h.For == "" {
				return true
			}
		}
	}
	return false
}

// openFor: the store's plaintext if an unlock is open to the cert with this nonce (standing, or for it)
func (c *Core) openFor(name, nonce string) (map[string]string, bool) {
	u := c.unlocked[name]
	if u == nil {
		return nil, false
	}
	for _, h := range u.ids {
		if h.For == "" || h.For == nonce {
			return u.values, true
		}
	}
	return nil, false
}

// releaseFor: lock every unlock that was for this nonce (its cert has pulled); the stores whose plaintext went
func (c *Core) releaseFor(nonce string) []string {
	out := []string{}
	for name, u := range c.unlocked {
		for id, h := range u.ids {
			if h.For == nonce {
				delete(u.ids, id)
			}
		}
		if len(u.ids) == 0 {
			delete(c.unlocked, name)
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// carryPayload: what a carry blob holds, under the carry key
type carryPayload struct {
	Kind     string                       `json:"kind"`    // "carry"
	Machine  string                       `json:"machine"` // the machine it is bound to
	Line     string                       `json:"line"`
	Cert     string                       `json:"cert"`   // the nonce of the cert it was sealed for
	Stores   map[string]map[string]string `json:"stores"` // per store: its values as that machine got them
	IssuedAt string                       `json:"issuedAt"`
}

func (c *Core) sealCarry(cert *Cert, perStore map[string]map[string]string) (string, error) {
	p := carryPayload{Kind: "carry", Machine: cert.Machine.ID, Line: cert.Line, Cert: cert.Nonce, Stores: perStore, IssuedAt: c.now().UTC().Format(time.RFC3339)}
	plain, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(gcmSeal(c.carryKey, plain, []byte(carryAAD))), nil
}

func (c *Core) openCarry(blob string) (*carryPayload, error) {
	raw, err := b64.DecodeString(blob)
	if err != nil {
		return nil, err
	}
	plain, err := gcmOpen(c.carryKey, raw, []byte(carryAAD))
	if err != nil {
		return nil, err
	}
	var p carryPayload
	if err := json.Unmarshal(plain, &p); err != nil || p.Kind != "carry" {
		return nil, fail(400, "not a carry blob")
	}
	return &p, nil
}

// openCarryFor: a carry blob's stores that this cert may read — the blob is this core's, sealed for this cert or
// for the cert it directly continues (the same machine's previous cert: an add-store, a downgrade; or the
// predecessor's newest: the successor the core certified), the cert is its machine's newest and that machine isn't
// killed, and only the stores the cert names. A blob from before a downgrade opens for nothing after it. nil
// otherwise (callers hold c.mu).
func (c *Core) openCarryFor(blob string, cert *Cert) map[string]map[string]string {
	if blob == "" || cert.Machine == nil || c.isKilled(cert.Machine.ID) || c.latest[cert.Machine.ID] != cert.Nonce {
		return nil
	}
	p, err := c.openCarry(blob)
	if err != nil || p.Machine == "" || p.Cert == "" {
		return nil
	}
	own := p.Machine == cert.Machine.ID && (p.Cert == cert.Nonce || p.Cert == cert.PredCert)
	pred := p.Machine == cert.PredID && p.Machine != cert.Machine.ID && p.Cert == cert.PredCert
	if !own && !pred {
		return nil
	}
	out := map[string]map[string]string{}
	for _, n := range cert.Stores {
		if v, ok := p.Stores[n]; ok {
			out[n] = v
		}
	}
	return out
}

// ForwardCarry: the line's carry blob rebound to the machine a cert names — its certified successor, or the
// same machine with a new cert (add-store, downgrade) — keeping only the stores that cert names, so a downgrade's
// dropped stores leave the blob at once. Open (normally the router, right after certify): the answer is sealed
// under the core's own key and opens only for that machine's certs.
func (c *Core) ForwardCarry(blob string, certDoc *SignedDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var cert Cert
	if err := c.verifyOwn(certDoc, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil {
		return SignedDoc{}, fail(400, "not a succession cert this core signed")
	}
	carried := c.openCarryFor(blob, &cert)
	if carried == nil {
		return SignedDoc{}, fail(409, "not a carry blob of this core for %s or its predecessor", cert.Machine.ID)
	}
	next, err := c.sealCarry(&cert, carried)
	if err != nil {
		return SignedDoc{}, err
	}
	names := make([]string, 0, len(carried))
	for n := range carried {
		names = append(names, n)
	}
	sort.Strings(names)
	c.logf("carry forwarded to %s (%v)", cert.Machine.ID, names)
	return c.sign(map[string]any{"kind": "carry", "machine": cert.Machine.ID, "stores": names, "carry": next})
}
