package main

// Taking over the lines of an earlier core (Deyao, 2026-10-15: the release of core continuity must not end the
// sessions running on the core before it, whose keys were random). Such a core's certs are worth as much as this
// core's when the master key vouches for that core: the master-signed claim that set it up names its signing key
// (the router keeps every claim it passed on: core-certs.json). So at a machine's kill (its pause) this core takes
// its line over: the cert of an earlier core the master key claimed, for that machine, and the snapshot its current key
// signed (so the cert is the machine's newest, or one with fewer stores: a downgrade's new key signs the snapshot). The
// core re-signs that cert as its own (the same payload): from then on it is the predecessor of a resume like any of
// this core's, and the successor's machine checks it with this core's key. The earlier core's carry blobs don't open
// here (its carry key went with it), so the first resume waits for an unlock of the session's stores, once.
//
// What this trusts the router for: which of a line's earlier certs is its newest, as far as fewer stores go, and that a
// line already continued on the earlier core isn't taken over from an older machine (the earlier core's used set went
// with it). Bounded to the lines of cores the master key claimed, once per machine, and only with a signed snapshot.

import "encoding/json"

// LegacyCert: an earlier core's cert and the master key's claim of that core
type LegacyCert struct {
	Cert     *SignedDoc `json:"cert"`
	CoreCert *struct {
		Statement string `json:"statement"`
		MasterSig string `json:"masterSig"`
	} `json:"coreCert"`
}

// legacyCert: the cert, when the claim is this core's master key's and names the core that signed it (callers hold c.mu)
func (c *Core) legacyCert(l *LegacyCert) (Cert, error) {
	var cert Cert
	if c.MasterKey == "" || l.Cert == nil || l.CoreCert == nil || !VerifyWith(c.MasterKey, []byte(l.CoreCert.Statement), l.CoreCert.MasterSig) {
		return cert, fail(403, "not a claim this core's master key signed")
	}
	var st claimStatement
	if json.Unmarshal([]byte(l.CoreCert.Statement), &st) != nil || st.Kind != "claim" || st.Master != c.MasterKey {
		return cert, fail(403, "not a claim by this core's master key")
	}
	signer := ""
	for _, k := range []string{st.Core.SigningKey, func() string {
		if st.Identity != nil {
			return st.Identity.SigningKey
		}
		return ""
	}()} {
		if k != "" && k != c.signer.PublicKey() && VerifyWith(k, []byte(l.Cert.Payload), l.Cert.Sig) {
			signer = k
		}
	}
	if signer == "" {
		return cert, fail(403, "the cert isn't signed by the core the claim names")
	}
	if json.Unmarshal([]byte(l.Cert.Payload), &cert) != nil || cert.Kind != "succession-cert" || cert.Machine == nil || cert.Nonce == "" {
		return cert, fail(400, "not a succession cert")
	}
	return cert, nil
}
