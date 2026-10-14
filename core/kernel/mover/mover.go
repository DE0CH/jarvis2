// Package mover is the grant mover: a grant G on a cert's predecessor, along that notarized cert with pair P, becomes
// (successor, G ⊓ P). It never refuses a move for what P says: a move can only narrow. It refuses only what isn't a
// move (a document not signed by who it claims, a cert not notarized, a grant on another object).
package mover

import "github.com/DE0CH/jarvis2/core/kernel"

type Mover struct {
	signer *kernel.Signer
	roster kernel.Roster
}

func New(s *kernel.Signer, r kernel.Roster) *Mover { return &Mover{s, r} }

// Move: the grant (by the mover, the merger, or ⊤ on the sink by the root key) along the notarized cert
func (m *Mover) Move(grant kernel.SignedDoc, cert kernel.NotarizedCert) (kernel.SignedDoc, error) {
	g, err := kernel.OpenGrant(m.roster, grant, kernel.RoleMover, kernel.RoleMerger, kernel.RoleRoot)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(403, "%v", err)
	}
	s, err := kernel.OpenNotarized(m.roster, cert)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(403, "%v", err)
	}
	if g.Machine != s.Predecessor {
		return kernel.SignedDoc{}, kernel.Fail(400, "the grant is on %s, the cert's predecessor is %s", g.Machine.ID, s.Predecessor.ID)
	}
	p := g.Pair().Meet(s.Pair())
	return kernel.Sign(m.signer, kernel.Grant{Kind: "grant", By: kernel.RoleMover, Machine: s.Successor, Allowed: p.Allowed,
		Conditions: p.Conditions, From: []string{grant.ID(), cert.Notarization.ID()}})
}

// Routes: POST /move {grant, cert} → the moved grant
func (m *Mover) Routes() map[string]kernel.Route {
	return map[string]kernel.Route{
		"POST /move": func(body []byte) (any, error) {
			var in struct {
				Grant kernel.SignedDoc     `json:"grant"`
				Cert  kernel.NotarizedCert `json:"cert"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return m.Move(in.Grant, in.Cert)
		},
	}
}
