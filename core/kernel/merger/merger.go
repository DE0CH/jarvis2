// Package merger is the grant merger: two grants on one machine with identical conditions become (M, allowed₁ ∪
// allowed₂, conditions); anything else is refused.
package merger

import "github.com/DE0CH/jarvis2/core/kernel"

type Merger struct {
	signer *kernel.Signer
	roster kernel.Roster
}

func New(s *kernel.Signer, r kernel.Roster) *Merger { return &Merger{s, r} }

// Merge: two grants made by the mover, the merger or the root key
func (m *Merger) Merge(a, b kernel.SignedDoc) (kernel.SignedDoc, error) {
	ga, err := kernel.OpenGrant(m.roster, a, kernel.RoleMover, kernel.RoleMerger, kernel.RoleRoot)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(403, "a: %v", err)
	}
	gb, err := kernel.OpenGrant(m.roster, b, kernel.RoleMover, kernel.RoleMerger, kernel.RoleRoot)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(403, "b: %v", err)
	}
	if ga.Machine != gb.Machine {
		return kernel.SignedDoc{}, kernel.Fail(409, "the grants are on different objects (%s, %s)", ga.Machine.ID, gb.Machine.ID)
	}
	if !kernel.SameConditions(ga.Conditions, gb.Conditions) {
		return kernel.SignedDoc{}, kernel.Fail(409, "the grants' conditions differ: only identical conditions merge")
	}
	return kernel.Sign(m.signer, kernel.Grant{Kind: "grant", By: kernel.RoleMerger, Machine: ga.Machine,
		Allowed: ga.Allowed.Union(gb.Allowed), Conditions: ga.Conditions, From: []string{a.ID(), b.ID()}})
}

// Routes: POST /merge {a, b} → the merged grant
func (m *Merger) Routes() map[string]kernel.Route {
	return map[string]kernel.Route{
		"POST /merge": func(body []byte) (any, error) {
			var in struct {
				A kernel.SignedDoc `json:"a"`
				B kernel.SignedDoc `json:"b"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return m.Merge(in.A, in.B)
		},
	}
}
