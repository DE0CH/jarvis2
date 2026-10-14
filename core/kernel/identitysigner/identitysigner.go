// Package identitysigner is the identity signer: it signs (M, M, P) for a Fly machine M and any P; the router picks P.
// Narrowing a running machine's grant is moving it along M's identity edge. It signs nothing else.
package identitysigner

import "github.com/DE0CH/jarvis2/core/kernel"

type Signer struct{ signer *kernel.Signer }

func New(s *kernel.Signer) *Signer { return &Signer{s} }

func (i *Signer) Sign(m kernel.Object, p kernel.Pair) (kernel.SignedDoc, error) {
	if err := m.Valid(); err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "%v", err)
	}
	if m.Kind() != kernel.KindMachine {
		return kernel.SignedDoc{}, kernel.Fail(403, "the identity signer signs only (M, M) for a Fly machine M")
	}
	if p.Conditions == nil {
		p.Conditions = kernel.Conditions{}
	}
	return kernel.Sign(i.signer, kernel.Succession{Kind: "succession", Signer: kernel.RoleIdentity, Predecessor: m, Successor: m,
		Allowed: p.Allowed, Conditions: p.Conditions})
}

// Routes: POST /sign {machine, allowed, conditions} → the succession cert (machine, machine, P)
func (i *Signer) Routes() map[string]kernel.Route {
	return map[string]kernel.Route{
		"POST /sign": func(body []byte) (any, error) {
			var in struct {
				Machine    kernel.Object     `json:"machine"`
				Allowed    kernel.Set        `json:"allowed"`
				Conditions kernel.Conditions `json:"conditions"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return i.Sign(in.Machine, kernel.Pair{Allowed: in.Allowed, Conditions: in.Conditions})
		},
	}
}
