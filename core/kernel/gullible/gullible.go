// Package gullible is the gullible signer: it signs any (X, Y, P) given to it. Its signature counts only where the
// table accepts any signer — ending a source, (source, sink).
package gullible

import "github.com/DE0CH/jarvis2/core/kernel"

type Signer struct{ signer *kernel.Signer }

func New(s *kernel.Signer) *Signer { return &Signer{s} }

// Sign: anything well-formed
func (g *Signer) Sign(pred, succ kernel.Object, p kernel.Pair) (kernel.SignedDoc, error) {
	if p.Conditions == nil {
		p.Conditions = kernel.Conditions{}
	}
	s := kernel.Succession{Kind: "succession", Signer: kernel.RoleGullible, Predecessor: pred, Successor: succ,
		Allowed: p.Allowed, Conditions: p.Conditions}
	if err := s.Valid(); err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "%v", err)
	}
	return kernel.Sign(g.signer, s)
}

// Routes: POST /sign {predecessor, successor, allowed, conditions} → the succession cert
func (g *Signer) Routes() map[string]kernel.Route {
	return map[string]kernel.Route{
		"POST /sign": func(body []byte) (any, error) {
			var in struct {
				Predecessor kernel.Object     `json:"predecessor"`
				Successor   kernel.Object     `json:"successor"`
				Allowed     kernel.Set        `json:"allowed"`
				Conditions  kernel.Conditions `json:"conditions"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return g.Sign(in.Predecessor, in.Successor, kernel.Pair{Allowed: in.Allowed, Conditions: in.Conditions})
		},
	}
}
