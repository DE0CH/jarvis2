// Package perm: permission pairs (DESIGN "Target design"). allowed is a finite ("only") or cofinite ("except") set of
// exact strings, covariant; conditions a finite set of exact strings, contravariant. P' ≤ P iff allowed' ⊆ allowed and
// conditions' ⊇ conditions; P ⊓ Q = (allowed ∩, conditions ∪). The kernel never reads what a string means: only these
// set operations. Strings are kept sorted and unique, so equal pairs marshal to equal bytes.
package perm

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"unicode"
)

// Set: Only xor Except is meaningful; Except = cofinite (everything but these). Only nil + Except nil = invalid.
type Set struct {
	Only   []string `json:"only,omitempty"`
	Except []string `json:"except,omitempty"`
}

// MarshalJSON: the one non-nil side, empty included ({"only":[]} is nothing, {"except":[]} everything)
func (s Set) MarshalJSON() ([]byte, error) {
	if s.Except != nil {
		return json.Marshal(map[string][]string{"except": s.Except})
	}
	if s.Only == nil {
		return nil, errors.New("an empty set value")
	}
	return json.Marshal(map[string][]string{"only": s.Only})
}

type Pair struct {
	Allowed    Set      `json:"allowed"`
	Conditions []string `json:"conditions"`
}

// Top: (everything, ∅)
func Top() Pair { return Pair{Allowed: Set{Except: []string{}}, Conditions: []string{}} }

// Only / Except build sets
func Only(s ...string) Set   { return Set{Only: norm(s)} }
func Except(s ...string) Set { return Set{Except: norm(s)} }

func (s Set) cofinite() bool { return s.Except != nil }

func norm(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func checkStrings(s []string) error {
	for _, x := range s {
		if x == "" || len(x) > 512 {
			return fmt.Errorf("bad string %q", x)
		}
		for _, r := range x {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				return fmt.Errorf("bad string %q", x)
			}
		}
	}
	if !slices.IsSorted(s) || len(slices.Compact(slices.Clone(s))) != len(s) {
		return errors.New("strings not sorted and unique")
	}
	return nil
}

// Valid: well formed, as a document carries it (exactly one of only/except, sorted and unique)
func (p Pair) Valid() error {
	a := p.Allowed
	switch {
	case (a.Only == nil) == (a.Except == nil):
		return errors.New("allowed: exactly one of only and except")
	case p.Conditions == nil:
		return errors.New("conditions missing")
	}
	if err := checkStrings(a.Only); err != nil {
		return err
	}
	if err := checkStrings(a.Except); err != nil {
		return err
	}
	return checkStrings(p.Conditions)
}

func (s Set) Contains(x string) bool {
	if s.cofinite() {
		return !slices.Contains(s.Except, x)
	}
	return slices.Contains(s.Only, x)
}

func inter(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func minus(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func union(a, b []string) []string { return norm(append(slices.Clone(a), b...)) }

// Meet of two sets
func (s Set) Meet(t Set) Set {
	switch {
	case !s.cofinite() && !t.cofinite():
		return Set{Only: inter(s.Only, t.Only)}
	case !s.cofinite():
		return Set{Only: minus(s.Only, t.Except)}
	case !t.cofinite():
		return Set{Only: minus(t.Only, s.Except)}
	}
	return Set{Except: union(s.Except, t.Except)}
}

// Join of two sets
func (s Set) Join(t Set) Set {
	switch {
	case !s.cofinite() && !t.cofinite():
		return Set{Only: union(s.Only, t.Only)}
	case !s.cofinite():
		return Set{Except: minus(t.Except, s.Only)}
	case !t.cofinite():
		return Set{Except: minus(s.Except, t.Only)}
	}
	return Set{Except: inter(s.Except, t.Except)}
}

// SubsetOf: s ⊆ t
func (s Set) SubsetOf(t Set) bool {
	switch {
	case !s.cofinite() && !t.cofinite():
		return len(minus(s.Only, t.Only)) == 0
	case !s.cofinite():
		return len(inter(s.Only, t.Except)) == 0
	case !t.cofinite():
		return false // a cofinite set is in no finite one
	}
	return len(minus(t.Except, s.Except)) == 0
}

// Meet: P ⊓ Q
func (p Pair) Meet(q Pair) Pair {
	return Pair{Allowed: p.Allowed.Meet(q.Allowed), Conditions: union(p.Conditions, q.Conditions)}
}

// Leq: p ≤ q
func (p Pair) Leq(q Pair) bool {
	return p.Allowed.SubsetOf(q.Allowed) && len(minus(q.Conditions, p.Conditions)) == 0
}

// SameConditions: what the merger requires
func (p Pair) SameConditions(q Pair) bool { return slices.Equal(p.Conditions, q.Conditions) }

// Merge: (allowed₁ ∪ allowed₂, conditions), for pairs with the same conditions
func (p Pair) Merge(q Pair) (Pair, error) {
	if !p.SameConditions(q) {
		return Pair{}, errors.New("the conditions differ")
	}
	return Pair{Allowed: p.Allowed.Join(q.Allowed), Conditions: slices.Clone(p.Conditions)}, nil
}
