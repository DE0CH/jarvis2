// Package kernel holds what every kernel part shares (docs/DESIGN.md "Target design"): exact-string sets that are
// finite or cofinite, permission pairs, the signed-document envelope, the hash-to-curve keys of sources and the sink,
// and the document formats (succession cert, notarization, grant, challenge). The kernel compares strings exactly and
// never gives them meaning: that is the guard's and the app's.
package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

// MaxElem: the longest string a set or a condition list takes (bytes)
const MaxElem = 1024

// Set: a finite or a cofinite set of exact strings. JSON: {"only":[…]} (finite) or {"except":[…]} (everything but
// those). Elements are sorted by byte order, each once, so equal sets have equal JSON.
type Set struct {
	cofinite bool
	elems    []string // sorted, each once
}

// Only: the finite set of xs; Except: every string but xs; Everything: Except()
func Only(xs ...string) Set   { return Set{false, canon(xs)} }
func Except(xs ...string) Set { return Set{true, canon(xs)} }
func Everything() Set         { return Set{true, nil} }

func canon(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	n := 0
	for i, x := range out {
		if i == 0 || x != out[n-1] {
			out[n] = x
			n++
		}
	}
	return out[:n]
}

// Finite: whether the set lists its members (else it lists what it leaves out)
func (s Set) Finite() bool { return !s.cofinite }

// Elems: the members of a finite set, or the strings a cofinite set leaves out
func (s Set) Elems() []string { return append([]string(nil), s.elems...) }

func has(xs []string, x string) bool {
	i := sort.SearchStrings(xs, x)
	return i < len(xs) && xs[i] == x
}

func (s Set) Contains(x string) bool { return has(s.elems, x) != s.cofinite }

func inter(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if has(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func minus(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if !has(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func union(a, b []string) []string { return canon(append(append([]string{}, a...), b...)) }

// Subset: s ⊆ t
func (s Set) Subset(t Set) bool {
	switch {
	case !s.cofinite && !t.cofinite:
		return len(minus(s.elems, t.elems)) == 0
	case !s.cofinite && t.cofinite:
		return len(inter(s.elems, t.elems)) == 0
	case s.cofinite && !t.cofinite:
		return false // the universe of strings is infinite
	default:
		return len(minus(t.elems, s.elems)) == 0
	}
}

// Intersect: s ∩ t
func (s Set) Intersect(t Set) Set {
	switch {
	case !s.cofinite && !t.cofinite:
		return Set{false, inter(s.elems, t.elems)}
	case !s.cofinite && t.cofinite:
		return Set{false, minus(s.elems, t.elems)}
	case s.cofinite && !t.cofinite:
		return Set{false, minus(t.elems, s.elems)}
	default:
		return Set{true, union(s.elems, t.elems)}
	}
}

// Union: s ∪ t
func (s Set) Union(t Set) Set {
	switch {
	case !s.cofinite && !t.cofinite:
		return Set{false, union(s.elems, t.elems)}
	case !s.cofinite && t.cofinite:
		return Set{true, minus(t.elems, s.elems)}
	case s.cofinite && !t.cofinite:
		return Set{true, minus(s.elems, t.elems)}
	default:
		return Set{true, inter(s.elems, t.elems)}
	}
}

func (s Set) Equal(t Set) bool { return s.Subset(t) && t.Subset(s) }

func (s Set) MarshalJSON() ([]byte, error) {
	e := s.elems
	if e == nil {
		e = []string{}
	}
	if s.cofinite {
		return json.Marshal(struct {
			Except []string `json:"except"`
		}{e})
	}
	return json.Marshal(struct {
		Only []string `json:"only"`
	}{e})
}

// UnmarshalJSON: exactly one of only/except, its elements canonical (sorted, each once, valid)
func (s *Set) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := strictJSON(b, &m); err != nil {
		return err
	}
	if len(m) != 1 {
		return errors.New(`a set is {"only":[…]} or {"except":[…]}`)
	}
	for k, v := range m {
		if k != "only" && k != "except" {
			return errors.New(`a set is {"only":[…]} or {"except":[…]}`)
		}
		var xs Conditions
		if err := xs.UnmarshalJSON(v); err != nil {
			return err
		}
		*s = Set{k == "except", []string(xs)}
	}
	return nil
}

// Conditions: a finite set of exact strings as a JSON array, sorted by byte order, each once. Conjunctive: only ever
// added to, so the kernel never compares their values ({until:12:10, until:12:00} means 12:00 to the guard).
type Conditions []string

func (c Conditions) MarshalJSON() ([]byte, error) {
	if c == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(c))
}

func (c *Conditions) UnmarshalJSON(b []byte) error {
	var xs []string
	if err := strictJSON(b, &xs); err != nil {
		return err
	}
	if xs == nil {
		return errors.New("a list of strings, not null")
	}
	for i, x := range xs {
		if err := validElem(x); err != nil {
			return err
		}
		if i > 0 && xs[i-1] >= x {
			return fmt.Errorf("strings sorted by byte order, each once (%q after %q)", x, xs[i-1])
		}
	}
	*c = xs
	return nil
}

func validElem(x string) error {
	if x == "" || len(x) > MaxElem || !utf8.ValidString(x) {
		return fmt.Errorf("a set's string is valid UTF-8, 1 to %d bytes", MaxElem)
	}
	return nil
}

// strictJSON: one JSON value, no unknown fields, nothing after it
func strictJSON(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// Pair: a permission pair (allowed, conditions). allowed is covariant, conditions contravariant.
type Pair struct {
	Allowed    Set        `json:"allowed"`
	Conditions Conditions `json:"conditions"`
}

// Top: ⊤ = (everything, ∅)
func Top() Pair { return Pair{Everything(), Conditions{}} }

// Leq: p ≤ q iff p.allowed ⊆ q.allowed and p.conditions ⊇ q.conditions
func (p Pair) Leq(q Pair) bool {
	return p.Allowed.Subset(q.Allowed) && len(minus(q.Conditions, p.Conditions)) == 0
}

// Meet: p ⊓ q = (allowed ∩, conditions ∪)
func (p Pair) Meet(q Pair) Pair {
	return Pair{p.Allowed.Intersect(q.Allowed), Conditions(union(p.Conditions, q.Conditions))}
}

// SameConditions: the two condition sets are equal (what the merger requires)
func SameConditions(a, b Conditions) bool {
	return len(minus(a, b)) == 0 && len(minus(b, a)) == 0
}

// CanonConditions: xs sorted, each once
func CanonConditions(xs ...string) Conditions { return Conditions(canon(xs)) }
