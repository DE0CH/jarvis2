package perm

import (
	"encoding/json"
	"math/rand"
	"testing"
)

var universe = []string{"a", "b", "c", "d"}

// every set over a small universe, checked against brute force (a cofinite set is judged on the universe plus one
// string none of them names, standing for "everything else")
func sets() []Set {
	var out []Set
	for m := 0; m < 16; m++ {
		var xs []string
		for i, u := range universe {
			if m&(1<<i) != 0 {
				xs = append(xs, u)
			}
		}
		out = append(out, Only(xs...), Except(xs...))
	}
	return out
}

func members(s Set) map[string]bool {
	m := map[string]bool{}
	for _, x := range append(cloneS(universe), "zz") {
		if s.Contains(x) {
			m[x] = true
		}
	}
	return m
}

func cloneS(s []string) []string { return append([]string{}, s...) }

func TestSetAlgebraAgainstBruteForce(t *testing.T) {
	for _, s := range sets() {
		for _, u := range sets() {
			ms, mu := members(s), members(u)
			mm, mj := members(s.Meet(u)), members(s.Join(u))
			sub := true
			for x := range ms {
				if !mu[x] {
					sub = false
				}
			}
			if s.SubsetOf(u) != sub {
				t.Fatalf("%v ⊆ %v", s, u)
			}
			for _, x := range append(cloneS(universe), "zz") {
				if mm[x] != (ms[x] && mu[x]) || mj[x] != (ms[x] || mu[x]) {
					t.Fatalf("%v, %v at %s", s, u, x)
				}
			}
		}
	}
}

func TestMeetOnlyNarrows(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	ss := sets()
	for i := 0; i < 2000; i++ {
		p := Pair{ss[r.Intn(len(ss))], norm([]string{universe[r.Intn(4)]})}
		q := Pair{ss[r.Intn(len(ss))], norm([]string{universe[r.Intn(4)], "until:x"})}
		m := p.Meet(q)
		if !m.Leq(p) || !m.Leq(q) || m.Valid() != nil {
			t.Fatal(p, q, m)
		}
	}
	if !Top().Meet(Pair{Only("x"), []string{"c"}}).Leq(Top()) || Top().Valid() != nil {
		t.Fatal("top")
	}
}

func TestMergeNeedsSameConditions(t *testing.T) {
	p := Pair{Only("store:a"), []string{"session:s1"}}
	q := Pair{Only("shell"), []string{"session:s1"}}
	m, err := p.Merge(q)
	if err != nil || !m.Allowed.Contains("shell") || !m.Allowed.Contains("store:a") {
		t.Fatal(m, err)
	}
	if _, err := p.Merge(Pair{Only("shell"), []string{"session:s1", "until:x"}}); err == nil {
		t.Fatal("merged different conditions")
	}
}

func TestValidRefuses(t *testing.T) {
	for _, s := range []string{
		`{"allowed":{},"conditions":[]}`,
		`{"allowed":{"only":["a"],"except":["b"]},"conditions":[]}`,
		`{"allowed":{"only":["b","a"]},"conditions":[]}`,
		`{"allowed":{"only":["a","a"]},"conditions":[]}`,
		`{"allowed":{"only":["a b"]},"conditions":[]}`,
		`{"allowed":{"only":["a"]}}`,
	} {
		var p Pair
		if json.Unmarshal([]byte(s), &p) == nil && p.Valid() == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	for _, p := range []Pair{Top(), {Only(), []string{}}, {Only("a"), []string{"x"}}, {Except("b"), []string{}}} {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var q Pair
		if err := json.Unmarshal(b, &q); err != nil || q.Valid() != nil {
			t.Fatal(string(b), err, q.Valid())
		}
		if b2, _ := json.Marshal(q); string(b2) != string(b) {
			t.Fatal(string(b), string(b2))
		}
	}
	if b, _ := json.Marshal(Top()); string(b) != `{"allowed":{"except":[]},"conditions":[]}` {
		t.Fatal(string(b))
	}
}
