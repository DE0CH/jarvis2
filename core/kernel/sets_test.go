package kernel

import (
	"encoding/json"
	"math/rand"
	"testing"
)

// members: the set restricted to a finite universe, plus "∞" standing for every string outside it (a cofinite set
// contains it, a finite one doesn't): enough to decide every operation on sets over that universe
func members(s Set, universe []string) map[string]bool {
	m := map[string]bool{"∞": s.cofinite}
	for _, x := range universe {
		m[x] = s.Contains(x)
	}
	return m
}

func randSet(r *rand.Rand, universe []string) Set {
	xs := []string{}
	for _, x := range universe {
		if r.Intn(2) == 0 {
			xs = append(xs, x)
		}
	}
	if r.Intn(2) == 0 {
		return Except(xs...)
	}
	return Only(xs...)
}

// Every operation agrees with its definition on membership, over many random finite/cofinite pairs
func TestSetOperationsAgreeWithMembership(t *testing.T) {
	universe := []string{"a", "b", "c", "d", "store:x"}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		s, u := randSet(r, universe), randSet(r, universe)
		ms, mu := members(s, universe), members(u, universe)
		mi, mn := members(s.Intersect(u), universe), members(s.Union(u), universe)
		sub, eq := true, true
		for x := range ms {
			if mi[x] != (ms[x] && mu[x]) || mn[x] != (ms[x] || mu[x]) {
				t.Fatalf("%v op %v wrong at %q", s, u, x)
			}
			sub = sub && (!ms[x] || mu[x])
			eq = eq && ms[x] == mu[x]
		}
		if s.Subset(u) != sub || s.Equal(u) != eq {
			t.Fatalf("subset/equal of %+v, %+v: got %v/%v want %v/%v", s, u, s.Subset(u), s.Equal(u), sub, eq)
		}
	}
}

func TestSetJSONIsCanonical(t *testing.T) {
	for _, c := range []struct {
		s    Set
		want string
	}{
		{Only("b", "a", "a"), `{"only":["a","b"]}`},
		{Except(), `{"except":[]}`},
		{Only(), `{"only":[]}`},
		{Except("store:z", "shell"), `{"except":["shell","store:z"]}`},
	} {
		b, _ := json.Marshal(c.s)
		if string(b) != c.want {
			t.Fatalf("%s, want %s", b, c.want)
		}
		var back Set
		if err := json.Unmarshal(b, &back); err != nil || !back.Equal(c.s) {
			t.Fatalf("%s doesn't read back: %v", b, err)
		}
	}
}

// Forbidden: any set JSON that isn't the one canonical form
func TestSetJSONRefusesNonCanonical(t *testing.T) {
	for _, bad := range []string{
		`{"only":["b","a"]}`, `{"only":["a","a"]}`, `{"only":["a"],"except":[]}`, `{}`, `{"some":[]}`,
		`{"only":null}`, `{"only":[""]}`, `{"only":"a"}`, `null`, `["a"]`, `{"only":["\xff"]}`,
	} {
		var s Set
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	var c Conditions
	for _, bad := range []string{`["b","a"]`, `["a","a"]`, `null`, `[1]`, `[""]`} {
		if err := json.Unmarshal([]byte(bad), &c); err == nil {
			t.Fatalf("conditions %s accepted", bad)
		}
	}
}

func TestPairsOrderAndMeet(t *testing.T) {
	top := Top()
	p := Pair{Only("shell", "store:claude"), CanonConditions("session:s1")}
	q := Pair{Except("shell"), CanonConditions("until:T")}
	if !p.Leq(top) || !q.Leq(top) || top.Leq(p) {
		t.Fatal("⊤ is the greatest pair")
	}
	m := p.Meet(q)
	if !m.Allowed.Equal(Only("store:claude")) || !SameConditions(m.Conditions, CanonConditions("session:s1", "until:T")) {
		t.Fatalf("meet: %+v", m)
	}
	if !m.Leq(p) || !m.Leq(q) {
		t.Fatal("the meet is below both")
	}
	// more conditions is smaller; more allowed is bigger
	if !(Pair{Only("a"), CanonConditions("x", "y")}).Leq(Pair{Only("a", "b"), CanonConditions("x")}) {
		t.Fatal("≤: allowed ⊆ and conditions ⊇")
	}
	if (Pair{Only("a"), CanonConditions()}).Leq(Pair{Only("a"), CanonConditions("x")}) {
		t.Fatal("dropping a condition is not narrowing")
	}
	// the meet with ⊤ changes nothing
	if mt := p.Meet(top); !mt.Allowed.Equal(p.Allowed) || !SameConditions(mt.Conditions, p.Conditions) {
		t.Fatal("p ⊓ ⊤ = p")
	}
}

// A meet is always ≤ both sides (random pairs)
func TestMeetIsAlwaysBelowBoth(t *testing.T) {
	universe := []string{"shell", "store:a", "store:b", "x"}
	conds := []string{"session:s", "until:1", "until:2", "cmd:h"}
	r := rand.New(rand.NewSource(2))
	rc := func() Conditions {
		xs := []string{}
		for _, c := range conds {
			if r.Intn(2) == 0 {
				xs = append(xs, c)
			}
		}
		return CanonConditions(xs...)
	}
	for i := 0; i < 2000; i++ {
		p, q := Pair{randSet(r, universe), rc()}, Pair{randSet(r, universe), rc()}
		m := p.Meet(q)
		if !m.Leq(p) || !m.Leq(q) {
			t.Fatalf("%+v ⊓ %+v = %+v not below both", p, q, m)
		}
	}
}
