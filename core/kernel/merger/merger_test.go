package merger

import (
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func TestIdenticalConditionsMerge(t *testing.T) {
	w := ktest.New(t)
	mg := New(w.Keys["merger"], w.Roster)
	m := ktest.NewMachine(t, "m1").Obj
	a := w.Grant(t, "mover", "mover", m, ktest.P([]string{"store:claude"}, "session:S", "until:T"))
	b := w.Grant(t, "mover", "mover", m, ktest.P([]string{"shell"}, "session:S", "until:T"))
	d, err := mg.Merge(a, b)
	if err != nil {
		t.Fatal(err)
	}
	g, err := kernel.OpenGrant(w.Roster, d, "merger")
	if err != nil {
		t.Fatal(err)
	}
	if g.Machine != m || !g.Allowed.Equal(kernel.Only("shell", "store:claude")) || !kernel.SameConditions(g.Conditions, kernel.CanonConditions("session:S", "until:T")) {
		t.Fatalf("%+v", g)
	}
	if g.From[0] != a.ID() || g.From[1] != b.ID() {
		t.Fatal("from")
	}
	// merged grants merge again (by the merger), and a cofinite side gives a cofinite union
	c := w.Grant(t, "mover", "mover", m, kernel.Pair{Allowed: kernel.Except("store:x", "shell"), Conditions: kernel.CanonConditions("session:S", "until:T")})
	d2, err := mg.Merge(d, c)
	if err != nil {
		t.Fatal(err)
	}
	g2, _ := kernel.OpenGrant(w.Roster, d2, "merger")
	if !g2.Allowed.Equal(kernel.Except("store:x")) {
		t.Fatalf("%+v", g2.Allowed)
	}
}

// Forbidden: different conditions (even a subset), different machines, grants nobody made
func TestWhatDoesntMerge(t *testing.T) {
	w := ktest.New(t)
	mg := New(w.Keys["merger"], w.Roster)
	m, m2 := ktest.NewMachine(t, "m1").Obj, ktest.NewMachine(t, "m2").Obj
	a := w.Grant(t, "mover", "mover", m, ktest.P([]string{"store:claude"}, "session:S"))
	for name, b := range map[string]kernel.SignedDoc{
		"more conditions":         w.Grant(t, "mover", "mover", m, ktest.P([]string{"shell"}, "session:S", "until:T")),
		"other conditions":        w.Grant(t, "mover", "mover", m, ktest.P([]string{"shell"}, "session:X")),
		"no conditions":           w.Grant(t, "mover", "mover", m, ktest.P([]string{"shell"})),
		"another machine":         w.Grant(t, "mover", "mover", m2, ktest.P([]string{"shell"}, "session:S")),
		"a forged grant":          w.Grant(t, "mover", "gullible", m, ktest.P([]string{"shell"}, "session:S")),
		"a grant by the identity": w.Grant(t, "identity", "identity", m, ktest.P([]string{"shell"}, "session:S")),
	} {
		if _, err := mg.Merge(a, b); err == nil {
			t.Fatalf("%s: merged", name)
		}
		if _, err := mg.Merge(b, a); err == nil {
			t.Fatalf("%s (swapped): merged", name)
		}
	}
}
