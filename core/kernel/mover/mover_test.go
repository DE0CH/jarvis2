package mover

import (
	"math/rand"
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func moved(t *testing.T, w *ktest.World, d kernel.SignedDoc) kernel.Grant {
	t.Helper()
	g, err := kernel.OpenGrant(w.Roster, d, "mover")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAMoveIsTheMeet(t *testing.T) {
	w := ktest.New(t)
	mv := New(w.Keys["mover"], w.Roster)
	src := ktest.Source(ktest.Image, `{"harness":"claude"}`)
	cert := w.Notarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), src, ktest.P([]string{"store:claude", "shell"}, "session:s1")))
	root := w.RootGrant(t)
	d, err := mv.Move(root, cert)
	if err != nil {
		t.Fatal(err)
	}
	g := moved(t, w, d)
	if g.Machine != src || !g.Allowed.Equal(kernel.Only("shell", "store:claude")) || !kernel.SameConditions(g.Conditions, kernel.CanonConditions("session:s1")) {
		t.Fatalf("%+v", g)
	}
	if len(g.From) != 2 || g.From[0] != root.ID() || g.From[1] != cert.Notarization.ID() {
		t.Fatalf("from: %v", g.From)
	}
	// on along a spawn (⊤): unchanged allowed and conditions, now on the machine
	m := ktest.NewMachine(t, "m1").Obj
	d2, err := mv.Move(d, w.Notarize(t, w.Cert(t, "spawner", "spawner", src, m, kernel.Top())))
	if err != nil {
		t.Fatal(err)
	}
	if g2 := moved(t, w, d2); g2.Machine != m || !g2.Allowed.Equal(g.Allowed) || !kernel.SameConditions(g2.Conditions, g.Conditions) {
		t.Fatalf("%+v", g2)
	}
	// narrowing along M's identity edge: (everything, {until:T}) adds the condition
	d3, err := mv.Move(d2, w.Notarize(t, w.Cert(t, "identity", "identity", m, m, kernel.Pair{Allowed: kernel.Everything(), Conditions: kernel.CanonConditions("until:T")})))
	if err != nil {
		t.Fatal(err)
	}
	if g3 := moved(t, w, d3); !kernel.SameConditions(g3.Conditions, kernel.CanonConditions("session:s1", "until:T")) {
		t.Fatalf("%+v", g3)
	}
}

// The mover never refuses a move for what P says: even (∅, …) moves, to an empty grant
func TestTheMoverNeverRefusesForP(t *testing.T) {
	w := ktest.New(t)
	mv := New(w.Keys["mover"], w.Roster)
	src := ktest.Source("", "")
	for _, p := range []kernel.Pair{{Allowed: kernel.Only(), Conditions: kernel.Conditions{}}, kernel.Top(), ktest.P(nil, "until:0")} {
		if _, err := mv.Move(w.RootGrant(t), w.Notarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), src, p))); err != nil {
			t.Fatalf("%+v: %v", p, err)
		}
	}
}

// The output is always ≤ the input grant and ≤ the cert's pair (random grants and pairs)
func TestAMoveOnlyNarrows(t *testing.T) {
	w := ktest.New(t)
	mv := New(w.Keys["mover"], w.Roster)
	m, m2 := ktest.NewMachine(t, "m1").Obj, ktest.NewMachine(t, "m2").Obj
	universe := []string{"shell", "store:a", "store:b", "x"}
	conds := []string{"session:s", "until:1", "until:2"}
	r := rand.New(rand.NewSource(3))
	pick := func(xs []string) []string {
		out := []string{}
		for _, x := range xs {
			if r.Intn(2) == 0 {
				out = append(out, x)
			}
		}
		return out
	}
	rp := func() kernel.Pair {
		a := kernel.Only(pick(universe)...)
		if r.Intn(2) == 0 {
			a = kernel.Except(pick(universe)...)
		}
		return kernel.Pair{Allowed: a, Conditions: kernel.CanonConditions(pick(conds)...)}
	}
	for i := 0; i < 200; i++ {
		gp, cp := rp(), rp()
		in := w.Grant(t, "merger", "merger", m, gp)
		pred, succ, signer := m, m, "identity"
		if i%2 == 0 {
			succ, signer = m2, "root"
		}
		d, err := mv.Move(in, w.Notarize(t, w.Cert(t, signer, signer, pred, succ, cp)))
		if err != nil {
			t.Fatal(err)
		}
		out := moved(t, w, d).Pair()
		if !out.Leq(gp) || !out.Leq(cp) {
			t.Fatalf("%+v moved along %+v gave %+v", gp, cp, out)
		}
	}
}

// Forbidden: whatever isn't a move
func TestWhatIsntAMoveIsRefused(t *testing.T) {
	w := ktest.New(t)
	mv := New(w.Keys["mover"], w.Roster)
	m, m2 := ktest.NewMachine(t, "m1").Obj, ktest.NewMachine(t, "m2").Obj
	idCert := w.Notarize(t, w.Cert(t, "identity", "identity", m, m, kernel.Top()))
	good := w.Grant(t, "mover", "mover", m, kernel.Top())
	if _, err := mv.Move(good, idCert); err != nil {
		t.Fatal(err)
	}
	unnotarized := idCert
	unnotarized.Notarization, _ = kernel.Sign(w.Keys["identity"], kernel.Notarization{Kind: "notarization", Cert: idCert.Cert.ID(), Challenge: idCert.Challenge.ID()})
	for name, c := range map[string]struct {
		g    kernel.SignedDoc
		cert kernel.NotarizedCert
	}{
		"a grant on another machine":            {w.Grant(t, "mover", "mover", m2, kernel.Top()), idCert},
		"a grant made by the gullible key":      {w.Grant(t, "mover", "gullible", m, kernel.Top()), idCert},
		"a grant made by the identity signer":   {w.Grant(t, "identity", "identity", m, kernel.Top()), idCert},
		"a root grant that isn't ⊤ on the sink": {w.Grant(t, "root", "root", m, kernel.Top()), idCert},
		"a cert not notarized":                  {good, unnotarized},
		"a cert notarized by nobody":            {good, kernel.NotarizedCert{Cert: idCert.Cert, Challenge: idCert.Challenge}},
		"a grant on a source, not the cert's":   {w.Grant(t, "mover", "mover", ktest.Source("", ""), kernel.Top()), idCert},
	} {
		if _, err := mv.Move(c.g, c.cert); err == nil {
			t.Fatalf("%s: moved", name)
		}
	}
}
