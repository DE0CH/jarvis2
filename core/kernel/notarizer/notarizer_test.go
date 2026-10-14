package notarizer

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func newN(t *testing.T, w *ktest.World) *Notarizer {
	t.Helper()
	n, err := New(w.Keys["notarizer"], w.Roster, "")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func notarize(t *testing.T, w *ktest.World, n *Notarizer, cert kernel.SignedDoc) (kernel.NotarizedCert, error) {
	t.Helper()
	return n.Notarize(cert, w.Challenge(t, cert.ID(), kernel.AboutSuccession))
}

// Every row of the table, with the right signer, is notarized, and the result checks out
func TestEveryRowOfTheTable(t *testing.T) {
	w := ktest.New(t)
	n := newN(t, w)
	sink, m := ktest.SinkObj(), ktest.NewMachine(t, "m1").Obj
	for _, c := range []struct {
		signer     string
		pred, succ kernel.Object
	}{
		{"phone", sink, ktest.Source(ktest.Image, "")},
		{"spawner", ktest.Source(ktest.Image, ""), m},
		{"phone", ktest.Source("", ""), m},
		{"identity", m, m},
		{"spawner", m, ktest.Source(ktest.Image, "")},
		{"gullible", ktest.Source(ktest.Image, ""), sink},
		{"root", m, sink},
	} {
		nc, err := notarize(t, w, n, w.Cert(t, c.signer, c.signer, c.pred, c.succ, ktest.P([]string{"shell"}, "until:T")))
		if err != nil {
			t.Fatalf("(%s, %s) by %s: %v", c.pred.Kind(), c.succ.Kind(), c.signer, err)
		}
		if _, err := kernel.OpenNotarized(w.Roster, nc); err != nil {
			t.Fatal(err)
		}
	}
}

// Forbidden: every shape not in the table, and every row with another signer
func TestShapesNotInTheTableAreRefused(t *testing.T) {
	w := ktest.New(t)
	n := newN(t, w)
	sink, m, m2 := ktest.SinkObj(), ktest.NewMachine(t, "m1").Obj, ktest.NewMachine(t, "m2").Obj
	src := func() kernel.Object { return ktest.Source(ktest.Image, "") }
	for name, c := range map[string]struct {
		signer     string
		pred, succ kernel.Object
	}{
		"gullible (source, Fly machine)":           {"gullible", src(), m},
		"identity (source, Fly machine)":           {"identity", src(), m},
		"identity (M, M') of two machines":         {"identity", m, m2},
		"identity (source, source)":                {"identity", src(), src()},
		"spawner (sink, source)":                   {"spawner", sink, src()},
		"spawner (M, M)":                           {"spawner", m, m},
		"spawner (source, sink)":                   {"spawner", src(), sink},
		"phone (M, M)":                             {"phone", m, m},
		"phone (M, sink): only a source is burned": {"phone", m, sink},
		"gullible (M, sink)":                       {"gullible", m, sink},
		"gullible (sink, source)":                  {"gullible", sink, src()},
		"phone (source, source)":                   {"phone", src(), src()},
		"phone (M, source)":                        {"phone", m, src()},
		"gullible (M, M)":                          {"gullible", m, m},
	} {
		if _, err := notarize(t, w, n, w.Cert(t, c.signer, c.signer, c.pred, c.succ, kernel.Top())); err == nil {
			t.Fatalf("%s: notarized", name)
		}
	}
}

// Root's (anything, anything) is accepted, even shapes no other row has
func TestRootSignsAnything(t *testing.T) {
	w := ktest.New(t)
	n := newN(t, w)
	sink, m := ktest.SinkObj(), ktest.NewMachine(t, "m1").Obj
	src := ktest.Source(ktest.Image, "")
	for _, c := range [][2]kernel.Object{{sink, sink}, {m, sink}, {m, ktest.NewMachine(t, "m2").Obj}, {src, ktest.Source("", "")}, {sink, m}, {src, m}, {src, m}} {
		if _, err := notarize(t, w, n, w.Cert(t, "root", "root", c[0], c[1], kernel.Top())); err != nil {
			t.Fatalf("root (%s, %s): %v", c[0].ID, c[1].ID, err)
		}
	}
}

// Forbidden: a second successor of a source, whichever row the first went through
func TestFirstSuccessorThroughAnyRow(t *testing.T) {
	w := ktest.New(t)
	n := newN(t, w)
	m, m2 := ktest.NewMachine(t, "m1").Obj, ktest.NewMachine(t, "m2").Obj

	// after a burn
	burned := ktest.Source(ktest.Image, "")
	if _, err := notarize(t, w, n, w.Cert(t, "gullible", "gullible", burned, ktest.SinkObj(), kernel.Top())); err != nil {
		t.Fatal(err)
	}
	for _, signer := range []string{"spawner", "phone"} {
		if _, err := notarize(t, w, n, w.Cert(t, signer, signer, burned, m, kernel.Top())); err == nil {
			t.Fatalf("a %s successor of a burned source notarized", signer)
		}
	}
	// burning it again ends nothing more and is harmless: the burn row has no condition
	if _, err := notarize(t, w, n, w.Cert(t, "gullible", "gullible", burned, ktest.SinkObj(), kernel.Top())); err != nil {
		t.Fatal(err)
	}

	// after a spawn: neither a second spawn nor the phone's (source, M) for the same source
	spawned := ktest.Source(ktest.Image, "")
	if _, err := notarize(t, w, n, w.Cert(t, "spawner", "spawner", spawned, m, kernel.Top())); err != nil {
		t.Fatal(err)
	}
	if _, err := notarize(t, w, n, w.Cert(t, "spawner", "spawner", spawned, m2, kernel.Top())); err == nil {
		t.Fatal("a second spawn of one source notarized")
	}
	if _, err := notarize(t, w, n, w.Cert(t, "phone", "phone", spawned, m2, kernel.Top())); err == nil {
		t.Fatal("the phone's successor of a spawned source notarized")
	}
	// after a root-signed successor
	rooted := ktest.Source("", "")
	if _, err := notarize(t, w, n, w.Cert(t, "root", "root", rooted, m, kernel.Top())); err != nil {
		t.Fatal(err)
	}
	if _, err := notarize(t, w, n, w.Cert(t, "phone", "phone", rooted, m, kernel.Top())); err == nil {
		t.Fatal("first successor after root's: notarized")
	}
	// but root itself has no condition
	if _, err := notarize(t, w, n, w.Cert(t, "root", "root", rooted, m2, kernel.Top())); err != nil {
		t.Fatal(err)
	}
	// the same source id with other contents is the same source
	twin := spawned
	twin.Settings = "other"
	if _, err := notarize(t, w, n, w.Cert(t, "spawner", "spawner", twin, m2, kernel.Top())); err == nil {
		t.Fatal("a source id reused with other contents notarized")
	}
}

// Forbidden: challenges that aren't the log notary's for this cert, and a challenge answered twice
func TestTheChallengeMustBeTheNotarysForThisCert(t *testing.T) {
	w := ktest.New(t)
	n := newN(t, w)
	cert := w.Cert(t, "phone", "phone", ktest.SinkObj(), ktest.Source(ktest.Image, ""), kernel.Top())
	other := w.Cert(t, "phone", "phone", ktest.SinkObj(), ktest.Source(ktest.Image, ""), kernel.Top())
	forged, _ := kernel.Sign(w.Keys["mover"], kernel.Challenge{Kind: "challenge", Subject: cert.ID(), About: "succession", Nonce: "00"})
	for name, ch := range map[string]kernel.SignedDoc{
		"another cert's challenge":   w.Challenge(t, other.ID(), "succession"),
		"a challenge about commands": w.Challenge(t, cert.ID(), "command"),
		"not signed by the notary":   forged,
	} {
		if _, err := n.Notarize(cert, ch); err == nil {
			t.Fatalf("%s: notarized", name)
		}
	}
	ch := w.Challenge(t, cert.ID(), "succession")
	if _, err := n.Notarize(cert, ch); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Notarize(cert, ch); err == nil {
		t.Fatal("a challenge answered twice")
	}
	// forbidden: a cert signed by another key than its signer's
	fake := w.Cert(t, "phone", "gullible", ktest.SinkObj(), ktest.Source(ktest.Image, ""), kernel.Top())
	if _, err := notarize(t, w, n, fake); err == nil {
		t.Fatal("a cert naming the phone, signed by the gullible key, notarized")
	}
}

// The sources already continued survive a restart (state file)
func TestFirstSuccessorSurvivesARestart(t *testing.T) {
	w := ktest.New(t)
	path := filepath.Join(t.TempDir(), "state")
	n, err := New(w.Keys["notarizer"], w.Roster, path)
	if err != nil {
		t.Fatal(err)
	}
	src, m := ktest.Source(ktest.Image, ""), ktest.NewMachine(t, "m1").Obj
	if _, err := notarize(t, w, n, w.Cert(t, "spawner", "spawner", src, m, kernel.Top())); err != nil {
		t.Fatal(err)
	}
	n2, err := New(w.Keys["notarizer"], w.Roster, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := notarize(t, w, n2, w.Cert(t, "spawner", "spawner", src, m, kernel.Top())); err == nil {
		t.Fatal("a restarted notarizer forgot the source was continued")
	}
}

// The table is data: the rows DESIGN lists, and Match is the one path
func TestTheTableIsDESIGNs(t *testing.T) {
	if len(Table) != 7 {
		t.Fatalf("%d rows", len(Table))
	}
	first := 0
	for _, r := range Table {
		if r.FirstSuccessor {
			first++
			if r.Pred != kernel.KindSource {
				t.Fatal("first successor is a source's rule")
			}
		}
	}
	if first != 2 {
		t.Fatal("two rows have the first-successor condition")
	}
}
