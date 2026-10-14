package gullible

import (
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func TestSignsAnythingWellFormed(t *testing.T) {
	w := ktest.New(t)
	g := New(w.Keys["gullible"])
	m := ktest.NewMachine(t, "m1").Obj
	for _, c := range [][2]kernel.Object{{ktest.Source("", ""), ktest.SinkObj()}, {ktest.Source("", ""), m}, {ktest.SinkObj(), ktest.Source("", "")}, {m, m}} {
		d, err := g.Sign(c[0], c[1], kernel.Top())
		if err != nil {
			t.Fatal(err)
		}
		if s, err := kernel.OpenSuccession(w.Roster, d); err != nil || s.Signer != "gullible" {
			t.Fatalf("%v %+v", err, s)
		}
	}
	// malformed objects are not documents at all
	if _, err := g.Sign(kernel.Object{ID: "sink", Image: "x"}, ktest.SinkObj(), kernel.Top()); err == nil {
		t.Fatal("a malformed object signed")
	}
}
