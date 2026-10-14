package identitysigner

import (
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func TestSignsMMForAnyP(t *testing.T) {
	w := ktest.New(t)
	i := New(w.Keys["identity"])
	m := ktest.NewMachine(t, "m1").Obj
	for _, p := range []kernel.Pair{kernel.Top(), ktest.P(nil, "until:T"), ktest.P([]string{"shell"}), {Allowed: kernel.Except("x")}} {
		d, err := i.Sign(m, p)
		if err != nil {
			t.Fatal(err)
		}
		s, err := kernel.OpenSuccession(w.Roster, d)
		if err != nil {
			t.Fatal(err)
		}
		if s.Signer != "identity" || s.Predecessor != m || s.Successor != m || !s.Allowed.Equal(p.Allowed) {
			t.Fatalf("%+v", s)
		}
	}
}

// Forbidden: anything but a Fly machine (a source, the sink, a malformed machine)
func TestSignsNothingElse(t *testing.T) {
	w := ktest.New(t)
	i := New(w.Keys["identity"])
	for _, o := range []kernel.Object{ktest.SinkObj(), ktest.Source(ktest.Image, ""), {ID: "m1"}} {
		if _, err := i.Sign(o, kernel.Top()); err == nil {
			t.Fatalf("%+v signed", o)
		}
	}
	if _, err := i.Routes()["POST /sign"]([]byte(`{"machine":{"id":"sink"},"allowed":{"except":[]},"conditions":[]}`)); err == nil {
		t.Fatal("the sink signed over HTTP")
	}
}
