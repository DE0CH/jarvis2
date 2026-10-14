package kernel_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/ktest"
)

func TestObjectShapes(t *testing.T) {
	m := ktest.NewMachine(t, "e2860a1b2c3d4e")
	src := ktest.Source(ktest.Image, `{"harness":"claude"}`)
	for _, ok := range []kernel.Object{ktest.SinkObj(), src, {ID: "source-00000000000000000000000000000000"}, m.Obj} {
		if err := ok.Valid(); err != nil {
			t.Fatalf("%+v: %v", ok, err)
		}
	}
	// forbidden shapes
	for name, bad := range map[string]kernel.Object{
		"sink with keys":          {ID: "sink", SigningKey: m.Obj.SigningKey},
		"sink with an image":      {ID: "sink", Image: ktest.Image},
		"source with keys":        {ID: src.ID, EncryptionKey: m.Obj.EncryptionKey},
		"source, bad snapshot":    {ID: src.ID, Snapshot: "abc"},
		"source, upper-case id":   {ID: "source-0123456789ABCDEF0123456789ABCDEF"},
		"machine without keys":    {ID: "e286"},
		"machine with an image":   {ID: "e286", SigningKey: m.Obj.SigningKey, EncryptionKey: m.Obj.EncryptionKey, Image: ktest.Image},
		"machine, key off-curve":  {ID: "e286", SigningKey: kernel.B64.EncodeToString(make([]byte, 65)), EncryptionKey: m.Obj.EncryptionKey},
		"machine id with a dash":  {ID: "e2-86", SigningKey: m.Obj.SigningKey, EncryptionKey: m.Obj.EncryptionKey},
		"empty id":                {},
		"source, huge settings":   {ID: src.ID, Settings: strings.Repeat("x", kernel.MaxSettings+1)},
		"source, image with tabs": {ID: src.ID, Image: "a\tb"},
	} {
		if bad.Valid() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// A cert counts only under the key of the role it names
func TestASuccessionIsCheckedAgainstTheKeyOfTheSignerItNames(t *testing.T) {
	w := ktest.New(t)
	src := ktest.Source(ktest.Image, "")
	good := w.Cert(t, "phone", "phone", ktest.SinkObj(), src, kernel.Top())
	if _, err := kernel.OpenSuccession(w.Roster, good); err != nil {
		t.Fatal(err)
	}
	// forbidden: the gullible signer's key on a cert naming the phone; an unknown role; an altered payload
	if _, err := kernel.OpenSuccession(w.Roster, w.Cert(t, "phone", "gullible", ktest.SinkObj(), src, kernel.Top())); err == nil {
		t.Fatal("a cert naming the phone, signed by the gullible key, accepted")
	}
	if _, err := kernel.OpenSuccession(w.Roster, w.Cert(t, "mover", "mover", ktest.SinkObj(), src, kernel.Top())); err == nil {
		t.Fatal("a cert signed by the mover accepted")
	}
	alt := good
	alt.Payload = strings.Replace(alt.Payload, `"except":[]`, `"except":["x"]`, 1)
	if _, err := kernel.OpenSuccession(w.Roster, alt); err == nil {
		t.Fatal("an altered cert accepted")
	}
	// an unknown field refuses the document
	var s map[string]any
	json.Unmarshal([]byte(good.Payload), &s)
	s["extra"] = 1
	d, _ := kernel.Sign(w.Keys["phone"], s)
	if _, err := kernel.OpenSuccession(w.Roster, d); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestOpenGrant(t *testing.T) {
	w := ktest.New(t)
	m := ktest.NewMachine(t, "m1")
	if _, err := kernel.OpenGrant(w.Roster, w.RootGrant(t), "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := kernel.OpenGrant(w.Roster, w.Grant(t, "mover", "mover", m.Obj, ktest.P([]string{"x"})), "mover", "merger"); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]kernel.SignedDoc{
		"root grant that isn't ⊤":        w.Grant(t, "root", "root", ktest.SinkObj(), ktest.P([]string{"x"})),
		"root grant ⊤ on a machine":      w.Grant(t, "root", "root", m.Obj, kernel.Top()),
		"a grant by the gullible signer": w.Grant(t, "gullible", "gullible", m.Obj, kernel.Top()),
		"mover's name, merger's key":     w.Grant(t, "mover", "merger", m.Obj, kernel.Top()),
		"mover's name, the identity key": w.Grant(t, "mover", "identity", m.Obj, kernel.Top()),
		"a grant on an invalid object":   w.Grant(t, "mover", "mover", kernel.Object{ID: "e286"}, kernel.Top()),
	} {
		if _, err := kernel.OpenGrant(w.Roster, d, "mover", "merger", "root"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	d, _ := kernel.Sign(w.Keys["mover"], map[string]any{"kind": "grant", "by": "mover", "machine": m.Obj, "allowed": kernel.Everything(), "conditions": []string{}, "from": nil})
	if _, err := kernel.OpenGrant(w.Roster, d, "mover"); err == nil {
		t.Fatal("from: null accepted")
	}
	// a part taking only mover/merger grants refuses root's ⊤
	if _, err := kernel.OpenGrant(w.Roster, w.RootGrant(t), "mover", "merger"); err == nil {
		t.Fatal("root's ⊤ accepted where only mover/merger grants are")
	}
}

func TestOpenNotarizedChecksEveryLink(t *testing.T) {
	w := ktest.New(t)
	src := ktest.Source(ktest.Image, "")
	cert := w.Cert(t, "phone", "phone", ktest.SinkObj(), src, kernel.Top())
	nc := w.Notarize(t, cert)
	if _, err := kernel.OpenNotarized(w.Roster, nc); err != nil {
		t.Fatal(err)
	}
	other := w.Notarize(t, w.Cert(t, "phone", "phone", ktest.SinkObj(), ktest.Source(ktest.Image, ""), kernel.Top()))
	wrongAbout := nc
	wrongAbout.Challenge = w.Challenge(t, cert.ID(), "command")
	forged := nc
	forged.Notarization, _ = kernel.Sign(w.Keys["mover"], kernel.Notarization{Kind: "notarization", Cert: cert.ID(), Challenge: nc.Challenge.ID()})
	for name, bad := range map[string]kernel.NotarizedCert{
		"another cert's challenge":    {Cert: cert, Challenge: other.Challenge, Notarization: nc.Notarization},
		"another cert's notarization": {Cert: cert, Challenge: nc.Challenge, Notarization: other.Notarization},
		"a challenge about commands":  wrongAbout,
		"notarized by the mover key":  forged,
		"no notarization":             {Cert: cert, Challenge: nc.Challenge},
	} {
		if _, err := kernel.OpenNotarized(w.Roster, bad); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestSealRoundTripAndWrongKey(t *testing.T) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, err := kernel.SealTo(kernel.B64.EncodeToString(k.PublicKey().Bytes()), []byte("hi"), "info")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := kernel.OpenSealed(k, s, "info"); err != nil || string(b) != "hi" {
		t.Fatal("round trip")
	}
	if _, err := kernel.OpenSealed(other, s, "info"); err == nil {
		t.Fatal("opened with another key")
	}
	if _, err := kernel.OpenSealed(k, s, "other info"); err == nil {
		t.Fatal("opened under another info")
	}
}

// Errors leave signed by the part; a body with an unknown field is a 400
func TestHandlerSignsErrorsAndDecodesStrictly(t *testing.T) {
	s, _ := kernel.NewSigner()
	h := kernel.Handler(s, map[string]kernel.Route{
		"POST /x": func(body []byte) (any, error) {
			var in struct {
				A string `json:"a"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return nil, kernel.Fail(409, "no %s", in.A)
		},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	for body, status := range map[string]int{`{"a":"y"}`: 409, `{"b":1}`: 400, `{"a":"y"} {}`: 400} {
		resp, err := http.Post(srv.URL+"/x", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var d kernel.SignedDoc
		json.Unmarshal(b, &d)
		if resp.StatusCode != status || !kernel.Verify(s.PublicKey(), []byte(d.Payload), d.Sig) || !strings.Contains(d.Payload, `"kind":"error"`) {
			t.Fatalf("%s: %d %s", body, resp.StatusCode, b)
		}
	}
	if resp, _ := http.Get(srv.URL + "/x"); resp.StatusCode != 405 {
		t.Fatalf("GET on a POST route: %d", resp.StatusCode)
	}
}
