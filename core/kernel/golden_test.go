package kernel_test

// Golden vectors (testdata/*.json): the exact bytes of every document type, made with the TEST keys in
// testdata/keys.json (derived from a public seed), for the router, the guard and the iOS app to test against. Signatures are random (ECDSA), so a
// vector pins a payload and a signature that verifies; every derived payload (a notarization, a moved or merged grant)
// is deterministic and the test recomputes it byte for byte.
//
//	go test ./kernel -run TestGolden -update    rewrites the vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/merger"
	"github.com/DE0CH/jarvis2/core/kernel/mover"
	"github.com/DE0CH/jarvis2/core/kernel/notarizer"
)

var update = flag.Bool("update", false, "rewrite testdata/*.json golden vectors")

type keyFile struct {
	Note   string                       `json:"note"`
	Roles  map[string]map[string]string `json:"roles"` // role → {scalar: hex private scalar, public: base64 X9.63}
	Roster kernel.Roster                `json:"roster"`
	// a Fly machine's public keys used in the vectors
	Machine kernel.Object `json:"machine"`
}

// testScalar: the TEST key of a role, from a public seed: the first counter c = 0, 1, … for which
// SHA-256("jarvis2 test key " + role + " " + c) is a valid P-256 scalar (in [1, n-1]). Never used outside tests.
func testScalar(role string) []byte {
	for c := 0; ; c++ {
		h := sha256.Sum256([]byte("jarvis2 test key " + role + " " + strconv.Itoa(c)))
		if _, err := kernel.SignerFromScalar(h[:]); err == nil {
			return h[:]
		}
	}
}

func loadKeys(t *testing.T) (map[string]*kernel.Signer, keyFile) {
	t.Helper()
	keys := map[string]*kernel.Signer{}
	gen := keyFile{Note: "TEST KEYS ONLY, derived from a public seed (golden_test.go testScalar): never used outside tests",
		Roles: map[string]map[string]string{}}
	for _, r := range append(rolesOf(), "machine-signing", "machine-encryption") {
		d := testScalar(r)
		s, err := kernel.SignerFromScalar(d)
		if err != nil {
			t.Fatal(err)
		}
		keys[r] = s
		gen.Roles[r] = map[string]string{"scalar": hex.EncodeToString(d), "public": s.PublicKey()}
	}
	p := func(r string) string { return keys[r].PublicKey() }
	gen.Roster = kernel.Roster{Notary: p("notary"), Notarizer: p("notarizer"), Mover: p("mover"), Merger: p("merger"), Spawner: p("spawner"),
		Identity: p("identity"), Gullible: p("gullible"), Secrets: p("secrets"), Phone: p("phone"), Root: p("root")}
	gen.Machine = kernel.Object{ID: "e2860a1b2c3d4e", SigningKey: p("machine-signing"), EncryptionKey: p("machine-encryption")}
	var kf keyFile
	if err := json.Unmarshal(golden(t, "keys.json", gen), &kf); err != nil {
		t.Fatal(err)
	}
	if kf.Roster != gen.Roster || kf.Machine != gen.Machine {
		t.Fatal("keys.json isn't what the seed derives")
	}
	return keys, kf
}

func rolesOf() []string {
	return []string{"notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "secrets", "phone", "root"}
}

// golden: write v to testdata/name with -update, else read it into v's type and return the bytes
func golden(t *testing.T, name string, v any) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		b, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (go test ./kernel -run TestGolden -update)", name, err)
	}
	return b
}

func mustSign(t *testing.T, s *kernel.Signer, v any) kernel.SignedDoc {
	t.Helper()
	d, err := kernel.Sign(s, v)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// ---- sets and pairs --------------------------------------------------------------------------------

type setCase struct {
	A            kernel.Set `json:"a"`
	B            kernel.Set `json:"b"`
	Subset       bool       `json:"subset"` // a ⊆ b
	Equal        bool       `json:"equal"`
	Intersection kernel.Set `json:"intersection"`
	Union        kernel.Set `json:"union"`
}

func TestGoldenSets(t *testing.T) {
	sets := []kernel.Set{kernel.Only(), kernel.Everything(), kernel.Only("a"), kernel.Only("a", "b"), kernel.Except("a"),
		kernel.Except("a", "b"), kernel.Only("store:claude", "shell"), kernel.Except("shell")}
	var gen []setCase
	for _, a := range sets {
		for _, b := range sets {
			gen = append(gen, setCase{a, b, a.Subset(b), a.Equal(b), a.Intersect(b), a.Union(b)})
		}
	}
	var cases []setCase
	if err := json.Unmarshal(golden(t, "sets.json", gen), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(gen) {
		t.Fatal("stale sets.json")
	}
	for _, c := range cases {
		if c.A.Subset(c.B) != c.Subset || c.A.Equal(c.B) != c.Equal || !c.A.Intersect(c.B).Equal(c.Intersection) || !c.A.Union(c.B).Equal(c.Union) {
			t.Fatalf("%+v", c)
		}
	}
}

type pairCase struct {
	P    kernel.Pair `json:"p"`
	Q    kernel.Pair `json:"q"`
	Leq  bool        `json:"leq"` // p ≤ q
	Meet kernel.Pair `json:"meet"`
}

func TestGoldenPairs(t *testing.T) {
	ps := []kernel.Pair{kernel.Top(), {Allowed: kernel.Only("shell"), Conditions: kernel.CanonConditions("session:s1", "until:2026-10-14T12:10Z")},
		{Allowed: kernel.Only("shell", "store:claude"), Conditions: kernel.CanonConditions("session:s1")},
		{Allowed: kernel.Everything(), Conditions: kernel.CanonConditions("until:2026-10-14T12:10Z")}, {Allowed: kernel.Only(), Conditions: kernel.Conditions{}}}
	var gen []pairCase
	for _, p := range ps {
		for _, q := range ps {
			gen = append(gen, pairCase{p, q, p.Leq(q), p.Meet(q)})
		}
	}
	var cases []pairCase
	if err := json.Unmarshal(golden(t, "pairs.json", gen), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		m := c.P.Meet(c.Q)
		if c.P.Leq(c.Q) != c.Leq || !m.Allowed.Equal(c.Meet.Allowed) || !kernel.SameConditions(m.Conditions, c.Meet.Conditions) {
			t.Fatalf("%+v", c)
		}
	}
}

// ---- objects ------------------------------------------------------------------------------------

type objectsFile struct {
	Valid   []kernel.Object   `json:"valid"`
	Invalid []json.RawMessage `json:"invalid"` // each refused by Valid or by strict decoding
	Keys    []struct {
		Object        kernel.Object `json:"object"`
		SigningKey    string        `json:"signingKey"`
		EncryptionKey string        `json:"encryptionKey"`
	} `json:"keys"` // the keys of each valid object (derived for sources and the sink)
}

func TestGoldenObjects(t *testing.T) {
	_, kf := loadKeys(t)
	src := kernel.Object{ID: "source-0123456789abcdef0123456789abcdef", Image: "ghcr.io/de0ch/jarvis2-session:1@sha256:" + strings.Repeat("1", 64),
		Settings: `{"harness":"claude","permissionMode":"auto","title":"t"}`}
	killed := kernel.Object{ID: "source-fedcba9876543210fedcba9876543210", Image: src.Image, Settings: src.Settings, Snapshot: strings.Repeat("ab", 32)}
	gen := objectsFile{Valid: []kernel.Object{{ID: "sink"}, src, killed, {ID: "source-00000000000000000000000000000000"}, kf.Machine}}
	for _, bad := range []string{`{"id":"sink","image":"x"}`, `{"id":"` + src.ID + `","signingKey":"` + kf.Machine.SigningKey + `"}`,
		`{"id":"e286"}`, `{"id":"E286","signingKey":"` + kf.Machine.SigningKey + `","encryptionKey":"` + kf.Machine.EncryptionKey + `"}`,
		`{"id":"source-xyz"}`, `{"id":"sink","extra":1}`, `{"id":"` + src.ID + `","snapshot":"short"}`} {
		gen.Invalid = append(gen.Invalid, json.RawMessage(bad))
	}
	for _, o := range gen.Valid {
		gen.Keys = append(gen.Keys, struct {
			Object        kernel.Object `json:"object"`
			SigningKey    string        `json:"signingKey"`
			EncryptionKey string        `json:"encryptionKey"`
		}{o, o.SigningKeyOf(), o.EncryptionKeyOf()})
	}
	var f objectsFile
	if err := json.Unmarshal(golden(t, "objects.json", gen), &f); err != nil {
		t.Fatal(err)
	}
	for _, o := range f.Valid {
		if err := o.Valid(); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range f.Invalid {
		var o kernel.Object
		if kernel.Decode(raw, &o) == nil && o.Valid() == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	for _, k := range f.Keys {
		if k.Object.SigningKeyOf() != k.SigningKey || k.Object.EncryptionKeyOf() != k.EncryptionKey {
			t.Fatalf("%s keys", k.Object.ID)
		}
	}
}

// ---- challenge, succession certs and the table, notarizations -----------------------------------------------

type successionCase struct {
	Name      string           `json:"name"`
	Cert      kernel.SignedDoc `json:"cert"`
	Challenge kernel.SignedDoc `json:"challenge"`
	// Notarization: the notarizer's answer (its payload is deterministic); absent when Refused says why
	Notarization *kernel.SignedDoc `json:"notarization,omitempty"`
	Refused      string            `json:"refused,omitempty"`
}

// the cases, in order (the first-successor rule depends on it), with one notarizer
func successionCases(t *testing.T, keys map[string]*kernel.Signer, kf keyFile) []successionCase {
	m := kf.Machine
	other := kernel.Object{ID: "e2860a1b2c3d4f", SigningKey: keys["identity"].PublicKey(), EncryptionKey: keys["secrets"].PublicKey()}
	x := kernel.Object{ID: "source-0123456789abcdef0123456789abcdef", Image: "ghcr.io/de0ch/jarvis2-session:1@sha256:" + strings.Repeat("1", 64),
		Settings: `{"harness":"claude","permissionMode":"auto","title":"t"}`}
	y := kernel.Object{ID: "source-fedcba9876543210fedcba9876543210", Image: x.Image, Settings: x.Settings, Snapshot: strings.Repeat("ab", 32)}
	add := kernel.Object{ID: "source-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	sink := kernel.Object{ID: "sink"}
	P := kernel.Pair{Allowed: kernel.Only("store:claude", "store:default"), Conditions: kernel.CanonConditions("session:s4f00")}
	Padd := kernel.Pair{Allowed: kernel.Only("shell"), Conditions: kernel.CanonConditions("session:s4f00", "until:2026-10-14T12:10Z")}
	narrow := kernel.Pair{Allowed: kernel.Everything(), Conditions: kernel.CanonConditions("until:2026-10-14T12:10Z")}
	return build(t, keys, []certSpec{
		{"new session: (sink, source-x) by the phone", "phone", "phone", sink, x, P},
		{"spawn: (source-x, M) by the spawner", "spawner", "spawner", x, m, kernel.Top()},
		{"refused: a second spawn of source-x", "spawner", "spawner", x, other, kernel.Top()},
		{"refused: the phone's (source-x, M') after the spawn", "phone", "phone", x, other, kernel.Top()},
		{"add: (sink, source-a, P_add) by the phone", "phone", "phone", sink, add, Padd},
		{"add: (source-a, M, ⊤) by the phone", "phone", "phone", add, m, kernel.Top()},
		{"narrow: (M, M, (everything, {until})) by the identity signer", "identity", "identity", m, m, narrow},
		{"refused: the identity signer's (M, M')", "identity", "identity", m, other, narrow},
		{"refused: a gullible (source, M)", "gullible", "gullible", add, m, kernel.Top()},
		{"refused: a cert naming the phone, signed by the gullible key", "phone", "gullible", sink, add, kernel.Top()},
		{"pause: (M, source-y, ⊤) by the spawner", "spawner", "spawner", m, y, kernel.Top()},
		{"end: (source-y, sink) by the gullible signer", "gullible", "gullible", y, sink, kernel.Top()},
		{"refused: a spawn of source-y after its burn", "spawner", "spawner", y, other, kernel.Top()},
		{"refused: (M, sink): only a source is burned", "gullible", "gullible", m, sink, kernel.Top()},
		{"root: (anything, anything)", "root", "root", y, other, kernel.Top()},
	})
}

// certSpec: a cert as `signer` names itself, signed with key's key
type certSpec struct {
	name, signer, key string
	pred, succ        kernel.Object
	p                 kernel.Pair
}

func build(t *testing.T, keys map[string]*kernel.Signer, cs []certSpec) []successionCase {
	out := []successionCase{}
	for _, v := range cs {
		cert := mustSign(t, keys[v.key], kernel.Succession{Kind: "succession", Signer: v.signer, Predecessor: v.pred, Successor: v.succ,
			Allowed: v.p.Allowed, Conditions: v.p.Conditions})
		ch := mustSign(t, keys["notary"], kernel.Challenge{Kind: "challenge", Seq: int64(len(out)), At: "2026-10-14T12:00:00.000000001Z",
			Subject: cert.ID(), About: "succession", Nonce: strings.Repeat("0", 31) + string(rune('a'+len(out)%6))})
		out = append(out, successionCase{Name: v.name, Cert: cert, Challenge: ch})
	}
	return out
}

func TestGoldenSuccession(t *testing.T) {
	keys, kf := loadKeys(t)
	gen := []successionCase{}
	if *update {
		gen = successionCases(t, keys, kf)
		n, _ := notarizer.New(keys["notarizer"], kf.Roster, "")
		for i := range gen {
			nc, err := n.Notarize(gen[i].Cert, gen[i].Challenge)
			if err != nil {
				gen[i].Refused = err.Error()
			} else {
				gen[i].Notarization = &nc.Notarization
			}
		}
	}
	var cases []successionCase
	if err := json.Unmarshal(golden(t, "succession.json", gen), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 10 {
		t.Fatal("too few succession vectors")
	}
	n, _ := notarizer.New(keys["notarizer"], kf.Roster, "")
	for _, c := range cases {
		if _, err := kernel.OpenChallenge(kf.Roster, c.Challenge); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		nc, err := n.Notarize(c.Cert, c.Challenge)
		if (err != nil) != (c.Refused != "") || strings.HasPrefix(c.Name, "refused") != (c.Refused != "") {
			t.Fatalf("%s: %v (recorded %q)", c.Name, err, c.Refused)
		}
		if err == nil {
			if nc.Notarization.Payload != c.Notarization.Payload || !kernel.Verify(kf.Roster.Notarizer, []byte(c.Notarization.Payload), c.Notarization.Sig) {
				t.Fatalf("%s: notarization %s, recorded %s", c.Name, nc.Notarization.Payload, c.Notarization.Payload)
			}
			if _, err := kernel.OpenNotarized(kf.Roster, kernel.NotarizedCert{Cert: c.Cert, Challenge: c.Challenge, Notarization: *c.Notarization}); err != nil {
				t.Fatal(err)
			}
		}
	}
	golden(t, "table.json", notarizer.Table) // the table itself, for readers in other languages
}

// ---- grants: root ⊤, moves, merges --------------------------------------------------------------------

type grantCase struct {
	Name   string                `json:"name"`
	Op     string                `json:"op"` // move | merge
	Grant  *kernel.SignedDoc     `json:"grant,omitempty"`
	Cert   *kernel.NotarizedCert `json:"cert,omitempty"`
	A      *kernel.SignedDoc     `json:"a,omitempty"`
	B      *kernel.SignedDoc     `json:"b,omitempty"`
	Result *kernel.SignedDoc     `json:"result,omitempty"` // its payload is deterministic
	Refuse bool                  `json:"refused,omitempty"`
}

type grantsFile struct {
	Root  kernel.SignedDoc `json:"root"` // ⊤ on the sink
	Cases []grantCase      `json:"cases"`
}

func TestGoldenGrants(t *testing.T) {
	keys, kf := loadKeys(t)
	mv, mg := mover.New(keys["mover"], kf.Roster), merger.New(keys["merger"], kf.Roster)
	var gen grantsFile
	if *update {
		var sc []successionCase
		b, err := os.ReadFile(filepath.Join("testdata", "succession.json")) // written by TestGoldenSuccession, which runs first
		if err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(b, &sc)
		nc := map[string]kernel.NotarizedCert{}
		for _, c := range sc {
			if c.Notarization != nil {
				nc[c.Name] = kernel.NotarizedCert{Cert: c.Cert, Challenge: c.Challenge, Notarization: *c.Notarization}
			}
		}
		gen.Root = mustSign(t, keys["root"], kernel.RootGrant())
		move := func(name string, g kernel.SignedDoc, cert string) kernel.SignedDoc {
			c := nc[cert]
			out, err := mv.Move(g, c)
			gc := grantCase{Name: name, Op: "move", Grant: &g, Cert: &c}
			if err != nil {
				gc.Refuse = true
			} else {
				gc.Result = &out
			}
			gen.Cases = append(gen.Cases, gc)
			return out
		}
		merge := func(name string, a, b kernel.SignedDoc) kernel.SignedDoc {
			out, err := mg.Merge(a, b)
			gc := grantCase{Name: name, Op: "merge", A: &a, B: &b}
			if err != nil {
				gc.Refuse = true
			} else {
				gc.Result = &out
			}
			gen.Cases = append(gen.Cases, gc)
			return out
		}
		g1 := move("⊤ along (sink, source-x, P)", gen.Root, "new session: (sink, source-x) by the phone")
		g2 := move("onto the machine along the spawn", g1, "spawn: (source-x, M) by the spawner")
		ga := move("⊤ along (sink, source-a, P_add)", gen.Root, "add: (sink, source-a, P_add) by the phone")
		ga = move("P_add onto M", ga, "add: (source-a, M, ⊤) by the phone")
		gn := move("the main grant narrowed along M's identity edge", g2, "narrow: (M, M, (everything, {until})) by the identity signer")
		move("refused: a grant on M along source-x's cert", g2, "new session: (sink, source-x) by the phone")
		merge("refused: different conditions", g2, ga)
		merge("main + terminal with identical conditions", gn, ga)
		move("the main grant to the paused source", g2, "pause: (M, source-y, ⊤) by the spawner")
		forged := mustSign(t, keys["gullible"], kernel.Grant{Kind: "grant", By: "mover", Machine: kf.Machine, Allowed: kernel.Everything(), Conditions: kernel.Conditions{}, From: []string{}})
		move("refused: a grant forged with the gullible key", forged, "narrow: (M, M, (everything, {until})) by the identity signer")
	}
	var f grantsFile
	if err := json.Unmarshal(golden(t, "grants.json", gen), &f); err != nil {
		t.Fatal(err)
	}
	if _, err := kernel.OpenGrant(kf.Roster, f.Root, "root"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		var out kernel.SignedDoc
		var err error
		if c.Op == "move" {
			out, err = mv.Move(*c.Grant, *c.Cert)
		} else {
			out, err = mg.Merge(*c.A, *c.B)
		}
		if (err != nil) != c.Refuse || strings.HasPrefix(c.Name, "refused") != c.Refuse {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if err == nil {
			if out.Payload != c.Result.Payload {
				t.Fatalf("%s: %s, recorded %s", c.Name, out.Payload, c.Result.Payload)
			}
			if _, err := kernel.OpenGrant(kf.Roster, *c.Result, "mover", "merger"); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// ---- challenge --------------------------------------------------------------------------------------

func TestGoldenChallenge(t *testing.T) {
	keys, kf := loadKeys(t)
	type file struct {
		Valid   []kernel.SignedDoc `json:"valid"`
		Invalid []kernel.SignedDoc `json:"invalid"` // not the notary's, or malformed
	}
	var gen file
	if *update {
		ok := kernel.Challenge{Kind: "challenge", Seq: 0, Prev: "", At: "2026-10-14T12:00:00.000000001Z", Subject: strings.Repeat("ab", 32), About: "succession", Nonce: strings.Repeat("01", 16)}
		gen.Valid = append(gen.Valid, mustSign(t, keys["notary"], ok))
		ok2 := ok
		ok2.Seq, ok2.Prev, ok2.About = 1, gen.Valid[0].ID(), "command"
		gen.Valid = append(gen.Valid, mustSign(t, keys["notary"], ok2))
		bad := ok
		bad.Subject = "AB"
		gen.Invalid = append(gen.Invalid, mustSign(t, keys["mover"], ok), mustSign(t, keys["notary"], bad))
	}
	var f file
	if err := json.Unmarshal(golden(t, "challenge.json", gen), &f); err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Valid {
		if _, err := kernel.OpenChallenge(kf.Roster, d); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range f.Invalid {
		if _, err := kernel.OpenChallenge(kf.Roster, d); err == nil {
			t.Fatalf("%s accepted", d.Payload)
		}
	}
}
