package kernel

// The document formats. Every document is a SignedDoc whose payload is one of the structs below, decoded strictly (an
// unknown field refuses the document). Golden vectors: testdata/*.json.

import (
	"fmt"
	"regexp"
)

// ---- objects --------------------------------------------------------------------------------------

const (
	KindSink    = "sink"
	KindSource  = "source"
	KindMachine = "machine"
)

// Sink: the one global sink (no image, no settings)
const Sink = "sink"

var (
	sourceIDRE  = regexp.MustCompile(`^source-[0-9a-f]{32}$`)
	machineIDRE = regexp.MustCompile(`^[0-9a-z]{1,32}$`) // a Fly machine id
	hex64RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	printableRE = regexp.MustCompile(`^[\x21-\x7e]*$`)
)

const (
	MaxImage    = 512
	MaxSettings = 64 << 10 // the session's start settings (the first prompt is the big part)
)

// Object: what a succession cert and a grant name. Exactly one of three shapes:
//
//	sink:         {"id":"sink"}
//	source:       {"id":"source-<32 hex>","image":…,"settings":…,"snapshot":…}  (each may be empty)
//	Fly machine:  {"id":"<fly id>","signingKey":…,"encryptionKey":…}            (both keys required)
//
// Objects are compared whole (every field), so a grant on a source names its contents too.
type Object struct {
	ID string `json:"id"`
	// a source's contents: the image (ref@digest), the start settings (exact text the kernel doesn't read), and for a
	// source made by a kill, the hex sha256 of the snapshot
	Image    string `json:"image,omitempty"`
	Settings string `json:"settings,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	// a Fly machine's keys, as the spawner read them (or the phone showed them)
	SigningKey    string `json:"signingKey,omitempty"`
	EncryptionKey string `json:"encryptionKey,omitempty"`
}

func (o Object) Kind() string {
	switch {
	case o.ID == Sink:
		return KindSink
	case sourceIDRE.MatchString(o.ID):
		return KindSource
	default:
		return KindMachine
	}
}

func (o Object) Valid() error {
	src := o.Image != "" || o.Settings != "" || o.Snapshot != ""
	keys := o.SigningKey != "" || o.EncryptionKey != ""
	switch o.Kind() {
	case KindSink:
		if src || keys {
			return fmt.Errorf("the sink has no contents and no keys")
		}
	case KindSource:
		if keys {
			return fmt.Errorf("%s: a source's keys are derived from its name, not given", o.ID)
		}
		if len(o.Image) > MaxImage || !printableRE.MatchString(o.Image) || len(o.Settings) > MaxSettings {
			return fmt.Errorf("%s: image is printable ASCII up to %d bytes, settings up to %d bytes", o.ID, MaxImage, MaxSettings)
		}
		if o.Snapshot != "" && !hex64RE.MatchString(o.Snapshot) {
			return fmt.Errorf("%s: snapshot is a hex sha256", o.ID)
		}
	default:
		if !machineIDRE.MatchString(o.ID) {
			return fmt.Errorf("%q is not sink, source-<32 hex> or a Fly machine id", o.ID)
		}
		if src {
			return fmt.Errorf("machine %s: no image, settings or snapshot (those are its source's)", o.ID)
		}
		if _, err := ParsePoint(o.SigningKey); err != nil {
			return fmt.Errorf("machine %s: signingKey: %v", o.ID, err)
		}
		if _, err := ParsePoint(o.EncryptionKey); err != nil {
			return fmt.Errorf("machine %s: encryptionKey: %v", o.ID, err)
		}
	}
	return nil
}

// SigningKeyOf / EncryptionKeyOf: a Fly machine's own keys; a source's or the sink's hashed from its name
func (o Object) SigningKeyOf() string    { return o.keyOf(UseSigning, o.SigningKey) }
func (o Object) EncryptionKeyOf() string { return o.keyOf(UseEncryption, o.EncryptionKey) }

func (o Object) keyOf(use, own string) string {
	switch o.Kind() {
	case KindSink:
		return HashToKey(SinkKeyName(use))
	case KindSource:
		return HashToKey(SourceKeyName(o.ID, use))
	}
	return own
}

// ---- roster: the public keys of every part and signer -------------------------------------------------

// Roles of succession-cert signers (Succession.Signer) and of grant makers (Grant.By)
const (
	RolePhone    = "phone"
	RoleRoot     = "root"
	RoleSpawner  = "spawner"
	RoleIdentity = "identity"
	RoleGullible = "gullible"
	RoleMover    = "mover"
	RoleMerger   = "merger"
)

// Roster: every public key a part may need to check (config: ROSTER_FILE). Each part holds only its own private key.
type Roster struct {
	Notary    string `json:"notary"`
	Notarizer string `json:"notarizer"`
	Mover     string `json:"mover"`
	Merger    string `json:"merger"`
	Spawner   string `json:"spawner"`
	Identity  string `json:"identity"`
	Gullible  string `json:"gullible"`
	Secrets   string `json:"secrets"`
	Phone     string `json:"phone"` // the iPhone key
	Root      string `json:"root"`  // the root key (a separate iPhone key)
}

// KeyOf: the key a role signs with ("" for an unknown role)
func (r Roster) KeyOf(role string) string {
	return map[string]string{RolePhone: r.Phone, RoleRoot: r.Root, RoleSpawner: r.Spawner, RoleIdentity: r.Identity,
		RoleGullible: r.Gullible, RoleMover: r.Mover, RoleMerger: r.Merger}[role]
}

// ---- succession cert --------------------------------------------------------------------------------

// Succession: (predecessor, successor, P), signed by Signer's key. With its log-notary challenge and the notarizer's
// notarization it is a notarized cert (NotarizedCert).
type Succession struct {
	Kind        string     `json:"kind"`   // "succession"
	Signer      string     `json:"signer"` // phone | root | spawner | identity | gullible
	Predecessor Object     `json:"predecessor"`
	Successor   Object     `json:"successor"`
	Allowed     Set        `json:"allowed"`
	Conditions  Conditions `json:"conditions"`
}

func (s Succession) Pair() Pair { return Pair{s.Allowed, s.Conditions} }

func (s Succession) Valid() error {
	if s.Kind != "succession" {
		return fmt.Errorf("not a succession cert")
	}
	switch s.Signer {
	case RolePhone, RoleRoot, RoleSpawner, RoleIdentity, RoleGullible:
	default:
		return fmt.Errorf("signer: phone, root, spawner, identity or gullible")
	}
	if err := s.Predecessor.Valid(); err != nil {
		return fmt.Errorf("predecessor: %v", err)
	}
	if err := s.Successor.Valid(); err != nil {
		return fmt.Errorf("successor: %v", err)
	}
	return nil
}

// OpenSuccession: a succession cert signed by the key of the role it names
func OpenSuccession(r Roster, d SignedDoc) (Succession, error) {
	var s Succession
	if err := strictJSON([]byte(d.Payload), &s); err != nil {
		return s, fmt.Errorf("not a succession cert: %v", err)
	}
	if err := s.Valid(); err != nil {
		return s, err
	}
	if err := Open(r.KeyOf(s.Signer), d, &s); err != nil {
		return s, fmt.Errorf("the cert isn't signed by the %s key", s.Signer)
	}
	return s, nil
}

// ---- log notary challenge -----------------------------------------------------------------------------

// Challenge: issued by the log notary with its own clock, one entry of its hash-chained log
type Challenge struct {
	Kind    string `json:"kind"`    // "challenge"
	Seq     int64  `json:"seq"`     // place in this notary's log (0 = the first since it started)
	Prev    string `json:"prev"`    // hex sha256 of the previous challenge's payload ("" = the first)
	At      string `json:"at"`      // RFC 3339 UTC, nanoseconds, the notary's clock
	Subject string `json:"subject"` // hex sha256 of what it is about (a cert's payload, a command…)
	About   string `json:"about"`   // a word, recorded as given ("succession" for a cert)
	Nonce   string `json:"nonce"`   // 16 random bytes, hex
}

// AboutSuccession: what a challenge for a succession cert is about
const AboutSuccession = "succession"

var AboutRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func OpenChallenge(r Roster, d SignedDoc) (Challenge, error) {
	var c Challenge
	if err := Open(r.Notary, d, &c); err != nil || c.Kind != "challenge" {
		return c, fmt.Errorf("not a challenge the log notary signed")
	}
	if !hex64RE.MatchString(c.Subject) || !AboutRE.MatchString(c.About) {
		return c, fmt.Errorf("challenge: bad subject or about")
	}
	return c, nil
}

// ---- notarization ------------------------------------------------------------------------------------

// Notarization: the succession notarizer's answer to a challenge for a cert it checked against the table
type Notarization struct {
	Kind      string `json:"kind"`      // "notarization"
	Cert      string `json:"cert"`      // ID of the succession cert
	Challenge string `json:"challenge"` // ID of the log notary's challenge
}

// NotarizedCert: a succession cert, the challenge for it and the notarization (the unit everything after takes)
type NotarizedCert struct {
	Cert         SignedDoc `json:"cert"`
	Challenge    SignedDoc `json:"challenge"`
	Notarization SignedDoc `json:"notarization"`
}

// OpenNotarized: every signature and every link checked; the cert's content
func OpenNotarized(r Roster, nc NotarizedCert) (Succession, error) {
	s, err := OpenSuccession(r, nc.Cert)
	if err != nil {
		return s, err
	}
	ch, err := OpenChallenge(r, nc.Challenge)
	if err != nil {
		return s, err
	}
	if ch.Subject != nc.Cert.ID() || ch.About != AboutSuccession {
		return s, fmt.Errorf("the challenge isn't for this cert")
	}
	var n Notarization
	if err := Open(r.Notarizer, nc.Notarization, &n); err != nil || n.Kind != "notarization" {
		return s, fmt.Errorf("not notarized by the succession notarizer")
	}
	if n.Cert != nc.Cert.ID() || n.Challenge != nc.Challenge.ID() {
		return s, fmt.Errorf("the notarization is for another cert or challenge")
	}
	return s, nil
}

// ---- grant -----------------------------------------------------------------------------------------

// Grant: (machine, allowed, conditions), made only by the grant mover and the grant merger, and ⊤ on the sink by the
// root key
type Grant struct {
	Kind       string     `json:"kind"` // "grant"
	By         string     `json:"by"`   // mover | merger | root
	Machine    Object     `json:"machine"`
	Allowed    Set        `json:"allowed"`
	Conditions Conditions `json:"conditions"`
	// From: the IDs of what it was made from — mover: [the grant, the cert's notarization]; merger: [both grants];
	// root: [] (an audit trail; nothing checks it)
	From []string `json:"from"`
}

func (g Grant) Pair() Pair { return Pair{g.Allowed, g.Conditions} }

// RootGrant: ⊤ on the sink, the one grant the root key makes
func RootGrant() Grant {
	return Grant{Kind: "grant", By: RoleRoot, Machine: Object{ID: Sink}, Allowed: Everything(), Conditions: Conditions{}, From: []string{}}
}

// OpenGrant: a grant made by one of `by` (mover, merger, root), signed by that role's key. A root grant is only ever
// ⊤ on the sink.
func OpenGrant(r Roster, d SignedDoc, by ...string) (Grant, error) {
	var g Grant
	if err := strictJSON([]byte(d.Payload), &g); err != nil || g.Kind != "grant" || g.From == nil {
		return g, fmt.Errorf("not a grant")
	}
	ok := false
	for _, b := range by {
		ok = ok || b == g.By
	}
	if !ok {
		return g, fmt.Errorf("a grant by %s isn't taken here", g.By)
	}
	if err := Open(r.KeyOf(g.By), d, &g); err != nil {
		return g, fmt.Errorf("the grant isn't signed by the %s key", g.By)
	}
	if err := g.Machine.Valid(); err != nil {
		return g, fmt.Errorf("grant machine: %v", err)
	}
	if g.By == RoleRoot {
		top := RootGrant()
		if g.Machine != top.Machine || !g.Allowed.Equal(top.Allowed) || len(g.Conditions) != 0 || len(g.From) != 0 {
			return g, fmt.Errorf("the root key makes only ⊤ on the sink")
		}
	}
	return g, nil
}
