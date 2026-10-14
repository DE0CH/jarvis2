// Package spawner alone holds the Fly token. It attests Fly facts only, so every cert it signs has P = ⊤:
//
//	spawn from source-x (given source-x's notarized cert): start a Fly machine with the source's image, read its keys
//	once it is up, sign (source-x, M, ⊤);
//	kill M (given M's notarized spawn cert): check it is alive, kill it, confirm it dead through the Fly API, take its
//	snapshot hash, sign (M, source-y, ⊤), source-y a fresh source holding M's image, settings and that hash.
//
// The machine's Fly config env is the spawner's alone: its own signing key and the router's address. Its state (which
// machines it created, which it killed) is in memory; the notarizer's first-successor rule is what stops a source from
// being continued twice, the spawner only avoids starting machines nobody can certify.
package spawner

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// SessionRepo: the one image repository machines run, pinned by digest
const SessionRepo = "ghcr.io/de0ch/jarvis2-session"

var imageRE = regexp.MustCompile(`^` + regexp.QuoteMeta(SessionRepo) + `(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@(sha256:[0-9a-f]{64})$`)

// imageDigest: the sha256:… of a pinned session image, "" when the reference isn't one
func imageDigest(ref string) string {
	m := imageRE.FindStringSubmatch(ref)
	if m == nil {
		return ""
	}
	return m[2]
}

// reportedDigest: the digest in what Fly reports a machine runs (registry/repository@sha256:…)
func reportedDigest(ref string) string {
	i := strings.LastIndex(ref, "@sha256:")
	if i < 0 || len(ref)-i-1 != len("sha256:")+64 {
		return ""
	}
	return ref[i+1:]
}

// Env names in every machine's Fly config
const (
	SpawnerKeyEnv = "JARVIS2_SPAWNER_KEY"
	RouterURLEnv  = "JARVIS2_URL"
)

var machineURLRE = regexp.MustCompile(`^http://[A-Za-z0-9][A-Za-z0-9._-]{0,200}(:[0-9]{1,5})?/?$`)

// MachineURL: the spawner deployment's MACHINE_URL (the router on Fly's private network), "" when unset or malformed
func MachineURL() string {
	u := strings.TrimSpace(os.Getenv("MACHINE_URL"))
	if !machineURLRE.MatchString(u) {
		return ""
	}
	return u
}

const infoFlyToken = "jarvis2/fly-token"

type Spawner struct {
	mu        sync.Mutex
	signer    *kernel.Signer
	agreement *ecdh.PrivateKey // the Fly token is sealed to it
	roster    kernel.Roster
	fly       Fly
	url       string // the router's address for machines ("" = it starts none)

	spawned map[string]string        // source ID → the machine created from it
	created map[string]kernel.Object // a machine created and not yet initialised → its source
	killing map[string]string        // a machine whose destroy was asked → the snapshot hash fixed then
	killed  map[string]kernel.SignedDoc
}

func New(s *kernel.Signer, r kernel.Roster, fly Fly, machineURL string) (*Spawner, error) {
	a, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Spawner{signer: s, agreement: a, roster: r, fly: fly, url: machineURL, spawned: map[string]string{},
		created: map[string]kernel.Object{}, killing: map[string]string{}, killed: map[string]kernel.SignedDoc{}}, nil
}

func (sp *Spawner) AgreementKey() string {
	return kernel.B64.EncodeToString(sp.agreement.PublicKey().Bytes())
}

// SetFlyToken: {"FLY_API_TOKEN": …} sealed to the spawner (open: a wrong token can only fail)
func (sp *Spawner) SetFlyToken(sealed kernel.Sealed) (kernel.SignedDoc, error) {
	plain, err := kernel.OpenSealed(sp.agreement, sealed, infoFlyToken)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(400, "can't open the Fly token")
	}
	var v struct {
		Token string `json:"FLY_API_TOKEN"`
	}
	if json.Unmarshal(plain, &v) != nil || v.Token == "" {
		return kernel.SignedDoc{}, kernel.Fail(400, "no FLY_API_TOKEN")
	}
	sp.fly.Configure(v.Token)
	log.Printf("Fly token set")
	return kernel.Sign(sp.signer, map[string]any{"kind": "fly-token-set"})
}

// Spawn: one Fly create from the source the notarized cert ends in. One machine per source. The router then calls
// Init until the machine is up.
func (sp *Spawner) Spawn(cert kernel.NotarizedCert, region, size string) (kernel.SignedDoc, error) {
	s, err := kernel.OpenNotarized(sp.roster, cert)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(403, "%v", err)
	}
	src := s.Successor
	if src.Kind() != kernel.KindSource {
		return kernel.SignedDoc{}, kernel.Fail(400, "a spawn is from a source; the cert ends in %s", src.ID)
	}
	if imageDigest(src.Image) == "" {
		return kernel.SignedDoc{}, kernel.Fail(400, "source %s's image isn't %s pinned by digest", src.ID, SessionRepo)
	}
	guest, ok := sizes[size]
	if !ok {
		return kernel.SignedDoc{}, kernel.Fail(400, "size: small, medium or large")
	}
	if sp.url == "" {
		return kernel.SignedDoc{}, kernel.Fail(503, "this spawner has no MACHINE_URL: it starts no machine")
	}
	sp.mu.Lock()
	if m, ok := sp.spawned[src.ID]; ok {
		sp.mu.Unlock()
		return kernel.SignedDoc{}, kernel.Fail(409, "source %s was already spawned (machine %s)", src.ID, m)
	}
	sp.spawned[src.ID] = "" // held while Fly creates
	sp.mu.Unlock()
	id, err := sp.fly.Create(CreateRequest{Image: src.Image, Region: region, Guest: guest,
		Env: map[string]string{SpawnerKeyEnv: sp.signer.PublicKey(), RouterURLEnv: sp.url}})
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if err != nil {
		delete(sp.spawned, src.ID)
		return kernel.SignedDoc{}, kernel.Fail(502, "fly create: %v", err)
	}
	sp.spawned[src.ID], sp.created[id] = id, src
	log.Printf("machine %s created from %s", id, src.ID)
	return kernel.Sign(sp.signer, map[string]any{"kind": "created", "machine": id, "source": src.ID})
}

// Init: one try at reading a created machine's keys — Fly must report it started and running the source's digest
// (else it is destroyed), then the image's init command prints them. 409 while it isn't up yet. → (source, M, ⊤)
func (sp *Spawner) Init(id string) (kernel.SignedDoc, error) {
	sp.mu.Lock()
	src, ok := sp.created[id]
	sp.mu.Unlock()
	if !ok {
		return kernel.SignedDoc{}, kernel.Fail(409, "machine %s isn't one this spawner created and hasn't initialised", id)
	}
	fm, err := sp.fly.Inspect(id)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(502, "fly: %v", err)
	}
	if fm.State != "started" {
		return kernel.SignedDoc{}, kernel.Fail(409, "machine %s is %s, not started", id, fm.State)
	}
	if reportedDigest(fm.Image) != imageDigest(src.Image) {
		derr := sp.fly.Destroy(id)
		sp.mu.Lock()
		delete(sp.created, id)
		sp.mu.Unlock()
		return kernel.SignedDoc{}, kernel.Fail(409, "machine %s runs %s, not %s: destroyed (%v)", id, fm.Image, src.Image, derr)
	}
	keys, err := sp.fly.Init(id)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(502, "fly exec init: %v", err)
	}
	m := kernel.Object{ID: id, SigningKey: keys.SigningKey, EncryptionKey: keys.EncryptionKey}
	if err := m.Valid(); err != nil {
		return kernel.SignedDoc{}, kernel.Fail(502, "jarvis2-init: %v", err)
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if _, ok := sp.created[id]; !ok {
		return kernel.SignedDoc{}, kernel.Fail(409, "machine %s was initialised meanwhile", id)
	}
	delete(sp.created, id)
	log.Printf("machine %s started from %s", id, src.ID)
	top := kernel.Top()
	return kernel.Sign(sp.signer, kernel.Succession{Kind: "succession", Signer: kernel.RoleSpawner, Predecessor: src, Successor: m,
		Allowed: top.Allowed, Conditions: top.Conditions})
}

// SnapshotClaim: what a machine signed over its snapshot (the hex sha256 of the tarball)
type SnapshotClaim struct {
	Sha256 string `json:"sha256"`
	Sig    string `json:"sig"`
}

func alive(state string) bool { return state != "destroying" && state != "destroyed" }

// Kill: M's notarized spawn cert, and optionally its snapshot claim (signed with M's key). The first call checks M is
// alive, fixes the snapshot and asks Fly to destroy it; 409 until Fly reports it destroyed (the router asks again).
// → (M, source-y, ⊤). Asked again after that, the same cert.
func (sp *Spawner) Kill(cert kernel.NotarizedCert, snap *SnapshotClaim) (kernel.SignedDoc, error) {
	s, err := kernel.OpenNotarized(sp.roster, cert)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(403, "%v", err)
	}
	if s.Signer != kernel.RoleSpawner || s.Predecessor.Kind() != kernel.KindSource || s.Successor.Kind() != kernel.KindMachine {
		return kernel.SignedDoc{}, kernel.Fail(400, "a kill takes the machine's spawn cert (source, M) signed by the spawner")
	}
	src, m := s.Predecessor, s.Successor
	sp.mu.Lock()
	if d, ok := sp.killed[m.ID]; ok {
		sp.mu.Unlock()
		return d, nil
	}
	sum, asked := sp.killing[m.ID]
	sp.mu.Unlock()
	if !asked {
		if snap != nil && snap.Sha256 != "" {
			if len(snap.Sha256) != 64 || strings.Trim(snap.Sha256, "0123456789abcdef") != "" || !kernel.Verify(m.SigningKey, []byte(snap.Sha256), snap.Sig) {
				return kernel.SignedDoc{}, kernel.Fail(403, "the snapshot isn't signed by machine %s's key", m.ID)
			}
			sum = snap.Sha256
		}
		fm, err := sp.fly.Inspect(m.ID)
		if err != nil {
			return kernel.SignedDoc{}, kernel.Fail(502, "fly: %v", err)
		}
		if !alive(fm.State) {
			return kernel.SignedDoc{}, kernel.Fail(409, "machine %s is %s: not alive, so not killed by this spawner", m.ID, fm.State)
		}
		sp.mu.Lock()
		if _, again := sp.killing[m.ID]; again {
			sum = sp.killing[m.ID] // a concurrent first call fixed it
		} else {
			sp.killing[m.ID] = sum
		}
		sp.mu.Unlock()
	}
	derr := sp.fly.Destroy(m.ID)
	fm, err := sp.fly.Inspect(m.ID)
	if err != nil {
		return kernel.SignedDoc{}, kernel.Fail(502, "fly: %v", err)
	}
	if fm.State != "destroyed" {
		return kernel.SignedDoc{}, kernel.Fail(409, "machine %s is %s, not destroyed yet (destroy: %v)", m.ID, fm.State, derr)
	}
	b := make([]byte, 16)
	rand.Read(b)
	y := kernel.Object{ID: "source-" + hex.EncodeToString(b), Image: src.Image, Settings: src.Settings, Snapshot: sum}
	top := kernel.Top()
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if d, ok := sp.killed[m.ID]; ok {
		return d, nil
	}
	d, err := kernel.Sign(sp.signer, kernel.Succession{Kind: "succession", Signer: kernel.RoleSpawner, Predecessor: m, Successor: y,
		Allowed: top.Allowed, Conditions: top.Conditions})
	if err != nil {
		return d, err
	}
	sp.killed[m.ID] = d
	delete(sp.killing, m.ID)
	log.Printf("machine %s killed into %s (snapshot %q)", m.ID, y.ID, sum)
	return d, nil
}

// Routes: the spawner's endpoints
func (sp *Spawner) Routes() map[string]kernel.Route {
	return map[string]kernel.Route{
		"POST /fly-token": func(body []byte) (any, error) {
			var in struct {
				Sealed kernel.Sealed `json:"sealed"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return sp.SetFlyToken(in.Sealed)
		},
		"POST /spawn": func(body []byte) (any, error) {
			var in struct {
				Cert   kernel.NotarizedCert `json:"cert"`
				Region string               `json:"region"`
				Size   string               `json:"size"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return sp.Spawn(in.Cert, in.Region, in.Size)
		},
		"POST /init": func(body []byte) (any, error) {
			var in struct {
				Machine string `json:"machine"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return sp.Init(in.Machine)
		},
		"POST /kill": func(body []byte) (any, error) {
			var in struct {
				Cert     kernel.NotarizedCert `json:"cert"`
				Snapshot *SnapshotClaim       `json:"snapshot"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return sp.Kill(in.Cert, in.Snapshot)
		},
	}
}
