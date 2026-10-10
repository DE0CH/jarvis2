//go:build fakefly

package main

// A Fly stand-in for CI only (go build -tags fakefly): machines are made up in memory, each with its
// own key pairs, so the app and router can be exercised end to end without Fly. The production image
// is built without the tag, and this build logs loudly that it is fake.

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"sync"
)

type fakeFlyMachine struct {
	enc, sig  *ecdh.PrivateKey
	destroyed bool
}

type FakeFly struct {
	mu       sync.Mutex
	n        int
	machines map[string]*fakeFlyMachine
}

func newFly() Fly {
	log.Printf("FAKE FLY: built with -tags fakefly; no real machines")
	return &FakeFly{machines: map[string]*fakeFlyMachine{}}
}

func (f *FakeFly) Configure(token string) {}

func (f *FakeFly) Create(r StartRequest) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := fmt.Sprintf("fake%06d", f.n)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, _ := ecdh.P256().GenerateKey(rand.Reader)
	f.machines[id] = &fakeFlyMachine{enc: e, sig: s}
	// a resume passes the pinned ref@digest: keep one digest, like Fly reports it
	return id, strings.SplitN(r.Image, "@", 2)[0] + "@sha256:0000000000000000000000000000000000000000000000000000000000000000", nil
}

func (f *FakeFly) Init(id string) (MachineKeys, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.machines[id]
	return MachineKeys{b64.EncodeToString(m.enc.PublicKey().Bytes()), b64.EncodeToString(m.sig.PublicKey().Bytes())}, nil
}

func (f *FakeFly) Destroy(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.machines[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	m.destroyed = true
	return nil
}

func (f *FakeFly) ConfirmDestroyed(id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.machines[id]
	return ok && m.destroyed, nil
}

// A GitHub stand-in for CI only: deploy keys kept in memory per repo. A repo named "*/no-admin" answers 403, as
// GitHub does for a token without Administration on it.
type FakeGitHub struct {
	mu   sync.Mutex
	n    int64
	keys map[string][]DeployKey
}

func newGitHub() GitHub {
	log.Printf("FAKE GITHUB: built with -tags fakefly; deploy keys stay in memory")
	return &FakeGitHub{keys: map[string][]DeployKey{}}
}

func (g *FakeGitHub) refuse(token, repo string) error {
	if token == "" || strings.HasSuffix(strings.ToLower(repo), "/no-admin") {
		return &GitHubError{403, "GitHub (fake): HTTP 403 Resource not accessible by personal access token"}
	}
	return nil
}

func (g *FakeGitHub) ListDeployKeys(token, repo string) ([]DeployKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.refuse(token, repo); err != nil {
		return nil, err
	}
	return append([]DeployKey{}, g.keys[strings.ToLower(repo)]...), nil
}

func (g *FakeGitHub) AddDeployKey(token, repo, title, publicKey string) (DeployKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.refuse(token, repo); err != nil {
		return DeployKey{}, err
	}
	g.n++
	k := DeployKey{ID: g.n, Title: title, Key: publicKey}
	g.keys[strings.ToLower(repo)] = append(g.keys[strings.ToLower(repo)], k)
	return k, nil
}

func (g *FakeGitHub) DeleteDeployKey(token, repo string, id int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.refuse(token, repo); err != nil {
		return err
	}
	ks := g.keys[strings.ToLower(repo)]
	out := ks[:0]
	for _, k := range ks {
		if k.ID != id {
			out = append(out, k)
		}
	}
	g.keys[strings.ToLower(repo)] = out
	return nil
}
