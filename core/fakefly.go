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

func (f *FakeFly) Configure(token, app string) {}

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
