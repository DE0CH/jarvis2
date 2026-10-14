package spawner

// A Fly stand-in (carried over from core/fakefly.go): machines made up in memory, each with its own key pairs. Tests
// use it directly; the spawner binary uses it only when built with -tags fakefly (CI end to end), and says so loudly.

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"

	"github.com/DE0CH/jarvis2/core/kernel"
)

type FakeMachine struct {
	Enc, Sig *ecdh.PrivateKey
	Image    string
	State    string
	Env      map[string]string
}

type FakeFly struct {
	mu       sync.Mutex
	n        int
	Machines map[string]*FakeMachine
	Token    string
	// Booting: new machines stay "starting" until a test sets them started; SlowKill: a destroy leaves "destroying";
	// SwapDigest: report this digest instead of the requested one (a registry serving other bytes)
	Booting, SlowKill bool
	SwapDigest        string
}

func NewFakeFly() *FakeFly { return &FakeFly{Machines: map[string]*FakeMachine{}} }

func (f *FakeFly) Configure(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Token = token
}

func (f *FakeFly) Create(r CreateRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := fmt.Sprintf("fake%06d", f.n)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, _ := ecdh.P256().GenerateKey(rand.Reader)
	ref, digest, _ := strings.Cut(r.Image, "@")
	if f.SwapDigest != "" {
		digest = f.SwapDigest
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i] // Fly reports registry/repository@digest
	}
	state := "started"
	if f.Booting {
		state = "starting"
	}
	f.Machines[id] = &FakeMachine{Enc: e, Sig: s, Image: ref + "@" + digest, State: state, Env: r.Env}
	return id, nil
}

func (f *FakeFly) Inspect(id string) (FlyMachine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.Machines[id]
	if !ok {
		return FlyMachine{}, fmt.Errorf("not found")
	}
	return FlyMachine{State: m.State, Image: m.Image}, nil
}

func (f *FakeFly) Init(id string) (MachineKeys, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.Machines[id]
	return MachineKeys{kernel.B64.EncodeToString(m.Enc.PublicKey().Bytes()), kernel.B64.EncodeToString(m.Sig.PublicKey().Bytes())}, nil
}

func (f *FakeFly) Destroy(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.Machines[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	m.State = "destroyed"
	if f.SlowKill {
		m.State = "destroying"
	}
	return nil
}

// SetState: tests only (a machine finishing boot, a crash)
func (f *FakeFly) SetState(id, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Machines[id].State = state
}
