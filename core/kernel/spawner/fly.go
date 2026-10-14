package spawner

// The Fly Machines API (carried over from core/fly.go). The token is held by the spawner alone, sealed to it by the
// setup session, and is narrowed to this app and to one command inside a machine: jarvis2-init, with no arguments.
// Its output is the machine's public keys, so their link to the machine is Fly's guarantee. The app is fixed here, in
// git: a token for any other app can't reach it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type MachineKeys struct {
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
}

// CreateRequest: what a Fly create needs
type CreateRequest struct {
	Image  string
	Region string
	Guest  map[string]any
	Env    map[string]string
}

// Fly: single calls, no waiting or retrying (the router retries)
type Fly interface {
	Configure(token string)
	Create(r CreateRequest) (id string, err error)
	Inspect(id string) (FlyMachine, error) // its state and the image Fly runs (registry/repository@digest)
	Init(id string) (MachineKeys, error)   // one run of jarvis2-init; its output is the machine's public keys
	Destroy(id string) error
}

type FlyMachine struct {
	State string // created, starting, started, stopped, …, destroying, destroyed
	Image string // what Fly reports it runs: registry/repository@sha256:…
}

const initPath = "/usr/local/bin/jarvis2-init"

var sizes = map[string]map[string]any{
	"small":  {"cpu_kind": "shared", "cpus": 2, "memory_mb": 2048},
	"medium": {"cpu_kind": "shared", "cpus": 4, "memory_mb": 4096},
	"large":  {"cpu_kind": "shared", "cpus": 8, "memory_mb": 8192},
}

// FlyApp: the one Fly app the spawner makes machines in
const FlyApp = "jarvis2-sessions"

type FlyAPI struct {
	mu    sync.Mutex
	token string
	base  string
	http  *http.Client
}

func NewFlyAPI() *FlyAPI {
	return &FlyAPI{base: "https://api.machines.dev/v1", http: &http.Client{Timeout: 90 * time.Second}}
}

func (f *FlyAPI) Configure(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = token
}

func (f *FlyAPI) call(method, path string, body any, out any) error {
	f.mu.Lock()
	token := f.token
	f.mu.Unlock()
	if token == "" {
		return fmt.Errorf("the spawner has no Fly token yet")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.base+"/apps/"+FlyApp+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t := strings.TrimSpace(string(b))
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, t[:min(300, len(t))])
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (f *FlyAPI) Create(r CreateRequest) (string, error) {
	var m struct {
		ID string `json:"id"`
	}
	body := map[string]any{"region": r.Region, "config": map[string]any{
		"image": r.Image, "guest": r.Guest, "env": r.Env, "restart": map[string]any{"policy": "no"},
	}}
	if err := f.call("POST", "/machines", body, &m); err != nil {
		return "", err
	}
	return m.ID, nil
}

func (f *FlyAPI) Inspect(id string) (FlyMachine, error) {
	var m struct {
		State  string `json:"state"`
		Config struct {
			Image string `json:"image"`
		} `json:"config"`
		ImageRef struct {
			Registry, Repository, Tag, Digest string
		} `json:"image_ref"`
	}
	if err := f.call("GET", "/machines/"+id, nil, &m); err != nil {
		return FlyMachine{}, err
	}
	image := m.Config.Image
	if m.ImageRef.Digest != "" {
		image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + "@" + m.ImageRef.Digest
	}
	return FlyMachine{State: m.State, Image: image}, nil
}

// Init: jarvis2-init waits for the machine's keys (made at boot), prints them and lets boot go on. One run.
func (f *FlyAPI) Init(id string) (MachineKeys, error) {
	var out struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	var k MachineKeys
	if err := f.call("POST", "/machines/"+id+"/exec", map[string]any{"command": []string{initPath}, "timeout": 60}, &out); err != nil {
		return k, err
	}
	if out.ExitCode != 0 {
		return k, fmt.Errorf("exit %d: %s", out.ExitCode, strings.TrimSpace(out.Stderr))
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out.Stdout)), &k) != nil || k.EncryptionKey == "" || k.SigningKey == "" {
		return k, fmt.Errorf("jarvis2-init gave no keys")
	}
	return k, nil
}

func (f *FlyAPI) Destroy(id string) error {
	return f.call("DELETE", "/machines/"+id+"?force=true", nil, nil)
}
