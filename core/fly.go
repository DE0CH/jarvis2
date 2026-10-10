package main

// The Fly Machines API, used only by start and kill. The token is held by the core alone (from a Recover
// bundle, or sealed to the core by the setup session) and is narrowed to this app and to one command inside a
// machine: jarvis2-init, with no arguments. Its output is the machine's public keys, so their link to the
// machine is Fly's guarantee, not anything the machine or the router says. The app is fixed here, in git: a
// token for any other app can't reach it (Fly app names are global, and only Deyao's org holds this one), so
// whoever hands the core a token can at worst hand it one that fails.

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

type Fly interface {
	Configure(token string) // from the core store (Recover) or SetFlyToken
	Create(r StartRequest) (id, image string, err error)
	Init(id string) (MachineKeys, error) // runs jarvis2-init; its output is the machine's public keys
	Destroy(id string) error
	ConfirmDestroyed(id string) (bool, error)
}

// the session image's one command the core may run (session-image/Dockerfile); the Fly token allows only it
const initPath = "/usr/local/bin/jarvis2-init"

var sizes = map[string]map[string]any{
	"small":  {"cpu_kind": "shared", "cpus": 2, "memory_mb": 2048},
	"medium": {"cpu_kind": "shared", "cpus": 4, "memory_mb": 4096},
	"large":  {"cpu_kind": "shared", "cpus": 8, "memory_mb": 8192},
}

// FlyApp: the one Fly app the core makes machines in
const FlyApp = "jarvis2-sessions"

// the core's own signing key goes into every machine it creates (Fly config env): the machine trusts the
// core that made it, through Fly, which only the core's token can create machines with
const coreKeyEnv = "JARVIS2_CORE_KEY"

type FlyAPI struct {
	mu    sync.Mutex
	token string
	base  string
	http  *http.Client
}

func (f *FlyAPI) Configure(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = token
}

func (f *FlyAPI) ready() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token == "" {
		return fmt.Errorf("the core has no Fly token yet (infra/setup.py backup-core sends it)")
	}
	return nil
}

func (f *FlyAPI) call(method, path string, body any, out any) error {
	if err := f.ready(); err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.base+"/apps/"+FlyApp+path, rd)
	f.mu.Lock()
	req.Header.Set("Authorization", "Bearer "+f.token)
	f.mu.Unlock()
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b))[:min(300, len(strings.TrimSpace(string(b))))])
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (f *FlyAPI) Create(r StartRequest) (string, string, error) {
	guest, ok := sizes[r.Size]
	if !ok {
		guest = sizes["medium"]
	}
	var m struct {
		ID     string `json:"id"`
		Config struct {
			Image string `json:"image"`
		} `json:"config"`
		ImageRef struct {
			Registry, Repository, Tag, Digest string
		} `json:"image_ref"`
	}
	body := map[string]any{"region": r.Region, "config": map[string]any{
		"image": r.Image, "guest": guest, "env": r.Env, "restart": map[string]any{"policy": "no"},
	}}
	if err := f.call("POST", "/machines", body, &m); err != nil {
		return "", "", err
	}
	// the first pull of the session image on a Fly host takes minutes: wait up to 10, then give up and
	// destroy the machine rather than leave it running unknown to anyone
	var werr error
	for i := 0; i < 10; i++ {
		if werr = f.call("GET", "/machines/"+m.ID+"/wait?state=started&timeout=60", nil, nil); werr == nil {
			break
		}
	}
	if werr != nil {
		f.call("DELETE", "/machines/"+m.ID+"?force=true", nil, nil)
		return "", "", werr
	}
	image := m.Config.Image
	if m.ImageRef.Digest != "" {
		image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + "@" + m.ImageRef.Digest
	}
	return m.ID, image, nil
}

func (f *FlyAPI) exec(id string, cmd []string, timeout int) (string, error) {
	var out struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := f.call("POST", "/machines/"+id+"/exec", map[string]any{"command": cmd, "timeout": timeout}, &out); err != nil {
		return "", err
	}
	if out.ExitCode != 0 {
		return out.Stdout, fmt.Errorf("exit %d: %s", out.ExitCode, strings.TrimSpace(out.Stderr))
	}
	return out.Stdout, nil
}

// Init: jarvis2-init waits for the machine's keys (made at boot), prints them and lets boot go on
func (f *FlyAPI) Init(id string) (MachineKeys, error) {
	var k MachineKeys
	var last error
	for i := 0; i < 10; i++ {
		out, err := f.exec(id, []string{initPath}, 60)
		if err == nil && json.Unmarshal([]byte(strings.TrimSpace(out)), &k) == nil && k.EncryptionKey != "" && k.SigningKey != "" {
			return k, nil
		}
		last = err
		time.Sleep(3 * time.Second)
	}
	return k, fmt.Errorf("jarvis2-init gave no keys: %v", last)
}

func (f *FlyAPI) Destroy(id string) error {
	return f.call("DELETE", "/machines/"+id+"?force=true", nil, nil)
}

// ConfirmDestroyed: Fly must report this existing machine as destroyed; a "not found" doesn't count
func (f *FlyAPI) ConfirmDestroyed(id string) (bool, error) {
	for i := 0; i < 20; i++ {
		var m struct {
			State string `json:"state"`
		}
		if err := f.call("GET", "/machines/"+id, nil, &m); err != nil {
			return false, err
		}
		if m.State == "destroyed" {
			return true, nil
		}
		time.Sleep(time.Second)
	}
	return false, nil
}
