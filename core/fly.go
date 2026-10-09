package main

// The Fly Machines API, used only by start / init / kill. The token is held by the core alone (set at
// setup). A machine's keys and its API key travel over Fly's own exec channel, so their link to the
// machine is Fly's guarantee, not anything the machine or the router says.

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
	Configure(token, app string) // from the unlocked `core` store; empty = locked
	Create(r StartRequest) (id, image string, err error)
	ReadKeys(id string) (MachineKeys, error)
	WriteMachineFiles(id, apiKey, coreKey string) error
	Init(id string) error
	Destroy(id string) error
	ConfirmDestroyed(id string) (bool, error)
}

// paths inside the session image (session-image/jarvis2-init)
const (
	keysPath    = "/run/jarvis2/keys.json"
	apiKeyPath  = "/run/jarvis2/api-key"
	coreKeyPath = "/run/jarvis2/core-key"
	initPath    = "/usr/local/bin/jarvis2-init"
)

var sizes = map[string]map[string]any{
	"small":  {"cpu_kind": "shared", "cpus": 2, "memory_mb": 2048},
	"medium": {"cpu_kind": "shared", "cpus": 4, "memory_mb": 4096},
	"large":  {"cpu_kind": "shared", "cpus": 8, "memory_mb": 8192},
}

type FlyAPI struct {
	mu    sync.Mutex
	token string
	app   string
	base  string
	http  *http.Client
}

func (f *FlyAPI) Configure(token, app string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token, f.app = token, app
}

func (f *FlyAPI) ready() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token == "" || f.app == "" {
		return fmt.Errorf("the core store is locked: unlock it to start or stop machines")
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
	req, _ := http.NewRequest(method, f.base+"/apps/"+f.app+path, rd)
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

func (f *FlyAPI) ReadKeys(id string) (MachineKeys, error) {
	var k MachineKeys
	var last error
	for i := 0; i < 30; i++ { // the image writes its keys at boot
		out, err := f.exec(id, []string{"cat", keysPath}, 10)
		if err == nil && json.Unmarshal([]byte(out), &k) == nil && k.EncryptionKey != "" {
			return k, nil
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return k, fmt.Errorf("no keys at %s: %v", keysPath, last)
}

// WriteMachineFiles: the machine's API key and the core's public signing key, through Fly exec — so the
// machine learns the core's key from Fly, never from the router
func (f *FlyAPI) WriteMachineFiles(id, apiKey, coreKey string) error {
	_, err := f.exec(id, []string{"/bin/sh", "-c", "umask 077; mkdir -p /run/jarvis2; printf %s \"$1\" > " + apiKeyPath +
		"; umask 022; printf %s \"$2\" > " + coreKeyPath + "; chown -R claude /run/jarvis2 2>/dev/null; true", "_", apiKey, coreKey}, 10)
	return err
}

func (f *FlyAPI) Init(id string) error {
	_, err := f.exec(id, []string{initPath}, 30)
	return err
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
