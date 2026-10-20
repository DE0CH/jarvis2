package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// the supervisor serves what it holds over its socket, only the keys a request names (never all of them); each
// request is logged with the key names and the caller, never a value; nothing is written to disk
func TestTheSupervisorServesSecretsFromRAM(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	old := secretsSock
	defer func() { secretsSock = old; held.set(map[string]string{}) }()
	secretsSock = filepath.Join(t.TempDir(), "s.sock")
	held.set(map[string]string{"API_KEY": "value-of-api-key", "OTHER": "other-value-123"})
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	go serveSecrets(nil)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(secretsSock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r, err := askSecrets(secretsReq{Op: "names"}, 5*time.Second)
	if err != nil || strings.Join(r.Names, ",") != "API_KEY,OTHER" {
		t.Fatalf("%+v %v", r, err)
	}
	// named keys: exactly those
	r, err = askSecrets(secretsReq{Op: "get", Keys: []string{"API_KEY"}}, 5*time.Second)
	if err != nil || len(r.Secrets) != 1 || r.Secrets["API_KEY"] != "value-of-api-key" {
		t.Fatalf("%+v %v", r, err)
	}
	// a name not held is an error naming it, and nothing is handed over
	r, err = askSecrets(secretsReq{Op: "get", Keys: []string{"API_KEY", "NOPE"}}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "NOPE") || len(r.Secrets) != 0 {
		t.Fatalf("an unknown key: %+v %v", r, err)
	}
	// no request for all keys: no "all" op, no empty list, no wildcard, no list naming every held key
	for _, req := range []secretsReq{{Op: "all"}, {Op: "get"}, {Op: "get", Keys: []string{"*"}}, {Op: "get", Keys: []string{}}, {Op: "dump everything"}} {
		if r, err := askSecrets(req, 5*time.Second); err == nil || len(r.Secrets) != 0 {
			t.Fatalf("%+v answered: %+v", req, r)
		}
	}
	// boot-env: only to the boot process (harness.pid), only before the machine has booted
	oldPID, oldBooted := harnessPIDPath, booted
	defer func() { harnessPIDPath, booted = oldPID, oldBooted }()
	harnessPIDPath = filepath.Join(t.TempDir(), "harness.pid")
	isBooted := false
	booted = func() bool { return isBooted }
	os.WriteFile(harnessPIDPath, []byte("1"), 0o644) // not this test process
	if r, err := askSecrets(secretsReq{Op: "boot-env"}, 5*time.Second); err == nil || len(r.Secrets) != 0 {
		t.Fatalf("boot-env to another process: %+v", r)
	}
	os.WriteFile(harnessPIDPath, []byte(itoa(os.Getpid())), 0o644)
	if r, err := askSecrets(secretsReq{Op: "boot-env"}, 5*time.Second); err != nil || len(r.Secrets) != 2 {
		t.Fatalf("boot-env to boot: %+v %v", r, err)
	}
	isBooted = true
	if r, err := askSecrets(secretsReq{Op: "boot-env"}, 5*time.Second); err == nil || len(r.Secrets) != 0 {
		t.Fatalf("boot-env after the boot: %+v", r)
	}
	l := logs.String()
	if strings.Contains(l, "value-of-api-key") || strings.Contains(l, "other-value") {
		t.Fatalf("a value in the log: %s", l)
	}
	for _, want := range []string{"secrets: get API_KEY for pid ", "secrets: refused get API_KEY NOPE for pid ", "(not held: NOPE)",
		"secrets: names (2) for pid ", "secrets: unknown op \"all\"", "secrets: refused get with no keys",
		"secrets: refused boot-env for pid", "secrets: boot-env (2 keys: API_KEY OTHER) for pid "} {
		if !strings.Contains(l, want) {
			t.Fatalf("log lacks %q: %s", want, l)
		}
	}
	if out, _ := os.ReadFile(filepath.Join(home, ".secrets")); len(out) > 0 {
		t.Fatal("~/.secrets written")
	}
	// a downgrade or a refresh replaces the copy at once
	held.set(map[string]string{"API_KEY": "v2-value-xx"})
	if r, _ := askSecrets(secretsReq{Op: "get", Keys: []string{"API_KEY"}}, 5*time.Second); len(r.Secrets) != 1 || r.Secrets["API_KEY"] != "v2-value-xx" {
		t.Fatalf("after the change %+v", r)
	}
}

// the keeper's memfd keeps the copy across a worker restart, in RAM
func TestSecretsSurviveAWorkerRestart(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	mem, err := newMemfd()
	if err != nil {
		t.Skip("no memfd:", err)
	}
	defer mem.Close()
	if link, _ := os.Readlink("/proc/self/fd/" + itoa(int(mem.Fd()))); !strings.HasPrefix(link, "/memfd:") {
		t.Fatalf("not a memfd: %s", link)
	}
	first := &heldSecrets{vals: map[string]string{}, mem: mem}
	first.set(map[string]string{"K": "kept-value"})
	// each "worker" gets its own fd of the memfd (a worker's *os.File closes its fd when collected)
	worker := func() *heldSecrets {
		fd, err := syscall.Dup(int(mem.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(secretsFDEnv, itoa(fd))
		h := &heldSecrets{vals: map[string]string{}}
		h.loadHeld()
		t.Cleanup(func() { h.mem.Close() })
		return h
	}
	again := worker()
	if again.snapshot()["K"] != "kept-value" {
		t.Fatalf("after a restart: %v", again.snapshot())
	}
	first.set(map[string]string{}) // a downgrade to nothing: the memfd holds nothing either
	third := worker()
	if len(third.snapshot()) != 0 {
		t.Fatalf("a dropped value survived: %v", third.snapshot())
	}
}
