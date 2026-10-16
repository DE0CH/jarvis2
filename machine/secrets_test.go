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

// the supervisor serves what it holds over its socket; each request is logged with the key names and the caller,
// never a value; nothing is written to disk
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
	r, err = askSecrets(secretsReq{Op: "get", Keys: []string{"API_KEY", "NOPE"}}, 5*time.Second)
	if err != nil || len(r.Secrets) != 1 || r.Secrets["API_KEY"] != "value-of-api-key" {
		t.Fatalf("%+v %v", r, err)
	}
	r, _ = askSecrets(secretsReq{Op: "all"}, 5*time.Second)
	if len(r.Secrets) != 2 {
		t.Fatalf("%+v", r)
	}
	if _, err := askSecrets(secretsReq{Op: "dump everything"}, 5*time.Second); err == nil {
		t.Fatal("an unknown op answered")
	}
	l := logs.String()
	if strings.Contains(l, "value-of-api-key") || strings.Contains(l, "other-value") {
		t.Fatalf("a value in the log: %s", l)
	}
	if !strings.Contains(l, "secrets: get API_KEY NOPE for pid ") || !strings.Contains(l, "(not held: NOPE)") || !strings.Contains(l, "secrets: names (2) for pid ") {
		t.Fatalf("log: %s", l)
	}
	if out, _ := os.ReadFile(filepath.Join(home, ".secrets")); len(out) > 0 {
		t.Fatal("~/.secrets written")
	}
	// a downgrade or a refresh replaces the copy at once
	held.set(map[string]string{"API_KEY": "v2-value-xx"})
	if r, _ := askSecrets(secretsReq{Op: "all"}, 5*time.Second); len(r.Secrets) != 1 || r.Secrets["API_KEY"] != "v2-value-xx" {
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
