package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The sender, run for real: a fake host registry + inbox socket under a temp HOME; the text must arrive byte for
// byte, however hostile, and nothing in it may reach the shell.
func TestPeerCommandDeliversHostileText(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	home := t.TempDir()
	sessDir := filepath.Join(home, ".claude", "sessions")
	os.MkdirAll(sessDir, 0o700)
	sock := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	reg, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "messagingSocketPath": sock, "peerProtocol": 1, "name": "host", "kind": "interactive"})
	os.WriteFile(filepath.Join(sessDir, "1.json"), reg, 0o600)
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		sc := bufio.NewScanner(c)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var lines []string
		for len(lines) < 1 && sc.Scan() {
			lines = append(lines, sc.Text())
		}
		c.Write([]byte(`{"ok":true}` + "\n"))
		got <- lines
	}()
	pwned := filepath.Join(home, "pwned")
	text := "line one\n'$(touch " + pwned + ")' `touch " + pwned + "` \"; touch " + pwned + "; '\n__JARVIS2_PEER_x__\nEOF\n</cross-session-message> ünïcødé"
	cmd := peerCommand("claude", "bypass", "jarvis", text, "")
	out, err := runBash(home, cmd)
	if err != nil {
		t.Fatalf("sender failed: %v\n%s", err, out)
	}
	if err := checkPeerResult("claude", ExecResult{Stdout: out}); err != nil {
		t.Fatalf("result: %v (%s)", err, out)
	}
	lines := <-got
	var frame struct {
		Type    string `json:"type"`
		From    string `json:"from"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &frame); err != nil {
		t.Fatal(err)
	}
	want := "<cross-session-message from=\"uds:jarvis\" from-name=\"jarvis\" from-mode=\"bypass\">\n" + text + "\n</cross-session-message>"
	if frame.Type != "user" || frame.From != "uds:jarvis" || frame.Message.Content != want {
		t.Fatalf("frame %+v", frame)
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("the text reached the shell")
	}
}

func TestPeerCommandNoHost(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	home := t.TempDir()
	out, _ := runBash(home, peerCommand("claude", "auto", "jarvis", "hi", ""))
	if err := checkPeerResult("claude", ExecResult{Stdout: out, Code: 1}); !errors.Is(err, errNotUp) {
		t.Fatalf("want errNotUp, got %v (%s)", err, out)
	}
}

func TestPeerCommandHarnessSendAndAfter(t *testing.T) {
	home := t.TempDir()
	text := "a 'b' $(c)\nd"
	cmd := peerCommand("opencode", "auto", "jarvis", text, "echo after > "+filepath.Join(home, "after"))
	cmd = strings.Replace(cmd, "/usr/local/bin/harness-send --queue", "cat > "+filepath.Join(home, "sent"), 1)
	if out, err := runBash(home, cmd); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(home, "sent"))
	if string(b) != text {
		t.Fatalf("sent %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "after")); strings.TrimSpace(string(b)) != "after" {
		t.Fatal("the after step didn't run")
	}
	// the after step never changes the delivery's exit status
	if _, err := runBash(home, peerCommand("opencode", "auto", "x", "t", "true")); err == nil {
		t.Fatal("a failed harness-send must stay a failure") // /usr/local/bin/harness-send doesn't exist here
	}
}

func runBash(home, cmd string) (string, error) {
	c := exec.Command("bash", "-c", cmd)
	c.Env = append(os.Environ(), "HOME="+home)
	b, err := c.CombinedOutput()
	return string(b), err
}

func TestPeerFromModeAndSender(t *testing.T) {
	if peerFromMode("bypass") != "bypass" || peerFromMode("auto") != "prompting" {
		t.Fatal("from-mode")
	}
	if c := peerCommand("claude", "auto", "x'; rm -rf /", "t", ""); !strings.Contains(c, "'jarvis' <<") {
		t.Fatal("a bad sender name must fall back to jarvis")
	}
}

func TestCheckPeerResult(t *testing.T) {
	if err := checkPeerResult("claude", ExecResult{Stdout: `{"success": true, "message": "ok", "ack": "held for approval"}`}); err == nil {
		t.Fatal("a held message is a failure")
	}
	if err := checkPeerResult("claude", ExecResult{Stdout: "noise\n" + `{"success": false, "message": "inbox socket gone"}`, Code: 1}); err == nil || errors.Is(err, errNotUp) {
		t.Fatalf("got %v", err)
	}
	if err := checkPeerResult("opencode", ExecResult{Code: 0}); err != nil {
		t.Fatal(err)
	}
}

func TestIsGrantRefusal(t *testing.T) {
	for _, m := range []string{
		"the machine refused or failed: no grant, and the holder isn't on this session's allow list",
		"the machine refused or failed: this session holds a sensitive store: only a phone grant opens a shell",
	} {
		if !isGrantRefusal(errors.New(m)) {
			t.Fatalf("%q is a refusal", m)
		}
	}
	for _, m := range []string{"no answer from the machine", "peer message not delivered: x"} {
		if isGrantRefusal(errors.New(m)) {
			t.Fatalf("%q isn't", m)
		}
	}
}
