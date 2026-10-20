package main

import (
	"os/exec"
	"strings"
	"testing"
)

// the delivery command is valid shell, and prefers the Jarvis channel where the image has it
func TestPeerCommandIsShellAndPrefersTheChannel(t *testing.T) {
	for _, after := range []string{"", "true"} {
		cmd := peerCommand("claude", "auto", "deyao", "hello 'there'\nsecond line", after)
		if out, err := exec.Command("bash", "-n", "-c", cmd).CombinedOutput(); err != nil {
			t.Fatalf("not valid shell: %v %s\n%s", err, out, cmd)
		}
		if !strings.Contains(cmd, "/usr/local/bin/jarvis-channel-send --from 'deyao'") || !strings.Contains(cmd, "peerProtocol") {
			t.Fatal("the channel branch or the peer-socket fallback is missing")
		}
	}
}
