package main

// The session's live status, reported by the machine itself (Jarvis 1 read it by Fly exec every tick:
// readRegistry's REG_CMD in jarvis/server.js, with lib/claudelogin.js and lib/downgrade.js REG_SECTIONs). The
// agent runs the same shell locally every 10 s and POSTs the raw output to /m/status when it changed, and at
// least once a minute as a heartbeat; the router parses it (router/registry.go). It prints claude's registry
// files, ai-title lines, background-job counts, the one-shot marker, transcript ids ending on "Please run
// /login", the credentials file's expiry and refusal entries — never a token.

import (
	"context"
	"log"
	"os/exec"
	"time"
)

const regCmd = `for f in /home/claude/.claude/sessions/*.json; do cat "$f" 2>/dev/null; echo; done; echo __TITLES__; ` +
	`for f in /home/claude/.claude/projects/*/*.jsonl; do t=$(grep -h '"type":"ai-title"' "$f" 2>/dev/null | tail -1); [ -n "$t" ] && echo "$t"; done; ` +
	`echo __BG__; for f in /home/claude/.claude/sessions/*.json; do p=$(grep -o '"pid":[0-9]*' "$f" | head -1 | cut -d: -f2); [ -n "$p" ] && echo "$p $(pgrep -c -P "$p" -f shell-snapshots 2>/dev/null || echo 0)"; done; ` +
	`echo __ONESHOT__; cat /home/claude/.claude/.one-shot-done 2>/dev/null; ` +
	// __AUTH__ / __CREDS__ (lib/claudelogin.js REG_SECTION)
	`echo __AUTH__; for f in $(ls -t /home/claude/.claude/projects/*/*.jsonl 2>/dev/null | head -3); do ` +
	`l=$(tail -c 400000 "$f" 2>/dev/null | grep '"type":"assistant"' | tail -1); ` +
	`case "$l" in *'"error":"authentication_failed"'*) ` +
	`echo "$(basename "$f" .jsonl) $(printf %s "$l" | grep -o '"uuid":"[^"]*"' | head -1 | cut -d'"' -f4)";; esac; done; ` +
	`echo __CREDS__; grep -o '"expiresAt":[0-9]*' /home/claude/.claude/.credentials.json 2>/dev/null | head -1 | cut -d: -f2; ` +
	// __REFUSAL__ (lib/downgrade.js REG_SECTION)
	`echo __REFUSAL__; for f in /home/claude/.claude/projects/*/*.jsonl; do grep -h -E '"stop_reason":"refusal"|"subtype":"model_refusal_fallback"' "$f" 2>/dev/null | tail -4; done; true`

const (
	statusEvery     = 10 * time.Second
	statusHeartbeat = 60 * time.Second
	statusMaxBytes  = 256 << 10
)

func readStatus() string {
	ctx, cancel := context.WithTimeout(context.Background(), statusEvery)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "bash", "-c", regCmd).Output()
	if len(out) > statusMaxBytes {
		out = out[:statusMaxBytes]
	}
	return string(out)
}

// statusReporter: the agent's status loop (started by agent())
func statusReporter(c *client) {
	var last string
	var sent time.Time
	for ; ; time.Sleep(statusEvery) {
		raw := readStatus()
		if raw == last && time.Since(sent) < statusHeartbeat {
			continue
		}
		if err := c.json("POST", "/m/status", map[string]string{"raw": raw}, nil); err != nil {
			log.Printf("status report failed: %v", err)
			continue
		}
		last, sent = raw, time.Now()
	}
}
