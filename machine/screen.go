package main

// The read-only terminal (Deyao, 2026-10-12: "a read only terminal that doesn't require a grant"): like the status
// report, the machine itself captures the harness's tmux pane every 2 s and POSTs it to /m/screen when it changed
// (and every 30 s as a heartbeat). Nothing goes INTO the machine for it: no command, no flag, no grant; the router
// only keeps the latest capture for the terminal page. Typing still goes through the "terminal" holder's grant.

import (
	"context"
	"log"
	"strings"
	"time"
)

// the same capture the router's terminal holder runs (router/terminal.go snapCmd)
const screenCmd = `tmux capture-pane -p -e -t claude; printf '\n__CUR__%s\n' "$(tmux display-message -p -t claude '#{cursor_x},#{cursor_y},#{pane_width},#{pane_height},#{cursor_flag}')"`

const (
	screenEvery     = 2 * time.Second
	screenHeartbeat = 30 * time.Second
	screenMaxBytes  = 256 << 10
)

// readScreen: the pane and the cursor line, or ok=false when there is no tmux session `claude`
func readScreen() (screen, cursor string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), screenEvery)
	defer cancel()
	out, err := rescueCommand(ctx, "bash", "-c", screenCmd).Output()
	if err != nil {
		return "", "", false
	}
	s := string(out)
	i := strings.LastIndex(s, "\n__CUR__")
	if i < 0 {
		return "", "", false
	}
	screen, cursor = s[:i], strings.TrimSpace(s[i+len("\n__CUR__"):])
	if len(screen) > screenMaxBytes {
		screen = screen[len(screen)-screenMaxBytes:]
	}
	return screen, cursor, cursor != ""
}

// screenReporter: the supervisor's screen component (started by supervise once booted); output only, unguarded
func screenReporter(c *client) {
	var last string
	var sent time.Time
	for ; ; time.Sleep(screenEvery) {
		screen, cursor, ok := readScreen()
		if !ok {
			continue
		}
		if screen+cursor == last && time.Since(sent) < screenHeartbeat {
			continue
		}
		if err := c.json("POST", "/m/screen", map[string]string{"screen": screen, "cursor": cursor}, nil); err != nil {
			log.Printf("screen report failed: %v", err)
			continue
		}
		last, sent = screen+cursor, time.Now()
	}
}
