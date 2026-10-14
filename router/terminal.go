package main

// The live terminal (Jarvis 1's lib/tty.js): the harness runs in tmux session `claude` inside the machine. The app
// polls the pane the machine pushes itself (output only, no grant); typing, Escape and resizing are shell commands,
// which run only while Deyao has opened a terminal for the session (a phone-signed add-on, addons.go).

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

const snapCmd = `tmux capture-pane -p -e -t claude; printf '\n__CUR__%s\n' "$(tmux display-message -p -t claude '#{cursor_x},#{cursor_y},#{pane_width},#{pane_height},#{cursor_flag}')"`

type TermSnap struct {
	Screen string `json:"screen"`
	Cursor string `json:"cursor"`       // x,y,width,height,visible
	At     string `json:"at,omitempty"` // when the machine pushed it (empty = read just now with a shell command)
}

// pushedScreen: a machine's screen push counts while its heartbeat (30 s) can still be on time
const screenFresh = 45 * time.Second

type pushedScreen struct {
	snap TermSnap
	at   time.Time
}

// pushedScreen: the latest pane the session's machine pushed itself (machine/screen.go), if it is fresh
func (r *Router) pushedScreen(session string) (TermSnap, bool) {
	var out TermSnap
	ok := false
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[session]; s != nil && s.Live != nil && s.Live.screen != nil && s.MachineID != "" && time.Since(s.Live.screen.at) < screenFresh {
			out, ok = s.Live.screen.snap, true
			out.At = s.Live.screen.at.UTC().Format(time.RFC3339)
		}
	})
	return out, ok
}

// TermSnapshot: the pane. Viewing needs no grant (Deyao, 2026-10-12): the machine pushes its own capture; with no
// fresh push, it is read with a shell command while a terminal is open.
func (r *Router) TermSnapshot(session string) (TermSnap, error) {
	if snap, ok := r.pushedScreen(session); ok {
		return snap, nil
	}
	res, err := r.Shell(session, snapCmd, 15*time.Second)
	if err != nil {
		return TermSnap{}, err
	}
	i := strings.LastIndex(res.Stdout, "\n__CUR__")
	if i < 0 {
		return TermSnap{}, errors.New("no tmux session (is the harness running?)")
	}
	return TermSnap{Screen: res.Stdout[:i], Cursor: strings.TrimSpace(res.Stdout[i+len("\n__CUR__"):])}, nil
}

// allowed tmux key names for TermInput (anything else is sent as literal text)
var tmuxKeys = map[string]bool{"Enter": true, "Escape": true, "Tab": true, "BTab": true, "BSpace": true, "Up": true, "Down": true,
	"Left": true, "Right": true, "C-c": true, "C-d": true, "C-j": true, "C-o": true, "C-r": true, "C-u": true, "PageUp": true, "PageDown": true}

func (r *Router) TermInput(session, text string, keys []string) error {
	var cmd []string
	if text != "" {
		if len(text) > 4000 {
			text = text[:4000]
		}
		cmd = append(cmd, "tmux send-keys -t claude -l -- "+shq(text))
	}
	for _, k := range keys {
		if !tmuxKeys[k] {
			return errors.New("unknown key " + k)
		}
		cmd = append(cmd, "tmux send-keys -t claude "+k)
	}
	if len(cmd) == 0 {
		return nil
	}
	_, err := r.Shell(session, strings.Join(cmd, " && "), 15*time.Second)
	return err
}

func (r *Router) TermResize(session string, cols, rows int) error {
	if cols < 20 || cols > 400 || rows < 5 || rows > 200 {
		return errors.New("bad size")
	}
	_, err := r.Shell(session, "tmux resize-window -t claude -x "+strconv.Itoa(cols)+" -y "+strconv.Itoa(rows), 15*time.Second)
	return err
}
