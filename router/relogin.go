package main

// Login repair (Jarvis 1's syncClaudeLogin, lib/claudelogin.js). The stored Claude pair is the router's own
// (claudelogin.go); a session with the store `claude` takes it and keeps in step by itself (machine/claudelogin.go),
// so the router writes nothing there. This is the router's repair path for a session that still ends up behind (no
// `claude` store, or a machine from before the self-login, behind past SelfLoginGrace): its credentials file expires
// before the stored pair, or its transcript ends on "Please run /login". The router writes the pair into
// ~/.claude/.credentials.json through holder "login" (never replacing a pair that expires later), and for a stuck
// session delivers "continue". The pair travels only inside the command text; nothing logs that text (router:
// grants.go; machine: runExec), and no error here carries it.

import (
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"time"
)

type sharedPair struct {
	Credentials string `json:"credentials"`
	Account     string `json:"account"`
	ExpiresAt   int64  `json:"expiresAt"`
}

// sharedLogin: the stored pair (claudelogin.go)
func (r *Router) sharedLogin() (sharedPair, error) {
	cur := r.loginHub().current()
	if cur.Credentials == "" {
		return sharedPair{}, errNoPair
	}
	return sharedPair{Credentials: cur.Credentials, Account: cur.Account, ExpiresAt: cur.ExpiresAt}, nil
}

// writeCredsPy: Jarvis 1's WRITE_PY, reading the pair from stdin: replace the file unless it already expires
// as late or later; atomic, 0600; prints "written" or "kept"
const writeCredsPy = `import json, os, sys
p = os.path.expanduser("~/.claude/.credentials.json"); new = sys.stdin.read()
ne = int(json.loads(new)["claudeAiOauth"]["expiresAt"])
try: cur = int(json.load(open(p))["claudeAiOauth"]["expiresAt"])
except Exception: cur = 0
if cur >= ne: print("kept"); sys.exit(0)
os.makedirs(os.path.dirname(p), exist_ok=True); os.umask(0o077); t = p + ".jarvis.tmp"
open(t, "w").write(new); os.replace(t, p); print("written")`

// writeCredsCmd: the pair goes in base64 through printf (a shell builtin: not in any process's argv) into the
// script's stdin
func writeCredsCmd(credentials string) string {
	return "printf %s " + shq(base64.StdEncoding.EncodeToString([]byte(credentials))) + " | base64 -d | python3 -c " + shq(writeCredsPy)
}

func (r *Router) repairLogin(a pilotAction) {
	if a.NoWrite { // the machine keeps its own pair in step: only the stuck turn needs "continue"
		if a.Repair != "" {
			r.deliverContinue(a)
		}
		return
	}
	p, err := r.sharedLogin()
	if err != nil {
		log.Printf("[login] %s: %v", a.Session, err)
		return
	}
	res, err := r.execAs(a.Session, "login", writeCredsCmd(p.Credentials), 30*time.Second)
	if err != nil {
		log.Printf("[login] %s: writing the credentials failed: %v", a.Session, errors.New(firstLine(err.Error())))
		return
	}
	out := res.Stdout
	if !strings.Contains(out, "written") && !strings.Contains(out, "kept") {
		log.Printf("[login] %s: could not write the credentials file (exit %d)", a.Session, res.Code)
		return
	}
	if strings.Contains(out, "written") {
		log.Printf("[login] %s (%s): copied the stored Claude credentials in", a.Session, a.Name)
	}
	if a.Repair == "" {
		return
	}
	r.deliverContinue(a)
}

func (r *Router) deliverContinue(a pilotAction) {
	if err := r.DeliverCanned(a.Session, Delivery{Kind: "continue"}, "continue"); err != nil {
		r.noteRefusal(a.Session, "scheduler", err)
		log.Printf("[login] %s: credentials written, delivering \"continue\" failed: %v", a.Session, err)
		return
	}
	log.Printf("[login] %s (%s): was stuck on \"Please run /login\" — credentials in step, \"continue\" delivered", a.Session, a.Name)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
