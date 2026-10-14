package main

// The stored Claude pair is the router's own (claudelogin.go); a session with the store `claude` takes it and keeps
// in step by itself (machine/claudelogin.go), so the router never writes credentials into a session (Deyao,
// 2026-10-14: no login repair). A turn that stopped on "Please run /login" only gets "continue" once its pair is in
// step.

import (
	"log"
	"strings"
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

func (r *Router) repairLogin(a pilotAction) {
	if a.Repair != "" {
		r.deliverContinue(a)
	}
}

func (r *Router) deliverContinue(a pilotAction) {
	if err := r.DeliverCanned(a.Session, Delivery{Kind: "continue"}, "continue"); err != nil {
		r.noteRefusal(a.Session, "scheduler", err)
		log.Printf("[login] %s: delivering \"continue\" failed: %v", a.Session, err)
		return
	}
	log.Printf("[login] %s (%s): was stuck on \"Please run /login\" — credentials in step, \"continue\" delivered", a.Session, a.Name)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
