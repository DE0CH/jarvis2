package main

// The Claude login is Jarvis 1's (Deyao, 2026-10-09): one OAuth pair shared by both Jarvises. Claude rotates
// the refresh token on every refresh, so a copy goes stale; Jarvis 1 keeps the pair that expires latest. A
// session with the `claude` store (JARVIS1_CREDENTIALS_ID/SECRET, an Access service token that reaches only
// jarvis.deyaochen.com/api/credentials) takes the pair at boot, pushes its own refreshed copy back, and takes
// Jarvis 1's when that is newer than its own, as Jarvis 1's sessions do.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	jarvis1Credentials = "https://jarvis.deyaochen.com/api/credentials" // tests point it elsewhere
	credsSyncEvery     = 30 * time.Second
)

type sharedLogin struct {
	Credentials string `json:"credentials"`
	Account     string `json:"account"`
	ExpiresAt   int64  `json:"expiresAt"`
}

func jarvis1Call(method string, body []byte) ([]byte, error) {
	id, sec := os.Getenv("JARVIS1_CREDENTIALS_ID"), os.Getenv("JARVIS1_CREDENTIALS_SECRET")
	if id == "" || sec == "" {
		return nil, errors.New("no JARVIS1_CREDENTIALS_ID/SECRET")
	}
	req, _ := http.NewRequest(method, jarvis1Credentials, bytes.NewReader(body))
	req.Header.Set("CF-Access-Client-Id", id)
	req.Header.Set("CF-Access-Client-Secret", sec)
	req.Header.Set("User-Agent", "jarvis2-machine/1") // Cloudflare refuses some default user agents
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Jarvis 1 answered %d", resp.StatusCode) // the body may hold nothing useful; never log it
	}
	return out, nil
}

func fetchSharedLogin() (sharedLogin, error) {
	var l sharedLogin
	raw, err := jarvis1Call("GET", nil)
	if err == nil {
		err = json.Unmarshal(raw, &l)
	}
	if err == nil && l.Credentials == "" {
		err = errors.New("no credentials in the answer")
	}
	return l, err
}

func credsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", ".credentials.json")
}

func expiresAt(raw []byte) int64 {
	var d struct {
		O struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	json.Unmarshal(raw, &d)
	return d.O.ExpiresAt
}

// sessionClaudeLogin: a session's first Claude login, at boot, before the harness starts (Deyao, 2026-10-11:
// a new session logs in by itself, no grant, no Face ID). With the `claude` store in the cert, the machine takes
// Jarvis 1's pair over the store's Access-confined token (a trusted provider over an authenticated channel,
// DESIGN "Inputs to a machine" (d); never router input), keeps a pair already here that expires later (a
// resumed snapshot's), and starts credsSync for the machine's life. Returns Jarvis 1's account record
// (~/.claude.json oauthAccount + userID) for CLAUDE_ACCOUNT, "" when there is none.
func sessionClaudeLogin(secrets map[string]string) string {
	id, sec := secrets["JARVIS1_CREDENTIALS_ID"], secrets["JARVIS1_CREDENTIALS_SECRET"]
	if id == "" || sec == "" {
		return ""
	}
	os.Setenv("JARVIS1_CREDENTIALS_ID", id)
	os.Setenv("JARVIS1_CREDENTIALS_SECRET", sec)
	if u := secrets["JARVIS1_CREDENTIALS_URL"]; strings.HasPrefix(u, "https://") {
		// another credentials endpoint, from the store itself (vouched like its token): the end-to-end test's
		// stand-in for Jarvis 1, which must never reach the real one
		jarvis1Credentials = u
	}
	var account string
	var l sharedLogin
	var err error
	for i := 0; i < 3; i++ { // a short retry: the harness starts right after, logged in or not (credsSync catches up)
		if l, err = fetchSharedLogin(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Printf("claude login: Jarvis 1's pair at boot: %v (credsSync keeps trying)", err)
	} else {
		account = l.Account
		switch took, err := takeIfLater([]byte(l.Credentials)); {
		case err != nil:
			log.Printf("claude login: writing the credentials file: %v", err)
		case took:
			log.Printf("claude login: took Jarvis 1's pair at boot")
		default:
			log.Printf("claude login: the pair here expires as late or later; kept")
		}
	}
	startCredsSync(id, sec)
	return account
}

// startCredsSync: credsSync in its own process (`jarvis2-machine creds-sync`) for the machine's life; a var so
// tests don't start one
var startCredsSync = func(id, sec string) {
	cmd := exec.Command("/proc/self/exe", "creds-sync")
	home, _ := os.UserHomeDir()
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "JARVIS1_CREDENTIALS_ID=" + id, "JARVIS1_CREDENTIALS_SECRET=" + sec,
		"JARVIS1_CREDENTIALS_URL=" + jarvis1Credentials}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // outlives the exec into Jarvis 1's entrypoint
	if err := cmd.Start(); err != nil {
		log.Printf("claude login: credsSync: %v", err)
		return
	}
	log.Printf("claude login: credsSync running (every 30 s, with Jarvis 1)")
}

// takeIfLater: write the pair unless the file here already expires as late or later; atomic, 0600
func takeIfLater(creds []byte) (bool, error) {
	ne := expiresAt(creds)
	if ne == 0 {
		return false, errors.New("the pair has no expiresAt")
	}
	if cur, err := os.ReadFile(credsPath()); err == nil && expiresAt(cur) >= ne {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(credsPath()), 0o700); err != nil {
		return false, err
	}
	tmp := credsPath() + ".new"
	if err := os.WriteFile(tmp, creds, 0o600); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, credsPath())
}

// credsSync: every 30 s, push this machine's pair when it changed, and take Jarvis 1's when it expires later
func credsSync() {
	if u := os.Getenv("JARVIS1_CREDENTIALS_URL"); strings.HasPrefix(u, "https://") {
		jarvis1Credentials = u // what boot used (sessionClaudeLogin)
	}
	var pushed []byte
	for ; ; time.Sleep(credsSyncEvery) {
		local, err := os.ReadFile(credsPath())
		if err != nil {
			continue
		}
		if !bytes.Equal(local, pushed) {
			body, _ := json.Marshal(map[string]string{"credentials": string(local)})
			if _, err := jarvis1Call("POST", body); err != nil {
				log.Printf("claude login: push failed: %v", err)
			} else {
				pushed = local
			}
		}
		l, err := fetchSharedLogin()
		if err != nil {
			log.Printf("claude login: fetch failed: %v", err)
			continue
		}
		if max(l.ExpiresAt, expiresAt([]byte(l.Credentials))) > expiresAt(local) {
			if took, err := takeIfLater([]byte(l.Credentials)); err == nil && took {
				pushed = []byte(l.Credentials)
				log.Printf("claude login: took Jarvis 1's newer pair")
			}
		}
	}
}
