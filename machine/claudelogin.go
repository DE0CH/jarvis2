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
	"path/filepath"
	"time"
)

const jarvis1Credentials = "https://jarvis.deyaochen.com/api/credentials"

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

// credsSync: every 30 s, push this machine's pair when it changed, and take Jarvis 1's when it expires later
func credsSync() {
	var pushed []byte
	for ; ; time.Sleep(30 * time.Second) {
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
		if l.ExpiresAt > expiresAt(local) {
			tmp := credsPath() + ".new"
			if os.WriteFile(tmp, []byte(l.Credentials), 0o600) == nil && os.Rename(tmp, credsPath()) == nil {
				pushed = []byte(l.Credentials)
				log.Printf("claude login: took Jarvis 1's newer pair")
			}
		}
	}
}
