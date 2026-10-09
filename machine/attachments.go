package main

// First-prompt attachments (router/uploads.go). The router stages the files the New Session form uploaded and
// binds them to this session; the first machine fetches them over the machine-signed /m/attachments before
// the harness starts, then the router drops them. Jarvis 1's session-attachments script (run by the
// supervisor for the first prompt) still does the rest exactly as in Jarvis 1 — copies them into ~/uploads,
// writes the paths into the first message, images inline — reading from a local file:// "box" instead of the
// Storage Box: SESSION_ATTACH_DAV_BASE=file://$HOME, SESSION_ATTACH_DIR=.jarvis2-uploads. (Not ~/uploads
// itself: the script opens its source and then truncates its destination, which must not be the same file.)

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const attachStaging = ".jarvis2-uploads"

// fetchAttachments: env for the harness, or nil when the session has none
func fetchAttachments(c *client) []string {
	if strings.TrimSpace(os.Getenv("SESSION_ATTACHMENTS_JSON")) == "" {
		return nil
	}
	home, _ := os.UserHomeDir()
	n, err := downloadAttachments(c, filepath.Join(home, attachStaging))
	if err != nil {
		log.Printf("attachments: %v", err)
	} else {
		log.Printf("attachments: %d file(s) fetched", n)
		if _, _, st, err := c.raw("DELETE", "/m/attachments", nil); err != nil || st != 200 {
			log.Printf("attachments: the router kept its copy (HTTP %d %v)", st, err)
		}
	}
	return attachmentEnv(home)
}

func attachmentEnv(home string) []string {
	u := url.URL{Scheme: "file", Path: home}
	return []string{"SESSION_ATTACH_DAV_BASE=" + u.String(), "SESSION_ATTACH_DIR=" + attachStaging,
		"SESSION_ATTACH_DAV_USER=", "SESSION_ATTACH_DAV_PASS="}
}

func downloadAttachments(c *client, dir string) (int, error) {
	var list struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	}
	if err := c.json("GET", "/m/attachments", nil, &list); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	n := 0
	for _, f := range list.Files {
		if !plainName(f.Name) {
			return n, fmt.Errorf("bad attachment name %q", f.Name)
		}
		// the signature covers the decoded path (as the router checks it); the URL carries it escaped
		st, _, body, err := c.signedDo("GET", "/m/attachments/"+f.Name, "/m/attachments/"+url.PathEscape(f.Name), "", nil, "")
		if err == nil && st != 200 {
			err = fmt.Errorf("HTTP %d", st)
		}
		if err != nil {
			return n, fmt.Errorf("%s: %w", f.Name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.Name), body, 0o600); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// plainName: one path segment (the router's safeName output)
func plainName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\\x00") && len(n) <= 200
}
