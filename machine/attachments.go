package main

// First-prompt attachments (router/uploads.go). The router stages the files the New Session form uploaded and
// binds them to this session; the first machine fetches them over the machine-signed /m/attachments before
// the harness starts, then the router drops them. Jarvis 1's session-attachments script (run by the
// supervisor for the first prompt) still does the rest exactly as in Jarvis 1 — copies them into ~/uploads,
// writes the paths into the first message, images inline — reading from a local file:// "box" instead of the
// Storage Box: SESSION_ATTACH_DAV_BASE=file://$HOME, SESSION_ATTACH_DIR=.jarvis2-uploads. (Not ~/uploads
// itself: the script opens its source and then truncates its destination, which must not be the same file.)
//
// Each file is taken only when its bytes hash to the sha256 and size the source's settings name (the phone signed
// them with the new session). One file failing refuses them all: the session starts with none.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const attachStaging = ".jarvis2-uploads"

// fetchAttachments: env for the harness, or nil when the files don't match the settings. Only the files the settings
// name (name, sha256, size: the phone approved them with the new session), each checked against its hash.
func fetchAttachments(c *client, refs []AttachmentRef) []string {
	home, _ := os.UserHomeDir()
	n, err := downloadAttachments(c, filepath.Join(home, attachStaging), refs)
	if err != nil {
		log.Printf("attachments: refused: %v", err)
		os.RemoveAll(filepath.Join(home, attachStaging))
		return nil
	}
	log.Printf("attachments: %d file(s) fetched, each the one the settings name", n)
	if _, _, st, err := c.raw("DELETE", "/m/attachments", nil); err != nil || st != 200 {
		log.Printf("attachments: the router kept its copy (HTTP %d %v)", st, err)
	}
	list := make([]string, 0, len(refs))
	for _, r := range refs {
		list = append(list, fmt.Sprintf(`{"name":%q,"isImage":%t}`, r.Name, isImageName(r.Name)))
	}
	return append(attachmentEnv(home), "SESSION_ATTACHMENTS_JSON=["+strings.Join(list, ",")+"]")
}

func isImageName(n string) bool {
	switch strings.ToLower(filepath.Ext(n)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".heif":
		return true
	}
	return false
}

func attachmentEnv(home string) []string {
	u := url.URL{Scheme: "file", Path: home}
	return []string{"SESSION_ATTACH_DAV_BASE=" + u.String(), "SESSION_ATTACH_DIR=" + attachStaging,
		"SESSION_ATTACH_DAV_USER=", "SESSION_ATTACH_DAV_PASS="}
}

func downloadAttachments(c *client, dir string, refs []AttachmentRef) (int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	n := 0
	for _, f := range refs {
		if !plainName(f.Name) {
			return n, fmt.Errorf("bad attachment name %q", f.Name)
		}
		// the signature covers the decoded path (as the router checks it); the URL carries it escaped
		st, _, body, err := c.signedDo("GET", "/m/attachments/"+f.Name, "/m/attachments/"+url.PathEscape(f.Name), "", nil, nil)
		if err == nil && st != 200 {
			err = fmt.Errorf("HTTP %d", st)
		}
		if err != nil {
			return n, fmt.Errorf("%s: %w", f.Name, err)
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != f.Sha256 || int64(len(body)) != f.Size {
			return n, fmt.Errorf("%s isn't the file the settings name", f.Name)
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
