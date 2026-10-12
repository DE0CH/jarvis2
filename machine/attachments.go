package main

// First-prompt attachments (router/uploads.go). The router stages the files the New Session form uploaded and
// binds them to this session; the first machine fetches them over the machine-signed /m/attachments before
// the harness starts, then the router drops them. Jarvis 1's session-attachments script (run by the
// supervisor for the first prompt) still does the rest exactly as in Jarvis 1 — copies them into ~/uploads,
// writes the paths into the first message, images inline — reading from a local file:// "box" instead of the
// Storage Box: SESSION_ATTACH_DAV_BASE=file://$HOME, SESSION_ATTACH_DIR=.jarvis2-uploads. (Not ~/uploads
// itself: the script opens its source and then truncates its destination, which must not be the same file.)
//
// Each file is taken only when (1) its bytes hash to the sha256 and size the cert names (the phone signed them with the
// new line) and (2) it carries the core's attestation over (this machine, "attachment", that sha256): every attachment
// is an entry in the core's hash-chained input log, as every other input (deliver.go). One file failing either
// refuses them all: the session starts with none.

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

// fetchAttachments: env for the harness, or nil when the files don't match the cert. Only the files the cert names
// (name, sha256, size: the phone approved them with the new line), each checked against its hash and attested.
func fetchAttachments(c *client, coreKey string, refs []AttachmentRef) []string {
	home, _ := os.UserHomeDir()
	n, err := downloadAttachments(c, coreKey, filepath.Join(home, attachStaging), refs)
	if err != nil {
		log.Printf("attachments: refused: %v", err)
		os.RemoveAll(filepath.Join(home, attachStaging))
		return nil
	}
	log.Printf("attachments: %d file(s) fetched, each the one the cert names", n)
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

func downloadAttachments(c *client, coreKey, dir string, refs []AttachmentRef) (int, error) {
	// the listing carries the core's attestation of each file (the router asked the core for it: the input log)
	var list struct {
		Attest map[string]*SignedDoc `json:"attest"`
	}
	if err := c.json("GET", "/m/attachments", nil, &list); err != nil {
		return 0, fmt.Errorf("the listing: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	n := 0
	for _, f := range refs {
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
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != f.Sha256 || int64(len(body)) != f.Size {
			return n, fmt.Errorf("%s isn't the file the cert names", f.Name)
		}
		if err := checkAttest(coreKey, c.me, "attachment", body, list.Attest[f.Name]); err != nil {
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
