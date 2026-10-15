package main

// A successor whose predecessor left no final snapshot (router/fallback.go): the phone approved a fallback in the
// cert's one-time inputs (OnceInputs.Fallback), and this machine restores exactly that, checking every byte:
//
//   - the snapshot of another machine of this line: its sha256 is the one the cert names, that machine's cert is a
//     succession cert signed by the core for the same line, and the snapshot is signed by that cert's machine key;
//   - each live transcript copy the cert names: its sha256 is the one the cert names, and the request that sent it
//     (POST /m/live-transcript) is signed by a machine of this line (the router kept the signature). A copy replaces
//     the restored transcript of the same name only when it is longer (transcripts only grow); a copy that fails a
//     check is skipped, a snapshot that fails one stops the boot (as a pause's snapshot does).
//
// What was restored goes to ~/artifacts/jarvis2-fallback.txt; the approved resume prompt tells the session.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fallbackTmp: where the fallback snapshot lands while it is checked (a var: tests move it)
var fallbackTmp = dir + "/fallback.tar.gz"

const fallbackFile = "artifacts/jarvis2-fallback.txt"

func restoreFallback(c *client, coreKey string, cert Cert, fb *FallbackRef) error {
	home, _ := os.UserHomeDir()
	certs := map[string]*Cert{}
	lineCert := func(machine string) (*Cert, error) {
		if lc := certs[machine]; lc != nil {
			return lc, nil
		}
		var out struct {
			Cert *SignedDoc `json:"cert"`
		}
		if err := c.json("GET", "/m/fallback/cert?machine="+url.QueryEscape(machine), nil, &out); err != nil || out.Cert == nil {
			return nil, fmt.Errorf("no cert for %s (%v)", machine, err)
		}
		var lc Cert
		if err := verifyDoc(coreKey, out.Cert, &lc); err != nil || lc.Kind != "succession-cert" || lc.Machine == nil || lc.Machine.ID != machine {
			return nil, fmt.Errorf("%s's cert isn't a succession cert signed by the core (%v)", machine, err)
		}
		if lc.Line != cert.Line || cert.Line == "" {
			return nil, fmt.Errorf("%s is on line %s, not this line (%s)", machine, lc.Line, cert.Line)
		}
		certs[machine] = &lc
		return &lc, nil
	}
	var report strings.Builder
	fmt.Fprintf(&report, "Jarvis 2, %s: this machine's predecessor (%s) left no final snapshot. Restored instead, as the phone approved:\n",
		time.Now().UTC().Format(time.RFC3339), fb.Lost)
	if fb.Machine != "" {
		lc, err := lineCert(fb.Machine)
		if err != nil {
			return err
		}
		tmp := fallbackTmp
		defer os.Remove(tmp)
		sum, hdr, err := c.download("/m/fallback/snapshot?machine="+url.QueryEscape(fb.Machine), tmp)
		if err != nil {
			return err
		}
		if sum != fb.Sha256 {
			return errors.New("the fallback snapshot isn't the one the cert names")
		}
		if !verify(lc.Machine.SigningKey, []byte(sum), hdr.Get("X-Snapshot-Sig")) {
			return fmt.Errorf("the fallback snapshot isn't signed by %s", fb.Machine)
		}
		n, err := unpackFile(tmp)
		if err != nil {
			return err
		}
		log.Printf("fallback: restored the snapshot of %s (%d files)", fb.Machine, n)
		fmt.Fprintf(&report, "- the snapshot of machine %s, taken %s (%d files): ~/workspace and ~/artifacts are as they were then\n", fb.Machine, fb.TakenAt, n)
	} else {
		fmt.Fprintf(&report, "- no snapshot of the files (the line left none)\n")
	}
	placed := 0
	for _, t := range fb.Transcripts {
		if err := placeLiveCopy(c, home, t, lineCert); err != nil {
			log.Printf("fallback: transcript %s: %v", t.Name, err)
			fmt.Fprintf(&report, "- transcript %s: not taken (%v)\n", t.Name, err)
			continue
		}
		placed++
	}
	fmt.Fprintf(&report, "- the newest live copies of %d of %d conversation transcript(s)\n", placed, len(fb.Transcripts))
	p := filepath.Join(home, fallbackFile)
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(report.String()), 0o644)
	log.Printf("fallback: %d of %d live transcript copies placed", placed, len(fb.Transcripts))
	return nil
}

// placeLiveCopy: one live transcript copy, checked, in place of a shorter restored one (or under the working
// directory's project when the snapshot had none)
func placeLiveCopy(c *client, home string, t LiveRef, lineCert func(string) (*Cert, error)) error {
	var body bytes.Buffer
	sum, hdr, _, err := c.downloadTo("/m/fallback/transcript?name="+url.QueryEscape(t.Name), func(r io.Reader) error {
		_, err := io.Copy(&body, io.LimitReader(r, 256<<20))
		return err
	})
	if err != nil {
		return err
	}
	if sum != t.Sha256 {
		return errors.New("its sha256 isn't the one the cert names")
	}
	sender := hdr.Get("X-Live-Machine")
	lc, err := lineCert(sender)
	if err != nil {
		return err
	}
	if !verify(lc.Machine.SigningKey, []byte("POST /m/live-transcript "+hdr.Get("X-Live-Time")+" "+sum), hdr.Get("X-Live-Sig")) {
		return fmt.Errorf("it isn't signed by %s", sender)
	}
	dst := ""
	if found, _ := filepath.Glob(filepath.Join(home, ".claude", "projects", "*", t.Name)); len(found) > 0 {
		dst = found[0]
		if fi, err := os.Stat(dst); err == nil && fi.Size() >= int64(body.Len()) {
			return nil // the restored one is as long: nothing newer
		}
	} else {
		dst = filepath.Join(home, ".claude", "projects", projectSlug(workingDir(home)), t.Name)
	}
	os.MkdirAll(filepath.Dir(dst), 0o700)
	tmp := dst + ".fallback"
	if err := os.WriteFile(tmp, body.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
