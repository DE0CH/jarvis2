package main

// A cert from a core that doesn't vouch for inputs (the held production core: no Vouch 2, no options.config) gets the
// machine's behaviour from before the input guard, exactly: the env the machine was started with (the router's
// settings: title, prompt, model, repos, restore, rollback, attachments, task parameters) reaches the harness as it
// did. The strict rules of vouch.go apply only to a cert that carries them (Deyao, 2026-10-11: machine and router
// changes keep working with the held core). docs/DESIGN.md "Inputs to a machine", DECISIONS 88.
//
// The started env is kept in startedEnvPath (0600, this machine only) when boot re-execs with the clean env; with a
// Vouch 2 cert it is deleted unread.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var startedEnvPath = "/tmp/.jarvis2-started-env" // a var so tests can move it

func saveStartedEnv(env []string) {
	if _, err := os.Stat(startedEnvPath); err == nil {
		return // the first boot's env (a re-exec keeps it)
	}
	var b bytes.Buffer
	for _, kv := range env {
		if !strings.ContainsRune(kv, '\n') {
			b.WriteString(kv + "\n")
		} else if k, v, ok := strings.Cut(kv, "="); ok { // a multi-line value: JSON-quoted
			q, _ := json.Marshal(v)
			b.WriteString(k + "=\x00" + string(q) + "\n")
		}
	}
	os.WriteFile(startedEnvPath, b.Bytes(), 0o600)
}

func readStartedEnv() []string {
	b, err := os.ReadFile(startedEnvPath)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if k, v, ok := strings.Cut(line, "=\x00"); ok {
			var s string
			if json.Unmarshal([]byte(v), &s) == nil {
				out = append(out, k+"="+s)
			}
			continue
		}
		out = append(out, line)
	}
	return out
}

// useLegacyEnv: the held core's machines run with the env they were started with (as before the guard); a vouching
// cert's machine drops the saved copy
func useLegacyEnv(v Vouched) {
	if v.V2 {
		os.Remove(startedEnvPath)
		return
	}
	env := readStartedEnv()
	if env == nil {
		return
	}
	keep := map[string]string{coreKeyEnv: os.Getenv(coreKeyEnv), "FLY_MACHINE_ID": os.Getenv("FLY_MACHINE_ID")}
	os.Clearenv()
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok {
			os.Setenv(k, val)
		}
	}
	for k, val := range keep { // what the checks already used stays what they used
		if val != "" {
			os.Setenv(k, val)
		}
	}
	log.Printf("a cert from a core that doesn't vouch for inputs: the machine's settings come from its env, as before")
}

// legacyExceptions: the agent's values (vouched.json) from the env, as before
func legacyExceptions() FormatExceptions {
	n, _ := strconv.Atoi(os.Getenv("JARVIS2_LIVE_SYNC_SECONDS"))
	return FormatExceptions{SessionID: os.Getenv("JARVIS2_SESSION_ID"), LiveSyncSeconds: n}
}

func legacySessionID(me string) string {
	if s := os.Getenv("JARVIS2_SESSION_ID"); s != "" {
		return s
	}
	return me
}

// legacyRollback: JARVIS2_ROLLBACK for the snapshot of JARVIS2_ROLLBACK_PRED
func legacyRollback(predID string) {
	marker, pred := os.Getenv("JARVIS2_ROLLBACK"), os.Getenv("JARVIS2_ROLLBACK_PRED")
	if marker == "" {
		return
	}
	if pred == "" || pred != predID {
		log.Printf("rollback asked for %q's snapshot, this machine succeeds %q: ignored", pred, predID)
		return
	}
	applyRollback(marker)
}

// legacyRestoreArchived: JARVIS2_RESTORE_CERT, the old cert checked against the core, the snapshot against its key
func legacyRestoreArchived(c *client, coreKey, me string, cert *Cert) error {
	raw := os.Getenv("JARVIS2_RESTORE_CERT")
	if raw == "" || cert.PredID != "" {
		return nil
	}
	var doc SignedDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("JARVIS2_RESTORE_CERT isn't a signed document: %w", err)
	}
	old, err := checkRestoreCert(coreKey, me, cert, &doc)
	if err != nil {
		return err
	}
	body, hdr, status, err := c.raw("GET", "/m/restore-snapshot", nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("a restore was asked for but the router serves no snapshot (HTTP %d)", status)
	}
	if err := checkSnapshotSig(old.Machine.SigningKey, body, hdr.Get("X-Snapshot-Sig")); err != nil {
		return err
	}
	n, err := unpack(body)
	if err != nil {
		return err
	}
	log.Printf("restored the archived snapshot of %s (line %s, %d files)", old.Machine.ID, old.Line, n)
	return nil
}

// legacyRepos: JARVIS2_REPOS
func legacyRepos() []string {
	out := []string{}
	for _, u := range strings.Split(os.Getenv("JARVIS2_REPOS"), ",") {
		if u = cloneURL(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// legacyAttachments: the router's list (SESSION_ATTACHMENTS_JSON set), fetched as before
func legacyAttachments(c *client) []string {
	if strings.TrimSpace(os.Getenv("SESSION_ATTACHMENTS_JSON")) == "" {
		return nil
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, attachStaging)
	var list struct {
		Files []struct {
			Name string `json:"name"`
		} `json:"files"`
	}
	n := 0
	err := c.json("GET", "/m/attachments", nil, &list)
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	for _, f := range list.Files {
		if err != nil {
			break
		}
		if !plainName(f.Name) {
			err = fmt.Errorf("bad attachment name %q", f.Name)
			break
		}
		st, _, body, e := c.signedDo("GET", "/m/attachments/"+f.Name, "/m/attachments/"+url.PathEscape(f.Name), "", nil, "")
		if e == nil && st != 200 {
			e = fmt.Errorf("HTTP %d", st)
		}
		if e == nil {
			e = os.WriteFile(filepath.Join(dir, f.Name), body, 0o600)
		}
		if err = e; err == nil {
			n++
		}
	}
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

// legacyHarnessEnv: the started env with the signed harness and mode, the secrets, the session id (as before)
func legacyHarnessEnv(c *client, cert Cert, me, secretsJSON string, secrets map[string]string) []string {
	env := withoutEnv(os.Environ(), "SESSION_HARNESS", "SESSION_PERMISSION_MODE") // the signed values replace the router's
	env = append(env, "SESSION_SECRETS_JSON="+secretsJSON, "SESSION_HARNESS="+cert.Options.Harness, "SESSION_PERMISSION_MODE="+certMode(cert), "SESSION_ID="+legacySessionID(me))
	if p := tunnelProof(c); p != "" {
		env = append(env, "TUNNEL_AGENT_SECRET="+p)
	}
	for _, k := range []string{"CLAUDE_CREDENTIALS", "CLAUDE_ACCOUNT"} {
		if s := secrets[k]; s != "" {
			env = append(env, k+"="+s)
		}
	}
	return append(env, legacyAttachments(c)...)
}
