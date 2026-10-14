package main

// The secrets, pulled with the grant the guard holds (docs/DESIGN.md "Secrets"; docs/API-grants.md /m/secrets/pull).
// The router passes the grant to the secrets component, which answers with the stores the grant's allowed set names,
// sealed to this machine's encryption key and signed. The guard takes the answer only when secrets' key (from the
// roster) signed it, for this very grant and this machine, and it opens with this machine's key. Then it rewrites
// ~/.secrets, the deploy keys and, from the `claude` store, the Claude login (claudelogin.go). Nothing is ever
// revoked: a store a newer grant no longer names stays in running processes until they exit, but leaves ~/.secrets.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DE0CH/jarvis2/core/kernel"
)

const infoSecrets = "jarvis2/secrets"

// SecretsAnswer: the secrets component's signed answer to a pull
type SecretsAnswer struct {
	Kind       string            `json:"kind"` // "secrets"
	Grant      string            `json:"grant"`
	Machine    kernel.Object     `json:"machine"`
	Conditions kernel.Conditions `json:"conditions"`
	Stores     []string          `json:"stores"`
	Versions   map[string]string `json:"versions"`
	Locked     []string          `json:"locked"`
	Missing    []string          `json:"missing"`
	Withheld   []string          `json:"withheld"`
	Sealed     kernel.Sealed     `json:"sealed"`
}

// openSecrets: the answer, checked (secrets' key, this grant, this machine) and opened → {store: {key: value}}
func (g *guard) openSecrets(doc kernel.SignedDoc, grantID string) (SecretsAnswer, map[string]map[string]string, error) {
	var a SecretsAnswer
	if err := kernel.Open(g.roster.Secrets, doc, &a); err != nil || a.Kind != "secrets" {
		return a, nil, errors.New("the answer isn't the secrets component's")
	}
	if a.Grant != grantID || a.Machine != g.me {
		return a, nil, errors.New("the secrets answer is for another grant or machine")
	}
	priv, err := loadPrivate()
	if err != nil {
		return a, nil, err
	}
	plain, err := kernel.OpenSealed(priv.enc, a.Sealed, infoSecrets)
	if err != nil {
		return a, nil, fmt.Errorf("the secrets don't open with this machine's key: %w", err)
	}
	stores := map[string]map[string]string{}
	if err := json.Unmarshal(plain, &stores); err != nil {
		return a, nil, err
	}
	return a, stores, nil
}

// pull: one pull with the grant held now
func (g *guard) pull() (SecretsAnswer, map[string]map[string]string, error) {
	cur := g.grant()
	if cur == nil {
		return SecretsAnswer{}, nil, errors.New("no grant to pull with")
	}
	var doc kernel.SignedDoc
	if err := g.c.json("POST", "/m/secrets/pull", map[string]any{"grant": cur.doc}, &doc); err != nil {
		return SecretsAnswer{}, nil, fmt.Errorf("pull secrets: %w", err)
	}
	return g.openSecrets(doc, cur.doc.ID())
}

// flatten: the stores' keys as one env (stores in name order; a key two stores define differently is a conflict,
// the later store's value wins and the clash is listed)
func flatten(stores map[string]map[string]string) (map[string]string, map[string][]string) {
	names := make([]string, 0, len(stores))
	for n := range stores {
		names = append(names, n)
	}
	sort.Strings(names)
	flat, from := map[string]string{}, map[string][]string{}
	conflicts := map[string][]string{}
	for _, n := range names {
		for k, v := range stores[n] {
			if old, ok := flat[k]; ok && old != v {
				conflicts[k] = append(append([]string{}, from[k]...), n)
			}
			flat[k] = v
			from[k] = append(from[k], n)
		}
	}
	return flat, conflicts
}

// pullAndApply: pull, then ~/.secrets, the deploy keys, the conflict list and the Claude login. atBoot: the harness
// hasn't started yet (claudelogin.go may then write ~/.claude.json directly).
func (g *guard) pullAndApply(atBoot bool) (SecretsAnswer, error) {
	g.secretsMu.Lock()
	defer g.secretsMu.Unlock()
	a, stores, err := g.pull()
	if err != nil {
		return a, err
	}
	flat, conflicts := flatten(stores)
	if err := writeSecrets(flat); err != nil {
		return a, err
	}
	if err := setupDeployKeys(flat); err != nil {
		log.Printf("deploy keys: %v", err)
	}
	writeConflicts(conflicts)
	g.lastSecrets = flat
	g.login.apply(flat, atBoot)
	log.Printf("secrets: %d keys from %v (locked %v, missing %v)", len(flat), a.Stores, a.Locked, a.Missing)
	return a, nil
}

// pullQuiet: a pull after a "pull" command or a new grant
func (g *guard) pullQuiet() {
	if _, err := g.pullAndApply(false); err != nil {
		log.Printf("secrets: %v", err)
	}
}

// writeConflicts: ~/.session-secret-conflicts.json (key → the stores defining it differently), removed when none
func writeConflicts(c map[string][]string) {
	p := filepath.Join(claudeHome, ".session-secret-conflicts.json")
	if home, err := os.UserHomeDir(); err == nil {
		p = filepath.Join(home, ".session-secret-conflicts.json")
	}
	if len(c) == 0 {
		os.Remove(p)
		return
	}
	b, _ := json.Marshal(c)
	os.WriteFile(p, b, 0o600)
}

// writeSecrets: ~/.secrets in the format Jarvis 1's entrypoint writes (shell-quoted export lines). A key that isn't
// an env name is left out (anyone may write a store key; the file is sourced by shells).
func writeSecrets(m map[string]string) error {
	home, _ := os.UserHomeDir()
	keys := make([]string, 0, len(m))
	for k := range m {
		if !envNameRE.MatchString(k) {
			log.Printf("~/.secrets: left out a key that isn't an env name (%d bytes)", len(k))
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "='" + strings.ReplaceAll(m[k], "'", `'\''`) + "'\n")
	}
	return shredWrite(filepath.Join(home, ".secrets"), []byte(b.String()), 0o600)
}
