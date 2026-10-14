package main

// jarvis2 stores [--keys | --json]: every store and the key NAMES it holds (never a value), with what each key is for,
// from the router's GET /m/stores, so a session knows which store to ask for (`jarvis2-request add-store <name>`). The
// store list, sensitivity and key names are the secrets component's signed list, checked here against secrets' key in
// the roster; the explanations are the router's record (words, not a trust decision). "in this session": the stores
// the grant the guard holds names (store:<name>).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/DE0CH/jarvis2/core/kernel"
)

type keyRow struct {
	Name        string `json:"name"`
	Explanation string `json:"explanation,omitempty"`
	At          string `json:"at,omitempty"`
	Writer      *struct {
		By           string `json:"by"`
		Session      string `json:"session,omitempty"`
		SessionLabel string `json:"sessionLabel,omitempty"`
	} `json:"writer,omitempty"`
}

type storeRow struct {
	Name      string   `json:"name"`
	Sensitive bool     `json:"sensitive"`
	Empty     bool     `json:"empty"`
	Unlocked  bool     `json:"unlocked"`
	About     string   `json:"about,omitempty"`
	Keys      []string `json:"keys"`    // names (null: not known)
	KeyInfo   []keyRow `json:"keyInfo"` // the same keys with what each is for
	KeysFrom  string   `json:"keysFrom"`
}

func (s storeRow) keyNames() string { return strings.Join(s.Keys, " ") }

// signedRow: a row of secrets' signed list
type signedRow struct {
	Name      string `json:"name"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Keys      []struct {
		Name string `json:"name"`
	} `json:"keys"`
}

func storesCmd(args []string) error {
	asJSON := len(args) == 1 && args[0] == "--json"
	withKeys := len(args) == 1 && args[0] == "--keys"
	if len(args) > 0 && !asJSON && !withKeys {
		return fmt.Errorf("usage: jarvis2 stores [--keys | --json]   (--keys: each key on its own line with what it is for)")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var out struct {
		Stores []storeRow        `json:"stores"`
		Signed *kernel.SignedDoc `json:"signed"`
	}
	if err := c.json("GET", "/m/stores", nil, &out); err != nil {
		return err
	}
	// the store list, sensitivity and key names: only as secrets signed them
	r, err := readRoster()
	if err != nil {
		return err
	}
	if out.Signed == nil {
		return fmt.Errorf("the router sent no signed store list")
	}
	var list struct {
		Kind   string      `json:"kind"`
		Stores []signedRow `json:"stores"`
	}
	if !kernel.Verify(r.Secrets, []byte(out.Signed.Payload), out.Signed.Sig) {
		return fmt.Errorf("the store list isn't signed by the secrets component")
	}
	if json.Unmarshal([]byte(out.Signed.Payload), &list) != nil || list.Kind != "stores" {
		return fmt.Errorf("the store list isn't signed by the secrets component")
	}
	signed := map[string]signedRow{}
	for _, s := range list.Stores {
		signed[s.Name] = s
	}
	if len(signed) != len(out.Stores) {
		return fmt.Errorf("the store list differs from secrets' list")
	}
	for _, s := range out.Stores {
		c, ok := signed[s.Name]
		if !ok || c.Sensitive != s.Sensitive || c.Empty != s.Empty {
			return fmt.Errorf("store %s differs from secrets' list", s.Name)
		}
		names := []string{}
		for _, k := range c.Keys {
			names = append(names, k.Name)
		}
		if s.Keys != nil && strings.Join(names, " ") != s.keyNames() {
			return fmt.Errorf("store %s's keys differ from secrets' list", s.Name)
		}
	}
	// this session's own stores: what the grant the guard holds names
	mine := map[string]bool{}
	if g, err := readHeldGrant(r); err == nil {
		for _, s := range out.Stores {
			mine[s.Name] = g.Allowed.Contains(storePrefix + s.Name)
		}
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(out.Stores)
	}
	for _, s := range out.Stores {
		var flags []string
		if mine[s.Name] {
			flags = append(flags, "in this session")
		}
		if s.Sensitive {
			flags = append(flags, "sensitive")
		}
		if s.Empty {
			flags = append(flags, "empty")
		} else if !s.Unlocked {
			flags = append(flags, "locked")
		}
		keys := s.keyNames()
		if s.Keys == nil {
			keys = "(key names not recorded)"
		}
		fmt.Printf("%s", s.Name)
		if len(flags) > 0 {
			fmt.Printf(" [%s]", strings.Join(flags, ", "))
		}
		if !withKeys {
			fmt.Printf(": %s\n", keys)
			continue
		}
		fmt.Println()
		if s.About != "" {
			fmt.Printf("  %s\n", s.About)
		}
		for _, k := range s.KeyInfo {
			what := k.Explanation
			if what == "" {
				what = "(no explanation yet)"
			}
			by := ""
			if k.Writer != nil && k.Writer.By == "machine" {
				by = " [written by session " + k.Writer.SessionLabel + " " + k.Writer.Session + "]"
			}
			fmt.Printf("  %s: %s%s\n", k.Name, what, by)
		}
	}
	return nil
}

// readRoster: the roster the guard wrote at boot (from the machine's Fly config)
func readRoster() (kernel.Roster, error) {
	var r kernel.Roster
	b, err := os.ReadFile(rosterPath)
	if err != nil {
		return r, fmt.Errorf("no roster on this machine (the guard writes it at boot): %v", err)
	}
	return r, json.Unmarshal(b, &r)
}

// readHeldGrant: the grant the guard holds (its copy for the CLI), checked again against the roster
func readHeldGrant(r kernel.Roster) (kernel.Grant, error) {
	var d kernel.SignedDoc
	b, err := os.ReadFile(grantPath)
	if err != nil {
		return kernel.Grant{}, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return kernel.Grant{}, err
	}
	return kernel.OpenGrant(r, d, kernel.RoleMover, kernel.RoleMerger)
}
