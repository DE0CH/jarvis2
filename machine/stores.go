package main

// jarvis2 stores [--json]: every store and the key NAMES it holds (never a value), from the router's GET /m/stores
// (router/storekeys.go), so a session knows which store to ask for with `jarvis2 add-store <name>`. Sensitivity and
// the store list are the core's signed list, checked here against the core's key; the key names are what the
// setup session recorded (or, for a repo's store, follow from the repo).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type storeRow struct {
	Name      string   `json:"name"`
	Sensitive bool     `json:"sensitive"`
	Empty     bool     `json:"empty"`
	Unlocked  bool     `json:"unlocked"`
	Keys      []string `json:"keys"`
	KeysFrom  string   `json:"keysFrom"`
}

func storesCmd(args []string) error {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		return fmt.Errorf("usage: jarvis2 stores [--json]")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var out struct {
		Stores []storeRow `json:"stores"`
		Signed *SignedDoc `json:"signed"`
	}
	if err := c.json("GET", "/m/stores", nil, &out); err != nil {
		return err
	}
	// the store list and sensitivity: only as the core signed them
	if coreKey, err := readTrim(coreKeyPath); err == nil && out.Signed != nil {
		var list struct {
			Kind   string     `json:"kind"`
			Stores []storeRow `json:"stores"`
		}
		if err := verifyDoc(coreKey, out.Signed, &list); err != nil || list.Kind != "stores" {
			return fmt.Errorf("the store list isn't signed by the core")
		}
		signed := map[string]storeRow{}
		for _, s := range list.Stores {
			signed[s.Name] = s
		}
		if len(signed) != len(out.Stores) {
			return fmt.Errorf("the store list differs from the core's")
		}
		for _, s := range out.Stores {
			if c, ok := signed[s.Name]; !ok || c.Sensitive != s.Sensitive || c.Empty != s.Empty {
				return fmt.Errorf("store %s differs from the core's list", s.Name)
			}
		}
	}
	// this session's own stores: from its core-signed cert
	mine := map[string]bool{}
	var certs struct {
		Cert *SignedDoc `json:"cert"`
	}
	if coreKey, err := readTrim(coreKeyPath); err == nil && c.json("GET", "/m/cert", nil, &certs) == nil && certs.Cert != nil {
		var cert struct {
			Stores []string `json:"stores"`
		}
		if verifyDoc(coreKey, certs.Cert, &cert) == nil {
			for _, n := range cert.Stores {
				mine[n] = true
			}
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
		keys := strings.Join(s.Keys, " ")
		if s.Keys == nil {
			keys = "(key names not recorded)"
		}
		fmt.Printf("%s", s.Name)
		if len(flags) > 0 {
			fmt.Printf(" [%s]", strings.Join(flags, ", "))
		}
		fmt.Printf(": %s\n", keys)
	}
	return nil
}
