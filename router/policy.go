package main

// The router's policy (policy/stores.json, baked into its image): which stores each harness brings. The router
// adds them to a session's stores; the app hides them. The kernel knows nothing about it.

import (
	"encoding/json"
	"fmt"
	"os"
)

// flyStore: the old core's own store's name, reserved by secrets (ReservedStore) — never a session's
const flyStore = "core"

type Policy struct {
	Harnesses map[string]struct {
		Stores []string `json:"stores"`
	} `json:"harnesses"`
}

func LoadPolicy(path string) (Policy, error) {
	var p Policy
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil || len(p.Harnesses) == 0 {
		return p, fmt.Errorf("%s: not a policy (%v)", path, err)
	}
	return p, nil
}
