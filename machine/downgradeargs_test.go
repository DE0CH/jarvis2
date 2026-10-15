package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDowngradeNeedsAMode(t *testing.T) {
	for _, bad := range [][]string{nil, {"default"}, {"default", "tunnel"}, {"--all"}, {"--keep"}, {"--drop"},
		{"--none", "default"}, {"--keep", "a", "--drop", "b"}} {
		if _, err := downgradeArgs(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	held := []string{"default", "github-claude-env", "infra", "tunnel"}
	keep := func(args ...string) ([]string, error) {
		sp, err := downgradeArgs(args)
		if err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		return sp.keepFor(held)
	}
	if k, err := keep("--keep", "default", "tunnel"); err != nil || strings.Join(k, " ") != "default tunnel" {
		t.Fatalf("--keep: %v %v", k, err)
	}
	if k, err := keep("--drop", "infra"); err != nil || strings.Join(k, " ") != "default github-claude-env tunnel" {
		t.Fatalf("--drop: %v %v", k, err)
	}
	if k, err := keep("--none"); err != nil || k == nil || len(k) != 0 {
		t.Fatalf("--none: %v %v", k, err)
	}
	// a store not held is already gone: the held ones named go, and naming only unheld ones changes nothing
	if k, err := keep("--drop", "identity", "infra"); err != nil || strings.Join(k, " ") != "default github-claude-env tunnel" {
		t.Fatalf("--drop with one unheld: %v %v", k, err)
	}
	if _, err := keep("--drop", "identity"); !errors.Is(err, errNothingToDrop) {
		t.Fatalf("--drop of only unheld stores: %v", err)
	}
	if _, err := keep("--keep", "default", "gmail"); err == nil {
		t.Fatal("keeping a store not held must be refused")
	}
	if _, err := keep("--drop", "default", "github-claude-env", "infra", "tunnel"); err == nil {
		t.Fatal("--drop of every held store must be refused (that is --none)")
	}
}
