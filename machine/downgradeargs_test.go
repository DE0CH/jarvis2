package main

import "testing"

func TestDowngradeNeedsStoreNames(t *testing.T) {
	if _, err := downgradeArgs(nil); err == nil {
		t.Fatal("no names must be refused, not read as keep none")
	}
	if _, err := downgradeArgs([]string{"--all"}); err == nil {
		t.Fatal("an unknown option must be refused")
	}
	if k, err := downgradeArgs([]string{"--none"}); err != nil || len(k) != 0 || k == nil {
		t.Fatalf("--none: %v %v", k, err)
	}
	if k, err := downgradeArgs([]string{"default", "tunnel"}); err != nil || len(k) != 2 {
		t.Fatalf("names: %v %v", k, err)
	}
}
