package main

import (
	"errors"
	"testing"
)

func TestIsGrantRefusal(t *testing.T) {
	for _, m := range []string{
		"the machine refused or failed: no grant, and the holder isn't on this session's allow list",
		"the machine refused or failed: this session holds a sensitive store: only a phone grant opens a shell",
	} {
		if !isGrantRefusal(errors.New(m)) {
			t.Fatalf("%q is a refusal", m)
		}
	}
	for _, m := range []string{"no answer from the machine", "peer message not delivered: x"} {
		if isGrantRefusal(errors.New(m)) {
			t.Fatalf("%q isn't", m)
		}
	}
}
