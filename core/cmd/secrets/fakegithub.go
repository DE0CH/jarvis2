//go:build fakefly

package main

import (
	"log"

	"github.com/DE0CH/jarvis2/core/kernel/secrets"
)

func newGitHub() secrets.GitHub {
	log.Printf("FAKE GITHUB: built with -tags fakefly; deploy keys stay in memory")
	return secrets.NewFakeGitHub()
}
