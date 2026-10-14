//go:build fakefly

package main

import (
	"log"

	"github.com/DE0CH/jarvis2/core/kernel/spawner"
)

func newFly() spawner.Fly {
	log.Printf("FAKE FLY: built with -tags fakefly; no real machines")
	return spawner.NewFakeFly()
}
