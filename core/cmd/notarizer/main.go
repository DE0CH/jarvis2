// The succession notarizer's binary (core/kernel/notarizer). Env: KEY_FILE, ROSTER_FILE, STATE_FILE (the sources
// already continued; optional), ADDR, BOX_KEY_FILE (optional).
package main

import (
	"log"
	"os"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/notarizer"
)

func main() {
	e := kernel.LoadEnv(":8090", true)
	n, err := notarizer.New(e.Signer, e.Roster, os.Getenv("STATE_FILE"))
	if err != nil {
		log.Fatalf("STATE_FILE: %v", err)
	}
	kernel.Serve(e, kernel.MakeIdentity("notarizer", e.Signer, "", e.Box), n.Routes())
}
