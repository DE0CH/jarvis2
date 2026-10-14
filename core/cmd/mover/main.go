// The grant mover's binary (core/kernel/mover). Env: KEY_FILE, ROSTER_FILE, ADDR, BOX_KEY_FILE (optional).
package main

import (
	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/mover"
)

func main() {
	e := kernel.LoadEnv(":8090", true)
	kernel.Serve(e, kernel.MakeIdentity("mover", e.Signer, "", e.Box), mover.New(e.Signer, e.Roster).Routes())
}
