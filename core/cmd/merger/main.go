// The grant merger's binary (core/kernel/merger). Env: KEY_FILE, ROSTER_FILE, ADDR, BOX_KEY_FILE (optional).
package main

import (
	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/merger"
)

func main() {
	e := kernel.LoadEnv(":8090", true)
	kernel.Serve(e, kernel.MakeIdentity("merger", e.Signer, "", e.Box), merger.New(e.Signer, e.Roster).Routes())
}
