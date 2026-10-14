// The gullible signer's binary (core/kernel/gullible). Env: KEY_FILE, ADDR, BOX_KEY_FILE (optional).
package main

import (
	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/gullible"
)

func main() {
	e := kernel.LoadEnv(":8090", false)
	kernel.Serve(e, kernel.MakeIdentity("gullible", e.Signer, "", e.Box), gullible.New(e.Signer).Routes())
}
