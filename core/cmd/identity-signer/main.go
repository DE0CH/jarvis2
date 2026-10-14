// The identity signer's binary (core/kernel/identitysigner). Env: KEY_FILE, ADDR, BOX_KEY_FILE (optional).
package main

import (
	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/identitysigner"
)

func main() {
	e := kernel.LoadEnv(":8090", false)
	kernel.Serve(e, kernel.MakeIdentity("identity", e.Signer, "", e.Box), identitysigner.New(e.Signer).Routes())
}
