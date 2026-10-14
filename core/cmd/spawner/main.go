// The spawner's binary (core/kernel/spawner). Env: KEY_FILE, ROSTER_FILE, MACHINE_URL (the router's address on Fly's
// private network; without it no machine starts), ADDR, BOX_KEY_FILE (optional). The Fly token arrives sealed to its
// agreement key (POST /fly-token). Built with -tags fakefly it uses an in-memory Fly (CI only).
package main

import (
	"log"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/spawner"
)

func main() {
	e := kernel.LoadEnv(":8090", true)
	sp, err := spawner.New(e.Signer, e.Roster, newFly(), spawner.MachineURL())
	if err != nil {
		log.Fatal(err)
	}
	kernel.Serve(e, kernel.MakeIdentity("spawner", e.Signer, sp.AgreementKey(), e.Box), sp.Routes())
}
