// Secrets' binary (core/kernel/secrets). Env: KEY_FILE, ROSTER_FILE (secrets takes grants signed by the mover's and
// the merger's keys), ADDR, BOX_KEY_FILE (optional). A new process is empty until the app claims it (Reset or Recover);
// a wipe ends the process and Kubernetes starts a new, empty one. Built with -tags fakefly it uses an in-memory GitHub.
package main

import (
	"log"
	"os"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/secrets"
)

func main() {
	e := kernel.LoadEnv(":8090", true)
	s, err := secrets.New(e.Signer, e.Roster, newGitHub())
	if err != nil {
		log.Fatal(err)
	}
	s.SetExit(func() { time.Sleep(500 * time.Millisecond); log.Printf("wiped: exiting"); os.Exit(0) })
	kernel.Serve(e, kernel.MakeIdentity("secrets", e.Signer, s.AgreementKey(), e.Box), s.Routes())
}
