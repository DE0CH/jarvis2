// The log notary's binary (core/kernel/notary). Env: KEY_FILE, LOG_FILE (append-only JSON lines; stdout too), ADDR,
// BOX_KEY_FILE (optional).
package main

import (
	"io"
	"log"
	"os"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/notary"
)

func main() {
	e := kernel.LoadEnv(":8090", false)
	var w io.Writer = os.Stdout
	if f := os.Getenv("LOG_FILE"); f != "" {
		lf, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatalf("LOG_FILE: %v", err)
		}
		w = io.MultiWriter(lf, os.Stdout)
	}
	n := notary.New(e.Signer, w)
	kernel.Serve(e, kernel.MakeIdentity("notary", e.Signer, "", e.Box), n.Routes())
}
