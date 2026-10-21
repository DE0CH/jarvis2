// Secrets' process (kernel/secrets): empty until the app claims it (Reset or Recover); a wipe ends the process.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/DE0CH/jarvis2/kernel/secrets"
)

func main() {
	b, err := os.ReadFile(os.Getenv("KERNEL_BOX_KEY"))
	if err != nil {
		log.Fatalf("KERNEL_BOX_KEY: %v", err)
	}
	box, err := secrets.SignerFromPEM(b)
	if err != nil {
		log.Fatalf("KERNEL_BOX_KEY: %v", err)
	}
	c, err := secrets.New(box, secrets.NewGitHubAPI())
	if err != nil {
		log.Fatal(err)
	}
	c.SetExit(func() { time.Sleep(500 * time.Millisecond); log.Printf("wiped: exiting"); os.Exit(0) })
	addr := os.Getenv("KERNEL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("secrets up, empty")
	log.Fatal(http.ListenAndServe(addr, secrets.Handler(c)))
}
