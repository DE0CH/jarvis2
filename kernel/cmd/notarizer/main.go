// The succession notarizer's process (kernel/notarizer): its state in KERNEL_DATA (its own volume).
package main

import (
	"os"
	"path/filepath"

	"github.com/DE0CH/jarvis2/kernel/internal/serve"
	"github.com/DE0CH/jarvis2/kernel/notarizer"
)

func main() {
	serve.Main("notarizer", func(s *serve.Server) error {
		n, err := notarizer.Open(filepath.Join(os.Getenv("KERNEL_DATA"), "notarizer.jsonl"), s.C.Signer, s.Box)
		if err != nil {
			return err
		}
		notarizer.Register(s, n)
		return nil
	})
}
