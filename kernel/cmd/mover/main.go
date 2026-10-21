// The grant mover's process (kernel/mover): no state.
package main

import (
	"github.com/DE0CH/jarvis2/kernel/internal/serve"
	"github.com/DE0CH/jarvis2/kernel/mover"
)

func main() {
	serve.Main("mover", func(s *serve.Server) error {
		mover.Register(s, mover.New(s.C.Signer, s.Box))
		return nil
	})
}
