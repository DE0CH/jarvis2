//go:build fakefly

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/DE0CH/jarvis2/core/kernel"
	"github.com/DE0CH/jarvis2/core/kernel/spawner"
)

func newFly() spawner.Fly {
	log.Printf("FAKE FLY: built with -tags fakefly; no real machines")
	f := spawner.NewFakeFly()
	if dir := os.Getenv("FAKEFLY_KEYS_DIR"); dir != "" {
		log.Printf("FAKE FLY: every machine's PRIVATE keys go to %s (CI's fake machine boots them: ios/ci/fake-machine.py)", dir)
		return &keyedFly{FakeFly: f, dir: dir}
	}
	return f
}

// keyedFly: the in-memory Fly that also writes each machine's private keys to a directory, so a stand-in machine in
// CI (ios/ci/fake-machine.py) can do what the guard does with them: boot, pull, answer the command channel
type keyedFly struct {
	*spawner.FakeFly
	dir string
}

func (k *keyedFly) Create(r spawner.CreateRequest) (string, error) {
	id, err := k.FakeFly.Create(r)
	if err != nil {
		return id, err
	}
	m := k.FakeFly.Machines[id]
	b, _ := json.Marshal(map[string]string{"id": id, "sig": kernel.B64.EncodeToString(m.Sig.Bytes()), "enc": kernel.B64.EncodeToString(m.Enc.Bytes())})
	tmp := filepath.Join(k.dir, id+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		os.Rename(tmp, filepath.Join(k.dir, id+".json"))
	}
	return id, nil
}
