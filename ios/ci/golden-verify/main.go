// golden-verify: the app's signatures in the kernel's form, checked by the kernel's own Go code. `swift run Golden`
// (GOLDEN_OUT) writes a draft signed with the TEST phone key and root's ⊤ on the sink signed with the TEST root key, as
// the app signs them; this opens the draft with kernel.OpenSuccession and the grant with kernel.OpenGrant against the
// TEST roster (core/kernel/testdata/keys.json). Usage: go run . KEYS.json GOLDEN_OUT.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DE0CH/jarvis2/core/kernel"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: golden-verify KEYS.json GOLDEN_OUT.json")
		os.Exit(2)
	}
	var keys struct {
		Roster kernel.Roster `json:"roster"`
	}
	var out struct{ Draft, Root kernel.SignedDoc }
	for i, v := range []any{&keys, &out} {
		b, err := os.ReadFile(os.Args[i+1])
		if err == nil {
			err = json.Unmarshal(b, v)
		}
		if err != nil {
			fmt.Println("FAIL", os.Args[i+1], err)
			os.Exit(1)
		}
	}
	failed := false
	if s, err := kernel.OpenSuccession(keys.Roster, out.Draft); err != nil || s.Signer != kernel.RolePhone {
		fmt.Println("FAIL the app's phone-signed draft:", err)
		failed = true
	} else {
		fmt.Println("ok   the kernel opens the app's phone-signed draft")
	}
	if g, err := kernel.OpenGrant(keys.Roster, out.Root, kernel.RoleRoot); err != nil || g.By != kernel.RoleRoot {
		fmt.Println("FAIL the app's root grant:", err)
		failed = true
	} else {
		fmt.Println("ok   the kernel opens the app's root grant (⊤ on the sink)")
	}
	if failed {
		os.Exit(1)
	}
}
