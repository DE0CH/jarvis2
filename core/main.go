package main

// HTTP surface of the core. It listens only inside the cluster (the router reaches it; NetworkPolicy keeps
// everything else out). Nothing here trusts the caller: what matters is signed (by the phone, the master
// key, or the core itself) or sealed to the core.

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	fly := newFly()
	c, err := NewCore(fly)
	if err != nil {
		log.Fatal(err)
	}
	// a new core is empty: no master key until the app sets it up (Reset or Recover). A wipe, authorised by
	// that master key, ends the process; Kubernetes starts a new, empty core.
	c.exit = func() { time.Sleep(500 * time.Millisecond); log.Printf("wiped: exiting"); os.Exit(0) }
	// the box key (planted when the box was made) vouches for this core's fresh keys
	bk, err := os.ReadFile(os.Getenv("BOX_KEY_FILE"))
	if err != nil {
		log.Fatalf("BOX_KEY_FILE: %v", err)
	}
	box, err := SignerFromPEM(bk)
	if err != nil {
		log.Fatalf("BOX_KEY_FILE: %v", err)
	}
	k := c.Key()
	if c.BoxSig, err = box.Sign([]byte(IdentityText(k["signingKey"], k["agreementKey"]))); err != nil {
		log.Fatal(err)
	}
	log.Printf("core up, empty; signing key %s", k["signingKey"])
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8090"
	}
	log.Fatal(http.ListenAndServe(addr, Handler(c)))
}

func Handler(c *Core) http.Handler {
	mux := http.NewServeMux()
	type body = map[string]json.RawMessage
	h := func(pattern string, fn func(r *http.Request, b body) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
			if err != nil {
				writeErr(c, w, fail(400, "body: %v", err))
				return
			}
			b := body{}
			if len(raw) != 0 {
				if err := json.Unmarshal(raw, &b); err != nil {
					writeErr(c, w, fail(400, "bad JSON: %v", err))
					return
				}
			}
			out, err := fn(r, b)
			if err != nil {
				writeErr(c, w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		})
	}
	str := func(b body, k string) string {
		var s string
		json.Unmarshal(b[k], &s)
		return s
	}
	doc := func(b body, k string) *SignedDoc {
		if len(b[k]) == 0 || string(b[k]) == "null" {
			return nil
		}
		var d SignedDoc
		if json.Unmarshal(b[k], &d) != nil {
			return nil
		}
		return &d
	}

	h("GET /key", func(r *http.Request, b body) (any, error) { return c.Key(), nil })

	sealed := func(b body, k string) (Sealed, error) {
		var s Sealed
		if json.Unmarshal(b[k], &s) != nil || s.E == "" {
			return s, fail(400, "%s must be sealed to the core's agreement key", k)
		}
		return s, nil
	}

	// ---- identity, and setting the core up (the iPhone, with the master key) ----
	h("GET /identity", func(r *http.Request, b body) (any, error) { return c.Identity() })
	h("GET /core-cert", func(r *http.Request, b body) (any, error) { return c.CoreCert() })
	h("POST /claim", func(r *http.Request, b body) (any, error) {
		s, err := sealed(b, "bundle")
		if err != nil {
			return nil, err
		}
		return c.Claim(str(b, "statement"), str(b, "masterSig"), s)
	})
	h("POST /wipe", func(r *http.Request, b body) (any, error) { return c.Wipe(str(b, "statement"), str(b, "masterSig")) })
	h("POST /fly-token", func(r *http.Request, b body) (any, error) {
		s, err := sealed(b, "sealed")
		if err != nil {
			return nil, err
		}
		return c.SetFlyToken(s)
	})

	// ---- stores (open: create and mark only add protection; a write can't reveal a secret) ----
	h("POST /stores", func(r *http.Request, b body) (any, error) { return c.Stores(str(b, "nonce")) })
	h("POST /stores/create", func(r *http.Request, b body) (any, error) { return c.CreateStore(str(b, "name")) })
	h("POST /stores/mark-sensitive", func(r *http.Request, b body) (any, error) { return c.MarkSensitive(str(b, "name")) })
	h("POST /stores/write", func(r *http.Request, b body) (any, error) {
		var s StoreBlob
		if json.Unmarshal(b["store"], &s) != nil {
			return nil, fail(400, "not a store blob")
		}
		return c.WriteStore(s)
	})

	// ---- machines ----
	h("POST /start", func(r *http.Request, b body) (any, error) {
		var sr StartRequest
		raw, _ := json.Marshal(b)
		json.Unmarshal(raw, &sr)
		return c.Start(sr)
	})
	h("POST /certify", func(r *http.Request, b body) (any, error) { return c.Certify(doc(b, "approval"), str(b, "machine")) })
	h("POST /kill", func(r *http.Request, b body) (any, error) { return c.Kill(str(b, "machine")) })

	// ---- succession ----
	h("POST /succession", func(r *http.Request, b body) (any, error) {
		var in SuccessionInput
		raw, _ := json.Marshal(b)
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fail(400, "bad succession request")
		}
		return c.Succession(in)
	})
	h("POST /approve/by-phone", func(r *http.Request, b body) (any, error) {
		return c.ApproveByPhone(doc(b, "challenge"), str(b, "signature"))
	})
	h("POST /approve/by-old-key", func(r *http.Request, b body) (any, error) {
		return c.ApproveByOldKey(doc(b, "challenge"), str(b, "signature"))
	})
	h("POST /approve/by-dead-machine", func(r *http.Request, b body) (any, error) { return c.ApproveByDeadMachine(doc(b, "challenge")) })

	// ---- unlock ----
	h("POST /unlock/begin", func(r *http.Request, b body) (any, error) { return c.UnlockBegin(str(b, "store")) })
	h("POST /unlock/finish", func(r *http.Request, b body) (any, error) {
		var s Sealed
		json.Unmarshal(b["share"], &s)
		return c.UnlockFinish(str(b, "pending"), s)
	})
	h("POST /lock", func(r *http.Request, b body) (any, error) { return c.Lock(str(b, "id")) })

	// ---- deploy keys (deploykeys.go): the phone signs the begin document and shares the token store ----
	h("POST /deploy-keys/begin", func(r *http.Request, b body) (any, error) {
		var sensitive bool
		json.Unmarshal(b["sensitive"], &sensitive)
		return c.DeployKeyBegin(str(b, "action"), str(b, "repo"), sensitive)
	})
	h("POST /deploy-keys/finish", func(r *http.Request, b body) (any, error) {
		var s Sealed
		json.Unmarshal(b["share"], &s)
		return c.DeployKeyFinish(str(b, "pending"), s, str(b, "signature"))
	})
	h("POST /unlocked", func(r *http.Request, b body) (any, error) { return c.ListUnlocked(str(b, "nonce")) })

	// ---- machines pull ----
	h("POST /pull-secrets", func(r *http.Request, b body) (any, error) {
		return c.PullSecrets(doc(b, "cert"))
	})
	h("POST /log", func(r *http.Request, b body) (any, error) { return c.Log(str(b, "nonce")) })
	return mux
}

// errors leave signed too
func writeErr(c *Core, w http.ResponseWriter, err error) {
	status := 500
	var e *Err
	if errors.As(err, &e) {
		status = e.Status
	}
	d, _ := c.sign(map[string]any{"kind": "error", "error": err.Error()})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(d)
}
