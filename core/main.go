package main

// HTTP surface of the core. It listens only inside the cluster (the router reaches it; NetworkPolicy
// keeps everything else out). Setup calls come through the router too, so each is signed by the setup
// session's key (SETUP_KEY, the public half, from git) over its method, path, time and body, and any
// secret in it is sealed to the core's agreement key: the router relays them but can't read or replay them.

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	fly := newFly()
	c, err := NewCore(fly)
	if err != nil {
		log.Fatal(err)
	}
	if c.SetupKey = os.Getenv("SETUP_KEY"); c.SetupKey == "" {
		log.Fatal("SETUP_KEY (the setup session's public key) is required")
	}
	if _, err := parseSigningKey(c.SetupKey); err != nil {
		log.Fatalf("SETUP_KEY: %v", err)
	}
	log.Printf("core up; signing key %s", c.signer.PublicKey())
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8090"
	}
	log.Fatal(http.ListenAndServe(addr, Handler(c)))
}

func Handler(c *Core) http.Handler {
	mux := http.NewServeMux()
	type body = map[string]json.RawMessage
	h := func(pattern string, setup bool, fn func(r *http.Request, b body) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
			if err != nil {
				writeErr(c, w, fail(400, "body: %v", err))
				return
			}
			if setup {
				if err := c.checkSetupSig(r.Method, r.URL.Path, r.Header.Get("X-Setup-Time"), r.Header.Get("X-Setup-Sig"), raw); err != nil {
					writeErr(c, w, err)
					return
				}
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

	h("GET /key", false, func(r *http.Request, b body) (any, error) { return c.Key(), nil })

	// ---- setup (signed by the setup key; secrets sealed to the core) ----
	sealed := func(b body, k string) ([]byte, error) {
		var s Sealed
		if json.Unmarshal(b[k], &s) != nil || s.E == "" {
			return nil, fail(400, "%s must be sealed to the core's agreement key", k)
		}
		return c.OpenSetup(s)
	}
	h("POST /setup/phone", true, func(r *http.Request, b body) (any, error) {
		return c.SetupPhone(str(b, "signingKey"), str(b, "agreementKey"))
	})
	h("POST /setup/store", true, func(r *http.Request, b body) (any, error) {
		plain, err := sealed(b, "values")
		if err != nil {
			return nil, err
		}
		var vals map[string]string
		if json.Unmarshal(plain, &vals) != nil {
			return nil, fail(400, "values: not a JSON object of strings")
		}
		var sens bool
		json.Unmarshal(b["sensitive"], &sens)
		return c.SeedStore(str(b, "name"), vals, sens)
	})

	// ---- stores ----
	h("POST /stores", false, func(r *http.Request, b body) (any, error) { return c.Stores(str(b, "nonce")) })
	h("POST /sensitive", false, func(r *http.Request, b body) (any, error) { return c.ListSensitive(str(b, "nonce")) })
	h("POST /mark-sensitive", false, func(r *http.Request, b body) (any, error) { return c.MarkSensitive(str(b, "name")) })

	// ---- machines ----
	h("POST /start", false, func(r *http.Request, b body) (any, error) {
		var sr StartRequest
		raw, _ := json.Marshal(b)
		json.Unmarshal(raw, &sr)
		return c.Start(sr)
	})
	h("POST /init", false, func(r *http.Request, b body) (any, error) { return c.Init(str(b, "machine")) })
	h("POST /kill", false, func(r *http.Request, b body) (any, error) { return c.Kill(str(b, "machine")) })

	// ---- succession ----
	h("POST /succession", false, func(r *http.Request, b body) (any, error) {
		var in SuccessionInput
		raw, _ := json.Marshal(b)
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fail(400, "bad succession request")
		}
		return c.Succession(in)
	})
	h("POST /respond/phone", false, func(r *http.Request, b body) (any, error) {
		return c.RespondPhone(doc(b, "challenge"), str(b, "signature"))
	})
	h("POST /respond/dead", false, func(r *http.Request, b body) (any, error) { return c.RespondDead(doc(b, "challenge")) })

	// ---- unlock ----
	h("POST /unlock/begin", false, func(r *http.Request, b body) (any, error) { return c.UnlockBegin(str(b, "store")) })
	h("POST /unlock/finish", false, func(r *http.Request, b body) (any, error) {
		var s Sealed
		json.Unmarshal(b["share"], &s)
		return c.UnlockFinish(str(b, "pending"), s)
	})
	h("POST /lock", false, func(r *http.Request, b body) (any, error) { return c.Lock(str(b, "id")) })
	h("POST /unlocked", false, func(r *http.Request, b body) (any, error) { return c.ListUnlocked(str(b, "nonce")) })

	// ---- machines pull ----
	h("POST /pull-secrets", false, func(r *http.Request, b body) (any, error) {
		return c.PullSecrets(doc(b, "cert"), str(b, "apiKey"))
	})
	h("POST /log", false, func(r *http.Request, b body) (any, error) { return c.Log(str(b, "nonce")) })
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
