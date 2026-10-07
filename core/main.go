package main

// HTTP surface of the core. It listens only inside the cluster (the router reaches it; NetworkPolicy
// keeps everything else out). Setup calls need the one-time setup token printed at start, which only
// the setup session (with cluster access to this pod's log) reads.

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	fly := &FlyAPI{base: "https://api.machines.dev/v1", http: &http.Client{Timeout: 90 * time.Second}}
	c, err := NewCore(fly)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("core up; signing key %s", c.signer.PublicKey())
	log.Printf("SETUP TOKEN %s", c.SetupToken)
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8090"
	}
	log.Fatal(http.ListenAndServe(addr, Handler(c, fly)))
}

func Handler(c *Core, fly *FlyAPI) http.Handler {
	mux := http.NewServeMux()
	type body = map[string]json.RawMessage
	h := func(pattern string, setup bool, fn func(r *http.Request, b body) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if setup && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Setup-Token")), []byte(c.SetupToken)) != 1 {
				writeErr(c, w, fail(403, "setup token required"))
				return
			}
			b := body{}
			if r.Body != nil && r.ContentLength != 0 {
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&b); err != nil {
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

	// ---- setup (token) ----
	h("POST /setup/phone", true, func(r *http.Request, b body) (any, error) {
		return c.SetupPhone(str(b, "signingKey"), str(b, "agreementKey"))
	})
	h("POST /setup/store", true, func(r *http.Request, b body) (any, error) {
		var vals map[string]string
		json.Unmarshal(b["values"], &vals)
		var sens bool
		json.Unmarshal(b["sensitive"], &sens)
		return c.SeedStore(str(b, "name"), vals, sens)
	})
	h("POST /setup/fly", true, func(r *http.Request, b body) (any, error) {
		fly.Configure(str(b, "token"), str(b, "app"))
		c.mu.Lock()
		c.logf("fly token set for app %s", str(b, "app"))
		c.mu.Unlock()
		return c.sign(map[string]any{"kind": "fly-set", "app": str(b, "app")})
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
