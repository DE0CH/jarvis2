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
	"strconv"
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
	c.box = box
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
			if m := c.Mode(); m != modeServing && !allowedIn(m, pattern) {
				// continuity.go: a core that handed off, or stands by for a takeover, serves nothing else
				writeErr(c, w, fail(409, "this core is %s: it serves nothing (%s)", m, map[string]string{
					modeHandedOff: "it handed off to the core Recovered after it", modeStandby: "it waits for the serving core's final line state"}[m]))
				return
			}
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
			c.syncLine() // continuity.go: a changed line state gets its next number before the answer leaves
			if n := c.LineSeq(); n > 0 {
				w.Header().Set(lineSeqHeader, strconv.Itoa(n))
			}
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

	sealed := func(b body, k string) (Sealed, error) {
		var s Sealed
		if json.Unmarshal(b[k], &s) != nil || s.E == "" {
			return s, fail(400, "%s must be sealed to the core's agreement key", k)
		}
		return s, nil
	}

	// ---- identity, and setting the core up (the iPhone, with the master key) ----
	h("GET /identity", func(r *http.Request, b body) (any, error) { return c.Identity() })
	h("POST /claim", func(r *http.Request, b body) (any, error) {
		s, err := sealed(b, "bundle")
		if err != nil {
			return nil, err
		}
		return c.Claim(str(b, "statement"), str(b, "masterSig"), s)
	})
	h("POST /store-key", func(r *http.Request, b body) (any, error) { return c.StoreKey(str(b, "phone"), str(b, "core")) })
	h("GET /line-state", func(r *http.Request, b body) (any, error) { return c.LineState() })
	h("POST /handoff", func(r *http.Request, b body) (any, error) { return c.Handoff() })
	h("POST /takeover", func(r *http.Request, b body) (any, error) {
		var d LineStateDoc
		if err := json.Unmarshal(b["lineState"], &d); err != nil {
			return nil, fail(400, "lineState: {head, sealed}")
		}
		return c.Takeover(&d)
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
	h("POST /stores/write-key", func(r *http.Request, b body) (any, error) {
		var in WriteKeyInput
		raw, _ := json.Marshal(b)
		if json.Unmarshal(raw, &in) != nil {
			return nil, fail(400, "bad write-key request")
		}
		return c.WriteKey(in)
	})

	// ---- versions and restore (history.go): the phone signs the begin document and shares the keys put back ----
	h("POST /stores/versions", func(r *http.Request, b body) (any, error) { return c.Versions(str(b, "store"), str(b, "nonce")) })
	h("POST /stores/restore/begin", func(r *http.Request, b body) (any, error) {
		var seq int
		if json.Unmarshal(b["seq"], &seq) != nil {
			return nil, fail(400, "seq: the version to put back")
		}
		return c.RestoreBegin(str(b, "store"), seq)
	})
	h("POST /stores/restore/finish", func(r *http.Request, b body) (any, error) {
		shares := map[string]Sealed{}
		if len(b["shares"]) != 0 && json.Unmarshal(b["shares"], &shares) != nil {
			return nil, fail(400, "shares: {key: sealed share}")
		}
		return c.RestoreFinish(str(b, "pending"), str(b, "signature"), shares)
	})
	h("POST /stores/restore/commit", func(r *http.Request, b body) (any, error) { return c.RestoreCommit(str(b, "pending")) })

	// ---- machines ----
	h("POST /start", func(r *http.Request, b body) (any, error) {
		var sr StartRequest
		raw, _ := json.Marshal(b)
		json.Unmarshal(raw, &sr)
		return c.Start(sr)
	})
	h("POST /init", func(r *http.Request, b body) (any, error) { return c.Init(str(b, "machine")) })
	h("POST /certify", func(r *http.Request, b body) (any, error) {
		return c.Certify(doc(b, "approval"), doc(b, "started"), str(b, "carry"))
	})
	h("POST /extend", func(r *http.Request, b body) (any, error) { // volumes.go: More disk
		var in struct {
			Machine string `json:"machine"`
			SizeGB  int    `json:"sizeGb"`
		}
		raw, _ := json.Marshal(b)
		json.Unmarshal(raw, &in)
		return c.Extend(in.Machine, in.SizeGB)
	})
	h("POST /kill", func(r *http.Request, b body) (any, error) {
		var snap *SnapshotClaim
		if len(b["snapshot"]) != 0 && string(b["snapshot"]) != "null" {
			snap = &SnapshotClaim{}
			if json.Unmarshal(b["snapshot"], snap) != nil {
				return nil, fail(400, "snapshot: {sha256, sig}")
			}
		}
		var legacy *LegacyCert
		if len(b["legacy"]) != 0 && string(b["legacy"]) != "null" {
			legacy = &LegacyCert{}
			if json.Unmarshal(b["legacy"], legacy) != nil {
				return nil, fail(400, "legacy: {cert, coreCert: {statement, masterSig}}")
			}
		}
		return c.Kill(str(b, "machine"), snap, legacy)
	})
	// ---- the input log (audit.go) ----
	h("POST /attest", func(r *http.Request, b body) (any, error) {
		return c.Attest(str(b, "machine"), str(b, "input"), str(b, "origin"), str(b, "sha256"))
	})

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
		return c.ApproveByPhone(doc(b, "challenge"), str(b, "signature"), str(b, "carry"), doc(b, "current"))
	})
	h("POST /approve/by-old-key", func(r *http.Request, b body) (any, error) {
		return c.ApproveByOldKey(doc(b, "challenge"), str(b, "signature"), str(b, "carry"))
	})
	h("POST /approve/by-dead-machine", func(r *http.Request, b body) (any, error) { return c.ApproveByDeadMachine(doc(b, "challenge")) })

	// ---- unlock ----
	h("POST /unlock/begin", func(r *http.Request, b body) (any, error) { return c.UnlockBegin(str(b, "store"), str(b, "for")) })
	h("POST /unlock/finish", func(r *http.Request, b body) (any, error) {
		shares := map[string]Sealed{}
		if json.Unmarshal(b["shares"], &shares) != nil {
			return nil, fail(400, "shares: {key: sealed share}")
		}
		return c.UnlockFinish(str(b, "pending"), shares)
	})
	h("POST /lock", func(r *http.Request, b body) (any, error) { return c.Lock(str(b, "id")) })

	// ---- deploy keys (deploykeys.go): the phone signs the begin document and shares the token store ----
	h("POST /deploy-keys/begin", func(r *http.Request, b body) (any, error) {
		var in DeployKeyRequest
		raw, _ := json.Marshal(b)
		if json.Unmarshal(raw, &in) != nil {
			return nil, fail(400, "bad deploy-key request")
		}
		return c.DeployKeyBegin(in)
	})
	h("POST /deploy-keys/finish", func(r *http.Request, b body) (any, error) {
		var s Sealed
		json.Unmarshal(b["share"], &s)
		return c.DeployKeyFinish(str(b, "pending"), s, str(b, "signature"))
	})
	h("POST /unlocked", func(r *http.Request, b body) (any, error) { return c.ListUnlocked(str(b, "nonce")) })

	// ---- machines pull ----
	h("POST /pull-secrets", func(r *http.Request, b body) (any, error) {
		return c.PullSecrets(doc(b, "cert"), str(b, "carry"))
	})
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
