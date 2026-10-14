package kernel

// The HTTP surface every part shares: POST routes take one strict JSON body, answers are JSON, errors leave signed by
// the part (as the core's do). Nothing here trusts the caller (the router): what matters is signed or sealed.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type Err struct {
	Status int
	Msg    string
}

func (e *Err) Error() string                    { return e.Msg }
func Fail(status int, f string, a ...any) error { return &Err{status, fmt.Sprintf(f, a...)} }

// Route: one endpoint; body is the raw request body (empty for GET)
type Route func(body []byte) (any, error)

// Decode: a request body into in, strictly (an unknown field is a 400)
func Decode(body []byte, in any) error {
	if err := strictJSON(body, in); err != nil {
		return Fail(400, "bad request: %v", err)
	}
	return nil
}

// Handler: the routes ("POST /move", "GET /identity", …) with signed errors
func Handler(s *Signer, routes map[string]Route) http.Handler {
	mux := http.NewServeMux()
	for pattern, fn := range routes {
		fn := fn
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
			if err != nil {
				writeErr(s, w, Fail(400, "body: %v", err))
				return
			}
			out, err := fn(raw)
			if err != nil {
				writeErr(s, w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		})
	}
	return mux
}

func writeErr(s *Signer, w http.ResponseWriter, err error) {
	status := 500
	var e *Err
	if errors.As(err, &e) {
		status = e.Status
	}
	d, _ := Sign(s, map[string]any{"kind": "error", "error": err.Error()})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(d)
}

// IdentityText: what the box key signs for a part (keys/box.pub checks it). The role is in the text, so one part's
// identity can't pass as another's.
func IdentityText(role, signingKey, agreementKey string) string {
	return "jarvis2-" + role + "-identity " + signingKey + " " + agreementKey
}

// Identity: a part's public keys, with the box key's signature over them when the part has a box key
type Identity struct {
	Role         string `json:"role"`
	SigningKey   string `json:"signingKey"`
	AgreementKey string `json:"agreementKey,omitempty"`
	BoxSig       string `json:"boxSig,omitempty"`
}

// ---- binaries ----------------------------------------------------------------------------------------

// Env: what every part's binary reads — its own key (KEY_FILE, PKCS#8 PEM), the roster (ROSTER_FILE, JSON), the box
// key that vouches for it (BOX_KEY_FILE, optional) and the address (ADDR)
type Env struct {
	Signer *Signer
	Roster Roster
	Box    *Signer // nil without BOX_KEY_FILE
	Addr   string
}

// LoadEnv: from the environment; exits on a bad or missing file. needRoster: the part checks other parts' signatures.
func LoadEnv(defaultAddr string, needRoster bool) Env {
	var e Env
	b, err := os.ReadFile(os.Getenv("KEY_FILE"))
	if err != nil {
		log.Fatalf("KEY_FILE: %v", err)
	}
	if e.Signer, err = SignerFromPEM(b); err != nil {
		log.Fatalf("KEY_FILE: %v", err)
	}
	if needRoster {
		rb, err := os.ReadFile(os.Getenv("ROSTER_FILE"))
		if err != nil {
			log.Fatalf("ROSTER_FILE: %v", err)
		}
		if err := strictJSON(rb, &e.Roster); err != nil {
			log.Fatalf("ROSTER_FILE: %v", err)
		}
	}
	if f := os.Getenv("BOX_KEY_FILE"); f != "" {
		bb, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("BOX_KEY_FILE: %v", err)
		}
		if e.Box, err = SignerFromPEM(bb); err != nil {
			log.Fatalf("BOX_KEY_FILE: %v", err)
		}
	}
	if e.Addr = os.Getenv("ADDR"); e.Addr == "" {
		e.Addr = defaultAddr
	}
	return e
}

// MakeIdentity: the identity answer, box-signed when there is a box key
func MakeIdentity(role string, s *Signer, agreementKey string, box *Signer) Identity {
	id := Identity{Role: role, SigningKey: s.PublicKey(), AgreementKey: agreementKey}
	if box != nil {
		id.BoxSig, _ = box.Sign([]byte(IdentityText(role, id.SigningKey, agreementKey)))
	}
	return id
}

// Serve: the part's routes plus GET /identity, on e.Addr
func Serve(e Env, id Identity, routes map[string]Route) {
	routes["GET /identity"] = func([]byte) (any, error) { return id, nil }
	log.Printf("%s up; signing key %s", id.Role, id.SigningKey)
	log.Fatal(http.ListenAndServe(e.Addr, Handler(e.Signer, routes)))
}
