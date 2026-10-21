// Package serve: what every kernel component's server shares. The box key (KERNEL_BOX_KEY, a PEM file mounted from
// a Secret only the kernel namespace reads) vouches for the component's fresh keys; GET /identity answers them; every
// answer leaves signed, errors too, so the untrusted router can't put words in a component's mouth.
package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/DE0CH/jarvis2/kernel/sig"
)

// Error: an error with the HTTP status it answers
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Fail: an error answered with code
func Fail(code int, format string, a ...any) error { return &Error{code, fmt.Sprintf(format, a...)} }

// Box: the box key from KERNEL_BOX_KEY
func Box() (*sig.Signer, error) {
	path := os.Getenv("KERNEL_BOX_KEY")
	if path == "" {
		return nil, errors.New("KERNEL_BOX_KEY (the box key's PEM file) isn't set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sig.SignerFromPEM(b)
}

// Server: a component's mux; Handle wraps a JSON handler
type Server struct {
	C   *sig.Component
	Box string // the box public key (to check the other components' identities)
	Mux *http.ServeMux
}

func New(c *sig.Component, boxPub string) *Server {
	s := &Server{C: c, Box: boxPub, Mux: http.NewServeMux()}
	s.Mux.HandleFunc("GET /identity", func(w http.ResponseWriter, _ *http.Request) { s.reply(w, 200, c.Identity) })
	return s
}

// Handle: POST pattern with a strict JSON body into In; fn's answer is signed
func Handle[In any](s *Server, pattern string, fn func(In) (any, error)) {
	s.Mux.HandleFunc(pattern, func(w http.ResponseWriter, req *http.Request) {
		var in In
		body, err := io.ReadAll(io.LimitReader(req.Body, 8<<20))
		if err == nil {
			err = sig.StrictJSON(body, &in)
		}
		if err != nil {
			s.reply(w, 400, map[string]string{"kind": "error", "error": "bad request: " + err.Error()})
			return
		}
		out, err := fn(in)
		if err != nil {
			code := 500
			var e *Error
			if errors.As(err, &e) {
				code = e.Code
			}
			if code >= 500 {
				log.Printf("%s: %v", pattern, err)
			}
			s.reply(w, code, map[string]string{"kind": "error", "error": err.Error()})
			return
		}
		if d, ok := out.(sig.Doc); ok { // already a signed document
			s.writeJSON(w, 200, d)
			return
		}
		s.reply(w, 200, out)
	})
}

// reply: v signed by the component
func (s *Server) reply(w http.ResponseWriter, code int, v any) {
	d, err := s.C.Signer.SignJSON(v)
	if err != nil {
		http.Error(w, "signing failed", 500)
		return
	}
	s.writeJSON(w, code, d)
}

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// Main: the component's process: its keys, its routes (setup adds them), then serve on KERNEL_ADDR (default :8080)
func Main(role string, setup func(*Server) error) {
	box, err := Box()
	if err != nil {
		log.Fatal(err)
	}
	c, err := sig.NewComponent(role, box)
	if err != nil {
		log.Fatal(err)
	}
	s := New(c, box.PublicKey())
	if err := setup(s); err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("KERNEL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("%s: serving on %s (signing key %s)", role, addr, c.Identity.SigningKey)
	log.Fatal(http.ListenAndServe(addr, s.Mux))
}
