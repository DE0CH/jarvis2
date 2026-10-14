// Package notary is the log notary: it issues challenges with its own timestamp and logs each one. Each challenge is
// an entry of a hash chain (seq, prev); the notary keeps only the head, and writes every entry to its log (a file,
// append-only, and stdout). Whoever answers a challenge (the succession notarizer for a cert, the guard for a command)
// proves the thing was logged before it took effect.
package notary

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

type Notary struct {
	mu     sync.Mutex
	signer *kernel.Signer
	seq    int64
	head   string    // hex sha256 of the last challenge's payload
	log    io.Writer // one JSON line per challenge (the signed document); nil = none
	now    func() time.Time
}

func New(s *kernel.Signer, log io.Writer) *Notary {
	return &Notary{signer: s, log: log, now: time.Now}
}

// SetClock: tests only
func (n *Notary) SetClock(now func() time.Time) { n.now = now }

// Challenge: a new log entry over subject (hex sha256) about a word
func (n *Notary) Challenge(subject, about string) (kernel.SignedDoc, error) {
	if len(subject) != 64 || hex.EncodeToString(mustHex(subject)) != subject {
		return kernel.SignedDoc{}, kernel.Fail(400, "subject: a hex sha256")
	}
	if !kernel.AboutRE.MatchString(about) {
		return kernel.SignedDoc{}, kernel.Fail(400, "about: a lower-case word")
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	n.mu.Lock()
	defer n.mu.Unlock()
	c := kernel.Challenge{Kind: "challenge", Seq: n.seq, Prev: n.head, At: n.now().UTC().Format(time.RFC3339Nano),
		Subject: subject, About: about, Nonce: hex.EncodeToString(nonce)}
	d, err := kernel.Sign(n.signer, c)
	if err != nil {
		return d, err
	}
	if n.log != nil {
		b, _ := json.Marshal(d)
		if _, err := n.log.Write(append(b, '\n')); err != nil {
			return kernel.SignedDoc{}, kernel.Fail(503, "the log can't be written: %v", err) // not logged = not issued
		}
	}
	n.seq, n.head = n.seq+1, d.ID()
	return d, nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// Routes: POST /challenge {subject, about} → the signed challenge
func (n *Notary) Routes() map[string]kernel.Route {
	return map[string]kernel.Route{
		"POST /challenge": func(body []byte) (any, error) {
			var in struct {
				Subject string `json:"subject"`
				About   string `json:"about"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return n.Challenge(in.Subject, in.About)
		},
	}
}
