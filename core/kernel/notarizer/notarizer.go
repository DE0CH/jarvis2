// Package notarizer is the succession notarizer: it checks a succession cert against the policy table, then answers
// the log notary's challenge for it. A shape not in the table is refused. The table is data (Table) and every cert
// takes the one code path in Notarize.
package notarizer

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/DE0CH/jarvis2/core/kernel"
)

// Any: a row's predecessor or successor that matches every kind of object
const Any = "any"

// Row: one shape the notarizer accepts — the kinds of predecessor and successor, the signer, and its condition
type Row struct {
	Pred   string `json:"pred"` // kernel.KindSink | KindSource | KindMachine | Any
	Succ   string `json:"succ"`
	Signer string `json:"signer"`
	// Same: predecessor and successor are the same object (an identity edge)
	Same bool `json:"same,omitempty"`
	// FirstSuccessor: the predecessor (a source) has no earlier notarized successor, through any row
	FirstSuccessor bool `json:"firstSuccessor,omitempty"`
}

// Table: DESIGN "The kernel", row for row
var Table = []Row{
	{Pred: kernel.KindSink, Succ: kernel.KindSource, Signer: kernel.RolePhone},
	{Pred: kernel.KindSource, Succ: kernel.KindMachine, Signer: kernel.RoleSpawner, FirstSuccessor: true},
	{Pred: kernel.KindSource, Succ: kernel.KindMachine, Signer: kernel.RolePhone, FirstSuccessor: true},
	{Pred: kernel.KindMachine, Succ: kernel.KindMachine, Signer: kernel.RoleIdentity, Same: true},
	{Pred: kernel.KindMachine, Succ: kernel.KindSource, Signer: kernel.RoleSpawner},
	{Pred: kernel.KindSource, Succ: kernel.KindSink, Signer: kernel.RoleGullible},
	{Pred: Any, Succ: Any, Signer: kernel.RoleRoot},
}

func kindIs(want, got string) bool { return want == Any || want == got }

// Match: the first row the cert's shape fits (nil = not in the table)
func Match(table []Row, s kernel.Succession) *Row {
	for i, r := range table {
		if kindIs(r.Pred, s.Predecessor.Kind()) && kindIs(r.Succ, s.Successor.Kind()) && r.Signer == s.Signer &&
			(!r.Same || s.Predecessor == s.Successor) {
			return &table[i]
		}
	}
	return nil
}

type Notarizer struct {
	mu     sync.Mutex
	signer *kernel.Signer
	roster kernel.Roster
	table  []Row
	// succeeded: the sources with a notarized successor (through any row). Kept in the state file, one id per line,
	// so a restart doesn't forget them.
	succeeded map[string]bool
	answered  map[string]bool // challenge IDs answered (each once)
	state     io.Writer       // nil = memory only
}

// New: with the state file's path ("" = memory only); the sources already listed in it count as succeeded
func New(s *kernel.Signer, r kernel.Roster, statePath string) (*Notarizer, error) {
	n := &Notarizer{signer: s, roster: r, table: Table, succeeded: map[string]bool{}, answered: map[string]bool{}}
	if statePath == "" {
		return n, nil
	}
	if f, err := os.Open(statePath); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if id := strings.TrimSpace(sc.Text()); id != "" {
				n.succeeded[id] = true
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(statePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	n.state = f
	return n, nil
}

// Notarize: the cert (signed by the key of the role it names), the log notary's challenge for it (subject = the cert's
// ID, about "succession"), the table, the first-successor rule → the notarized cert
func (n *Notarizer) Notarize(cert, challenge kernel.SignedDoc) (kernel.NotarizedCert, error) {
	s, err := kernel.OpenSuccession(n.roster, cert)
	if err != nil {
		return kernel.NotarizedCert{}, kernel.Fail(403, "%v", err)
	}
	ch, err := kernel.OpenChallenge(n.roster, challenge)
	if err != nil {
		return kernel.NotarizedCert{}, kernel.Fail(403, "%v", err)
	}
	if ch.Subject != cert.ID() || ch.About != kernel.AboutSuccession {
		return kernel.NotarizedCert{}, kernel.Fail(403, "the challenge isn't for this cert")
	}
	row := Match(n.table, s)
	if row == nil {
		return kernel.NotarizedCert{}, kernel.Fail(403, "(%s, %s) signed by %s is not in the table", s.Predecessor.Kind(), s.Successor.Kind(), s.Signer)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.answered[challenge.ID()] {
		return kernel.NotarizedCert{}, kernel.Fail(409, "this challenge was already answered")
	}
	pred := s.Predecessor
	if row.FirstSuccessor && n.succeeded[pred.ID] {
		return kernel.NotarizedCert{}, kernel.Fail(409, "%s already has a notarized successor", pred.ID)
	}
	if pred.Kind() == kernel.KindSource && !n.succeeded[pred.ID] {
		if n.state != nil {
			if _, err := fmt.Fprintln(n.state, pred.ID); err != nil {
				return kernel.NotarizedCert{}, kernel.Fail(503, "the state file can't be written: %v", err)
			}
		}
		n.succeeded[pred.ID] = true
	}
	n.answered[challenge.ID()] = true
	d, err := kernel.Sign(n.signer, kernel.Notarization{Kind: "notarization", Cert: cert.ID(), Challenge: challenge.ID()})
	if err != nil {
		return kernel.NotarizedCert{}, err
	}
	return kernel.NotarizedCert{Cert: cert, Challenge: challenge, Notarization: d}, nil
}

// Routes: POST /notarize {cert, challenge} → {cert, challenge, notarization}
func (n *Notarizer) Routes() map[string]kernel.Route {
	return map[string]kernel.Route{
		"POST /notarize": func(body []byte) (any, error) {
			var in struct {
				Cert      kernel.SignedDoc `json:"cert"`
				Challenge kernel.SignedDoc `json:"challenge"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return n.Notarize(in.Cert, in.Challenge)
		},
		"GET /table": func([]byte) (any, error) { return n.table, nil },
	}
}
