package main

// Grants (docs/DESIGN.md "Grants"): each router feature that needs a shell in a session has its own key pair
// (a holder), kept on the router's volume. A session's machine runs a holder's command when the phone signed a
// grant (10 minutes at most) or a standing rule for that holder and line, or when the session put the holder on
// its own allow list (`jarvis2-machine allow`). The machine checks all of it against its core-signed cert; the
// router only drafts the text for the phone, keeps what the phone signed, and relays requests and results.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// the features that may hold grants
var holderNames = []string{"terminal", "scheduler", "status", "login", "archive", "remote"}

type StoredGrant struct {
	ID      string    `json:"id"`
	Session string    `json:"session"` // the router's session id
	Holder  string    `json:"holder"`  // the feature's name
	Kind    string    `json:"kind"`    // grant | rule
	Ends    time.Time `json:"ends"`
	Doc     *Doc      `json:"doc"`
}

type grantText struct {
	Kind    string `json:"kind"`
	Holder  string `json:"holder"`
	Session string `json:"session"` // the line id (the machine's cert names it)
	Scope   string `json:"scope"`
	Issued  string `json:"issued"`
	Expires string `json:"expires,omitempty"`
	Until   string `json:"until,omitempty"`
}

type ExecResult struct {
	ID     string `json:"id"`
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Error  string `json:"error,omitempty"`
}

type execItem struct {
	Request string `json:"request"`
	Sig     string `json:"sig"`
	Grant   *Doc   `json:"grant,omitempty"`
}

type holders struct {
	once sync.Once
	keys map[string]*ecdh.PrivateKey
	err  error
}

// holderKeys: made once and kept in DATA_DIR/holders (mode 600), so standing rules naming a key survive restarts
func (r *Router) holderKeys() (map[string]*ecdh.PrivateKey, error) {
	r.hk.once.Do(func() {
		dir := filepath.Join(r.cfg.DataDir, "holders")
		if r.hk.err = os.MkdirAll(dir, 0o700); r.hk.err != nil {
			return
		}
		r.hk.keys = map[string]*ecdh.PrivateKey{}
		for _, n := range holderNames {
			p := filepath.Join(dir, n+".key")
			b, err := os.ReadFile(p)
			var k *ecdh.PrivateKey
			if err == nil {
				k, err = ecdh.P256().NewPrivateKey(b)
			} else if os.IsNotExist(err) {
				if k, err = ecdh.P256().GenerateKey(rand.Reader); err == nil {
					err = os.WriteFile(p, k.Bytes(), 0o600)
				}
			}
			if err != nil {
				r.hk.err = fmt.Errorf("holder %s: %w", n, err)
				return
			}
			r.hk.keys[n] = k
		}
	})
	return r.hk.keys, r.hk.err
}

func (r *Router) HolderPublicKeys() (map[string]string, error) {
	ks, err := r.holderKeys()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for n, k := range ks {
		out[n] = base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	}
	return out, nil
}

func signP256(k *ecdh.PrivateKey, payload []byte) (string, error) {
	e, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), k.Bytes())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(payload)
	s, err := ecdsa.SignASN1(rand.Reader, e, h[:])
	return base64.StdEncoding.EncodeToString(s), err
}

// certField: one field of a session's latest succession cert (the line id, the phone key)
func certField(c *Doc, field string) string {
	if c == nil {
		return ""
	}
	var m map[string]any
	json.Unmarshal([]byte(c.Payload), &m)
	s, _ := m[field].(string)
	return s
}

// DraftGrant: the exact text the phone signs. kind "grant" lasts minutes (≤ 10); "rule" lasts until `until`.
func (r *Router) DraftGrant(session, holder, kind string, minutes int, until time.Time) (string, error) {
	pub, err := r.HolderPublicKeys()
	if err != nil {
		return "", err
	}
	if pub[holder] == "" {
		return "", fmt.Errorf("unknown holder %s", holder)
	}
	var line string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[session]; s != nil {
			line = certField(s.Cert, "line")
		}
	})
	if line == "" {
		return "", errors.New("the session has no certified machine yet")
	}
	now := time.Now().UTC()
	g := grantText{Kind: kind, Holder: pub[holder], Session: line, Scope: "shell", Issued: now.Format(time.RFC3339)}
	switch kind {
	case "grant":
		if minutes < 1 || minutes > 10 {
			return "", errors.New("a grant lasts 1 to 10 minutes")
		}
		g.Expires = now.Add(time.Duration(minutes) * time.Minute).Format(time.RFC3339)
	case "rule":
		if !until.After(now) {
			return "", errors.New("a standing rule needs an end in the future")
		}
		g.Until = until.UTC().Format(time.RFC3339)
	default:
		return "", errors.New("kind is grant or rule")
	}
	b, _ := json.Marshal(g)
	return string(b), nil
}

// AddGrant: keep what the phone signed, after checking it against the phone key in the session's cert
func (r *Router) AddGrant(session string, doc *Doc) (*StoredGrant, error) {
	var g grantText
	if doc == nil || json.Unmarshal([]byte(doc.Payload), &g) != nil {
		return nil, errors.New("bad grant")
	}
	pub, err := r.HolderPublicKeys()
	if err != nil {
		return nil, err
	}
	holder := ""
	for n, k := range pub {
		if k == g.Holder {
			holder = n
		}
	}
	end, err := time.Parse(time.RFC3339, g.Expires+g.Until)
	if holder == "" || err != nil {
		return nil, errors.New("the grant names no holder of this router, or has no end")
	}
	var sg *StoredGrant
	r.st.Do(func(d *persisted) {
		s := d.Sessions[session]
		if s == nil || certField(s.Cert, "line") != g.Session {
			err = errors.New("the grant is for another session")
			return
		}
		if phone := certField(s.Cert, "phone"); phone == "" || !verifyP256(phone, []byte(doc.Payload), doc.Sig) {
			err = errors.New("not signed by the phone this session's cert names")
			return
		}
		sg = &StoredGrant{ID: randID(), Session: session, Holder: holder, Kind: g.Kind, Ends: end, Doc: doc}
		d.Grants[sg.ID] = sg
	})
	return sg, err
}

func (r *Router) Grants(session string) []*StoredGrant {
	out := []*StoredGrant{}
	now := time.Now()
	r.st.Do(func(d *persisted) {
		for id, g := range d.Grants {
			if !now.Before(g.Ends) || d.Sessions[g.Session] == nil {
				delete(d.Grants, id)
				continue
			}
			if session == "" || g.Session == session {
				out = append(out, g)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Ends.Before(out[j].Ends) })
	return out
}

func (r *Router) ForgetGrant(id string) {
	r.st.Do(func(d *persisted) { delete(d.Grants, id) })
}

// Exec runs cmd as holder in the session's machine: with a live phone grant if one exists, else a standing
// rule, else no grant (the session's own allow list). The machine decides.
func (r *Router) Exec(session, holder, cmd string, timeout time.Duration) (ExecResult, error) {
	return r.execWith(session, holder, cmd, timeout, false)
}

// GrantNeeded: no grant that allows this; Phone = only a fresh phone grant would
type GrantNeeded struct {
	Holder string
	Phone  bool
}

func (e *GrantNeeded) Error() string {
	if e.Phone {
		return "this needs a fresh phone grant for " + e.Holder
	}
	return "no grant for " + e.Holder
}

// HasPhoneGrant: a live phone grant (not a rule) for holder on the session
func (r *Router) HasPhoneGrant(session, holder string) bool {
	for _, g := range r.Grants(session) {
		if g.Holder == holder && g.Kind == "grant" {
			return true
		}
	}
	return false
}

// ExecPhone: like Exec, but only under a live phone grant, and the machine is told so (it refuses a rule or its
// allow list for this request). For raising a session to bypass (Deyao, 2026-10-09).
func (r *Router) ExecPhone(session, holder, cmd string, timeout time.Duration) (ExecResult, error) {
	return r.execWith(session, holder, cmd, timeout, true)
}

func (r *Router) execWith(session, holder, cmd string, timeout time.Duration, phoneOnly bool) (ExecResult, error) {
	ks, err := r.holderKeys()
	if err != nil {
		return ExecResult{}, err
	}
	k := ks[holder]
	if k == nil {
		return ExecResult{}, fmt.Errorf("unknown holder %s", holder)
	}
	var machine, line string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[session]; s != nil {
			machine, line = s.MachineID, certField(s.Cert, "line")
		}
	})
	if machine == "" || line == "" {
		return ExecResult{}, errors.New("the session has no running machine")
	}
	var grant *Doc
	best := ""
	for _, g := range r.Grants(session) {
		if g.Holder == holder && (!phoneOnly || g.Kind == "grant") && (best == "" || (best == "rule" && g.Kind == "grant")) {
			grant, best = g.Doc, g.Kind
		}
	}
	if phoneOnly && grant == nil {
		return ExecResult{}, &GrantNeeded{Holder: holder, Phone: true}
	}
	secs := int(timeout / time.Second)
	req, _ := json.Marshal(map[string]any{"id": randID(), "session": line, "holder": base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
		"cmd": cmd, "timeout": secs, "at": time.Now().Unix(), "phoneOnly": phoneOnly})
	var id struct{ ID string }
	json.Unmarshal(req, &id)
	sig, err := signP256(k, req)
	if err != nil {
		return ExecResult{}, err
	}
	ch := make(chan ExecResult, 1)
	r.cmdMu.Lock()
	r.results[id.ID] = ch
	q := r.execQueue(machine)
	r.cmdMu.Unlock()
	defer func() { r.cmdMu.Lock(); delete(r.results, id.ID); r.cmdMu.Unlock() }()
	select {
	case q <- execItem{Request: string(req), Sig: sig, Grant: grant}:
	default:
		return ExecResult{}, errors.New("the machine has too many commands waiting")
	}
	select {
	case res := <-ch:
		if res.Error != "" {
			return res, fmt.Errorf("the machine refused or failed: %s", res.Error)
		}
		return res, nil
	case <-time.After(timeout + 60*time.Second):
		return ExecResult{}, errors.New("no answer from the machine")
	}
}

// execQueue: callers hold cmdMu
func (r *Router) execQueue(machine string) chan execItem {
	q := r.execs[machine]
	if q == nil {
		q = make(chan execItem, 16)
		r.execs[machine] = q
	}
	return q
}

func (r *Router) execResult(res ExecResult) {
	r.cmdMu.Lock()
	ch := r.results[res.ID]
	r.cmdMu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
		}
	}
}
