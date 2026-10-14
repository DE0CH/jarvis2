package main

// Every kernel document the router has carried, by ID (hex sha256 of its payload), on its data volume: succession
// certs, the log notary's challenges, notarizations and grants, plus root's ⊤ on the sink. Nobody trusts the router
// for any of it (each document is signed by its maker and checked by whoever uses it); the router keeps them so it can
// serve a machine its boot chain and the app any session's chain.
//
//	GET /api/kernel/docs/{id}          one document
//	GET /api/kernel/notarized/{id}     a notarized cert by its cert's ID: {cert, challenge, notarization}
//	GET /api/sessions/{id}/chain       the session's chain: every cert and grant in order, and the grants in force
//	GET /api/kernel/root-grant         root's ⊤ on the sink (404 until the phone gave it)
//	PUT /api/kernel/root-grant         the phone's root grant (made once with the root key at setup)
//	GET /api/kernel/roster             the parts' signing keys as each answers /identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/DE0CH/jarvis2/core/kernel"
)

var docIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type DocStore struct {
	dir string
	mu  sync.Mutex
}

func newDocStore(dataDir string) *DocStore {
	s := &DocStore{dir: filepath.Join(dataDir, "kernel")}
	os.MkdirAll(filepath.Join(s.dir, "docs"), 0o700)
	os.MkdirAll(filepath.Join(s.dir, "notarized"), 0o700)
	return s
}

func writeAtomic(p string, b []byte) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Put: the document kept (once) → its ID
func (s *DocStore) Put(d kernel.SignedDoc) string {
	id := d.ID()
	p := filepath.Join(s.dir, "docs", id+".json")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(p); err != nil {
		b, _ := json.Marshal(d)
		writeAtomic(p, b)
	}
	return id
}

func (s *DocStore) Get(id string) (kernel.SignedDoc, bool) {
	var d kernel.SignedDoc
	if !docIDRE.MatchString(id) {
		return d, false
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "docs", id+".json"))
	if err != nil || json.Unmarshal(b, &d) != nil {
		return d, false
	}
	return d, true
}

type notarizedIndex struct {
	Challenge    string `json:"challenge"`
	Notarization string `json:"notarization"`
}

// PutNotarized: the three documents kept, and the cert's ID indexed to them → the cert's ID
func (s *DocStore) PutNotarized(nc kernel.NotarizedCert) string {
	id := s.Put(nc.Cert)
	idx := notarizedIndex{Challenge: s.Put(nc.Challenge), Notarization: s.Put(nc.Notarization)}
	b, _ := json.Marshal(idx)
	s.mu.Lock()
	writeAtomic(filepath.Join(s.dir, "notarized", id+".json"), b)
	s.mu.Unlock()
	return id
}

// Notarized: a notarized cert by its cert's ID
func (s *DocStore) Notarized(id string) (kernel.NotarizedCert, bool) {
	var nc kernel.NotarizedCert
	if !docIDRE.MatchString(id) {
		return nc, false
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "notarized", id+".json"))
	var idx notarizedIndex
	if err != nil || json.Unmarshal(b, &idx) != nil {
		return nc, false
	}
	var ok1, ok2, ok3 bool
	nc.Cert, ok1 = s.Get(id)
	nc.Challenge, ok2 = s.Get(idx.Challenge)
	nc.Notarization, ok3 = s.Get(idx.Notarization)
	return nc, ok1 && ok2 && ok3
}

// rootGrant: root's ⊤ on the sink, as the phone gave it
func (r *Router) rootGrant() (kernel.SignedDoc, error) {
	var id string
	r.st.Do(func(d *persisted) { id = d.RootGrant })
	if id == "" {
		return kernel.SignedDoc{}, errors.New("no root grant yet: the app gives it once at setup (PUT /api/kernel/root-grant)")
	}
	g, ok := r.docs.Get(id)
	if !ok {
		return kernel.SignedDoc{}, errors.New("the root grant is missing from the volume")
	}
	return g, nil
}

// setRootGrant: the shape checked (the parts check the root key's signature on every use)
func (r *Router) setRootGrant(d kernel.SignedDoc) error {
	g, err := grantOf(d)
	top := kernel.RootGrant()
	if err != nil || g.Kind != "grant" || g.By != kernel.RoleRoot || g.Machine != top.Machine || !g.Allowed.Equal(top.Allowed) ||
		len(g.Conditions) != 0 || len(g.From) != 0 || d.Sig == "" {
		return &badRequest{"not root's ⊤ on the sink"}
	}
	id := r.docs.Put(d)
	r.st.Do(func(p *persisted) { p.RootGrant = id })
	return nil
}

// ---- chains as served -------------------------------------------------------------------------------------------

// ChainView: a session's chain for the app — every step's documents (resolved), the main grant and the held one
type ChainView struct {
	Session string                `json:"session"`
	Steps   []ChainStepView       `json:"steps"`
	Main    *kernel.SignedDoc     `json:"main"`
	Held    *kernel.SignedDoc     `json:"held"`
	AddOns  []AddOnView           `json:"addOns"`
	Source  *kernel.Object        `json:"source"`
	Machine *kernel.Object        `json:"machine"`
	Origin  *kernel.NotarizedCert `json:"origin"`
	Spawn   *kernel.NotarizedCert `json:"spawn"`
}

type ChainStepView struct {
	Kind      string                `json:"kind"` // cert | grant
	ID        string                `json:"id"`
	Notarized *kernel.NotarizedCert `json:"notarized,omitempty"`
	Grant     *kernel.SignedDoc     `json:"grant,omitempty"`
}

type AddOnView struct {
	AddOn
	GrantDoc  *kernel.SignedDoc `json:"grantDoc"`
	MergedDoc *kernel.SignedDoc `json:"mergedDoc,omitempty"`
}

func (r *Router) chainView(sid string) (ChainView, error) {
	var c *Chain
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Chain != nil {
			x := s.Chain.clone()
			c = &x
		} else {
			for _, rec := range d.Records {
				if rec.ID == sid && rec.Chain != nil {
					x := rec.Chain.clone()
					c = &x
					break
				}
			}
		}
	})
	if c == nil {
		return ChainView{}, errNoSession
	}
	v := ChainView{Session: sid, Steps: []ChainStepView{}, AddOns: []AddOnView{}}
	doc := func(id string) *kernel.SignedDoc {
		if d, ok := r.docs.Get(id); ok {
			return &d
		}
		return nil
	}
	nota := func(id string) *kernel.NotarizedCert {
		if nc, ok := r.docs.Notarized(id); ok {
			return &nc
		}
		return nil
	}
	for _, st := range c.Steps {
		sv := ChainStepView{Kind: st.Kind, ID: st.ID}
		if st.Kind == "cert" {
			sv.Notarized = nota(st.ID)
		} else {
			sv.Grant = doc(st.ID)
		}
		v.Steps = append(v.Steps, sv)
	}
	v.Main, v.Held = doc(c.Main), doc(c.Held)
	for _, a := range c.AddOns {
		v.AddOns = append(v.AddOns, AddOnView{AddOn: a, GrantDoc: doc(a.Grant), MergedDoc: doc(a.Merged)})
	}
	if c.Source.ID != "" {
		src := c.Source
		v.Source = &src
	}
	v.Machine = c.Machine
	v.Origin, v.Spawn = nota(c.Origin), nota(c.Spawn)
	return v, nil
}

func (r *Router) registerDocs(app appRoute) {
	app("GET /api/kernel/docs/{id}", func(w http.ResponseWriter, req *http.Request) {
		d, ok := r.docs.Get(req.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "no such document"})
			return
		}
		writeJSON(w, 200, d)
	})
	app("GET /api/kernel/notarized/{id}", func(w http.ResponseWriter, req *http.Request) {
		nc, ok := r.docs.Notarized(req.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "no such notarized cert"})
			return
		}
		writeJSON(w, 200, nc)
	})
	app("GET /api/sessions/{id}/chain", func(w http.ResponseWriter, req *http.Request) {
		v, err := r.chainView(req.PathValue("id"))
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "the session has no chain yet"})
			return
		}
		writeJSON(w, 200, v)
	})
	app("GET /api/kernel/root-grant", func(w http.ResponseWriter, req *http.Request) {
		g, err := r.rootGrant()
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, g)
	})
	app("PUT /api/kernel/root-grant", func(w http.ResponseWriter, req *http.Request) {
		var d kernel.SignedDoc
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&d); err != nil {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("bad JSON: %v", err)})
			return
		}
		if err := r.setRootGrant(d); err != nil {
			writeRequestErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": d.ID()})
	})
	app("GET /api/kernel/roster", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]any{"parts": r.k.Roster()})
	})
}
