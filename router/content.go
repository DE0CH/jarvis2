package main

// Content stores (Jarvis 1's lib/content.js, PARITY "Stores, repos, content"): named folders of files on the Storage
// Box, claude-records/.content/<store>/ — the same folders Jarvis 1 used, read and written in place. They are the
// file counterpart of the key stores, and hold no secret: a store is data a session reads and writes, not a credential.
//
//   - Deyao manages them in the app's Content tab: list, create, delete a store; list, upload, download, delete a file
//     (/api/content…, his Access login).
//   - A session gets the stores picked in New session. The pick is a signed setting (SessionConfig.Content: the phone
//     approves it with the line, every machine of the line gets the same ones). The machine's local API proxy turns
//     Jarvis 1's content-sync calls (`$JARVIS_URL/api/sessions/<id>/content…`) into machine-signed /m/api calls, and
//     the router answers them with its own Storage Box credentials, only for the stores the calling machine's cert
//     names. The machine never holds Storage Box credentials.
//   - Each file a machine downloads carries the core's attestation (input "content", origin "router", its sha256):
//     the machine's proxy refuses a file without it, so every content file a machine took is in the input log. The
//     bytes are the router's word (the Storage Box is the router's storage): a content store is data the session
//     reads, as it reads the web, kept in ~/content (never the cwd, never run). DECISIONS 132-133.
//
// The box is Apache mod_dav: PROPFIND with Depth infinity is refused, so a store is walked one level at a time.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	contentRoot    = "claude-records/.content"
	contentMaxFile = 25 << 20 // per file (Jarvis 1's limit: the cf-tunnel caps a request body at 25 MB)
	contentCacheOK = time.Minute
)

var contentNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)

type contentErr struct {
	status int
	msg    string
}

func (e *contentErr) Error() string { return e.msg }

func contentFail(status int, format string, a ...any) error {
	return &contentErr{status, fmt.Sprintf(format, a...)}
}

func contentWriteErr(w http.ResponseWriter, err error) {
	var ce *contentErr
	if errors.As(err, &ce) {
		writeJSON(w, ce.status, map[string]string{"error": ce.msg})
		return
	}
	writeJSON(w, 502, map[string]string{"error": err.Error()})
}

func contentName(raw string) (string, error) {
	n := strings.TrimSpace(raw)
	if !contentNameRE.MatchString(n) {
		return "", contentFail(400, "invalid content store name %q (lowercase letters, digits, dashes)", n)
	}
	return n, nil
}

// contentPath: a file inside a store: relative, "/"-separated, no empty / "." / ".." segments, no control
// characters or backslashes; returned without leading/trailing slashes
func contentPath(raw string) (string, error) {
	p := strings.Trim(raw, "/")
	segs := strings.Split(p, "/")
	bad := p == "" || len(p) > 1024 || strings.ContainsAny(p, "\\")
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			bad = true
		}
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || len(s) > 255 {
			bad = true
		}
	}
	if bad {
		return "", contentFail(400, "invalid file path %q", p)
	}
	return p, nil
}

// contentPathOf: ?path= or Jarvis 1's x-content-path header
func contentPathOf(req *http.Request) (string, error) {
	raw := req.URL.Query().Get("path")
	if raw == "" {
		raw = req.Header.Get("X-Content-Path")
		if u, err := url.PathUnescape(raw); err == nil {
			raw = u
		}
	}
	return contentPath(raw)
}

type ContentFile struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

type ContentStore struct {
	Name  string `json:"name"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

// ---- WebDAV listing ------------------------------------------------------------------------------------

type davEntry struct {
	Href     string
	Name     string
	Dir      bool
	Size     int64
	Modified string
}

type davMultistatus struct {
	Responses []struct {
		Href string `xml:"href"`
		Prop []struct {
			Prop struct {
				Type struct {
					Collection *struct{} `xml:"collection"`
				} `xml:"resourcetype"`
				Length   string `xml:"getcontentlength"`
				Modified string `xml:"getlastmodified"`
			} `xml:"prop"`
		} `xml:"propstat"`
	} `xml:"response"`
}

// parseMultistatus: a Depth 1 PROPFIND body → its entries (namespace prefixes don't matter to encoding/xml)
func parseMultistatus(body []byte) ([]davEntry, error) {
	var ms davMultistatus
	if err := xml.Unmarshal(body, &ms); err != nil {
		return nil, err
	}
	out := []davEntry{}
	for _, r := range ms.Responses {
		href, err := url.PathUnescape(r.Href)
		if err != nil {
			href = r.Href
		}
		if u, err := url.Parse(href); err == nil && u.Host != "" {
			href = u.Path
		}
		e := davEntry{Href: href}
		for _, ps := range r.Prop {
			if ps.Prop.Type.Collection != nil {
				e.Dir = true
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(ps.Prop.Length), 10, 64); err == nil {
				e.Size = n
			}
			if t, err := http.ParseTime(strings.TrimSpace(ps.Prop.Modified)); err == nil {
				e.Modified = t.UTC().Format(time.RFC3339)
			}
		}
		e.Name = href[strings.LastIndex(strings.TrimSuffix(href, "/"), "/")+1:]
		e.Name = strings.TrimSuffix(e.Name, "/")
		out = append(out, e)
	}
	return out, nil
}

// children: the direct children of a directory (relative to the box root); nil, false when it doesn't exist
func (b *StorageBox) children(dir string) ([]davEntry, bool, error) {
	resp, err := b.do("PROPFIND", strings.TrimSuffix(dir, "/")+"/", nil, 0, map[string]string{"Depth": "1"})
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, false, nil
	}
	if resp.StatusCode != 207 && resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("PROPFIND %s: HTTP %d", dir, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, false, err
	}
	all, err := parseMultistatus(body)
	if err != nil {
		return nil, false, fmt.Errorf("PROPFIND %s: %v", dir, err)
	}
	self := "/" + strings.Trim(dir, "/") + "/"
	out := []davEntry{}
	for _, e := range all {
		if strings.TrimSuffix(e.Href, "/")+"/" == self || e.Name == "" {
			continue
		}
		out = append(out, e)
	}
	return out, true, nil
}

// ---- stores ---------------------------------------------------------------------------------------------

var contentCache = struct {
	sync.Mutex
	at     time.Time
	stores []ContentStore
}{}

func invalidateContent() {
	contentCache.Lock()
	contentCache.at = time.Time{}
	contentCache.Unlock()
}

func (r *Router) contentBox() (*StorageBox, error) {
	b := r.box()
	if b == nil {
		return nil, contentFail(503, "content stores need the router's Storage Box (STORAGEBOX_HOST/USER/PASSWORD)")
	}
	return b, nil
}

// contentFiles: every file of a store, sorted by path; nil, false when the store doesn't exist
func (r *Router) contentFiles(name string) ([]ContentFile, bool, error) {
	n, err := contentName(name)
	if err != nil {
		return nil, false, err
	}
	b, err := r.contentBox()
	if err != nil {
		return nil, false, err
	}
	base := contentRoot + "/" + n
	top, ok, err := b.children(base)
	if err != nil || !ok {
		return nil, ok, err
	}
	files := []ContentFile{}
	var walk func(rel string, entries []davEntry, depth int) error
	walk = func(rel string, entries []davEntry, depth int) error {
		for _, e := range entries {
			p := e.Name
			if rel != "" {
				p = rel + "/" + e.Name
			}
			if e.Dir {
				if depth > 32 {
					continue
				}
				kids, _, err := b.children(base + "/" + p)
				if err != nil {
					return err
				}
				if err := walk(p, kids, depth+1); err != nil {
					return err
				}
				continue
			}
			files = append(files, ContentFile{Path: p, Size: e.Size, Modified: e.Modified})
		}
		return nil
	}
	if err := walk("", top, 0); err != nil {
		return nil, true, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, true, nil
}

// ContentStores: every store with its file count and size (cached a minute; any write through here drops it)
func (r *Router) ContentStores(fresh bool) ([]ContentStore, error) {
	contentCache.Lock()
	if !fresh && time.Since(contentCache.at) < contentCacheOK {
		out := append([]ContentStore{}, contentCache.stores...)
		contentCache.Unlock()
		return out, nil
	}
	contentCache.Unlock()
	b, err := r.contentBox()
	if err != nil {
		return nil, err
	}
	top, _, err := b.children(contentRoot)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, e := range top {
		if e.Dir && contentNameRE.MatchString(e.Name) {
			names = append(names, e.Name)
		}
	}
	sort.Strings(names)
	out := make([]ContentStore, len(names))
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			files, _, err := r.contentFiles(n)
			out[i], errs[i] = ContentStore{Name: n, Files: len(files)}, err
			for _, f := range files {
				out[i].Bytes += f.Size
			}
		}(i, n)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return nil, e
		}
	}
	contentCache.Lock()
	contentCache.at, contentCache.stores = time.Now(), out
	contentCache.Unlock()
	return append([]ContentStore{}, out...), nil
}

// contentExists: whether the store's folder is there
func (r *Router) contentExists(name string) (bool, error) {
	n, err := contentName(name)
	if err != nil {
		return false, err
	}
	b, err := r.contentBox()
	if err != nil {
		return false, err
	}
	resp, err := b.do("PROPFIND", contentRoot+"/"+n+"/", nil, 0, map[string]string{"Depth": "0"})
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == 404:
		return false, nil
	case resp.StatusCode == 207 || resp.StatusCode < 300:
		return true, nil
	}
	return false, fmt.Errorf("PROPFIND %s: HTTP %d", n, resp.StatusCode)
}

// checkContentStores: the names cleaned, unique, sorted, each an existing store
func (r *Router) checkContentStores(in []string) ([]string, error) {
	set := map[string]bool{}
	for _, raw := range in {
		n, err := contentName(raw)
		if err != nil {
			return nil, err
		}
		set[n] = true
	}
	out := []string{}
	for n := range set {
		ok, err := r.contentExists(n)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, contentFail(400, "no content store %q", n)
		}
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (r *Router) createContentStore(name string) error {
	n, err := contentName(name)
	if err != nil {
		return err
	}
	ok, err := r.contentExists(n)
	if err != nil {
		return err
	}
	if ok { // already there: what was asked for holds
		return nil
	}
	b, _ := r.contentBox()
	defer invalidateContent()
	return b.Mkcols(contentRoot + "/" + n)
}

func (r *Router) deleteContentStore(name string) error {
	n, err := contentName(name)
	if err != nil {
		return err
	}
	ok, err := r.contentExists(n)
	if err != nil {
		return err
	}
	if !ok { // already gone: what was asked for holds
		return nil
	}
	b, _ := r.contentBox()
	defer invalidateContent()
	return b.Delete(contentRoot + "/" + n + "/")
}

// readContentFile: a file's bytes (at most contentMaxFile; the box gzips text, so identity is asked for)
func (r *Router) readContentFile(name, p string) ([]byte, error) {
	b, err := r.contentBox()
	if err != nil {
		return nil, err
	}
	resp, err := b.do("GET", contentRoot+"/"+name+"/"+p, nil, 0, map[string]string{"Accept-Encoding": "identity"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, contentFail(404, "no such file")
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s/%s: HTTP %d", name, p, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, contentMaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > contentMaxFile {
		return nil, contentFail(413, "file over %d MB", contentMaxFile>>20)
	}
	return data, nil
}

// writeContentFile: the file into an existing store, its parent folders made
func (r *Router) writeContentFile(name, p string, data []byte) (ContentFile, error) {
	if len(data) > contentMaxFile {
		return ContentFile{}, contentFail(413, "file too large (max %d MB)", contentMaxFile>>20)
	}
	ok, err := r.contentExists(name)
	if err != nil {
		return ContentFile{}, err
	}
	if !ok {
		return ContentFile{}, contentFail(404, "no content store %q", name)
	}
	b, _ := r.contentBox()
	if i := strings.LastIndex(p, "/"); i > 0 {
		if err := b.Mkcols(contentRoot + "/" + name + "/" + p[:i]); err != nil {
			return ContentFile{}, err
		}
	}
	defer invalidateContent()
	if err := b.PutBytes(contentRoot+"/"+name+"/"+p, data); err != nil {
		return ContentFile{}, err
	}
	return ContentFile{Path: p, Size: int64(len(data))}, nil
}

// deleteContentFile: the file, then any folders it leaves empty (up to the store's root)
func (r *Router) deleteContentFile(name, p string) error {
	b, err := r.contentBox()
	if err != nil {
		return err
	}
	full := contentRoot + "/" + name + "/" + p
	resp, err := b.do("DELETE", full, nil, 0, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	invalidateContent()
	if resp.StatusCode == 404 { // already gone: what was asked for holds
		return nil
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("DELETE %s/%s: HTTP %d", name, p, resp.StatusCode)
	}
	segs := strings.Split(p, "/")
	for segs = segs[:len(segs)-1]; len(segs) > 0; segs = segs[:len(segs)-1] {
		dir := contentRoot + "/" + name + "/" + strings.Join(segs, "/")
		kids, ok, err := b.children(dir)
		if err != nil || !ok || len(kids) > 0 {
			break
		}
		b.Delete(dir + "/")
	}
	return nil
}

// ---- a session's stores ------------------------------------------------------------------------------------

// certContent: the content stores the machine's current cert names (its signed config); a machine with no cert,
// or a cert naming none, has none
func (r *Router) certContent(machine string) []string {
	var cert *Doc
	r.st.Do(func(d *persisted) { cert = d.Certs[machine] })
	config, _ := certOptions(cert)
	if config == "" {
		return nil
	}
	var c struct {
		Content []string `json:"content"`
	}
	if json.Unmarshal([]byte(config), &c) != nil {
		return nil
	}
	return c.Content
}

func (r *Router) machineContentStore(machine, name string) (string, error) {
	for _, n := range r.certContent(machine) {
		if n == name {
			return n, nil
		}
	}
	return "", contentFail(403, "content store %q is not one this session was started with", name)
}

// attestContent: the core's input-log entry for a content file a machine is about to take
func (r *Router) attestContent(machine string, data []byte) (*Doc, error) {
	sum := sha256Hex(data)
	a, err := r.core.Call("/attest", map[string]string{"machine": machine, "input": "content", "origin": "router", "sha256": sum})
	if err != nil {
		return nil, err
	}
	r.logInputs(a)
	return a, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---- routes ---------------------------------------------------------------------------------------------

func (r *Router) registerContent(app appRoute, m machineRoute) {
	app("GET /api/content", func(w http.ResponseWriter, req *http.Request) {
		stores, err := r.ContentStores(req.URL.Query().Get("fresh") == "1")
		if err != nil {
			contentWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"stores": stores})
	})
	app("POST /api/content", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		if err := r.createContentStore(in.Name); err != nil {
			contentWriteErr(w, err)
			return
		}
		log.Printf("[content] store %s made", strings.TrimSpace(in.Name))
		writeJSON(w, 200, map[string]any{"ok": true, "name": strings.TrimSpace(in.Name)})
	})
	app("DELETE /api/content/{name}", func(w http.ResponseWriter, req *http.Request) {
		if err := r.deleteContentStore(req.PathValue("name")); err != nil {
			contentWriteErr(w, err)
			return
		}
		log.Printf("[content] store %s deleted", req.PathValue("name"))
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("GET /api/content/{name}/files", func(w http.ResponseWriter, req *http.Request) {
		files, ok, err := r.contentFiles(req.PathValue("name"))
		if err == nil && !ok {
			err = contentFail(404, "no content store %q", req.PathValue("name"))
		}
		if err != nil {
			contentWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"name": req.PathValue("name"), "files": files})
	})
	fileOp := func(w http.ResponseWriter, req *http.Request) (string, string, bool) {
		n, err := contentName(req.PathValue("name"))
		var p string
		if err == nil {
			p, err = contentPathOf(req)
		}
		if err != nil {
			contentWriteErr(w, err)
			return "", "", false
		}
		return n, p, true
	}
	app("GET /api/content/{name}/file", func(w http.ResponseWriter, req *http.Request) {
		n, p, ok := fileOp(w, req)
		if !ok {
			return
		}
		data, err := r.readContentFile(n, p)
		if err != nil {
			contentWriteErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(p[strings.LastIndex(p, "/")+1:]))
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})
	app("POST /api/content/{name}/file", func(w http.ResponseWriter, req *http.Request) {
		n, p, ok := fileOp(w, req)
		if !ok {
			return
		}
		data, err := io.ReadAll(io.LimitReader(req.Body, contentMaxFile+1))
		if err == nil {
			var f ContentFile
			if f, err = r.writeContentFile(n, p, data); err == nil {
				writeJSON(w, 200, f)
				return
			}
		}
		contentWriteErr(w, err)
	})
	app("DELETE /api/content/{name}/file", func(w http.ResponseWriter, req *http.Request) {
		n, p, ok := fileOp(w, req)
		if !ok {
			return
		}
		if err := r.deleteContentFile(n, p); err != nil {
			contentWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})

	// ---- the session (through its machine's local proxy: Jarvis 1's content-sync, a task's script) ----------
	own := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte)) {
		m(pattern, func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if id := req.PathValue("id"); id != sid && id != machine {
				writeJSON(w, 403, map[string]string{"error": fmt.Sprintf("this machine is session %s, not %s", sid, id)})
				return
			}
			fn(w, req, machine, body)
		})
	}
	own("GET /m/api/sessions/{id}/content", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		stores := map[string][]ContentFile{}
		for _, n := range r.certContent(machine) {
			files, _, err := r.contentFiles(n)
			if err != nil {
				contentWriteErr(w, err)
				return
			}
			if files == nil {
				files = []ContentFile{} // a store deleted since the line began: empty
			}
			stores[n] = files
		}
		writeJSON(w, 200, map[string]any{"ok": true, "stores": stores})
	})
	mFile := func(w http.ResponseWriter, req *http.Request, machine string) (string, string, bool) {
		n, err := r.machineContentStore(machine, req.PathValue("name"))
		var p string
		if err == nil {
			p, err = contentPathOf(req)
		}
		if err != nil {
			contentWriteErr(w, err)
			return "", "", false
		}
		return n, p, true
	}
	own("GET /m/api/sessions/{id}/content/{name}/file", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		n, p, ok := mFile(w, req, machine)
		if !ok {
			return
		}
		data, err := r.readContentFile(n, p)
		if err != nil {
			contentWriteErr(w, err)
			return
		}
		a, err := r.attestContent(machine, data)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "the core's attestation: " + err.Error()})
			return
		}
		aj, _ := json.Marshal(a)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Jarvis2-Attest", string(aj))
		w.Write(data)
	})
	own("PUT /m/api/sessions/{id}/content/{name}/file", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		n, p, ok := mFile(w, req, machine)
		if !ok {
			return
		}
		f, err := r.writeContentFile(n, p, body)
		if err != nil {
			contentWriteErr(w, err)
			return
		}
		writeJSON(w, 200, f)
	})
	own("DELETE /m/api/sessions/{id}/content/{name}/file", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		n, p, ok := mFile(w, req, machine)
		if !ok {
			return
		}
		if err := r.deleteContentFile(n, p); err != nil {
			contentWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}

func orEmptyS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
