package main

// The session-facing API, machine side. Jarvis 1's session scripts (schedule-wakeup.sh, schedule-cron.sh, lease.py,
// transcript-search.py, pull-secrets, content-sync, retire-session.sh, jarvis2-request, …) call `$JARVIS_URL/api/...`
// with Cloudflare Access headers and the session's SESSION_API_TOKEN. In a Jarvis 2 session JARVIS_URL is this proxy
// (127.0.0.1:7171, served by the guard): it drops those headers and forwards each request to the router as
// /m/api/<rest>, signed with the machine key like every other /m call (docs/API-grants.md "/m/api").
//
// Kept on the machine:
//   - GET …/secrets: the session's stores, pulled fresh with the grant the guard holds;
//   - GET …/changes: the repos' uncommitted/unpushed work;
//   - the session's own texts: arming a wakeup, cron or watch, or taking a lease, keeps the prompt (and a watch's
//     give-up prompt, a lease's note) in the guard's records and sends the router the request without it, with the id
//     the guard gave it ("id"); an Inbox filing is kept by a filing id (header X-Jarvis2-Filing), so its outcome's
//     text is built from what the session asked, not from what the router says it asked;
//   - a content file is taken only with the log notary's challenge over exactly its bytes (header X-Jarvis2-Challenge).

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DE0CH/jarvis2/core/kernel"
)

const (
	apiProxyAddr = "127.0.0.1:7171"
	apiMaxBody   = 64 << 20
	aboutContent = "content"
)

// serveAPIProxy: runs for the guard's life
func serveAPIProxy(g *guard) {
	addr := os.Getenv("JARVIS2_API_ADDR")
	if addr == "" {
		addr = apiProxyAddr
	}
	srv := &http.Server{Addr: addr, Handler: apiProxyHandler(g), ReadHeaderTimeout: 30 * time.Second}
	log.Printf("session API on http://%s (→ router /m/api)", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("session API stopped: %v", err)
	}
}

func apiProxyHandler(g *guard) http.Handler {
	c := g.c
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sessions/{id}/secrets", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, g, req.PathValue("id")) {
			return
		}
		a, err := g.pullAndApply(false)
		if err != nil {
			writeJSONResp(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSONResp(w, 200, map[string]any{"ok": true, "environment": strings.Join(a.Stores, ","), "locked": a.Locked, "secrets": g.secrets()})
	})
	mux.HandleFunc("GET /api/sessions/{id}/changes", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, g, req.PathValue("id")) {
			return
		}
		home, _ := os.UserHomeDir()
		writeJSONResp(w, 200, map[string]any{"checked": true, "repos": repoChanges(filepath.Join(home, "workspace")), "status": ""})
	})
	mux.HandleFunc("GET /api/sessions/{id}/content/{name}/file", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, g, req.PathValue("id")) {
			return
		}
		status, hdr, body, err := forwardToRouter(c, req, nil, nil)
		if err != nil {
			writeJSONResp(w, 502, map[string]string{"error": "Jarvis 2 router unreachable: " + err.Error()})
			return
		}
		if status == 200 {
			if err := g.checkContent(hdr.Get("X-Jarvis2-Challenge"), body); err != nil {
				log.Printf("content: refused %s: %v", req.URL.Query().Get("path"), err)
				writeJSONResp(w, 502, map[string]string{"error": "content file refused: " + err.Error()})
				return
			}
		}
		copyResp(w, status, hdr, body)
	})
	for _, p := range []string{"POST /api/sessions/{id}/wakeup", "POST /api/sessions/{id}/wakeups", "POST /api/sessions/{id}/crons",
		"POST /api/sessions/{id}/watches", "POST /api/sessions/{id}/leases/{device}"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) {
			if !ownSession(w, g, req.PathValue("id")) {
				return
			}
			body, err := io.ReadAll(io.LimitReader(req.Body, apiMaxBody))
			if err != nil {
				writeJSONResp(w, 400, map[string]string{"error": err.Error()})
				return
			}
			status, hdr, out, err := g.arm(req.URL.Path, req.PathValue("device"), body)
			if err != nil {
				writeJSONResp(w, status, map[string]string{"error": err.Error()})
				return
			}
			copyResp(w, status, hdr, out)
		})
	}
	for _, p := range []string{"POST /api/requests/", "POST /api/actions/requests/", "POST /api/sessions"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) { g.file(w, req) })
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, req *http.Request) {
		status, hdr, body, err := forwardToRouter(c, req, nil, nil)
		if err != nil {
			writeJSONResp(w, 502, map[string]string{"error": "Jarvis 2 router unreachable: " + err.Error()})
			return
		}
		copyResp(w, status, hdr, body)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		writeJSONResp(w, 404, map[string]string{"error": "only /api/… is served here"})
	})
	return mux
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func copyResp(w http.ResponseWriter, status int, hdr http.Header, body []byte) {
	for _, h := range []string{"Content-Type", "Content-Range", "Content-Disposition"} {
		if v := hdr.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(status)
	w.Write(body)
}

// ownSession: Jarvis 1's scripts name the session by SESSION_ID (the settings' session) or FLY_MACHINE_ID
func ownSession(w http.ResponseWriter, g *guard, id string) bool {
	if id == g.st.Session || id == g.c.me {
		return true
	}
	writeJSONResp(w, 403, map[string]string{"error": "this is session " + g.st.Session + ", not " + id})
	return false
}

// forwardToRouter: the request as /m/api/<rest>; the signature covers the decoded path, as the router checks it.
// body: instead of the request's own (nil: read it); hdr: extra headers.
func forwardToRouter(c *client, req *http.Request, body []byte, hdr map[string]string) (int, http.Header, []byte, error) {
	if body == nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, apiMaxBody+1))
		if err != nil {
			return 0, nil, nil, err
		}
		if len(b) > apiMaxBody {
			return 0, nil, nil, errors.New("request body too large")
		}
		body = b
	}
	h := map[string]string{"Content-Type": req.Header.Get("Content-Type")}
	for k, v := range hdr {
		h[k] = v
	}
	return c.signedDo(req.Method, "/m"+req.URL.Path, "/m"+req.URL.EscapedPath(), req.URL.RawQuery, body, h)
}

// checkContent: the log notary's challenge over the content file's bytes (about "content")
func (g *guard) checkContent(header string, body []byte) error {
	var d kernel.SignedDoc
	if header == "" || json.Unmarshal([]byte(header), &d) != nil {
		return errors.New("no log-notary challenge over the file")
	}
	sum := sha256.Sum256(body)
	return g.checkChallenge(d, hex.EncodeToString(sum[:]), aboutContent)
}

// ---- the session's own texts ---------------------------------------------------------------------------------

func newTextID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var watchNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// arm: a wakeup, cron, watch or lease the session asks for (path /api/sessions/<id>/…): its text into the records,
// the request without it to the router (as /m/api/…, with "id"). A refusal by the router takes the record back.
func (g *guard) arm(path, device string, body []byte) (int, http.Header, []byte, error) {
	var in map[string]any
	if err := json.Unmarshal(body, &in); err != nil || in == nil {
		return 400, nil, nil, errors.New("the body is a JSON object")
	}
	str := func(k string) string { s, _ := in[k].(string); return s }
	id := newTextID()
	var undo func(*recordsData)
	var rec func(*recordsData) error
	switch {
	case strings.HasSuffix(path, "/wakeup") || strings.HasSuffix(path, "/wakeups"):
		prompt := oneLine(str("prompt"))
		if prompt == "" {
			return 400, nil, nil, errors.New("a wakeup needs a prompt")
		}
		name := strings.TrimSpace(fmt.Sprint(in["name"]))
		if in["name"] == nil || name == "" {
			name = "default"
		}
		rec = func(r *recordsData) error {
			for k, x := range r.Wakeups { // the router replaces a wakeup of the same name
				if x.Name == name && x.Delivered == "" {
					delete(r.Wakeups, k)
				}
			}
			r.Wakeups[id] = wakeupText{Name: name, Prompt: prompt}
			return nil
		}
		undo = func(r *recordsData) { delete(r.Wakeups, id) }
		delete(in, "prompt")
	case strings.HasSuffix(path, "/crons"):
		prompt := oneLine(str("prompt"))
		every, _ := in["everySeconds"].(float64)
		if prompt == "" || every <= 0 {
			return 400, nil, nil, errors.New("a cron needs a prompt and everySeconds")
		}
		name := strings.TrimSpace(fmt.Sprint(in["name"]))
		if in["name"] == nil || name == "" {
			name = "default"
		}
		until, _ := in["until"].(float64)
		rec = func(r *recordsData) error {
			r.Crons[id] = cronText{Name: name, Prompt: prompt, EverySeconds: int64(every), Until: int64(until)}
			return nil
		}
		undo = func(r *recordsData) { delete(r.Crons, id) }
		delete(in, "prompt")
	case strings.HasSuffix(path, "/watches"):
		name := strings.TrimSpace(str("name"))
		prompt := oneLine(str("prompt"))
		if !watchNameRE.MatchString(name) || prompt == "" || str("script") == "" {
			return 400, nil, nil, errors.New("a watch needs a name, a script and a prompt")
		}
		rec = func(r *recordsData) error {
			r.Watches[id] = watchText{Name: name, Script: str("script"), Prompt: prompt, FailPrompt: oneLine(str("failPrompt"))}
			return nil
		}
		undo = func(r *recordsData) { delete(r.Watches, id) }
		delete(in, "prompt")
		delete(in, "failPrompt")
	case device != "":
		if !leaseNameRE.MatchString(device) {
			return 400, nil, nil, errors.New("not a device name")
		}
		var old string
		var had bool
		note := str("prompt")
		rec = func(r *recordsData) error {
			old, had = r.Leases[device]
			r.Leases[device] = note
			return nil
		}
		undo = func(r *recordsData) {
			if had {
				r.Leases[device] = old
			} else {
				delete(r.Leases, device)
			}
		}
		delete(in, "prompt")
	default:
		return 404, nil, nil, errors.New("not something the session arms")
	}
	in["id"] = id
	if err := g.rec.update(rec); err != nil {
		return 500, nil, nil, err
	}
	fwd, _ := json.Marshal(in)
	escaped := (&url.URL{Path: path}).EscapedPath()
	status, hdr, out, err := g.c.signedDo("POST", "/m"+path, "/m"+escaped, "", fwd, map[string]string{"Content-Type": "application/json"})
	if err != nil || status/100 != 2 {
		g.rec.update(func(r *recordsData) error { undo(r); return nil })
		if err != nil {
			return 502, nil, nil, fmt.Errorf("Jarvis 2 router unreachable: %v", err)
		}
	}
	return status, hdr, out, nil
}

// file: an Inbox filing (jarvis2-request): kept by a filing id, forwarded with it
func (g *guard) file(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, apiMaxBody))
	if err != nil {
		writeJSONResp(w, 400, map[string]string{"error": err.Error()})
		return
	}
	id := newTextID()
	raw := json.RawMessage("null")
	if json.Valid(body) {
		raw = append(json.RawMessage(nil), body...)
	}
	g.rec.update(func(r *recordsData) error {
		r.Filings[id] = filing{Path: req.URL.Path, Body: raw}
		return nil
	})
	status, hdr, out, err := forwardToRouter(g.c, req, body, map[string]string{"X-Jarvis2-Filing": id})
	if err != nil || status/100 != 2 {
		g.rec.update(func(r *recordsData) error { delete(r.Filings, id); return nil })
	}
	if err != nil {
		writeJSONResp(w, 502, map[string]string{"error": "Jarvis 2 router unreachable: " + err.Error()})
		return
	}
	copyResp(w, status, hdr, out)
}

// signedDo: like client.raw, with a query string (unsigned: the router signs the path only), an escaped path and
// extra headers
func (c *client) signedDo(method, path, escaped, query string, body []byte, hdr map[string]string) (int, http.Header, []byte, error) {
	t := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(body)
	sig, err := sign(c.sig, []byte(method+" "+path+" "+t+" "+hex.EncodeToString(sum[:])))
	if err != nil {
		return 0, nil, nil, err
	}
	u := c.base + escaped
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("X-Machine", c.me)
	req.Header.Set("X-Time", t)
	req.Header.Set("X-Sig", sig)
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b, err
}

// ---- changes (Jarvis 1's GET /api/sessions/:id/changes) ------------------------------------------------------

type repoChange struct {
	Name        string `json:"name"`
	Uncommitted int    `json:"uncommitted"`
	Unpushed    int    `json:"unpushed"` // -1: the branch has no upstream
}

func repoChanges(workspace string) []repoChange {
	out := []repoChange{}
	dirs, _ := filepath.Glob(filepath.Join(workspace, "*", ".git"))
	sort.Strings(dirs)
	for _, gd := range dirs {
		d := filepath.Dir(gd)
		rc := repoChange{Name: filepath.Base(d)}
		if b, err := exec.Command("git", "-C", d, "status", "--porcelain").Output(); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(l) != "" {
					rc.Uncommitted++
				}
			}
		}
		if exec.Command("git", "-C", d, "rev-parse", "--abbrev-ref", "@{u}").Run() != nil {
			rc.Unpushed = -1
		} else if b, err := exec.Command("git", "-C", d, "rev-list", "@{u}..HEAD", "--count").Output(); err == nil {
			rc.Unpushed, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		out = append(out, rc)
	}
	return out
}
