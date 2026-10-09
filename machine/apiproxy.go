package main

// The session-facing API, machine side. Jarvis 1's session scripts (schedule-wakeup.sh, schedule-cron.sh,
// lease.py, transcript-search.py, pull-secrets, content-sync, retire-session.sh, …) call `$JARVIS_URL/api/...`
// with Cloudflare Access headers and the session's SESSION_API_TOKEN. In a Jarvis 2 session JARVIS_URL is this
// proxy (127.0.0.1:7171, served by `jarvis2-machine agent`): it drops those headers and forwards each request to
// the router as /m/api/<rest>, signed with the machine key like every other /m call.
//
// Two calls never leave the machine: GET …/secrets (the session's stores, pulled fresh through the core-signed
// /m/pull-secrets and answered in Jarvis 1's shape) and GET …/changes (the repos' uncommitted/unpushed work).
//
// Arming a wakeup or a cron is the session approving the scheduler for itself: after the router accepts it, the
// proxy puts the scheduler holder on this session's allow list until the wakeup is due + 1 h (a cron: a month or
// two periods, renewed at each firing by `jarvis2-machine allow-at-least`). A session holding a sensitive store
// ignores its allow list; its wakeups then need a phone grant.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	apiProxyAddr = "127.0.0.1:7171"
	apiMaxBody   = 64 << 20
	wakeupAllow  = time.Hour // beyond the due time
	cronAllowMin = 31 * 24 * time.Hour
)

// serveAPIProxy: runs for the agent's life
func serveAPIProxy(c *client) {
	addr := os.Getenv("JARVIS2_API_ADDR")
	if addr == "" {
		addr = apiProxyAddr
	}
	srv := &http.Server{Addr: addr, Handler: apiProxyHandler(c), ReadHeaderTimeout: 30 * time.Second}
	log.Printf("session API on http://%s (→ router /m/api)", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("session API stopped: %v", err)
	}
}

func apiProxyHandler(c *client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sessions/{id}/secrets", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, c, req.PathValue("id")) {
			return
		}
		localSecrets(w, c)
	})
	mux.HandleFunc("GET /api/sessions/{id}/changes", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, c, req.PathValue("id")) {
			return
		}
		home, _ := os.UserHomeDir()
		writeJSONResp(w, 200, map[string]any{"checked": true, "repos": repoChanges(filepath.Join(home, "workspace")), "status": ""})
	})
	for _, p := range []string{"POST /api/sessions/{id}/wakeup", "POST /api/sessions/{id}/wakeups", "POST /api/sessions/{id}/crons"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) { armAndAllow(w, req, c) })
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, req *http.Request) {
		status, hdr, body, err := forwardToRouter(c, req)
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

// ownSession: Jarvis 1's scripts name the session by SESSION_ID (the router's id) or FLY_MACHINE_ID
func ownSession(w http.ResponseWriter, c *client, id string) bool {
	if id == sessionID(c.me) || id == c.me {
		return true
	}
	writeJSONResp(w, 403, map[string]string{"error": "this is session " + sessionID(c.me) + ", not " + id})
	return false
}

// forwardToRouter: the request as /m/api/<rest>; the signature covers the decoded path, as the router checks it
func forwardToRouter(c *client, req *http.Request) (int, http.Header, []byte, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, apiMaxBody+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(body) > apiMaxBody {
		return 0, nil, nil, errors.New("request body too large")
	}
	return c.signedDo(req.Method, "/m"+req.URL.Path, "/m"+req.URL.EscapedPath(), req.URL.RawQuery, body, req.Header.Get("Content-Type"))
}

// signedDo: like client.raw, with a query string (unsigned: the router signs the path only) and an escaped path
func (c *client) signedDo(method, path, escaped, query string, body []byte, contentType string) (int, http.Header, []byte, error) {
	if k, err := loadPrivate(); err == nil {
		c.sig = k.sig
	}
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
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b, err
}

// ---- pull-secrets (Jarvis 1's GET /api/sessions/:id/secrets) ----------------------------------------------

func localSecrets(w http.ResponseWriter, c *client) {
	cert, err := currentCert()
	if err != nil {
		writeJSONResp(w, 409, map[string]string{"error": "no valid cert: " + err.Error()})
		return
	}
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		writeJSONResp(w, 409, map[string]string{"error": err.Error()})
		return
	}
	var doc SignedDoc
	if err := c.json("POST", "/m/pull-secrets", map[string]string{}, &doc); err != nil {
		// never the answer's body: only the error the router or core gave
		writeJSONResp(w, 502, map[string]string{"error": "pull secrets: " + err.Error()})
		return
	}
	secrets, err := openSecretsDoc(coreKey, c.me, &doc)
	if err != nil {
		writeJSONResp(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSONResp(w, 200, map[string]any{"ok": true, "environment": strings.Join(cert.Stores, ","), "secrets": secrets})
}

// openSecretsDoc: the core-signed secrets answer, opened with this machine's key (as pullSecrets, one attempt)
func openSecretsDoc(coreKey, me string, doc *SignedDoc) (map[string]string, error) {
	var out struct {
		Kind    string `json:"kind"`
		Machine string `json:"machine"`
		Sealed  struct {
			E    string `json:"e"`
			Data string `json:"data"`
		} `json:"sealed"`
	}
	if err := verifyDoc(coreKey, doc, &out); err != nil || out.Kind != "secrets" || out.Machine != me {
		return nil, fmt.Errorf("the secrets answer isn't core-signed for this machine (%v)", err)
	}
	priv, err := loadPrivate()
	if err != nil {
		return nil, err
	}
	plain, err := openSealed(priv.enc, out.Sealed.E, out.Sealed.Data, "jarvis2/secrets")
	if err != nil {
		return nil, fmt.Errorf("the secrets don't decrypt with this machine's key: %w", err)
	}
	m := map[string]string{}
	return m, json.Unmarshal(plain, &m)
}

// ---- changes (Jarvis 1's GET /api/sessions/:id/changes, archive.REPO_CHANGES_SH) ---------------------------

type repoChange struct {
	Name        string `json:"name"`
	Uncommitted int    `json:"uncommitted"`
	Unpushed    int    `json:"unpushed"` // -1: the branch has no upstream
}

func repoChanges(workspace string) []repoChange {
	out := []repoChange{}
	dirs, _ := filepath.Glob(filepath.Join(workspace, "*", ".git"))
	for _, g := range dirs {
		d := filepath.Dir(g)
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

// ---- arming = approving the scheduler ----------------------------------------------------------------------

func armAndAllow(w http.ResponseWriter, req *http.Request, c *client) {
	status, hdr, body, err := forwardToRouter(c, req)
	if err != nil {
		writeJSONResp(w, 502, map[string]string{"error": "Jarvis 2 router unreachable: " + err.Error()})
		return
	}
	var ans map[string]any
	if status != 200 || json.Unmarshal(body, &ans) != nil || ans["ok"] != true {
		copyResp(w, status, hdr, body)
		return
	}
	until, ok := allowUntil(ans, time.Now())
	if ok {
		if err := extendAllow(c, "scheduler", until); err != nil {
			ans["schedulerError"] = "armed, but the scheduler couldn't be put on this session's allow list: " + err.Error()
		} else {
			ans["scheduler"] = "allowed until " + until.UTC().Format(time.RFC3339)
		}
	}
	if cert, err := currentCert(); err == nil && cert.Sensitive {
		ans["note"] = "this session holds a sensitive store: the scheduler gets in only under a phone grant; when it is due and can't, Deyao gets a DM"
	}
	writeJSONResp(w, 200, ans)
}

// allowUntil: from the router's answer — a wakeup: due + 1 h; a cron: the longer of its first firing + 1 h and
// now + max(a month, two periods + 1 h)
func allowUntil(ans map[string]any, now time.Time) (time.Time, bool) {
	ms := func(v any) (time.Time, bool) {
		f, ok := v.(float64)
		return time.UnixMilli(int64(f)), ok
	}
	if wu, ok := ans["wakeup"].(map[string]any); ok {
		at, ok := ms(wu["at"])
		return at.Add(wakeupAllow), ok
	}
	if cr, ok := ans["cron"].(map[string]any); ok {
		next, ok := ms(cr["nextAt"])
		every, _ := cr["everySeconds"].(float64)
		u := now.Add(cronAllowFor(int64(every)))
		if n := next.Add(time.Hour); n.After(u) {
			u = n
		}
		return u, ok
	}
	return time.Time{}, false
}

func cronAllowFor(every int64) time.Duration {
	return max(cronAllowMin, 2*time.Duration(every)*time.Second+time.Hour)
}

// extendAllow: the holder stays on the allow list at least until `until`; a later end already there is kept
func extendAllow(c *client, name string, until time.Time) error {
	var holders map[string]string
	if err := c.json("GET", "/m/holders", nil, &holders); err != nil {
		return err
	}
	key := holders[name]
	if key == "" {
		return fmt.Errorf("the router names no holder %q", name)
	}
	home, _ := os.UserHomeDir()
	lock, err := os.OpenFile(filepath.Join(home, ".jarvis2-allow.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	out := []allowEntry{}
	for _, a := range readAllow() {
		if a.Name != name {
			out = append(out, a)
			continue
		}
		if u, err := time.Parse(time.RFC3339, a.Until); err == nil && u.After(until) && a.Holder == key {
			until = u
		}
	}
	out = append(out, allowEntry{Holder: key, Name: name, Until: until.UTC().Format(time.RFC3339)})
	b, _ := json.MarshalIndent(out, "", " ")
	tmp := filepath.Join(home, allowFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(home, allowFile))
}

// allowAtLeastCmd: `jarvis2-machine allow-at-least <holder> <duration>` — like allow, but never shortens an
// existing entry (what a cron's firing runs to renew the session's approval)
func allowAtLeastCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: jarvis2-machine allow-at-least <holder> <duration>")
	}
	d, err := time.ParseDuration(args[1])
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	return extendAllow(c, args[0], time.Now().Add(d))
}
