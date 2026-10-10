package main

// Deyao's repo list and the GitHub picker (Jarvis 1's /api/repos, /api/github/repos), and the Claude usage
// quota (Jarvis 1's /api/usage, forwarded).
//
// Every repo on the list is a GitHub repo with its own deploy key (Deyao, 2026-10-10): adding one in the app's
// Settings asks the core for a deploy key (docs/DESIGN.md "Deploy keys"), which the phone approves with Face ID;
// the core makes the key pair, adds the public half to the repo on GitHub and keeps the private half in the
// store github-<repo>. Removing one deletes both, the same way. The router only relays: it holds no GitHub
// token that can push or manage keys (the picker lists repos with GITHUB_READ_TOKEN, metadata read only), and
// it records an entry only from the core's answer. Sessions clone, pull and push a repo over SSH with its
// store's key (machine/deploykeys.go); the picker only fills New session's `repos`.
// The repo list is the router's own (DATA_DIR/repos.json), shown in /api/state `repos`.
// Usage needs the Claude login, which lives in Jarvis 1: forwarded with the services token.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// RepoEntry: a repo on the list. Repo, URL and Store follow from the GitHub name; Sensitive, Fingerprint and
// KeyAt come from the core's answer when its deploy key was made.
type RepoEntry struct {
	Name        string `json:"name"`  // the clone's directory in ~/workspace
	URL         string `json:"url"`   // https://github.com/<owner>/<name>.git
	Repo        string `json:"repo"`  // <owner>/<name>
	Store       string `json:"store"` // the store holding its deploy key
	Sensitive   bool   `json:"sensitive"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyAt       string `json:"keyAt,omitempty"`
}

var githubRepoRE = regexp.MustCompile(`^(?:https://github\.com/|git@github\.com:)?([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$`)

// parseGitHubRepo: "owner/name" from a GitHub URL or name ("" when it isn't one)
func parseGitHubRepo(s string) string {
	m := githubRepoRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || m[2] == "." || m[2] == ".." || strings.Contains(m[2], "..") {
		return ""
	}
	return m[1] + "/" + m[2]
}

// repoStore: the core's RepoStore (core/deploykeys.go) — github-<name> for DE0CH's repos, else
// github-<owner>-<name>, lower case, anything outside [a-z0-9-] as "-"
func repoStore(repo string) string {
	owner, name, _ := strings.Cut(strings.ToLower(repo), "/")
	slug := name
	if owner != "de0ch" {
		slug = owner + "-" + name
	}
	b := []byte(slug)
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			b[i] = '-'
		}
	}
	return "github-" + strings.Trim(string(b), "-")
}

func repoEntry(repo string) RepoEntry {
	_, name, _ := strings.Cut(repo, "/")
	return RepoEntry{Name: name, URL: "https://github.com/" + repo + ".git", Repo: repo, Store: repoStore(repo)}
}

func (r *Router) reposPath() string { return filepath.Join(r.cfg.DataDir, "repos.json") }

func (r *Router) Repos() []RepoEntry {
	r.ops.reposMu.Lock()
	defer r.ops.reposMu.Unlock()
	return r.readRepos()
}

// readRepos: the list; every entry is a GitHub repo, its derived fields recomputed from its URL
func (r *Router) readRepos() []RepoEntry {
	var raw []RepoEntry
	if b, err := os.ReadFile(r.reposPath()); err == nil {
		json.Unmarshal(b, &raw)
	}
	out := []RepoEntry{}
	for _, e := range raw {
		repo := parseGitHubRepo(e.URL)
		if repo == "" {
			log.Printf("repos: %q isn't a GitHub repo: left off the list", e.URL)
			continue
		}
		n := repoEntry(repo)
		n.Sensitive, n.Fingerprint, n.KeyAt = e.Sensitive, e.Fingerprint, e.KeyAt
		out = append(out, n)
	}
	return out
}

// updateRepos: read-modify-write under the lock (two adds at once used to drop one in Jarvis 1)
func (r *Router) updateRepos(fn func([]RepoEntry) []RepoEntry) error {
	r.ops.reposMu.Lock()
	defer r.ops.reposMu.Unlock()
	next := fn(r.readRepos())
	b, _ := json.MarshalIndent(next, "", " ")
	tmp := r.reposPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.reposPath())
}

// keyAnswer: the core's answer to a finished deploy-key request, applied to the list
type keyAnswer struct {
	Kind        string `json:"kind"` // deploy-key-added | deploy-key-removed
	Repo        string `json:"repo"`
	Sensitive   bool   `json:"sensitive"`
	Fingerprint string `json:"fingerprint"`
}

func (r *Router) applyKeyAnswer(a keyAnswer) error {
	repo := parseGitHubRepo(a.Repo)
	if repo == "" {
		return fmt.Errorf("the core's answer names no GitHub repo")
	}
	same := func(e RepoEntry) bool { return strings.EqualFold(e.Repo, repo) }
	return r.updateRepos(func(rs []RepoEntry) []RepoEntry {
		out := []RepoEntry{}
		for _, e := range rs {
			if !same(e) {
				out = append(out, e)
			}
		}
		if a.Kind == "deploy-key-added" {
			e := repoEntry(repo)
			e.Sensitive, e.Fingerprint, e.KeyAt = a.Sensitive, a.Fingerprint, time.Now().UTC().Format(time.RFC3339)
			out = append(out, e)
		}
		return out
	})
}

func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		if r != nil {
			out["repos"] = r.Repos()
		}
	})
}

// ---- deploy keys: the core's two calls, relayed; the list follows the core's signed answer ----------------

func (r *Router) registerDeployKeys(app appRoute) {
	app("POST /api/repos/key/begin", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Action    string `json:"action"`
			Repo      string `json:"repo"`
			Sensitive bool   `json:"sensitive"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		repo := parseGitHubRepo(in.Repo)
		if repo == "" || (in.Action != "add" && in.Action != "remove") {
			writeJSON(w, 400, map[string]string{"error": "a GitHub repo (owner/name or its URL) and action add or remove"})
			return
		}
		b, _ := json.Marshal(map[string]any{"action": in.Action, "repo": repo, "sensitive": in.Sensitive})
		r.relayDeployKey(w, "/deploy-keys/begin", b, false)
	})
	app("POST /api/repos/key/finish", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		r.relayDeployKey(w, "/deploy-keys/finish", b, true)
	})
}

// relayDeployKey: the core's answer unchanged; a finished add or remove also updates the list. A core from
// before deploy keys answers its mux's plain-text 404: say so plainly.
func (r *Router) relayDeployKey(w http.ResponseWriter, path string, body []byte, finish bool) {
	status, b, err := r.core.Raw("POST", path, body)
	if err != nil {
		log.Printf("core %s: %v", path, err)
		writeJSON(w, 503, map[string]any{"error": "the core isn't running", "coreDown": true})
		return
	}
	var d Doc
	if status == 404 && json.Unmarshal(b, &d) != nil {
		writeJSON(w, 501, map[string]string{"error": "the running core predates deploy keys: it makes them once it has been restarted with the new core image (then Recover)"})
		return
	}
	if finish && status == 200 && json.Unmarshal(b, &d) == nil {
		var a keyAnswer
		if d.Decode(&a) == nil && (a.Kind == "deploy-key-added" || a.Kind == "deploy-key-removed") {
			if err := r.applyKeyAnswer(a); err != nil {
				log.Printf("repos: %v", err)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

// ---- the GitHub picker -------------------------------------------------------------------------------------

type ghRepo struct {
	FullName    string `json:"fullName"`
	URL         string `json:"url"`
	HTMLURL     string `json:"htmlUrl"`
	Private     bool   `json:"private"`
	Fork        bool   `json:"fork"`
	Archived    bool   `json:"archived"`
	Description string `json:"description"`
	Language    string `json:"language"`
	PushedAt    string `json:"pushedAt"`
	Owner       string `json:"owner"`
}

type ghCache struct {
	at    time.Time
	repos []ghRepo
}

var githubAPI = "https://api.github.com"
var githubClient = &http.Client{Timeout: 20 * time.Second}

const ghTTL = 5 * time.Minute

// GitHubRepos: every repo the read token sees, newest push first; cached 5 minutes. The token never leaves.
func (r *Router) GitHubRepos(refresh bool) ([]ghRepo, time.Time, error) {
	tok := os.Getenv("GITHUB_READ_TOKEN")
	if tok == "" {
		return nil, time.Time{}, &httpStatusErr{503, "the router has no GITHUB_READ_TOKEN: it can't list your GitHub repos"}
	}
	r.ops.mu.Lock()
	c := r.ops.gh
	r.ops.mu.Unlock()
	if !refresh && c.repos != nil && time.Since(c.at) < ghTTL {
		return c.repos, c.at, nil
	}
	out := []ghRepo{}
	for page := 1; page <= 10; page++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/user/repos?per_page=100&page=%d&sort=pushed&direction=desc&affiliation=owner,collaborator,organization_member", githubAPI, page), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "jarvis2-router/1")
		resp, err := githubClient.Do(req)
		if err != nil {
			return nil, time.Time{}, &httpStatusErr{502, "GitHub unreachable: " + err.Error()}
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, time.Time{}, &httpStatusErr{502, fmt.Sprintf("GitHub /user/repos: HTTP %d %s", resp.StatusCode, clip(string(b), 200))}
		}
		var items []struct {
			FullName    string `json:"full_name"`
			CloneURL    string `json:"clone_url"`
			HTMLURL     string `json:"html_url"`
			Private     bool   `json:"private"`
			Fork        bool   `json:"fork"`
			Archived    bool   `json:"archived"`
			Description string `json:"description"`
			Language    string `json:"language"`
			PushedAt    string `json:"pushed_at"`
			UpdatedAt   string `json:"updated_at"`
			Owner       struct {
				Login string `json:"login"`
			} `json:"owner"`
		}
		if err := json.Unmarshal(b, &items); err != nil {
			return nil, time.Time{}, &httpStatusErr{502, "GitHub /user/repos: " + err.Error()}
		}
		for _, it := range items {
			u := it.CloneURL
			if u == "" {
				u = "https://github.com/" + it.FullName + ".git"
			}
			p := it.PushedAt
			if p == "" {
				p = it.UpdatedAt
			}
			out = append(out, ghRepo{it.FullName, u, it.HTMLURL, it.Private, it.Fork, it.Archived, it.Description, it.Language, p, it.Owner.Login})
		}
		if len(items) < 100 {
			break
		}
	}
	now := time.Now()
	r.ops.mu.Lock()
	r.ops.gh = ghCache{now, out}
	r.ops.mu.Unlock()
	return out, now, nil
}

func (r *Router) registerRepos(app appRoute) {
	app("GET /api/repos", func(w http.ResponseWriter, req *http.Request) { writeJSON(w, 200, map[string]any{"repos": r.Repos()}) })
	r.registerDeployKeys(app)
	app("GET /api/github/repos", func(w http.ResponseWriter, req *http.Request) {
		configured := os.Getenv("GITHUB_READ_TOKEN") != ""
		repos, at, err := r.GitHubRepos(req.URL.Query().Get("refresh") == "1")
		if err != nil {
			st := 502
			if he, ok := err.(*httpStatusErr); ok {
				st = he.status
			}
			writeJSON(w, st, map[string]any{"error": err.Error(), "configured": configured})
			return
		}
		writeJSON(w, 200, map[string]any{"repos": repos, "cachedAt": at.UnixMilli(), "configured": configured})
	})
	// the Claude usage quota: Jarvis 1 holds the login (query kept: ?refresh=1)
	app("GET /api/usage", func(w http.ResponseWriter, req *http.Request) { r.forwardJarvis1(w, req, "", nil) })
}
