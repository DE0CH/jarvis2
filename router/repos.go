package main

// Deyao's repo list and the GitHub picker (Jarvis 1's /api/repos, /api/github/repos), and the Claude usage
// quota (Jarvis 1's /api/usage, forwarded).
//
// The router holds no GitHub token that can push: the picker lists repos with GITHUB_READ_TOKEN, a
// fine-grained token with metadata read only. Sessions clone and push with their own per-repo tokens from
// their stores (machine/main.go cloneRepos); the picker only fills New session's `repos`.
// The repo list is the router's own (DATA_DIR/repos.json), shown in /api/state `repos`.
// Usage needs the Claude login, which lives in Jarvis 1: forwarded with the services token.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type RepoEntry struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

var repoURLRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+$`)
var repoNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

func (r *Router) reposPath() string { return filepath.Join(r.cfg.DataDir, "repos.json") }

func (r *Router) Repos() []RepoEntry {
	r.ops.reposMu.Lock()
	defer r.ops.reposMu.Unlock()
	return r.readRepos()
}

func (r *Router) readRepos() []RepoEntry {
	out := []RepoEntry{}
	if b, err := os.ReadFile(r.reposPath()); err == nil {
		json.Unmarshal(b, &out)
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

func (r *Router) AddRepo(name, url string) error {
	url = strings.TrimSpace(url)
	if !repoURLRE.MatchString(url) || strings.Contains(url, "..") {
		return bad("url: an https clone URL")
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(url), ".git")
	}
	if !repoNameRE.MatchString(name) {
		return bad("bad repo name")
	}
	return r.updateRepos(func(rs []RepoEntry) []RepoEntry {
		out := []RepoEntry{}
		for _, x := range rs {
			if x.URL != url {
				out = append(out, x)
			}
		}
		return append(out, RepoEntry{name, url})
	})
}

func (r *Router) RemoveRepo(name string) error {
	return r.updateRepos(func(rs []RepoEntry) []RepoEntry {
		out := []RepoEntry{}
		for _, x := range rs {
			if x.Name != name {
				out = append(out, x)
			}
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
	app("POST /api/repos", func(w http.ResponseWriter, req *http.Request) {
		var in RepoEntry
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		if err := r.AddRepo(strings.TrimSpace(in.Name), in.URL); err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("DELETE /api/repos/{name}", func(w http.ResponseWriter, req *http.Request) {
		if err := r.RemoveRepo(req.PathValue("name")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
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
