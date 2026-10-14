package secrets

// A GitHub stand-in (carried over from core/fakefly.go): deploy keys kept in memory per repo. A repo named "*/no-admin"
// answers 403, as GitHub does for a token without Administration on it. Tests use it directly; the secrets binary only
// when built with -tags fakefly.

import (
	"strings"
	"sync"
)

type FakeGitHub struct {
	mu   sync.Mutex
	n    int64
	Keys map[string][]DeployKey
}

func NewFakeGitHub() *FakeGitHub { return &FakeGitHub{Keys: map[string][]DeployKey{}} }

func (g *FakeGitHub) refuse(token, repo string) error {
	if token == "" || strings.HasSuffix(strings.ToLower(repo), "/no-admin") {
		return &GitHubError{403, "GitHub (fake): HTTP 403 Resource not accessible by personal access token"}
	}
	return nil
}

func (g *FakeGitHub) ListDeployKeys(token, repo string) ([]DeployKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.refuse(token, repo); err != nil {
		return nil, err
	}
	return append([]DeployKey{}, g.Keys[strings.ToLower(repo)]...), nil
}

func (g *FakeGitHub) AddDeployKey(token, repo, title, publicKey string) (DeployKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.refuse(token, repo); err != nil {
		return DeployKey{}, err
	}
	g.n++
	k := DeployKey{ID: g.n, Title: title, Key: publicKey}
	g.Keys[strings.ToLower(repo)] = append(g.Keys[strings.ToLower(repo)], k)
	return k, nil
}

func (g *FakeGitHub) DeleteDeployKey(token, repo string, id int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.refuse(token, repo); err != nil {
		return err
	}
	ks := g.Keys[strings.ToLower(repo)]
	out := ks[:0]
	for _, k := range ks {
		if k.ID != id {
			out = append(out, k)
		}
	}
	g.Keys[strings.ToLower(repo)] = out
	return nil
}
