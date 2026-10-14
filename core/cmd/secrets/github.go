//go:build !fakefly

package main

import "github.com/DE0CH/jarvis2/core/kernel/secrets"

func newGitHub() secrets.GitHub { return secrets.NewGitHubAPI() }
