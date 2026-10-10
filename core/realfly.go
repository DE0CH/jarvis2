//go:build !fakefly

package main

import (
	"net/http"
	"time"
)

func newGitHub() GitHub { return newGitHubAPI() }

func newFly() Fly {
	return &FlyAPI{base: "https://api.machines.dev/v1", http: &http.Client{Timeout: 90 * time.Second}}
}
