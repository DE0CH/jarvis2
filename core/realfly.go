//go:build !fakefly

package main

import (
	"net/http"
	"time"
)

type flyClient interface {
	Fly
	configurable
}

func newFly() flyClient {
	return &FlyAPI{base: "https://api.machines.dev/v1", http: &http.Client{Timeout: 90 * time.Second}}
}
