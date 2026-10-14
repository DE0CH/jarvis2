//go:build !fakefly

package main

import "github.com/DE0CH/jarvis2/core/kernel/spawner"

func newFly() spawner.Fly { return spawner.NewFlyAPI() }
