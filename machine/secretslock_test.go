package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Two add-store waiters approved together (2026-10-13): the first pulled with the older cert, the second pulled with
// the newer one and took it, then the first put its older pull over it. Under the lock the second pulls
// only after the first has written, from the router's newest cert at that moment, so the copy ends with the newest.
func TestASlowerWaiterNeverWritesAnOlderPullOverANewerFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var mu sync.Mutex
	version := 1 // the router's newest cert: 1 = yyc added, 2 = identity added too
	current := func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		if version == 1 {
			return map[string]string{"YYC": "y"}
		}
		return map[string]string{"YYC": "y", "IDENTITY": "i"}
	}
	firstPulled := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the yyc waiter: pulls the older cert, then is slow to write
		defer wg.Done()
		if _, err := refreshSecrets(func() error { return nil }, func() (map[string]string, error) {
			m := current()
			close(firstPulled)
			time.Sleep(300 * time.Millisecond)
			return m, nil
		}); err != nil {
			t.Error(err)
		}
	}()
	<-firstPulled
	mu.Lock()
	version = 2 // identity approved meanwhile
	mu.Unlock()
	go func() { // the identity waiter
		defer wg.Done()
		if _, err := refreshSecrets(func() error { return nil }, func() (map[string]string, error) { return current(), nil }); err != nil {
			t.Error(err)
		}
	}()
	wg.Wait()
	defer held.set(map[string]string{})
	if got := held.snapshot(); len(got) != 2 || got["IDENTITY"] != "i" {
		t.Fatalf("the supervisor ends with %v", got)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".secrets")); err == nil {
		t.Fatal("~/.secrets written")
	}
}
