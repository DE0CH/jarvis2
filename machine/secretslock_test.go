package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Two add-store waiters approved together (2026-10-13): the first pulled with the older cert, the second pulled with
// the newer one and wrote ~/.secrets, then the first wrote its older pull over it. Under the lock the second pulls
// only after the first has written, from the router's newest cert at that moment, so the file ends with the newest.
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
	b, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".secrets"))
	if string(b) != "IDENTITY='i'\nYYC='y'\n" {
		t.Fatalf("~/.secrets ends as %q", b)
	}
}
