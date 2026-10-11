package main

// A new core (a restart, a core/ deploy, a box rebuild; empty, then Reset or Recovered) can't continue the lines of
// the core before it: their certs are signed by the earlier core, its killed/used sets are gone, and the secrets
// they carry (carry.go) were sealed under the earlier core's carry key. Deyao, 2026-10-11: "They are just
// automatically destroyed. Core restart is infrequent enough. No need to engineer around it." So when the router
// sees a new core identity it marks every session that has a line (OldCore) and destroys each one once it is paused,
// the normal way: the archive is kept as a record (Previous), the carry blob and snapshots go, the onDestroy hooks
// clean up (the Discord channel). A running one goes when it next pauses. Restoring one from Previous is an ordinary
// new line approved on the phone.

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

var coreChangeEvery = 30 * time.Second

// a destroy that failed (an archive the Storage Box refused) is tried again 10 minutes later, not every tick
var (
	oldCoreMu    sync.Mutex
	oldCoreTried = map[string]time.Time{}
)

func (r *Router) coreChangeLoop() {
	for {
		r.coreChangeTick()
		time.Sleep(coreChangeEvery)
	}
}

// coreIdentityKey: the running core's signing key, from an identity whose state document it signed itself ("" when
// the core can't be reached or answers something else: nothing is decided on that)
func (r *Router) coreIdentityKey() string {
	status, b, err := r.core.Raw("GET", "/identity", nil)
	if err != nil || status != 200 {
		return ""
	}
	var id struct {
		SigningKey string `json:"signingKey"`
		State      Doc    `json:"state"`
	}
	if json.Unmarshal(b, &id) != nil || id.SigningKey == "" || !verifyP256(id.SigningKey, []byte(id.State.Payload), id.State.Sig) {
		return ""
	}
	return id.SigningKey
}

func (r *Router) coreChangeTick() {
	key := r.coreIdentityKey()
	if key == "" {
		return
	}
	var marked int
	var gone []string
	r.st.Do(func(d *persisted) {
		switch d.CoreKey {
		case key:
		case "":
			d.CoreKey = key // first sight (a router that predates this): the sessions are this core's
		default:
			d.CoreKey = key
			for _, s := range d.Sessions {
				if s.Cert != nil && !s.OldCore {
					s.OldCore = true
					marked++
				}
			}
		}
		for id, s := range d.Sessions {
			if s.OldCore && s.State == "paused" {
				gone = append(gone, id)
			}
		}
	})
	if marked > 0 {
		log.Printf("a new core (%.16s…): %d session(s) belong to the earlier core and are destroyed once paused", key, marked)
	}
	for _, id := range gone {
		oldCoreMu.Lock()
		recent := time.Since(oldCoreTried[id]) < 10*time.Minute
		if !recent {
			oldCoreTried[id] = time.Now()
		}
		oldCoreMu.Unlock()
		if recent {
			continue
		}
		if err := r.destroy(id, destroyOpts{}); err != nil {
			log.Printf("session %s (an earlier core's): destroy: %v", id, err)
		} else {
			log.Printf("session %s (an earlier core's): destroying; Restore it from Previous as a new line", id)
		}
	}
}
