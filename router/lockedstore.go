package main

import (
	"errors"
	"regexp"
)

// A machine boots by pulling its secrets from the core; while one of its stores is locked the core answers 423
// "store X is locked" and the machine retries every few seconds. Nothing waits silently: the session carries the
// store it waits on (lockedStore) until a pull goes through, and the app shows it with the phone's unlock page one
// tap away. The next retry after the unlock carries on.
var lockedStoreRE = regexp.MustCompile(`store (\S+) is locked`)

func lockedStoreOf(err error) string {
	var ce *CoreError
	if errors.As(err, &ce) && ce.Status == 423 {
		if m := lockedStoreRE.FindStringSubmatch(ce.Msg); m != nil {
			return m[1]
		}
		return "?"
	}
	return ""
}

func (r *Router) noteSecretsPull(machine string, err error) {
	locked := lockedStoreOf(err)
	if err != nil && locked == "" {
		return // another failure: leave what is known
	}
	ask := ""
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
			if locked != "" && s.LockedStore == "" && s.CarryLost {
				ask = s.ID
			}
			if err == nil {
				s.CarryLost = false // its secrets came: from now on they are carried as usual
			}
			s.LockedStore = locked
		}
	})
	if ask != "" { // legacy.go: a line taken over from an earlier core waits once for its stores
		r.fileRefresh([]string{ask}, "This session moved to the new core at its pause; the secrets it carried were sealed by the core before, which is gone. Unlock gives it its stores once; it carries them again from then on.")
	}
}
