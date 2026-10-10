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
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
			s.LockedStore = locked
		}
	})
}
