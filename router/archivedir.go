package main

import (
	"strings"
	"time"
)

// archiveDir: a session's folder on the Storage Box, Jarvis 1's layout (lib/archive.js dirName):
// claude-records/<yyyy-mm-dd of creation> <title, unsafe characters → space, ≤60 chars>. The archive and the
// Discord export (discord/…) both go here, so Jarvis 1's transcript search indexes them.
func (r *Router) archiveDir(s Session) string {
	created := s.Created
	if created.IsZero() {
		created = time.Now()
	}
	return "claude-records/" + created.UTC().Format("2006-01-02") + " " + safeTitle(sessionTitle(s), s.ID)
}

func safeTitle(t, fallback string) string {
	t = strings.Map(func(c rune) rune {
		if strings.ContainsRune(`/\:*?"<>|`, c) || c < 0x20 {
			return ' '
		}
		return c
	}, t)
	t = strings.Join(strings.Fields(t), " ")
	if r := []rune(t); len(r) > 60 {
		t = strings.TrimSpace(string(r[:60]))
	}
	if t == "" {
		return fallback
	}
	return t
}
