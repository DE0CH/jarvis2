package main

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// GET /term/{id}: the terminal page the iPhone app shows in a web view — self-contained, no script from anywhere else
func TestTermPage(t *testing.T) {
	r := newTestRouter(t)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	w := get("/term/abc-123")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "Cache-Control"} {
		if w.Header().Get(h) == "" {
			t.Fatalf("no %s header", h)
		}
	}
	page := w.Body.String()
	for _, want := range []string{"Terminal input", "Terminal status", "Allow terminal for 10 minutes", `const SID = "abc-123"`, "jarvis2Refresh"} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %q", want)
		}
	}
	if strings.Contains(page, "__SESSION_ID__") {
		t.Fatal("session id placeholder left in the page")
	}
	if regexp.MustCompile(`(?i)<script[^>]*\bsrc=`).MatchString(page) || regexp.MustCompile(`(?i)<link[^>]*\bhref=`).MatchString(page) {
		t.Fatal("the page loads something from elsewhere")
	}
	for _, bad := range []string{"/term/a%22b", "/term/a.b", "/term/a%3Cscript%3E", "/term/" + strings.Repeat("a", 81)} {
		if w := get(bad); w.Code != 404 {
			t.Fatalf("%s: status %d, want 404", bad, w.Code)
		}
	}
}
