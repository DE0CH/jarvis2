package main

// Transcript search and the iCloud index: their own pods on this box (services/search, services/icloud-index;
// k8s/apps/search.yaml, k8s/apps/icloud-index.yaml, namespace jarvis2-edge). The router forwards to them, for the
// app's Search tab (/api/...) and for sessions (/m/api/..., the machine's local proxy; any session may search).
// The iCloud index is identity-level (Deyao, 2026-10-13): its paths, OCR'd text and downloads act as Deyao's own
// files, so a session reaches it only while the grant its machine holds names store:identity (where the iCloud login
// lives);
// any other session gets 403. Deyao's app keeps it. Transcript search is open to every running session.
// The services have no login of their own: only the router can reach them (their NetworkPolicies), and the router
// is behind Cloudflare Access (the app) or the machine signature (sessions). Shapes: docs/API.md "Transcript
// search", "iCloud index" (unchanged from Jarvis 1, whose services these were).
//
// router env: SEARCH_URL (default http://search.jarvis2-edge.svc.cluster.local:8090), ICLOUD_INDEX_URL (default
// http://icloud-index.jarvis2-edge.svc.cluster.local:8091).

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// icloudStore: the store a session's held grant must name to reach the iCloud index
const icloudStore = "identity"

type svcRoute struct{ pattern, svc, path string }

// searchRoutes: method + path under /api (the app; sessions get the same under /m/api) → service + its own path
var searchRoutes = []svcRoute{
	{"GET /api/search", "search", "/search"},
	{"GET /api/search/context", "search", "/context"},
	{"GET /api/search/status", "search", "/status"},
	{"POST /api/search/reindex", "search", "/reindex"},
	{"GET /api/icloud/search", "icloud", "/search"},
	{"GET /api/icloud/file", "icloud", "/file"},
	{"GET /api/icloud/status", "icloud", "/status"},
	{"POST /api/icloud/relist", "icloud", "/relist"},
	{"POST /api/icloud/retry", "icloud", "/retry"},
}

var searchClient = &http.Client{Timeout: 2 * time.Minute}

func serviceBase(svc string) (base, name string) {
	if svc == "icloud" {
		return strings.TrimSuffix(env("ICLOUD_INDEX_URL", "http://icloud-index.jarvis2-edge.svc.cluster.local:8091"), "/"), "the iCloud index"
	}
	return strings.TrimSuffix(env("SEARCH_URL", "http://search.jarvis2-edge.svc.cluster.local:8090"), "/"), "transcript search"
}

func (r *Router) registerSearchServices(app appRoute, m machineRoute) {
	for _, rt := range searchRoutes {
		rt := rt
		app(rt.pattern, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			forwardService(w, req, rt, b)
		})
		m(strings.Replace(rt.pattern, " /api/", " /m/api/", 1), func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if rt.svc == "icloud" && !r.machineHoldsStore(sid, icloudStore) {
				writeJSON(w, 403, map[string]any{"error": "the iCloud index needs the " + icloudStore + " store in this session: jarvis2-request add-store " + icloudStore + ` --why "…"`, "needsStore": icloudStore})
				return
			}
			forwardService(w, req, rt, body)
		})
	}
}

// forwardService: method, the service's path, the query and body unchanged; the service's status and JSON back
func forwardService(w http.ResponseWriter, req *http.Request, rt svcRoute, body []byte) {
	base, name := serviceBase(rt.svc)
	u := base + rt.path
	if req.URL.RawQuery != "" {
		u += "?" + req.URL.RawQuery
	}
	out, _ := http.NewRequestWithContext(req.Context(), req.Method, u, bytes.NewReader(body))
	if ct := req.Header.Get("Content-Type"); ct != "" {
		out.Header.Set("Content-Type", ct)
	}
	resp, err := searchClient.Do(out)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": name + " unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[search] %s %s: %v", req.Method, u, err)
	}
}

// pokeSearch: index what was just archived now, not at the next crawl (10 min). Never blocks, never fails.
func pokeSearch() {
	go func() {
		base, _ := serviceBase("search")
		req, _ := http.NewRequest("POST", base+"/reindex", nil)
		c := &http.Client{Timeout: 10 * time.Second}
		if resp, err := c.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}
