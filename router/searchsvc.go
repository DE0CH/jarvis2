package main

// Transcript search and the iCloud index: their own pods on the services box (services/search, services/icloud-index;
// k8s/services/apps/search, k8s/services/apps/icloud-index, namespace jarvis2-services). The router forwards to them, for the
// app's Search tab (/api/...) and for sessions (/m/api/..., the machine's local proxy; any session may search).
// The iCloud index is identity-level (Deyao, 2026-10-13): its paths, OCR'd text and downloads act as Deyao's own
// files, so a session reaches it only while its cert holds the `identity` store (where the iCloud login lives);
// any other session gets 403. Deyao's app keeps it. Transcript search is open to every running session.
// The services have no login of their own: only the router can reach them (their NetworkPolicies), and the router
// is behind Cloudflare Access (the app) or the machine signature (sessions). Shapes: docs/API.md "Transcript
// search", "iCloud index" (unchanged from Jarvis 1, whose services these were).
//
// router env: SEARCH_URL (default http://10.77.0.3:30090), ICLOUD_INDEX_URL (default
// http://10.77.0.3:30091).

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// icloudStore: the store a session's cert must hold to reach the iCloud index
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

// searchClient: a search may take its time, but the services box answers a connect at once over the private Network;
// one that doesn't (the box down, or no services box at all, as in CI) is an error in seconds, not after two minutes
var searchClient = &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	TLSHandshakeTimeout: 10 * time.Second,
	MaxIdleConnsPerHost: 4,
}}

func serviceBase(svc string) (base, name string) {
	if svc == "icloud" {
		return strings.TrimSuffix(env("ICLOUD_INDEX_URL", "http://10.77.0.3:30091"), "/"), "the iCloud index"
	}
	return strings.TrimSuffix(env("SEARCH_URL", "http://10.77.0.3:30090"), "/"), "transcript search"
}

func (r *Router) registerSearchServices(app appRoute, m machineRoute) {
	for _, rt := range searchRoutes {
		rt := rt
		app(rt.pattern, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			forwardService(w, req, rt, b)
		})
		m(strings.Replace(rt.pattern, " /api/", " /m/api/", 1), func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			stores, err := r.machineSessionStores(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if rt.svc == "icloud" && !slices.Contains(stores, icloudStore) {
				writeJSON(w, 403, map[string]any{"error": "the iCloud index needs the " + icloudStore + " store in this session: jarvis2-request add-store " + icloudStore + ` --why "…"`, "needsStore": icloudStore})
				return
			}
			forwardService(w, req, rt, body)
		})
	}
}

// machineSessionStores: the stores in the cert of the machine's running session (the cert's own list: it follows
// add-store and downgrade)
func (r *Router) machineSessionStores(machine string) ([]string, error) {
	var stores []string
	found := false
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
			found, stores = true, append([]string{}, s.Stores...)
		}
	})
	if !found {
		return nil, errors.New("this machine isn't a running session")
	}
	return stores, nil
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
