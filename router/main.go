// The Jarvis 2 router (docs/API.md): chains the core's primitives into sessions and serves the app, the web
// page and the session machines. It is untrusted by design (claude-env selfhost/SECRETS-CONTROLLER.md): a
// bug here can fail or stall an action, but every document that matters is signed by the core or the
// iPhone and checked at the far end, so it can't move a store to a machine nobody approved.
package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Config struct {
	CoreURL         string        // the core, inside the cluster
	DataDir         string        // state.json + snapshots (a volume on the box)
	WebDir          string        // the web page (expo export), served at /
	SessionImage    string        // the image new sessions get (a tag; resume pins what Fly reported)
	Region          string        // Fly region for session machines
	MachineURL      string        // how machines reach the router (JARVIS2_URL on the machine)
	MachineAccessID string        // the Access service token machines pass at the edge
	MachineSecret   string        //
	AccessTeam      string        // e.g. de0ch.cloudflareaccess.com
	AppAUD          string        // the Access app audience for /api and /
	MachineAUD      string        // the Access app audience for /m
	AllowedEmail    string        // the only person
	NoAccess        bool          // CI only: no Cloudflare in front, skip the JWT checks
	SnapshotWait    time.Duration // how long a pause waits for the machine's snapshot
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	wait, _ := strconv.Atoi(env("SNAPSHOT_WAIT_SECONDS", "600"))
	cfg := Config{
		CoreURL:         env("CORE_URL", "http://core.jarvis2-core.svc.cluster.local:8090"),
		DataDir:         env("DATA_DIR", "/data"),
		WebDir:          env("WEB_DIR", "/web"),
		SessionImage:    env("SESSION_IMAGE", "ghcr.io/de0ch/jarvis2-session:latest"),
		Region:          env("FLY_REGION", "lhr"),
		MachineURL:      env("MACHINE_URL", "https://jarvis2.deyaochen.com"),
		MachineAccessID: os.Getenv("MACHINE_ACCESS_ID"),
		MachineSecret:   os.Getenv("MACHINE_ACCESS_SECRET"),
		AccessTeam:      env("ACCESS_TEAM", "de0ch.cloudflareaccess.com"),
		AppAUD:          os.Getenv("ACCESS_APP_AUD"),
		MachineAUD:      os.Getenv("ACCESS_MACHINE_AUD"),
		AllowedEmail:    env("ALLOWED_EMAIL", "chendeyao000@gmail.com"),
		NoAccess:        os.Getenv("NO_ACCESS") == "1",
		SnapshotWait:    time.Duration(wait) * time.Second,
	}
	if cfg.NoAccess {
		log.Printf("NO_ACCESS=1: Cloudflare Access checks are OFF (CI only)")
	} else if cfg.AppAUD == "" || cfg.MachineAUD == "" {
		log.Fatal("ACCESS_APP_AUD and ACCESS_MACHINE_AUD are required (or NO_ACCESS=1 in CI)")
	}
	st, err := LoadState(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	r := NewRouter(cfg, st, &CoreClient{base: cfg.CoreURL, http: &http.Client{Timeout: 3 * time.Minute}})
	addr := env("ADDR", ":8080")
	log.Printf("router on %s (core %s)", addr, cfg.CoreURL)
	log.Fatal(http.ListenAndServe(addr, r.Handler()))
}
