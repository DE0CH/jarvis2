// The Jarvis 2 router (docs/API.md): chains the core's primitives into sessions and serves the app, the web
// page and the session machines. It is untrusted by design (docs/DESIGN.md): a
// bug here can fail or stall an action, but every document that matters is signed by the core or the
// iPhone and checked at the far end, so it can't move a store to a machine nobody approved.
package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type Config struct {
	CoreURL         string        // the core, inside the cluster
	DataDir         string        // state.json + snapshots (a volume on the box)
	WebDir          string        // the web page (expo export), served at /
	SessionImage    string        // the image new sessions get (a tag; resume pins what Fly reported)
	SessionImageSig string        // CI's signature over it (images.yml; keys/ci.pub)
	Region          string        // Fly region for session machines
	MachineURL      string        // how machines reach the router (JARVIS2_URL on the machine): its Fly private-network address
	AccessTeam      string        // e.g. de0ch.cloudflareaccess.com
	AppAUD          string        // the Access app audience for /api and /
	SetupAUD        string        // the Access app audience for /setup (service token jarvis2-setup)
	SetupKey        string        // the setup session's public key: it signs every /setup call
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
		SessionImageSig: os.Getenv("SESSION_IMAGE_SIG"),
		Region:          env("FLY_REGION", "lhr"),
		MachineURL:      os.Getenv("MACHINE_URL"),
		AccessTeam:      env("ACCESS_TEAM", "de0ch.cloudflareaccess.com"),
		AppAUD:          os.Getenv("ACCESS_APP_AUD"),
		SetupAUD:        os.Getenv("ACCESS_SETUP_AUD"),
		SetupKey:        os.Getenv("SETUP_KEY"),
		AllowedEmail:    env("ALLOWED_EMAIL", "chendeyao000@gmail.com"),
		NoAccess:        os.Getenv("NO_ACCESS") == "1",
		SnapshotWait:    time.Duration(wait) * time.Second,
	}
	if cfg.NoAccess {
		log.Printf("NO_ACCESS=1: Cloudflare Access checks are OFF (CI only)")
	} else if cfg.AppAUD == "" || cfg.SetupAUD == "" {
		log.Fatal("ACCESS_APP_AUD and ACCESS_SETUP_AUD are required (or NO_ACCESS=1 in CI)")
	}
	if cfg.MachineURL == "" {
		log.Printf("MACHINE_URL unset: machines will have no router address")
	}
	st, err := LoadState(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	policy, err := LoadPolicy(env("POLICY_FILE", "/policy/stores.json"))
	if err != nil {
		log.Fatal(err)
	}
	r := NewRouter(cfg, st, &CoreClient{base: cfg.CoreURL, http: &http.Client{Timeout: 15 * time.Minute}}, policy)
	r.startFeatures()
	addr, maddr := env("ADDR", ":8080"), env("MACHINE_ADDR", ":8081")
	log.Printf("router on %s (core %s)", addr, cfg.CoreURL)
	// two listeners: the public one (cloudflared → app, web, setup) and the machines' one, which only
	// Fly's private network reaches (the WireGuard peer); /m exists only on the second
	if wg := os.Getenv("WG_CONFIG"); wg != "" {
		// production: only on the Fly private network (wg.go)
		go func() { log.Fatal(serveWG(wg, 8081, r.MachineHandler())) }()
		log.Printf("machines: WireGuard peer from %s, port 8081", wg)
	} else {
		go func() { log.Fatal(http.ListenAndServe(maddr, r.MachineHandler())) }()
	}
	// SIGTERM (a rollout): a Claude login refresh in flight is let finish, so its answer reaches the volume (the old
	// refresh token is dead the moment the token endpoint answers)
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
		r.loginHub().drain(20 * time.Second)
		os.Exit(0)
	}()
	log.Fatal(http.ListenAndServe(addr, r.Handler()))
}
