# Decisions made while building milestone 1 (for Deyao to review)

Deyao asked for the full build with his review at the end (2026-10-08). Every choice he may want to change
is listed here, numbered; the app's own list is `app/DECISIONS.md`.

## Shape

1. **One Go module per part** (`core/`, `router/`, `machine/`, `e2e/`), no shared code. The core stays
   exactly as small as before plus two changes (7, 8); the machine tool re-implements the few crypto calls
   it needs in the core's formats.
2. **The router is new code, not Jarvis 1's backend adapted.** Jarvis 1's Node backend is large and tied to
   its k8s/Storage-Box/Discord design. The router is ~1,000 lines of Go that serves the API in
   `docs/API.md`, returning session objects in Jarvis 1's shape so the app's views carry over. Not in M1:
   tasks, schedules, wakeups/crons/watches, terminal, transcripts/search, content stores, repo picker,
   Discord channels, the Fly budget cap, auto-pause on idle.
3. **The session image is Jarvis 1's image (pinned by digest) with `jarvis2-machine` as its entry point.**
   It makes the machine's keys, waits for the core's init, checks the cert, restores the snapshot, pulls
   the secrets, then execs Jarvis 1's unchanged entrypoint (harness, supervisor, Remote Control). Moving
   the base is a visible one-line commit.

## Security-relevant

4. **Machines reach the router through the same hostname, path `/m`, under a second Access app** that admits
   only the service token `jarvis2-machines` (PLAN said "no service tokens" for Deyao's app; the machines
   need some edge credential, and this one can only reach `/m`, where every request must also be signed by
   a machine the core started). The token travels in the machine's Fly env (via the core's `start`), so a
   session can read it — it grants nothing beyond `/m` signing as that machine.
5. **The app signs in by carrying the Access JWT**: `/api/auth/start` behind Access redirects to
   `jarvis2://auth#token=<JWT>`, the app sends it as `cf-access-token`. The router verifies the JWT itself
   too (issuer, audience, Deyao's email). Access session length: 30 days (both apps).
6. **The router keeps its records in a JSON file on a 20 GiB volume**, and pause snapshots on the same
   volume (tar.gz, signed by the machine). Snapshots are not encrypted at rest; the box is untrusted by the
   design, so a box compromise could read a paused conversation (not a key store). Option later: seal
   snapshots to the successor… which doesn't exist yet at pause time — or to the phone.
7. **The core now writes its own public key onto each machine through Fly exec**, next to the API key, so
   the machine checks its cert without trusting the router (the design said the machine checks the core's
   signature but not how it learns the key).
8. **The core waits up to 10 min for a machine to start** (the 8 GB image's first pull on a Fly host took
   95 s) and destroys a machine that never starts.
9. **A CI-only fake Fly** (`go build -tags fakefly`) lets the app's CI run the real core and router; the
   production image is built without the tag and the fake logs loudly.
10. **Resume with the latest image burns the old machine before asking the iPhone** (as the design says);
    rejecting that approval therefore ends the session. The app should say so before Deyao starts it.
11. **The core still prints its one-time setup token in its log**, read with the box's admin token (in the
    `default` store as `JARVIS2_K8S_ADMIN_TOKEN`). Whoever holds that token can set up a fresh core.
12. **The k8s API (6443) and SSH (22) are open to the internet** on the box (token / key auth only), like
    Jarvis 1, so a session can manage it. Option: restrict to Tailscale or close SSH.
13. **Flux applies as a limited identity** (admin in the three Jarvis 2 namespaces only); the bootstrap
    set (namespaces, RBAC) is applied once at box creation and never reconciled from git. The repo holds no
    secrets: the tunnel token and router settings are k8s Secrets created from user-data at boot.
14. **Network policies**: only the router reaches the core; the core reaches only the internet on 443
    (Fly), not the cluster; the router is reachable only from cloudflared.

## Infra

15. **Box**: Hetzner cx23 (2 vCPU, 4 GB, 40 GB) in fsn1, EUR 6.588/month gross plus its IPv4, in the
    `jarvis2-mock` project (not renamed yet: a Hetzner project can only be renamed in the console).
16. **Fly**: app `jarvis2-sessions` in org `jarvis2-370`, region `lhr`, sizes small/medium/large =
    2/4/8 shared CPUs with 2/4/8 GB. No budget cap yet (Jarvis 1's is a Jarvis 1 feature).
17. **Images** on GHCR (`jarvis2-core`, `-router`, `-session`, public because the repo is), with GitHub
    build attestations, so the phone can later check "CI build from <date>" (the check itself is not in M1).
18. **Repos for a session** are cloned by the machine itself with the session's own `GITHUB_TOKEN` (from its
    stores), not handed over by the router.
19. **Claude credentials come from the stores**: `CLAUDE_CREDENTIALS` / `CLAUDE_ACCOUNT` keys in a store the
    session gets. Which stores move over, and with which keys, is Deyao's call (PLAN). Note: sharing Jarvis
    1's refreshing OAuth pair with Jarvis 2 sessions can make the two fight over the refresh token; a
    long-lived `claude setup-token` token in its own store avoids that.
