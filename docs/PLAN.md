# Jarvis 2 — plan

Jarvis 2 is a second, independent Jarvis built on the secrets-controller design
(`docs/DESIGN.md`). It runs **side by side with Jarvis 1, which keeps running exactly as
it is**: nothing here touches Jarvis 1's box, cluster, repo paths, session image, Fly app or budget.

## Where things run

| Piece | Where |
|---|---|
| Cluster | Its own Hetzner Cloud project (`jarvis2`), one box, single-node **k3s** reconciled by **Flux** from this repo (public). **Changes only through git** (Deyao, 2026-10-09): no SSH, no reachable k8s API, no inbound port; a box git can't fix is replaced (recovery path to be designed) |
| Core (secrets controller) | Go, its own namespace + pod on that box, minimal network surface; all state in memory |
| Router | The Jarvis 2 backend (API for the app and the web page); outside the core; untrusted |
| Sessions | Fly Machines in a **new Fly organisation** (`jarvis2-370`), so Jarvis 1's budget scan never sees them |
| Public address | `jarvis2.deyaochen.com`, a Cloudflare Tunnel (cloudflared on the box) behind its own Cloudflare Access app: Deyao's login; `/setup` admits only the setup session's service token. Session machines never come through Cloudflare: they reach the router over Fly's private network (the box is a WireGuard peer of the org), because Jarvis 1's Access apps admit any service token of the account |
| iPhone app | "Jarvis 2" (`dev.de0ch.jarvis2`, its own TestFlight app): a Swift shell + the React Native UI in an ExtensionKit extension (lessons/73) |
| CI | GitHub Actions (this repo is public, so macOS runners are free): images to GHCR, the app to TestFlight |

## Initialisation (decided with Deyao, 2026-10-07)

The trusted Claude session that set Jarvis 2 up drives initialisation:
- it starts the core, then sends Deyao the core's public key as a string he pastes into the app;
- the app displays the phone's public key, Deyao pastes it to that session, and the session gives it to
  the core;
- the session seeds the core's keys directly (which stores move over: Deyao decides later).
Recovery after a core restart: designed only when needed.

## Milestone 1 (all of it)

1. Core in Go: the primitives of docs/DESIGN.md, signed answers, in-memory state, tests.
2. Infra: Hetzner box + k3s + Flux, cloudflared tunnel + Access app, Fly org + its token held by the core.
3. Router: Jarvis 1's backend adapted: sessions created / paused / resumed / destroyed through the core.
4. Session image: Jarvis 1's image adapted: an init entry point that pulls its cert and secrets.
5. App: the mock's shell + extension pointed at the router; TestFlight.

## Status (2026-10-08)

- Core: `core/`, tests pass; now also hands each machine the core's key through Fly, waits for slow first
  pulls. Running on the box, holding the Fly token, **waiting for the iPhone pairing** (docs/RUNBOOK.md).
- Infra: box `jarvis2` (cx23, fsn1) with k3s + Flux from this repo; tunnel `jarvis2` + Access apps
  (`jarvis2.deyaochen.com` for Deyao, `/m` for machines); Fly app `jarvis2-sessions` in org `jarvis2-370`.
- Router: `router/` (docs/API.md), deployed.
- Session image: `session-image/` + `machine/`, built by CI.
- End-to-end test on real Fly with a software phone: passed (every flow).
- App: `app/` — see app/DECISIONS.md.
- Decisions to review: docs/DECISIONS.md.
