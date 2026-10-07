# Jarvis 2 — plan

Jarvis 2 is a second, independent Jarvis built on the secrets-controller design (claude-env
`selfhost/SECRETS-CONTROLLER.md`). It runs **side by side with Jarvis 1, which keeps running exactly as
it is**: nothing here touches Jarvis 1's box, cluster, repo paths, session image, Fly app or budget.

## Where things run

| Piece | Where |
|---|---|
| Cluster | Its own Hetzner Cloud project (`jarvis2`), one box, single-node **k3s** reconciled by **Flux** from this repo (public) |
| Core (secrets controller) | Go, its own namespace + pod on that box, minimal network surface; all state in memory |
| Router | The Jarvis 2 backend (API for the app and the web page); outside the core; untrusted |
| Sessions | Fly Machines in a **new Fly organisation** (`jarvis2`), so Jarvis 1's budget scan never sees them |
| Public address | `jarvis2.deyaochen.com`, a Cloudflare Tunnel (cloudflared on the box) behind its own Cloudflare Access app: Deyao's login only, no service tokens |
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

1. Core in Go: the primitives of SECRETS-CONTROLLER.md, signed answers, in-memory state, tests.
2. Infra: Hetzner box + k3s + Flux, cloudflared tunnel + Access app, Fly org + its token held by the core.
3. Router: Jarvis 1's backend adapted: sessions created / paused / resumed / destroyed through the core.
4. Session image: Jarvis 1's image adapted: an init entry point that pulls its cert and secrets.
5. App: the mock's shell + extension pointed at the router; TestFlight.

## Status (paused 2026-10-07)

- Core: written (`core/`), 11 tests pass (setup, seeding, split-key unlock, pull secrets, new lines,
  dead-machine resume exactly once, burns, mismatch/fork refusals, kill rejecting null).
- Cloudflare: scoped token `jarvis2-infra` minted (`CF_JARVIS2_INFRA_TOKEN` in claude-env's `default` store).
- Hetzner: project created (named `jarvis2-mock`, to rename to `jarvis2`), token `HETZNER_JARVIS2_MOCK_API`; no server yet.
- Fly: blocked on billing. A linked org was refused ("Parent organization trust is too low"); no `jarvis2`
  org exists. Waiting on Deyao's choice of how to pay for Jarvis 2's sessions.
- Not started: infra bring-up, router, session image, app.
