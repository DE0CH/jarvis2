# Jarvis 2 — plan

Jarvis 2 is a second, independent Jarvis built on the secrets-controller design
(`docs/DESIGN.md`). It runs **side by side with Jarvis 1, which keeps running exactly as
it is**: nothing here touches Jarvis 1's box, cluster, repo paths, session image, Fly app or budget.

## Where things run

| Piece | Where |
|---|---|
| Cluster | Its own Hetzner Cloud project (`jarvis2`), one box, single-node **k3s** reconciled by **Flux** from this repo (public). **Changes only through git** (Deyao, 2026-10-09): no SSH, no reachable k8s API, no inbound port; a box git can't fix is replaced and set up again (Recover) |
| Core (secrets controller) | Go, its own namespace + pod on that box, minimal network surface; all state in memory |
| Router | The Jarvis 2 backend (API for the app and the web page); outside the core; untrusted |
| Sessions | Fly Machines in a **new Fly organisation** (`jarvis2-370`), so Jarvis 1's budget scan never sees them |
| Public address | `jarvis2.deyaochen.com`, a Cloudflare Tunnel (cloudflared on the box) behind its own Cloudflare Access app: Deyao's login; `/setup` admits only the setup session's service token. Session machines never come through Cloudflare: they reach the router over Fly's private network (the box is a WireGuard peer of the org), because Jarvis 1's Access apps admit any service token of the account |
| iPhone app | "Jarvis 2" (`dev.de0ch.jarvis2`, its own TestFlight app): a Swift shell + the React Native UI in an ExtensionKit extension (lessons/73) |
| CI | GitHub Actions (this repo is public, so macOS runners are free): images to GHCR, the app to TestFlight |

## Setting up (Deyao, 2026-10-10)

A new core is empty. Deyao sets it up in the app, with no one else involved: **Reset** (a new recovery kit, the
stores start empty; the setup session then fills them with `infra/fill-stores.sh`) or **Recover** (his kit brings
every store back from the backups). docs/DESIGN.md "Setting a core up".

## Milestone 1 (all of it)

1. Core in Go: the primitives of docs/DESIGN.md, signed answers, in-memory state, tests.
2. Infra: Hetzner box + k3s + Flux, cloudflared tunnel + Access app, Fly org + its token held by the core.
3. Router: Jarvis 1's backend adapted: sessions created / paused / resumed / destroyed through the core.
4. Session image: Jarvis 1's image adapted: an init entry point that pulls its cert and secrets.
5. App: the mock's shell + extension pointed at the router; TestFlight.

## Status (2026-10-08)

- Core: `core/`, tests pass; now also hands each machine the core's key through Fly, waits for slow first
  pulls. Running on the box, **empty, waiting for Reset in the app** (docs/RUNBOOK.md "After a Reset").
- Infra: box `jarvis2` (cx23, fsn1) with k3s + Flux from this repo; tunnel `jarvis2` + Access apps
  (`jarvis2.deyaochen.com` for Deyao, `/m` for machines); Fly app `jarvis2-sessions` in org `jarvis2-370`.
- Router: `router/` (docs/API.md), deployed.
- Session image: `session-image/` + `machine/`, built by CI.
- End-to-end test on real Fly with a software phone: passed (every flow).
- App: `app/` — see app/DECISIONS.md.
- Decisions to review: docs/DECISIONS.md.

## Later (Deyao, 2026-10-09)

- **Device leases and content stores for Jarvis 2 sessions.** Jarvis 1 accepts a Jarvis 2 session's identity from
  the confined `jarvis2-services` token (`X-Jarvis2-Session`), and wakes a queued Jarvis 2 session through a new
  Jarvis 2 router endpoint behind its own confined token. The router already forwards the paths
  (`router/sessionapi.go`); add them to the Worker's `CONFINED_TOKENS` when Jarvis 1 accepts them.
- **Device pairing for Deyao's OpenClaw/Paseo apps** (`/api/remotes`): Jarvis 1's list could include Jarvis 2's,
  or the apps get Jarvis 2 as a second server.
- **Before Jarvis 1 retires** (Deyao keeps using Jarvis 1 until Jarvis 2 is ready and polished, then retires it and
  handles the conflicts then): Jarvis 2 must stop depending on it. Today it uses Jarvis 1 for the stored Claude
  login (`/api/credentials`, refresh and Re-login), transcript search and the iCloud index (forwarded with
  `jarvis2-services`), the usage quota, and the Browserbase budget DM; leases and content stores are planned the
  same way. Each moves into Jarvis 2 (or a service of its own) at retirement, and the confined Jarvis 1 tokens
  go away.

