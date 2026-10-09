# Decisions made while building milestone 1 (for Deyao to review)

The design itself is `docs/DESIGN.md` (decided with Deyao, 2026-10-03 → 10-09). These are the choices Claude
made around it; the app's own list is `app/DECISIONS.md`.

## Shape

1. **One Go module per part** (`core/`, `router/`, `machine/`, `e2e/`), no shared code; the machine and the
   tests re-implement the few crypto calls they need in the core's formats.
2. **The router is new code** (~1,200 lines of Go), not Jarvis 1's backend. Not in M1: tasks, schedules,
   wakeups, terminal, transcript search, content stores, repo picker, Discord channels, the Fly budget cap,
   auto-pause on idle.
3. **The session image is Jarvis 1's image (pinned by digest)** with `jarvis2-machine` in front: keys, wait for
   `jarvis2-init`, check the core (master key) and the cert, restore the snapshot, pull the secrets, then Jarvis
   1's unchanged entrypoint. A second image, `jarvis2-session-test`, is the same with the public TEST master key
   (`e2e/testdata`), for the end-to-end test and CI only.

## Security-relevant

4. **Session machines reach the router over Fly's private network**, not through Cloudflare: the box is a
   WireGuard peer of org `jarvis2-370` (`fly wireguard create`), run inside the router in userspace
   (wireguard-go + netstack, no privileges); `/m` exists only on that listener. Reason: Jarvis 1's Access apps
   admit any service token of the account, so a token on every machine would have opened Jarvis 1.
5. **The setup session** reaches `/setup/*` through its own Access app and service token `jarvis2-setup`, and
   the router checks the setup key's signature on every call (method, path, time, body; once, within 2 min).
6. **The app signs in by carrying the Access JWT** (`/api/auth/start` → `jarvis2://auth#token=…`, sent as
   `cf-access-token`); the router verifies it too. Access sessions last 30 days.
7. **Pause snapshots sit on the router's volume**, signed by the machine, not encrypted at rest.
8. **The Fly token is narrowed** (`infra/fly-token.sh`): app jarvis2-sessions only, read/write/create/delete/
   control (Fly refuses to create a machine without write), and exec of exactly `/usr/local/bin/jarvis2-init`
   with no arguments. Tested on a real machine: create and destroy allowed, `cat` refused, `jarvis2-init` with an
   argument refused. Write also lets a holder change a running machine's config; the machine then restarts
   without its keys and, with no cert, gets nothing.
9. **The core waits up to 10 min for a machine to start** (the image's first pull on a Fly host is slow) and
   destroys a machine whose init fails.
10. **A CI-only fake Fly** (`go build -tags fakefly`) lets the app's CI run the real core and router.
11. **The identity words** are 8 BIP39 English words over SHA-256 of
    `"jarvis2-core-identity <signingKey> <agreementKey>"` (88 bits).
12. **The recovery kit is two password-manager items:** the master private key (made on the iPhone) and the
    backup bucket's read keys (Claude shows them to Deyao once, on a private page). The phone reads the backups
    itself, so nothing on the box can reach the bucket.
13. **Backups:** `stores/<name>.json` (values sealed to the master key, the name as associated data; sensitive
    flag; signed by the setup key) and `sensitive/<name>.json` markers, in the versioned bucket
    `jarvis2-backup-de0ch`. A store is not sensitive at recovery only if its backup says so and no marker exists.
14. **The box changes only through git:** no SSH (sshd off, a throwaway key so Hetzner mails no root
    password), no k8s API from outside, a Hetzner firewall with no inbound rules. Flux applies as a limited
    identity (admin in the three Jarvis 2 namespaces only). Secrets (tunnel token, WireGuard peer, box key)
    arrive once in user-data; Hetzner keeps serving user-data from the metadata address, which every pod's
    network policy blocks.
15. **The core restarts only when `core/` changes** (CI pins its image separately), because a restart means a
    recovery.

## Infra

16. **Box**: Hetzner cx23 (2 vCPU, 4 GB, 40 GB) in fsn1, EUR 6.588/month gross plus its IPv4, in the
    `jarvis2-mock` project (renaming a Hetzner project needs the console).
17. **Fly**: app `jarvis2-sessions` in org `jarvis2-370`, region `lhr`, sizes small/medium/large = 2/4/8 shared
    CPUs with 2/4/8 GB. No budget cap yet.
18. **Images** on GHCR (public, like the repo), with GitHub build attestations (the phone doesn't check them
    yet).
19. **Repos for a session** are cloned by the machine with the session's own `GITHUB_TOKEN`.
20. **Harness stores** (`policy/stores.json`, baked into the router image): `claude` brings the store `claude`
    (the Claude login), `opencode` brings `openrouter`. A separate long-lived `claude setup-token` in the
    `claude` store avoids fighting Jarvis 1 over the refresh token.
21. **Stores that can reach a code push are sensitive** (Deyao, 2026-10-09): one GitHub token per repo, each
    limited to its repo — `github-claude-env` (DE0CH/claude-env, not sensitive) and `github-jarvis2`
    (DE0CH/jarvis2, sensitive). claude-env holds no Jarvis 2 code or design.
