# Feature parity with Jarvis 1 (inventory, 2026-10-09)

Deyao asked for full parity with Jarvis 1. This lists every Jarvis 1 feature against Jarvis 2. J1 = claude-env
`selfhost/` (line numbers in `jarvis/server.js` unless named). Dependencies: SB Storage Box creds, FX arbitrary
Fly exec into the machine, FT Fly token, DT Discord bot token, GH GitHub token, CF Cloudflare API, CFA an Access
service token on the machine, OR OpenRouter, AT the Claude OAuth pair, K8s the box's API.

Facts: the router has no Fly token (it calls the core's start/kill/certify); its only way into a machine is the
`/m/commands` poll, which carries just `snapshot`.

## Session lifecycle
- **Create** (FT, AT): present. Idempotent `requestId`: stored, not deduplicated. Lifecycle lock: 409 present, no `busy` in state.
- **Pause / resume / resume on newer image**: present (snapshot on the router volume, machine-signed, not encrypted).
- **Resume prompt**: present (`POST /api/sessions/:id/resume {prompt}`, delivered as a peer message once started; router/schedule.go). Jarvis 1 typed it as a user prompt instead.
- **Start on another size**: missing; size is an option, so it needs approval.
- **Wake job status**: missing.
- **Restart / env patch / env-resync / transcript rollback** (FT, SB, FX): missing; re-pull secrets exists only inside add-store and downgrade.
- **Permission-mode switch** (FX): missing; mode is unsigned env.
- **Auto-pause + idle countdown**: present (machine-reported status, `POST /api/sessions/:id/auto-pause`, `pauseInMs`; `autoPauseVeto` hook for the scheduler). Not ported: Jarvis 1's "don't release if it moved during the snapshot" check.
- **Destroy + archive + uncommitted-work check** (SB): present. Destroy pauses a running session first (its final signed snapshot), the router archives it to the Storage Box with its own creds (`router/archive.go`: Jarvis 1 layout + `jarvis2/` signed snapshot, cert, core cert; index `.index/jarvis2-destroyed-sessions.json`), runs `onDestroy` hooks, then burns. A failed archive leaves it paused (`?force=1` destroys anyway). `GET /api/sessions/:id/changes`: running via the `archive` holder's grant, paused from the snapshot's `.jarvis2-changes.txt`.
- **One-shot sessions**: present (`oneShot` → `SESSION_ONE_SHOT=1`; the router destroys on the supervisor's marker). Destroy doesn't archive yet, nor DM about lost work.
- **First prompt**: present (unsigned env). **First-prompt attachments** (SB on machine): missing.

## Previous sessions
- List: present (router-local). Transcript tail (paused: the volume's snapshot; destroyed: the archive), delete/purge: present. Restore a destroyed session: present as a NEW line (phone-approved like a new session) whose first machine restores the archived snapshot, checking the old core-signed cert passed in its env and the snapshot's signature (`router/restore.go`, `machine/restore.go`). Not phone-signed: which old snapshot is restored (the core's Options can't carry it). Indexing an archive by hand (J1 `POST /api/records`): missing.

## Terminal, remote control, title
- Registry read: present (the machine reports it: `/m/status {raw}`, `router/registry.go`). Live terminal (FX), remote page for opencode/openclaw (FX, CFA), `/api/remotes`, app title sync (AT), per-session tunnel origin (CFA): missing.

## Automatic behaviour
- Auto-pause, Escape-cancel of a stale prompt (holder `status`), "needs you"/idle/dead DMs (+ `notify-idle` mute), model-downgrade DM (incl. the dialog, holder `status`), stall nudge (via `Deliver`): present (`router/autopilot.go`). Refused commands set `needsGrant`.
- Claude credential refresh: via Jarvis 1 (shared login). Fan-out: machine polls; login repair + "continue": present (router fetches the pair with `JARVIS1_CREDENTIALS_ID/SECRET`, holder `login`; no separate fast-repair timers, the 30 s tick covers them).
- Fly budget cap and "Also on Fly": present (`router/budget.go`, read-only `FLY_READ_TOKEN` on app jarvis2-sessions; estimate in router state, DM at `FLY_BUDGET_WARN_USD` 25, pause everything at `FLY_BUDGET_USD` 30; `/api/state` `budget`, `fly`).
- Browserbase budget DM: missing (could stay in J1).
- Discord channel per session (DT, SB): present (`router/discord.go`, Jarvis 1's bot lobster, category "Jarvis 2"): made at
  start/resume and passed as `LOBSTER_CHANNEL` (unsigned machine env), renamed as the title changes (2 edits per 10
  min), exported to `claude-records/<date> <title>/discord/` and deleted on destroy (a failed export keeps it and
  DMs). `r.DM` posts to the lobster DM. Topic has no Remote Control link (Jarvis 2 doesn't know it).
  Deyao's own rename beats the label only once status reports fill `Session.UserTitle`.
- Live transcript sync to SB: missing.

## Scheduling and devices
- Wakeups, crons: present (router/schedule.go; same shapes as Jarvis 1, under `/api` and `/m/api`). Delivery through the `scheduler` grant; arming puts the scheduler on the session's allow list; a sensitive session needs a phone grant (DM, stays pending).
- Watches (store plaintext on the box): missing; conflicts.
- Device leases (iphone, mac, wechat-phone): forwarded to Jarvis 1 (`/m/api` → JARVIS1_SERVICES token); needs Jarvis 1 to accept Jarvis 2 sessions (docs/API.md "Session-facing API").
- Tasks + schedules (k8s Jobs, SOPS hidden params): missing; conflicts.

## Stores, repos, content
- Store editor in the app: partial (values only from the setup session). Copy keys between stores: missing.
- Multi-store merge conflict file: unverified. Repo picker: missing (API takes free text). Repo delivery: replaced by per-repo tokens.
- Content stores: forwarded to Jarvis 1 like leases (same Jarvis 1 change needed). Drop tokens: missing.

## Account and apps
- Re-login: via J1. Usage quota: missing. Device pairing for OpenClaw/Paseo apps, device list/revoke: missing.
- Dashboard: Sessions, Stores, Records, Settings, New session present; Search, Tasks, Schedules, Devices, Content, Repos, usage, banners, lease pills, "Also on Fly": missing.

## Harnesses and image
- Claude: present. OpenCode + Paseo: partial (models list, Paseo UI needs a tunnel). OpenClaw + claw-code: missing. `harness-send`: missing. API proxy: missing.
- Workspace layer: to verify. on-start hooks: present.
- Peer-message delivery: present (`r.Deliver`, router/peer.go; Jarvis 1's lib/peer.js run through the `scheduler` grant, text base64 in argv).
- Session-facing API (`$JARVIS_URL` for Jarvis 1's session scripts): present — the machine's local proxy (machine/apiproxy.go) signs to `/m/api`; pull-secrets and changes answered on the machine; notify-idle and self-retire (refused while wakeups/crons are pending) on the router; watches answer 501.
- Transcript search, iCloud index: forwarded to Jarvis 1 (`/m/api` → JARVIS1_SERVICES token).

## Design questions parity forces
1. A command channel replacing Fly exec (terminal, peer messages, status, relogin, mode, Escape, remote info, changes check): a fixed set of `/m/commands` verbs?
2. Free text into machines (wakeup/cron/resume prompts, nudges): who signs it?
3. Where archives and transcripts live durably, encrypted to what, and who holds the bucket creds.
4. Restore after a burn: what the restored machine trusts its snapshot by.
5. Secrets outside sessions (watches, tasks, Discord/Browserbase/budget DMs).
6. Fly read access for the budget cap.
7. Where the Discord bot token lives; does it need a narrower bot?
8. Per-session tunnel origins without opening Jarvis 1's Access.
9. Cross-Jarvis services (leases, search, iCloud, content, schedule scripts): Worker-confined J1 tokens, or reimplement on `/m`?
10. Which options are signed (mode, model, size, auto-pause, one-shot, API proxy, repos).
11. Arbitrary env injection: allowed at all?
12. Store authoring in the app (the app as trusted writer), copy between stores.
13. Attachments and content stores without SB creds on every machine.
14. Device pairing for OpenClaw/Paseo.
15. A machine reporting "busy" forever defeats auto-pause and the budget.

Deyao's direction (2026-10-09): features learn trust and are approved through the core in time-limited grants
(10 minutes at a time), so not everything goes through the core.
