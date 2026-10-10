# Feature parity with Jarvis 1 (inventory, updated 2026-10-10)

Deyao asked for full parity with Jarvis 1. This lists every Jarvis 1 feature against Jarvis 2. J1 = claude-env
`selfhost/` (line numbers in `jarvis/server.js` unless named). Dependencies: SB Storage Box creds, FX arbitrary
Fly exec into the machine, FT Fly token, DT Discord bot token, GH GitHub token, CF Cloudflare API, CFA an Access
service token on the machine, OR OpenRouter, AT the Claude OAuth pair, K8s the box's API.

Facts: the router has no Fly token (it calls the core's start/kill/certify). Its ways into a machine are the
`/m/commands` poll (`snapshot`, and shell commands signed by a holder that the machine runs only under a phone grant,
a standing rule or its own allow list — DESIGN.md "Grants") and what the machine sends by itself (status reports,
snapshots, live transcripts, task results).

Deferred by Deyao (PLAN.md "Later"): device leases, content stores, device pairing for the OpenClaw/Paseo apps,
watches.

## Session lifecycle
- **Create** (FT, AT): present. Idempotent `requestId`: present (a repeat answers the session it made). Lifecycle lock: 409 and `busy {kind, since}` in `/api/state`.
- **Pause / resume / resume on newer image**: present (snapshot on the router volume, machine-signed, not encrypted).
- **Resume prompt**: present (`POST /api/sessions/:id/resume {prompt}`, delivered as a peer message once started; router/schedule.go). Jarvis 1 typed it as a user prompt instead.
- **Start on another size / model**: present (`POST …/resume {size, model, apiProxy}`), unsigned: no phone step.
- **Wake job status**: present for permission-mode and restart (`wake {kind, phase, error, finishedAt}` in `/api/state`).
- **Restart / env patch / transcript rollback**: present (`router/sessionops.go`): restart = pause + resume on the same image; `env` takes NON-secret keys only and stays for later starts; the rollback is applied by the next machine after it verified the snapshot (`machine/rollback.go`). env-resync: every resume re-pulls the stores; re-pull without a restart exists only inside add-store and downgrade.
- **Permission-mode switch**: present. The mode is signed (DECISIONS 30): a resume in another mode needs the phone; raising a running session to bypass needs a fresh phone grant for `terminal`; lowering runs Jarvis 1's `set-permission-mode` in place.
- **Auto-pause + idle countdown**: present (machine-reported status, `POST /api/sessions/:id/auto-pause`, `pauseInMs`; the scheduler vetoes it before a due wakeup). Not ported: Jarvis 1's "don't release if it moved during the snapshot" check.
- **Destroy + archive + uncommitted-work check** (SB): present. Destroy pauses a running session first (its final signed snapshot), the router archives it to the Storage Box with its own creds (`router/archive.go`: Jarvis 1 layout + `jarvis2/` signed snapshot, cert, core cert; index `.index/jarvis2-destroyed-sessions.json`), runs `onDestroy` hooks (Discord export, the live copy removed), then burns. A failed archive leaves it paused (`?force=1` destroys anyway). `GET /api/sessions/:id/changes`: running via the `archive` holder's grant, paused from the snapshot's `.jarvis2-changes.txt`.
- **One-shot sessions**: present (`oneShot` → `SESSION_ONE_SHOT=1`). On the supervisor's marker the router destroys with force (archived, a failed archive doesn't stop it) and DMs when work was lost: dirty repos from the final snapshot, an unchecked state, a failed archive (`router/oneshot.go`, DECISIONS 40).
- **First prompt**: present (unsigned env). **First-prompt attachments**: present on the router (`router/uploads.go`: staged on the router's volume, fetched by the first machine over `/m/attachments`); not in the app (a file picker the extension doesn't carry).

## Previous sessions
- List, transcript tail (paused: the volume's snapshot; destroyed: the archive), remove/purge: present. Restore a destroyed session: present as a NEW line (phone-approved like a new session) whose first machine restores the archived snapshot, checking the old core-signed cert and the snapshot's signature (`router/restore.go`, `machine/restore.go`). Not phone-signed: which old snapshot is restored.
- **Indexing an archive by hand** (J1 `POST /api/records`): present (`router/records.go`): on the list with tail / Remove / Delete; Restore refused (no machine-signed snapshot; DECISIONS 41).

## Terminal, remote control, title
- Registry read: present (the machine reports it: `/m/status {raw}`, `router/registry.go`).
- Live terminal: present (`router/terminal.go`, holder `terminal`; the app draws tmux's capture, app/DECISIONS 27).
- **App title sync (AT)**: present. The machine reads the Claude app's title of its Remote Control entry with its own Claude login and reports it (`/m/status {appTitle}`, `machine/apptitle.go`); it names the card, the Discord channel and the archive folder first (Jarvis 1's pickTitle: app title → CLI-pinned name → label → AI title), is kept while paused, and a resume without a label passes it as `SESSION_RESUME_TITLE`. Not ported: Jarvis 1's rename-back of a fresh Remote Control entry after a Start (`keepAppTitle`; DECISIONS 39).
- Remote page for opencode/openclaw: present (`GET /api/sessions/:id/remote`, `router/remote.go`, holder `remote`).
- `/api/remotes?harness=`: present on the router. Deyao's OpenClaw/Paseo apps don't see it yet (device pairing, deferred).
- Per-session tunnel origin (CFA): present — harnesses opencode/openclaw bring the store `tunnel` (Access service token `jarvis2-tunnel`); the machine fetches a proof for its own session id (`GET /m/tunnel-proof`); the cf-tunnel Worker confines the token to `AGENT jarvis2` with that proof (claude-env `cf-tunnel/wrangler.toml` `CONFINED_TOKENS`). A paused Jarvis 2 session's link gives the Worker's bare 503 (its Unpause page is for Jarvis 1 ids only).

## Automatic behaviour
- Auto-pause, Escape-cancel of a stale prompt (holder `status`), "needs you"/idle/dead DMs (+ `notify-idle` mute), model-downgrade DM (holder `status`), stall nudge, one-shot destroy: present (`router/autopilot.go`, `router/oneshot.go`). Refused commands set `needsGrant`.
- Claude credential refresh: via Jarvis 1 (shared login). Login repair + "continue": present (holder `login`).
- Fly budget cap and "Also on Fly": present (`router/budget.go`, read-only `FLY_READ_TOKEN`).
- Browserbase budget DM: stays in Jarvis 1.
- Discord channel per session (DT, SB): present (`router/discord.go`, lobster, category "Jarvis 2"), named by the title above and renamed as it changes (2 edits per 10 min), exported to `claude-records/<date> <title>/discord/` and deleted on destroy. Topic has no Remote Control link.
- **Live transcript sync to SB**: present. The machine sends changed transcripts every 5 min (`machine/livesync.go`); the router writes `claude-records/.live/<session id>/` with its own creds, so Jarvis 1's search indexes running Jarvis 2 sessions; removed on destroy. No grant (the machine pushes; DECISIONS 38).

## Scheduling and devices
- Wakeups, crons: present (router/schedule.go; Jarvis 1's shapes, under `/api` and `/m/api`; delivery through the `scheduler` grant).
- Watches: deferred (they run a script with store plaintext on the box; `/m/api/…/watches` answers 501).
- Device leases (iphone, mac, wechat-phone): deferred. The router forwards the paths to Jarvis 1, which doesn't accept Jarvis 2 sessions yet, so no lease can be held and the app shows no lease pills.
- Tasks + schedules: present on the router (`router/tasks.go`, `machine/task.go`, templates in `tasks/`; DECISIONS 32–37) and in the app (Tasks and Schedules tabs, app/DECISIONS 35). Jarvis 1's templates aren't ported (many need content stores).

## Stores, repos, content
- Store editor in the app: partial — the shell's Stores page creates, unlocks, locks and marks stores sensitive; values are written only by the setup session (`infra/setup.py`). Copy keys between stores: missing (design question 12).
- Multi-store merge conflict file: unverified. Repo picker: present (`router/repos.go`, the app's Settings → Repos). Repo delivery: replaced by per-repo deploy keys (SSH).
- Content stores: deferred. Drop tokens: missing.

## Account and apps
- Re-login: via Jarvis 1. Usage quota: forwarded to Jarvis 1 (Settings card). Device pairing for OpenClaw/Paseo apps: deferred.
- Dashboard (app/DECISIONS.md 23–38): Sessions (live status, auto-pause/idle switches, resume prompt, destroy with the changes check, transcript, Discord link, needsGrant one-tap, permission mode, copy id), Grants (secure page, phone-signed), Terminal, Remote (with copy), per-session wakeups/crons, **Search** (conversations of both Jarvises, iCloud files), Previous (restore/tail/remove/delete), Tasks, Schedules, Stores, Repos, Settings (usage, Fly spend, core keys with copy), New session (one-shot, auto-pause, repos, API proxy, permission mode), banners, "Also on Fly": present. Devices, Content, lease pills, first-prompt attachments, the per-tab transcript filter on Sessions/Previous: missing.

## Harnesses and image
- Claude: present. OpenCode + Paseo, OpenClaw + claw-code: present (policy: opencode brings `openrouter` + `tunnel`, openclaw brings `claude` + `tunnel`; `GET /api/models[?harness=]`; the harness is signed in the cert's options). `harness-send`: present (holder `scheduler`). API proxy: present.
- Workspace layer: to verify. on-start hooks: present.
- Peer-message delivery: present (`r.Deliver`, router/peer.go; Jarvis 1's lib/peer.js run through the `scheduler` grant).
- Session-facing API (`$JARVIS_URL`): present — the machine's local proxy signs to `/m/api`; pull-secrets and changes answered on the machine; notify-idle and self-retire on the router; watches answer 501.
- Transcript search, iCloud index: forwarded to Jarvis 1 with the confined `jarvis2-services` token — for sessions (`/m/api`) and for the app (`/api/search*`, `/api/icloud/*`).

## Design questions parity raised
1. A command channel replacing Fly exec: answered — grants (DESIGN.md "Grants", DECISIONS 24).
2. Free text into machines (wakeup/cron/resume prompts, nudges): open — unsigned today (DESIGN.md "Open").
3. Where archives and transcripts live: answered — the Storage Box in Jarvis 1's layout with the router's creds, the signed snapshot alongside (DECISIONS 27, 38).
4. Restore after a burn: answered — the old core-signed cert + the snapshot's signature (DECISIONS 28).
5. Secrets outside sessions: tasks answered (DECISIONS 32–34); watches deferred; Discord and the budget cap use the router's own secrets (DECISIONS 25).
6. Fly read access for the budget cap: answered (`FLY_READ_TOKEN`, DECISIONS 17).
7. The Discord bot token: answered — lobster, in the router's SOPS secrets (DECISIONS 25–26).
8. Per-session tunnel origins: answered — the confined `jarvis2-tunnel` token + per-id proof.
9. Cross-Jarvis services: answered for now — Worker-confined Jarvis 1 tokens; each moves into Jarvis 2 before Jarvis 1 retires (PLAN.md "Later").
10. Which options are signed: answered — the harness and the permission mode (DECISIONS 30); size, model, one-shot, auto-pause, API proxy unsigned.
11. Arbitrary env injection: non-secret names only (DECISIONS 31).
12. Store authoring in the app (the app as trusted writer), copy between stores: open.
13. Attachments without SB on machines: answered (router-staged uploads); content stores deferred.
14. Device pairing for OpenClaw/Paseo: deferred ("Device pairing" below).
15. A machine reporting "busy" forever defeats auto-pause and the budget: open (the budget cap still pauses it).

## Device pairing for OpenClaw/Paseo (deferred)

Jarvis 1 mints one Access service token per paired app (`CF_DEVICE_TOKENS_API`); the apps then call only
`jarvis.deyaochen.com` (`/api/devices/pair`, `/api/remotes`, Start) and reach `<id>-s.deyaochen.com` with that
token. The Jarvis 2 router can't mint tokens and shouldn't. Smallest design, no app change: Jarvis 1's
`/api/remotes` appends Jarvis 2's list, fetched from `jarvis2.deyaochen.com/api/remotes` with one service token
(`jarvis2-remotes`: router env `JARVIS2_REMOTES_CLIENT_ID` = its client id; Access admits it on a path-scoped app
`jarvis2.deyaochen.com/api/remotes`, audience in router env `ACCESS_REMOTES_AUD`, policies Deyao's email + that token).
The apps' own device tokens already reach Jarvis 2 session hosts. Costs: a Jarvis 1 change; Jarvis 1 then holds a
token that reads every Jarvis 2 session's gateway token / pair link (as far as the `remote` grants allow); Start of a
paused Jarvis 2 session from the Paseo app stays Jarvis 1-only. The alternative is a second server in each app,
paired with Jarvis 2, which needs app work and a token story of its own.
