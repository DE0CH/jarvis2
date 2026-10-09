# Feature parity with Jarvis 1 (inventory, 2026-10-09)

Deyao asked for full parity with Jarvis 1. This lists every Jarvis 1 feature against Jarvis 2. J1 = claude-env
`selfhost/` (line numbers in `jarvis/server.js` unless named). Dependencies: SB Storage Box creds, FX arbitrary
Fly exec into the machine, FT Fly token, DT Discord bot token, GH GitHub token, CF Cloudflare API, CFA an Access
service token on the machine, OR OpenRouter, AT the Claude OAuth pair, K8s the box's API.

Facts: the router has no Fly token (it calls the core's start/kill/certify); its only way into a machine is the
`/m/commands` poll, which carries just `snapshot`.

## Session lifecycle
- **Create** (FT, AT): present. Idempotent `requestId`: present (a repeat answers the session it made). Lifecycle lock: 409 and `busy {kind, since}` in `/api/state`.
- **Pause / resume / resume on newer image**: present (snapshot on the router volume, machine-signed, not encrypted).
- **Resume prompt**: present (`POST /api/sessions/:id/resume {prompt}`, delivered as a peer message once started; router/schedule.go). Jarvis 1 typed it as a user prompt instead.
- **Start on another size / model**: present (`POST …/resume {size, model, apiProxy}`). Size goes to the core's open `start`, model to the env; neither is in the core's Options (only the harness is), so the dead-machine rule approves it with no phone step.
- **Wake job status**: present for permission-mode and restart (`wake {kind, phase, error, finishedAt}` in `/api/state`).
- **Restart / env patch / transcript rollback**: present (`router/sessionops.go`): restart = pause + resume on the same image; `env` takes NON-secret keys only (names that look like secrets, and Jarvis's own, are refused) and stays for later starts; the rollback is applied by the next machine after it verified the snapshot (`machine/rollback.go`, `JARVIS2_ROLLBACK`/`_PRED`). env-resync: every resume already re-pulls the stores; re-pull without a restart exists only inside add-store and downgrade.
- **Permission-mode switch**: present. Running: Jarvis 1's `set-permission-mode` in place through the `terminal` holder (any grant, standing rule or the allow list); paused: the next start's env. Mode stays unsigned env.
- **Auto-pause + idle countdown**: present (machine-reported status, `POST /api/sessions/:id/auto-pause`, `pauseInMs`; `autoPauseVeto` hook for the scheduler). Not ported: Jarvis 1's "don't release if it moved during the snapshot" check.
- **Destroy + archive + uncommitted-work check** (SB): present. Destroy pauses a running session first (its final signed snapshot), the router archives it to the Storage Box with its own creds (`router/archive.go`: Jarvis 1 layout + `jarvis2/` signed snapshot, cert, core cert; index `.index/jarvis2-destroyed-sessions.json`), runs `onDestroy` hooks, then burns. A failed archive leaves it paused (`?force=1` destroys anyway). `GET /api/sessions/:id/changes`: running via the `archive` holder's grant, paused from the snapshot's `.jarvis2-changes.txt`.
- **One-shot sessions**: present (`oneShot` → `SESSION_ONE_SHOT=1`; the router destroys on the supervisor's marker). Destroy doesn't archive yet, nor DM about lost work.
- **First prompt**: present (unsigned env). **First-prompt attachments**: present without SB on machines (`router/uploads.go`: `POST /api/uploads` staged on the router's volume, bound to the session at create; the first machine fetches them over `/m/attachments` and Jarvis 1's `session-attachments` reads them from a local `file://` staging dir into `~/uploads`).

## Previous sessions
- List: present (router-local). Transcript tail (paused: the volume's snapshot; destroyed: the archive), delete/purge: present. Restore a destroyed session: present as a NEW line (phone-approved like a new session) whose first machine restores the archived snapshot, checking the old core-signed cert passed in its env and the snapshot's signature (`router/restore.go`, `machine/restore.go`). Not phone-signed: which old snapshot is restored (the core's Options can't carry it). Indexing an archive by hand (J1 `POST /api/records`): missing.

## Terminal, remote control, title
- Registry read: present (the machine reports it: `/m/status {raw}`, `router/registry.go`). Live terminal (FX), app title sync (AT): missing.
- Remote page for opencode/openclaw: present (`GET /api/sessions/:id/remote`, `router/remote.go`): the Paseo pair URL or
  the OpenClaw gateway token, read through holder `remote` (its own key: a phone grant, standing rule or allow-list
  entry for `remote` opens it; refused → 403 `needsGrant: "remote"`), cached a minute per machine.
- `/api/remotes?harness=`: present on the router (Deyao's login, or the one service token `JARVIS2_REMOTES_CLIENT_ID`).
  Deyao's OpenClaw/Paseo apps don't see it yet: they pair with and poll only `jarvis.deyaochen.com` (below, "Device pairing").
- Per-session tunnel origin (CFA): built on the router side — harnesses opencode/openclaw bring the store `tunnel`
  (`CF_ACCESS_CLIENT_ID/SECRET` = Access service token `jarvis2-tunnel`); the machine fetches a proof for its own session id at boot (`GET /m/tunnel-proof` → `TUNNEL_AGENT_SECRET`, sent by agent.js
  as `x-agent-secret`). Needs the Worker + Access changes in "Tunnel token" below before it works. A paused Jarvis 2
  session's link gives the Worker's bare 503 (its Unpause page is for Jarvis 1 ids only).

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
- Multi-store merge conflict file: unverified. Repo picker: present (`router/repos.go`: `GET /api/github/repos` with a metadata-read-only `GITHUB_READ_TOKEN`; `GET|POST /api/repos`, `DELETE /api/repos/:name`, `repos` in `/api/state`). Repo delivery: replaced by per-repo tokens.
- Content stores: forwarded to Jarvis 1 like leases (same Jarvis 1 change needed). Drop tokens: missing.

## Account and apps
- Re-login: via J1. Usage quota: forwarded to J1 (`GET /api/usage`, services token). Device pairing for OpenClaw/Paseo apps, device list/revoke: missing
  (design question 14, below).
- Dashboard (app/DECISIONS.md 23–33): Sessions (live status, auto-pause/idle switches, resume prompt, destroy with the
  changes check, transcript, Discord link, needsGrant one-tap), Grants (secure page, phone-signed), Terminal, Remote,
  per-session wakeups/crons, Previous (restore/tail/remove/delete), Stores, Repos, Settings (usage, Fly spend), New session
  (one-shot, auto-pause, repos, API proxy), banners, "Also on Fly": present. Search, Tasks, task Schedules, Devices,
  Content, lease pills, first-prompt attachments: missing.

## Harnesses and image
- Claude: present. OpenCode + Paseo, OpenClaw + claw-code: present on the router (policy: opencode brings
  `openrouter` + `tunnel`, openclaw brings `claude` + `tunnel`; `GET /api/models[?harness=]` lists Jarvis 1's models
  per harness; the harness is signed in the cert's options → `SESSION_HARNESS`, the model goes as `SESSION_MODEL`,
  a model of another harness becomes the harness's default, an unknown one is refused). Their web UI needs the
  tunnel token (above). `harness-send`: present (`router/peer.go` queues prompts with `harness-send --queue` for
  both harnesses, holder `scheduler`). API proxy: present (`apiProxy` at New session and resume →
  `SESSION_API_PROXY=1`, read by Jarvis 1's claude supervisor; openclaw runs its own api-proxy.js).
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
8. Per-session tunnel origins without opening Jarvis 1's Access: answered by the confined `jarvis2-tunnel` token +
   per-id proof ("Tunnel token" below); waiting for the Worker deploy.
9. Cross-Jarvis services (leases, search, iCloud, content, schedule scripts): Worker-confined J1 tokens, or reimplement on `/m`?
10. Which options are signed (mode, model, size, auto-pause, one-shot, API proxy, repos). Today only the harness; raising the mode to bypass in place takes any `terminal` grant — should it need a fresh phone grant?
11. Arbitrary env injection: allowed at all? Today non-secret names only (a name filter, not a guarantee).
12. Store authoring in the app (the app as trusted writer), copy between stores.
13. Attachments and content stores without SB creds on every machine.
14. Device pairing for OpenClaw/Paseo: open ("Device pairing" below).
15. A machine reporting "busy" forever defeats auto-pause and the budget.

Deyao's direction (2026-10-09): features learn trust and are approved through the core in time-limited grants
(10 minutes at a time), so not everything goes through the core.

## Tunnel token (what the cf-tunnel Worker and Access need; not deployed from here)

1. Mint an Access service token `jarvis2-tunnel` (duration forever). Write the store `tunnel` (not sensitive) with
   `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` = its client id / secret, BEFORE the router with the new policy
   rolls out (the core refuses a session with an unknown store).
2. Access app `tunnel.deyaochen.com` ("Claude Tunnel"): its `allow-agent-service-token` policy includes the agent's
   token only; add `{service_token: {token_id: <jarvis2-tunnel's UUID>}}` to that policy's `include` (and to
   cf-tunnel/deploy.sh `ensure_app`, or a re-run drops it). The session hosts `*-s.deyaochen.com` already admit
   any token; `jarvis.deyaochen.com` too, which is why the Worker must confine it.
3. Worker: `CONFINED_TOKENS["<jarvis2-tunnel client id>"] = ["AGENT jarvis2"]`, a new rule kind: the token may
   only open `wss://tunnel.deyaochen.com/__agent/<id>` with `<id>` matching `^s[0-9a-f]{16}$` (the router's ids,
   `"s" + randID()`), nothing on jarvis.deyaochen.com or any session host, and only with `x-agent-secret` = hex
   HMAC-SHA256(Worker secret `JARVIS2_TUNNEL_KEY`, `"jarvis2-tunnel:" + id`) (fails closed without the secret;
   the header is stripped before the Durable Object). The same key goes in the router's env `JARVIS2_TUNNEL_KEY`.
   The token is shared by every Jarvis 2 session; the proof is what stops one session from registering
   another's id.
4. Deyao opens `https://<id>-s.deyaochen.com/` with his own login, as in Jarvis 1.

## Device pairing for OpenClaw/Paseo (open)

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
