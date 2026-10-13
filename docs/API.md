# Jarvis 2 — router API

The router (`router/`) is the only thing reachable from outside: `https://jarvis2.deyaochen.com`, through a
Cloudflare Tunnel behind Cloudflare Access. It is untrusted: everything security-relevant it relays is a
document signed by the core (`{payload, sig}`) or by the iPhone, and the receiving end checks the signature.

Formats (same as the core, `core/crypto.go`): a signed document is `{"payload": "<JSON text>", "sig":
"<base64 DER ECDSA-P256-SHA256 over the payload bytes>"}`; public keys are base64 of the 65-byte uncompressed
X9.63 point (CryptoKit `x963Representation`). Errors are JSON `{"error": "..."}` with an HTTP status; errors
that come from the core are relayed as the core's signed error document `{payload, sig}` whose payload is
`{"kind":"error","error":"..."}`.

## Who may call what

| Prefix | Caller | Access |
|---|---|---|
| `/api/*`, `/` (web page) | Deyao's app / browser | Access app `jarvis2.deyaochen.com`, Deyao's email only. The iPhone app sends the Access token in the `cf-access-token` header (got once from `/api/auth/start`). The router also verifies the `Cf-Access-Jwt-Assertion` header itself. |
| `/setup/*` | the trusted setup session | Access app `jarvis2.deyaochen.com/setup`, service token `jarvis2-setup` only (kept in Jarvis 1's `default` store, never on a machine). The router then checks the setup key's signature on each call (below). |
| `/actions/*` | anyone holding the actions key (`default` store) | Access app `jarvis2.deyaochen.com/actions`, service token `jarvis2-actions` only; the router checks the JWT's audience and client id (below, "Actions"). |
| `/m/*` | session machines | Not on the public hostname at all: the router serves `/m` on a second port (8081) that only Fly's private network reaches (the box is a WireGuard peer of org `jarvis2-370`). The router checks the machine's own signature on each request. |

## App sign-in

`GET /api/auth/start?redirect=jarvis2://auth` — Access makes Deyao log in first; the router then redirects to
`<redirect>#token=<the Access JWT>`. Only `jarvis2://` redirects are allowed. The app keeps the token in the
Keychain and sends it as `cf-access-token` on every request; when a request comes back 302/401/403 from
Access (token expired), it runs sign-in again.

## Sessions

A session's `id` is the router's (`s…`), stable for the session's life. `machineId` is the machine it is on now
(null before the first start and while paused). Session objects keep the Jarvis 1 shape where a field means the
same thing:

```
{ id, machineId, released, name, state, status, created, region, environment /* stores, comma-joined */,
  stores, harness /* claude | opencode | openclaw */, label, model, permissionMode, guest, pausedAt, error,
  autoPause /* "on" | "off" */, notifyIdle /* "on" | "off" */, oneShot, needsGrant /* a holder the machine refused */,
  lastReport /* the machine's last status report */,
  // while started, from the machine's report (fresh within 3 min), as in Jarvis 1:
  status /* busy | idle | waiting | … */, aiTitle, liveName, nameSource, bgTasks, statusUpdatedAt, bridgeSessionId,
  sessionId /* claude's conversation id */, authFailed, credsExpiresAt, sessionsInside, oneShotDone,
  refusals: [{kind: "fallback" | "refusal", at, uuid, from, to, model, category}],
  pauseInMs /* while the auto-pause countdown runs */,
  serverTitle /* the Claude app's own title of its Remote Control entry (the machine reads it; kept while paused) */,
  userTitle /* a name pinned in the CLI */, title /* what the card, channel and archive use: serverTitle → userTitle →
  label → aiTitle → id, Jarvis 1's pickTitle */, liveSync /* {at, files: {<name>: bytes}, stored, error} — the last live
  transcript copy (below) */,
  discordChannel /* the session's Discord channel id */, waiting /* what a pause or destroy waits on, plain words, or "" */, lockedStore /* the store the machine waits on at boot: its secrets pull got the core's 423 "store X is locked"; cleared by the next pull that goes through */, oldCore /* its line is an earlier core's: destroyed (archived in Previous) once paused (DESIGN "Carried secrets") */, wakeups: [wakeup view], crons: [cron view], watches: [watch view] /* below */,
  resumePrompt /* a prompt queued for delivery once started */ }
```

What the router does by itself with a running session (`router/autopilot.go`, every 30 s), from that report:
auto-pause after 1 h plain idle (unless `autoPause` is off, the session is one-shot, or another feature vetoes);
destroy a one-shot session once `oneShotDone` — forcefully (a failed archive doesn't stop it) and with a DM when work
was lost: dirty repos as its final snapshot recorded them, a repo check that couldn't run, or a failed archive
(`router/oneshot.go`, Jarvis 1's finishOneShot); Escape a prompt left `waiting` for 1 h (holder `status`); DM
"needs you" / idle / dead after 5 min in that state (the idle one muted by `notifyIdle` off); DM new safeguard
refusals and the "switch model?" dialog (holder `status` reads the pane); a Jarvis watchdog peer message every
15 min while idle with background jobs; and login repair: when the session's credentials expire before the
router's stored pair ("The Claude login" below) or its transcript ends on "Please run /login", write the pair
(holder `login`) and, for the latter, deliver "continue". A session holding the store
`claude` logs in and keeps in step by itself (machine/claudelogin.go): the router writes nothing there unless it
stays behind for 5 min, and only delivers "continue" to a stuck one once its pair is in step. A command the machine
refuses sets `needsGrant` to that holder and the loop leaves it alone for 10 min, or until a phone grant for that
holder is saved.

`state`: `approval` (waiting for the iPhone; no machine yet) → `starting` (the core makes the machine) →
`initialising` → `started` (running) → `pausing` → `paused` (no machine) → `resuming` → … ; `destroying` →
gone (moved to records); `failed` (with `error`).

| Call | Does |
|---|---|
| `GET /api/state` | `{sessions, approvals, core: {up, signingKey, agreementKey}}` |
| `GET /api/sizes` | `{sizes: [{id, label}]}` (small / medium / large) |
| `GET /api/models` | `?harness=` optional → `{models: [{id, label, harness}], default, defaults: {<harness>: id}, harnesses: {<harness>: {label, detail}}}` — Jarvis 1's list (Claude, OpenRouter via OpenCode, Claude via OpenClaw), only harnesses the policy has. In `POST /api/sessions` an empty model or one of another harness becomes the harness's default; an unknown one is refused (400). |
| `GET /api/stores` | Every store and the key NAMES it holds (never a value): `{stores: [{name, sensitive, empty, unlocked, keys /* sorted names, or null when not recorded */, keysFrom /* "setup" \| "deploy-key" \| "empty" \| "" */, keysAt?}], signed /* the core's signed list it was built from */}`. The list, sensitivity, empty and unlocked are the core's (`POST /stores`); the names come from the router's own record (`store-keys.json` in its data volume), written by the setup session (`POST /setup/store-keys`, sent by every `infra/setup.py write`), or, for a repo's store, follow from the repo (`GITHUB_DEPLOY_KEY_<SLUG>`, `GITHUB_DEPLOY_REPO_<SLUG>`). Only stores in the core are listed. Same answer at `GET /m/stores` and `GET /setup/stores/keys`. |
| `GET /api/policy` | `{harnesses: {<harness>: {stores: […]}}}` — the stores each harness brings (the router adds them; the app hides them) |
| `POST /api/sessions` | Body `{requestId, label, prompt, model, permissionMode, size, harness, stores: [], oneShot, autoPause, apiProxy, attachments: {uploadId, files: [{name}]}}` (`apiProxy`: `SESSION_API_PROXY=1`, claude through Jarvis 1's api-proxy.js; `attachments`: files staged by `POST /api/uploads`, bound to this session) (`oneShot`: the machine gets `SESSION_ONE_SHOT=1` and the session is destroyed when its prompt is done; `autoPause` defaults to true, false for one-shot; both show in the approval's `options`). The router adds the harness's stores and asks the core for a challenge (`succession(null, …)`, before any machine); the approval (kind `new-session`) appears at once. Answers `{id, requestId}`; a repeat with a `requestId` already on a session answers that session and makes nothing. |
| `POST /api/sessions/:id/pause` | The machine snapshots itself (signed), then the core kills it. |
| `POST /api/sessions/:id/resume` | Optional `prompt` (≤ 4000 chars): delivered into the session as a peer message once it is `started` again (dropped if the start fails or is rejected). Optional `size` (small/medium/large), `model`, `apiProxy` (bool): kept for this and later starts (not in the core's Options, so no approval). Body `{upgrade: false}`: the same image, `approve_by_dead_machine`, then start + certify — no approval. `{upgrade: true}`: the newest session image; an approval of kind `resume-upgrade` first (reject = stays paused), then start + certify. |
| `POST /api/sessions/:id/destroy` | A running session is paused first (the machine's final signed snapshot, then the core's kill); the snapshot is archived to the Storage Box (below); then a burn: a succession to the null image, approved by the dead-machine rule and certified. The session moves to `GET /api/records`. A failed archive leaves the session `paused` with `error: "archive: …"`; `?force=1` destroys anyway (the record keeps `archiveError`). |
| `GET /api/sessions/:id/changes` | Uncommitted / unpushed work per repo under `~/workspace`: `{checked, paused?, reason?, status?, repos: [{name, uncommitted, unpushed /* -1 = no upstream */}]}`. Running: a shell command under the `archive` holder (a grant, standing rule or the session's allow list); paused: as the last snapshot recorded it. |
| `GET /api/sessions/:id/cert` | The line's latest core-signed succession cert `{payload, sig}` (404 before the first certify). The app's grant page reads `line`, `phone`, `stores` and `sensitive` from it after checking the core's signature. |
| `GET /api/holders` | `{holders: {<name>: <public key>}}`: the router's features that may hold grants (terminal, scheduler, status, login, archive). |
| `POST /api/sessions/:id/grants/draft` | Body `{holder, kind: "grant" \| "rule", minutes /* grant: 1–10 */, until /* rule: RFC 3339 */}` → `{text}`: exactly what the phone signs, `{kind, holder /* its public key */, session /* the line */, scope: "shell", issued, expires \| until}`. |
| `POST /api/sessions/:id/grants` | Body `{payload: text, sig}` (the phone's signature) → the stored grant `{id, session, holder, kind, ends, doc}`; refused unless the cert's phone key signed it for this line. |
| `GET /api/sessions/:id/grants` | `{grants: [...]}` (live ones; ended ones are dropped). `DELETE /api/grants/:gid` forgets one (the router stops using it; the signed text stays valid on the machine until it ends). |
| `GET /api/sessions/:id/terminal` | `{screen /* tmux capture-pane -e */, cursor: "x,y,width,height,visible", at?}` — no grant: the pane the machine pushes itself every 2 s when it changes (`POST /m/screen`, `machine/screen.go`; `at` = when, fresh for 45 s); a machine without the push is read by an exec under holder `terminal`. `POST` `{text?, keys?: [tmux key names]}` types, `{cols, rows}` resizes the window. |
| `GET /term/:id` | The terminal as a web page (`router/web/terminal.html`, one self-contained file: no outside scripts, strict CSP, `no-store`): polls the snapshot above once a second, sends keys and text in order, fits the window to the screen. The iPhone app shows it in a WKWebView and listens on the message handler `jarvis2`: `{action: "grant", holder: "terminal"}` (open the app's Face ID grant review) and `{action: "signin"}` (the Access login expired); it calls `window.jarvis2Refresh()` once the grant is signed or the login renewed. In a plain browser the grant button files `POST /api/requests/grant` (minutes 10) and an expired login reloads the page once. The id must be `[A-Za-z0-9-]` (else 404). |
| `GET /api/sessions/:id/tail` | A paused session's conversation end, from its snapshot: `{title, sessionId, messages: [{role, text, at}]}` (409 while it runs, 404 without a snapshot). |
| `GET /api/state` (extra fields) | `budget`: `{month, spentUsd, capUsd, warnUsd, warned, capped, cappedAt, ratePerHour, perMonth, running, volumes, sampledAt}` or null; `fly`: `{apps, app, machines, volumes, other: [{kind, app, id, name, state, region, created, detail}], error, checkedAt}` ("Also on Fly": machines in app jarvis2-sessions that are no running session of the router's, and volumes); `flyApp`. |
| `GET /api/state` (`browserbaseBudget`) | `{month, capUsd, warnUsd, overUsd, parts: {time, proxyMb, proxyBytes, total}, usage: {count, minutes, proxyMb, proxyBytes}, warned, capped, sampledAt}` or null (`router/bbbudget.go`: the month re-priced from Browserbase's session list every 10 min; one DM at the warn line, one at the cap; nothing is blocked). |
| `GET /api/machines` | The Machines tab (`router/machines.go`): every machine in Fly app jarvis2-sessions, live from Fly with the read-only `FLY_READ_TOKEN`, newest first: `{app, machines: [{id, name, state, region, size /* small\|medium\|large or "" */, guest, image, created, updated, sessionId /* "" = no session */, current /* the session's machine now; false = an earlier one */, routerUrl /* its JARVIS2_URL */, test /* routerUrl isn't jarvis2-box's */, noDestroy /* why Destroy isn't offered, "" = it is */, attention /* why it stands out (stopped, failed, stuck, no session), "" = it doesn't */}], orgs: [{org, via /* "fly" \| "Jarvis 1" */, error, checkedAt, apps: [{app, label /* "Jarvis 2 sessions"…, "" = an app no Jarvis uses */, own /* jarvis2-sessions */, status, error, machines: [same fields; other apps: no session/router, noDestroy "read-only", otherSession /* a Jarvis 1 session id */], volumes: [{id, name, state, region, sizeGb, attachedTo, created, attention}]}]}], attention /* how many things stand out */, configError, checkedAt}`. Every org Deyao has (`router/flyorgs.go`): jarvis2-370 and kamyee read from Fly with READ-ONLY org tokens (`FLY_ORG_READ_TOKENS`), personal from Jarvis 1's sanitized `GET /api/fly/machines` (the confined services token; no Fly token for personal: it would read Jarvis 1's session secrets in their Fly env). An org that can't be read comes back with `error`. 502 `{error}` when jarvis2-sessions can't be listed. |
| `POST /api/machines/:id/destroy` | Destroy a machine that belongs to NO session, re-checked on a fresh Fly list: the router never started it (no session mapping, Started entry or cert) and it is at least 15 minutes old (a Start's machine exists before the router records it). The router asks the core's `kill` (the call a pause makes; the core alone holds a destroying Fly token). → `{ok, id}`; 409 `{error}` for a session machine or a too-new one; 400 for an unknown id; the core's signed error when the kill fails. |
| `GET /api/records` | Destroyed sessions `{records: [...]}`; each has `archive: {dir, title, transcripts, artifacts, signer, snapshotAt, last}` when it was archived, `archiveError`, `restored: [{sessionId, at}]`. |
| `POST /api/records` | Index an archive ALREADY on the Storage Box, by hand (Jarvis 1's call): `{archiveDir: "claude-records/<folder>", transcripts: [file…], artifacts?, title?, environment? \| stores?, repos?, permissionMode?, model?, size?, harness?, created?, destroyedAt?}` → `{ok, record}` (id `archive-<the first transcript's uuid prefix>`). The transcripts must exist; nothing is scanned. Such a record has no machine-signed snapshot (`archive.signer` empty), so its tail, Remove and Delete work and Restore is refused (400). |
| `GET /api/records/:id/tail` | The archived conversation's end (a Range read of its newest transcript), same shape as the session tail. |
| `DELETE /api/records/:id` | Off the list and the Storage Box index; `?purge=1` deletes its archive too (the whole dir, or only its own files when another record shares the dir). |
| `POST /api/records/:id/restore` | Body `{requestId?}` → `{id, requestId}`. A NEW session (new line) with the record's options; an approval of kind `new-session` with `options.restore` naming the record. Its first machine restores the archived snapshot (below). |
| `POST /api/sessions/:id/auto-pause` | Body `{on}` (Jarvis 1's `{enabled}` works too) → `{ok, autoPause: "on" | "off"}`; restarts the idle countdown. |
| `POST /api/sessions/:id/notify-idle` | Body `{on}` → `{ok, notifyIdle}`: mutes only the idle DM; "needs you", dead and downgrade DMs still come. |
| `GET /api/sessions/:id/remote` | OpenCode/OpenClaw only (400 otherwise; 409 unless `started`): `{webUrl, harness, pairUrl, relay}` (opencode: the Paseo app's pairing link) or `{webUrl /* …#token= */, harness, url /* wss://<id>-s.deyaochen.com */, token}` (openclaw: the gateway token). Read in the machine as holder `remote` (a grant, standing rule or allow-list entry); refused → 403 `{error, needsGrant: "remote"}`; front end not up → 503 `{error}`. Cached 1 min per machine. `webUrl` = `https://<session id>-s.deyaochen.com/` (suffix: router env `SESSION_TUNNEL_SUFFIX`). |
| `GET /api/remotes?harness=openclaw\|opencode` | Jarvis 1's shape: `{sessions: [{id, title, state, model, + url, token, webUrl (openclaw) \| pairUrl (opencode), or error (+ needsGrant)}]}`; secrets only for a started session. Deyao, or a paired app's Access service token ("Paired apps" below). |
| `POST /api/sessions/:id/start` | The paired apps' Start of a paused session (Jarvis 1's call): a resume on the same image, no phone step → 202 `{ok}`. Deyao or a paired app. |
| `POST /api/sessions/:id/permission-mode` | Body `{mode: "auto" | "bypass"}`. Running → 202 `{started, inPlace}`: Jarvis 1's `set-permission-mode` under the `terminal` holder (claude relaunches `--resume` in the new mode; nothing else restarts); a refusal sets `needsGrant: "terminal"`. Paused → 200 `{nextStart: true}`. Same mode → `{unchanged: true}`. |
| `POST /api/sessions/:id/restart` | Body `{env?, rollback?: {dropFromMarker}, prompt?, size?, model?, apiProxy?}` → 202. Pause (if running) + resume on the same image. `env`: `{NAME: value}` patch kept for later starts (`""`/null removes); names that look like secrets (TOKEN, SECRET, PASSWORD, API_KEY, `_KEY`, `_API`, AUTH, …) or Jarvis's own (`JARVIS*_`, `SESSION_`, `CLAUDE_`, `ANTHROPIC_`, `CF_ACCESS_`, `LOBSTER_`, `FLY_`, `LD_`, PATH, HOME…) → 400: secrets come only from stores. `rollback`: the next machine, after verifying the paused snapshot, drops every conversation-transcript line from the first containing the marker (env `JARVIS2_ROLLBACK` + `JARVIS2_ROLLBACK_PRED` = the paused machine; ignored by any other start). |
| `POST /api/sessions/:id/env` | Jarvis 1's shape `{env}` = a restart with only `env`. |
| `POST /api/sessions/:id/upgrade` | The one tap out of a memory-starvation episode (`router/memory.go`) → 202 `{started, kind: "upgrade", from, to}`. A running session moves to the next size (small → medium → large; no size = medium): the machine frees memory first (command `free`: the harness SIGSTOPped, every other process of the session user SIGKILLed, their list in `~/artifacts/jarvis2-upgrade-freed.txt`), then the usual pause (its signed snapshot) and resume on the bigger size (no approval: size isn't in the core's Options), then the canned `upgraded` delivery tells the session what was stopped. Job `wake: {kind: "upgrade", phase: freeing → snapshotting → resuming → done \| failed}`, `busy: {kind: "upgrading"}`. 409 when not running, busy, or already large. |
| `GET /api/state` (per session) | `busy: {kind: pausing | starting | destroying | mode | restarting | upgrading, since}` while a lifecycle action holds it (others 409); `wake: {kind, phase, error, startedAt, finishedAt}` for a permission-mode / restart job (kept 10 min after it ends); `apiProxy`, `envKeys`. A running session also carries `memory: {totalMb, availMb, at}` (its latest report, while fresh) and, during a memory-starvation episode, `memAlert: {since, reason, detail, nextSize /* "medium" \| "large", "" = already the biggest */}` (`router/memory.go`: an OOM kill, PSI memory full avg60 ≥ 10 %, MemAvailable < 5 %, or no report for 90 s while under 15 % free; DMed once per episode, ends after 15 min healthy). Top level: `repos`. |
| `POST /api/uploads` | First-prompt attachments: one raw file per request, headers `x-upload-id` (`[A-Za-z0-9_-]{1,64}`, groups a form's files) and `x-upload-name` (URI-encoded; made a safe basename as in Jarvis 1) → `{name, size, isImage}`. ≤ 20 files, 25 MB each (413). Staged on the router's volume; unbound uploads go after 24 h, bound ones with their session. Each bound file's sha256 and size go into the new line's signed config (`attachments: [{name, sha256, size}]`). |
| `GET /api/sessions/:id/attachments/:name` | The bytes of a file staged for that session (until its first machine has fetched them; 404 after): the app's approval page shows it and hashes it against the signed config. |
| `GET /api/repos` | Deyao's repo list, for Settings → Repos and New session's `repos`: `{repos: [{name, url /* https://github.com/<repo>.git */, repo /* owner/name */, store /* github-<repo> */, sensitive, fingerprint?, keyAt?}]}`. GitHub repos only; an entry is added or removed only by the core's answer to `POST /api/repos/key/finish` (below). |
| `POST /api/repos/key/begin {action: add \| remove, repo: owner/name \| GitHub URL, sensitive?, store, title, publicKey?, blob?}` | Relayed to the core's `deploy-keys/begin` (the repo normalised to `owner/name`; the app's store, title and key pair as sent): its signed begin document, which the shell's secure page checks and the phone answers. 400 for a non-GitHub repo or another action; 501 `{error}` from a core older than deploy keys. |
| `POST /api/repos/key/finish {pending, signature, share}` | Relayed to `deploy-keys/finish`; on the core's signed `deploy-key-added` the repo goes on the list (with `sensitive`, and `fingerprint` = SHA256 of the answer's `publicKey`, or the answer's own `fingerprint` from a core before R2), on `deploy-key-removed` it comes off. The answer is the core's, unchanged. |
| `GET /api/github/repos` | `{repos: [{fullName, url, htmlUrl, private, fork, archived, description, language, pushedAt, owner}], cachedAt, configured}` (5 min cache, `?refresh=1`), listed with `GITHUB_READ_TOKEN` (router env; Metadata read picked explicitly, else GitHub lists public repos only — sessions push with their repos' deploy keys). 503 without it. |
| `GET /api/usage` | The Claude quota, read by the router with its stored access token (Jarvis 1's shape, `router/claudelogin.go`): `{fetchedAt, limits: [{kind, group, percent, severity, resetsAt, model, surface, active}], extraUsage: {enabled, monthlyLimit, usedCredits, utilization, currency, decimalPlaces, disabledReason, spendLimitReached} \| null, cached, stale?, error?}`; cached a minute (`?refresh=1` skips it); a failed fetch answers the last good reading with `stale`; 409 `{error, needLogin}` when Claude refuses the token. |
| `GET /api/claude-login` | The Claude login, no secrets: `{mode: "own" \| "follow", hasLogin, expiresAt, expired, email, accountUuid, source, updatedAt, refreshedAt, participants: [{id, seen}], loginInProgress, preparing, error?, rejected?, needLogin?}` (below, "The Claude login"). |
| `POST /api/claude-login/refresh` | Refresh now (mode `own` only; 409 in `follow`) → `{ok, refreshed, expiresAt}`; 409/502 `{error, needLogin}`. |
| `POST /api/claude-login/start` | Re-login, step 1 → `{url}`: the CLI's sign-in page (claude.com/cai/oauth/authorize, PKCE, the manual redirect). The verifier is kept on the router's volume for 15 minutes, so a rollout doesn't lose it. |
| `POST /api/claude-login/code` | Re-login, step 2: `{code}` = the `code#state` the sign-in page shows → the CLI's token exchange and profile → stored (any account: Deyao's own action) → `{ok, email, expiresAt}`; sessions stuck on "Please run /login" get "continue" on the next tick. In mode `follow` the new pair also goes to Jarvis 1. |
| `GET /api/search`, `/api/search/context`, `/api/search/status`, `POST /api/search/reindex`; `GET /api/icloud/search`, `/api/icloud/file`, `/api/icloud/status`; `POST /api/icloud/relist`, `/api/icloud/retry` | The app's Search tab: forwarded to the box's own services (`router/searchsvc.go`; "Transcript search" and "iCloud index" below) with the query and body unchanged. 502 `{error: "… unreachable: …"}` when the service is down. |

### Archives (Storage Box, router env `STORAGEBOX_HOST/USER/PASSWORD`)

`claude-records/<yyyy-mm-dd> <title>/` (Jarvis 1's layout; ` 2`, ` 3`… when taken): `transcript-<id>.jsonl`, `artifacts/**`,
`session.json`, `restore-<session id>.json`, and `jarvis2/snapshot.tar.gz` + `snapshot.sig` (the machine's signature over the
sha256 hex) + `cert.json` (the signer's core-signed cert) + `core-cert.json` (the master-signed claim naming the core's key). Index:
`claude-records/.index/jarvis2-destroyed-sessions.json` (newest first). `RECORDS_OFF=1` (the e2e test) destroys without archiving.
While a session runs, its transcripts are also copied to `claude-records/.live/<session id>/<uuid>.jsonl` (`POST /m/live-transcript`
above), deleted on destroy.

Restore trust: the router passes the old cert to the new line's first machine in `JARVIS2_RESTORE_CERT`; the machine accepts
it only with no predecessor, checks it against the core key, the snapshot (`GET /m/restore-snapshot`) against the cert's
machine key, and refuses a sensitive line's snapshot into a line without a sensitive store. Which snapshot is restored is the
router's word, not the phone's (the core's options can't carry it).

### Jarvis 1 import (`router/jarvis1import.go`, `machine/jarvis1import.go`)

A paused Jarvis 1 session (`claude-records/.paused/<id>/` on the Storage Box: `<uuid>.jsonl`, `claude.json`,
`workspace.tar.gz`, `artifacts.tar.gz`, `harness.tar.gz`, `session.json`, `manifest.txt` written last) becomes a NEW
line, approved on the phone like a new session, whose first machine restores it and resumes the same conversation.

| Call | Does |
|---|---|
| `GET /api/jarvis1/paused` (`/setup/…` too) | `{sessions: [{id, title, pausedAt, size, model, environment, repos, prepare?, sha256?, sessions: [{id, state}], imported?}]}` from Jarvis 1's index `claude-records/.index/paused-sessions.json`, with each one's import state here. |
| `GET /api/jarvis1/paused/{id}` | That one's state: `prepare {state preparing\|ready\|failed, file, bytesDone, bytesTotal, error, sha256}`, `sha256` (the prepared manifest's), the Jarvis 2 sessions made from it, `imported {session, at}` once one came up. |
| `POST /api/jarvis1/paused/{id}/prepare` | 202: the router streams every file once (the names above; `changes.txt` and `artifacts-manifest.txt` are not taken) and hashes it, then writes the import manifest `{kind: "jarvis1-import", v: 1, session, files: [{name, sha256, size}]}` and Jarvis 1's record onto its volume (`jarvis1-imports/<id>/`). Refused without `manifest.txt` (an incomplete snapshot). |
| `POST /api/jarvis1/paused/{id}/import` | Body `{stores: [...], explanation, prompt?, size?}` (the harness's stores come with it; `explanation` required from the setup session) → `{id, from, approval: true}`: a new session in `approval` (Inbox kind `new-session`, `options.restore` = "Jarvis 1 session “title” (id, paused date)"). Its cert's config: `label` = Jarvis 1's app title, `prompt` = a move notice typed into the resumed conversation (or the given one), Jarvis 1's model, permission mode, repos, auto-pause; `size` Jarvis 1's (`xlarge` → `large`); `restore = {machine: <Jarvis 1 id>, sha256: <the manifest's sha256>}`. The same import again answers the same session (`createRequestId` `jarvis1-import:<id>:<sha prefix>`). 400 before a prepare. |

The machine (only the line's first, only when its cert names the restore) fetches the manifest (`GET /m/restore-snapshot`),
checks its sha256 against the cert, then each file (`GET /m/import-file/{name}`, streamed from the Storage Box: the machine
holds no Storage Box credential) against the manifest's sha256 and size, extracting tarballs into a staging dir while
hashing and moving them into place only once they match (entries outside `workspace/`, `artifacts/` or the harness roots, or
through a symlink, are skipped). The transcripts go to `~/.claude/projects/<slug of the working dir>/` after the repos are
cloned, `~/.claude.json` without `oauthAccount`/`userID`, GitHub remotes without embedded credentials (ending in `.git`, so
the deploy-key rewrites apply). Jarvis 1's armed wakeups and crons (`metadata.wake_*`, `cron_*`) are armed again as the
line's own signed requests: a passed wakeup 5 minutes after boot; a cron with its period, time zone and end, next run after
now, plus a one-off wakeup `missed-<name>` 5 minutes after boot when a run fell while paused. What was armed:
`~/artifacts/jarvis1-import/rearmed.txt` (beside Jarvis 1's `session.json`).

## Approvals (the shell's secure pages)

```
approval = { id, kind: "new-session" | "resume-upgrade" | "add-store", created, session, machine /* add-store */,
             label, challenge /* the core-signed challenge doc */, options /* the form's fields, for display */,
             origin: {caller, call} /* who asked, from the credential (Requests) */, explanation /* a session's add-store */ }
```

| Call | Does |
|---|---|
| `GET /api/approvals` | `{approvals: [...]}` |
| `POST /api/approvals/:id/respond` | Body `{signature}` = base64 DER signature by the phone's signing key over **exactly** `challenge.payload`. Router → core `approve/by-phone`. Answers `{answer, session}`: a core-signed `approval` (then the router starts and certifies the machine) or, for `add-store`, the new `succession-cert`. |
| `POST /api/approvals/:id/reject` | Drops it; a new session disappears, a resume-upgrade stays paused. |

The phone may approve anything; it shows exactly what it signs (`request.stores`, `request.sensitive`,
`request.options`, `request.image`, `request.addedStore`).

## Requests (the app's Inbox, `router/inbox.go`)

A request asks the phone for something that needs Face ID; it waits in the app's Inbox until Deyao reviews it on the
shell's secure page (docs/DESIGN.md "Requests"). The **intent endpoints** are the same under three prefixes, one per
kind of caller; the router records the caller from the credential (never from the body) and the call:

| Prefix | Caller | Credential |
|---|---|---|
| `/api/requests/…` | the web page, or the app (`cf-access-token` header) | Deyao's Access login |
| `/setup/requests/…` | Claude, the setup session | the setup key's signature (as every `/setup` call) |
| `/m/api/requests/…` | a session (`$JARVIS_URL/api/requests/…` through the machine's proxy; `jarvis2-request` in the image) | the machine key |

| Intent | Body (`explanation` in every one) | Who |
|---|---|---|
| `POST …/repo/add` | `{repo /* owner/name or a GitHub URL */, sensitive?}` | anyone |
| `POST …/repo/remove` | `{repo}` | not a session |
| `POST …/grant` | `{session, holder, minutes /* 1–10, default 10 */}` or `{session, holder, days /* 1–365: a standing rule */}` | a session only for itself (it may leave `session` out) |
| `POST …/unlock` | `{session}`: the locked stores that session waits on | a session only for itself |
| `POST /m/api/requests/add-store` | `{store}` → the router's `add-store` approval (as `POST /m/add-store`) | a session, for itself |
| `POST /m/api/sessions` | `POST /api/sessions`'s body without `attachments`, plus `explanation` (required) → `{id, requestId, approval: true}`: a session PROPOSES a new session (`jarvis2-request new-session`). The same line and `new-session` approval as the app's New session (a succession from null, so it starts only on Deyao's Face ID); the approval's caller is the proposing session and it carries the explanation. `requestId` is scoped to the proposing session; at most 3 proposals wait per session (429). | a session |

`explanation`: the caller's reason, required from a session and the setup session (plain text; control and format
characters dropped; ≤ 600 characters, ≤ 8 lines; 400 otherwise). Answer `{id, duplicate, expires}`: the same kind and
arguments already pending answer that request (`duplicate: true`); 400 for bad arguments, 403 for what this caller may
not ask; at most 20 pending per caller. A request goes after 10 minutes, when its session is destroyed, when it is done
(a repo request when the core's deploy-key answer for that repo comes back by any path; a grant request when a grant
for that feature is stored), or on Deny.

```
item = { id, kind: "repo-key" | "grant" | "unlock" | "new-session" | "resume-upgrade" | "add-store", approval /* bool */,
         params: {action, repo, sensitive, session, holder, minutes, days}, session, sessionName,
         caller: {kind: "web" | "app" | "session" | "setup" | "router", session}, callerText /* "session “X” (s…)",
         "the web page", "Claude (setup session)" */, call: {method, path, args},
         explanation, created, expires, options /* an approval's form fields */,
         open: {kind /* the shell page */, options /* its options, with inboxId */} }
```

| Call | Does |
|---|---|
| `GET /api/requests` | `{requests: [item]}`, newest first; also `inbox` in `GET /api/state` (the badge) |
| `GET /api/requests/:id` | one item (404 when answered, denied or expired); the shell reads the call and the reason here |
| `DELETE /api/requests/:id` | Deny: dropped (an approval is rejected, as `…/approvals/:id/reject`) |
| `POST /api/requests/:id/done` | the shell's page went through: the request leaves the Inbox |
| `GET /setup/requests`, `GET /m/api/requests` | the same list for Claude; a session sees only its own |
| `GET /setup/repos` | the router's repo list (`infra/setup.py repos`) |
| `GET /setup/sessions` | `{sessions: [{id, machineId, state, title}]}` (`infra/setup.py sessions`; the phone replica finds a session's machine here) |

The app never takes the title from the router: the list renders it from `kind` + `params` (`src/lib/inbox.ts`), and
the review page renders "What you sign (exact)" from the signed content (`Shell/SignedAction.swift`). The shell checks
that the item's `open.options` equal its own page's (repo, action, session, feature, length) and says so when not.

## The core, relayed (`/api/core/*`)

When the core can't be reached at all (its pod restarting, e.g. after a wipe) every one of these answers 503
`{error: "the core isn't running", coreDown: true}`; the app waits or shows it as a plain note.
Pass-through to the core's own endpoints, answers unchanged (signed): `GET identity`, `POST stores {nonce}`,
`POST stores/create {name}`, `POST stores/mark-sensitive {name}`, `POST stores/write {store}`, `POST unlock/begin
{store, for?}`, `POST unlock/finish {pending, share}`, `POST lock {id}`, `POST unlocked {nonce}`, `POST store-key {phone}`, and
— only from the app's device login (the `cf-access-token` header; 403 otherwise) — `POST claim {statement,
masterSig, bundle}` and `POST wipe {statement, masterSig}`. Formats: `docs/DESIGN.md`, `core/core.go`, the app's
`Shell/CoreSetup.swift`, and the reference client `e2e/main.go`. A claim the core accepts is kept by the router
(`DATA_DIR/core-certs.json`, the newest 10): the master-signed statement naming the core verifies on its own, so the
core keeps no copy; the router serves the running core's at `GET /setup/core-cert` and into each archive.

Setting the core up (Reset and Recover, the app's Reset or recover page):

- `GET identity` → `{signingKey, agreementKey, boxSig, state}`: `boxSig` = the box key's signature over
  `"jarvis2-core-identity <signingKey> <agreementKey>"` (checked against `keys/box.pub` from GitHub); `state` = a
  core-signed doc `{"kind":"core-state","master": <the master public key it was set up with, "" while empty>,
  "phone": {signingKey, agreementKey} | null}`.
- `claim`: `statement` = the JSON text `{"kind":"claim","master","core":{signingKey,agreementKey},"phone":{…},
  "bundleSha256"}`, `masterSig` = that master key's base64 DER ECDSA over it, `bundle` = `{"format":"blobs",
  "stores":"blobs", blobs: [StoreBlob], notSensitive: [names], owners: {store: "owner/name"}, flyToken}` sealed to the
  core's agreement key (ephemeral P-256, HKDF-SHA256 info `"jarvis2/claim"`, AES-256-GCM combined) → the core's
  signed `{"kind":"claimed","stores": n}`; 409 when the core is set up already, 400 "bad bundle" for any other bundle
  (the older plaintext form `{stores:[{name, values}]}` among them). Each blob is a store the app wrapped itself to the
  store key (`store-key`, below), so the core never sees a store's plaintext; `owners` names each deploy-key store's
  repo (the app reads it from the store's `GITHUB_DEPLOY_REPO_*`); `flyToken` is the `core` store's `FLY_API_TOKEN`,
  which never becomes a store. Reset sends no blobs; Recover every store from the backups.
- `wipe`: `statement` = `{"kind":"wipe","core": <the core's signing key>}`, signed by the master key the core was
  set up with → the core's signed `{"kind":"wiping","core"}`, then it exits; a new, empty core follows.

## Backups (`/api/backups`)

`GET /api/backups` → `{bucket, objects: [{key, body}]}`: every object under `stores/` and `sensitive/` in the
versioned bucket `jarvis2-backup-de0ch`, `body` its text unchanged — `stores/<name>.json` = `{doc, sig}` with `doc`
= `{"kind":"store-backup","name","sensitive","sealed":{e,data},"at"}` (the values sealed to the master key, HKDF info
`"jarvis2/backup"`, the store's name as associated data) and `sig` the setup key's ECDSA over `doc`;
`sensitive/<name>.json` = a signed `{"kind":"store-sensitive","name","at"}` marker. The router reads them with its
own read credential (router env `BACKUP_READ_ACCESS_KEY/SECRET_KEY`; `BACKUP_ENDPOINT`, `BACKUP_REGION`,
`BACKUP_BUCKET` default to the production bucket) and answers 503 without it, 502 when the bucket refuses. The app
checks each `sig` against `keys/setup.pub` (from GitHub) and opens each backup with the master key from the kit. Settings → Encrypted backup saves the same answer, checked but unopened, as one file for
`tools/decrypt-backup.py` (RUNBOOK "Offline copy of the stores").

Unlocks for one session (DESIGN "Carried secrets"): `unlock/begin {store, for}` with `for` = the nonce of the challenge
(New session's Start, an approval of a new line, an add-store) or of the session's cert (Unlock…) → the begin doc
carries `for`; only the cert with that nonce reads the store, its first pull that goes through locks it again, and an
unused one lapses after 30 min. No `for` = a standing unlock (the Stores page), open to every session until locked. The
signed `stores` list's `unlocked` means standing only; `unlocked` rows carry `for` ("" = standing). `for` that isn't a 64-hex nonce: 400.

Unlock, phone side: verify `unlock/begin`'s doc (kind `unlock-begin`, fields `pending, store, e, t, for`); Face
ID → Enclave key agreement of the phone's agreement key with `e` → the 32-byte x-coordinate; seal it to `t`:
ephemeral P-256 key `r`, `x' = x(r·t)`, key = HKDF-SHA256(ikm `x'`, salt empty, info `"jarvis2/unlock-share"`,
32 bytes), AES-256-GCM combined (`nonce‖ciphertext‖tag`) → `share = {e: base64(r.pub x963), data:
base64(combined)}` → `unlock/finish {pending, share}`.

## Deploy keys (the core: `deploy-keys/*`, `core/deploykeys.go`)

- `POST deploy-keys/begin {action: add | remove, repo: owner/name, sensitive, store, title, publicKey, blob}`: the
  app names the store (`github-<name>` for DE0CH, else `github-<owner>-<name>`) and the key's title on GitHub
  (`jarvis2 <store>`), and for an add makes the key pair: `publicKey` ("ssh-ed25519 <base64 wire>") and `blob`, the
  store `{GITHUB_DEPLOY_REPO_<SLUG>: "owner/name", GITHUB_DEPLOY_KEY_<SLUG>: base64(OpenSSH private key file)}`
  (`<SLUG>` = `OWNER_NAME`, upper case, other characters `_`) wrapped to the store key from `POST store-key` → the
  core's signed `{"kind":"deploy-key-begin", pending, action, repo, store, sensitive /* add: asked for, OR the store
  is sensitive already; remove: the store's */, replaces /* add: the store exists */, title, publicKey, blobE,
  blobSha256 /* add: the blob's E and the sha256 hex of its data */, tokenStore: "github-deploy-keys", tokenWriter,
  tokenDataSha256, e /* that store's E */, t /* a one-off key */}`, so the phone's signature covers the key and the
  blob. The app keeps `DE0CH/jarvis2`'s store sensitive itself (it asks for it, and refuses a begin that isn't).
  400 for an add without the key pair or with a blob for another store, or a title that isn't one short line; 404
  while `github-deploy-keys` has no contents; 409 on an empty core; 409 `store github-x belongs to <owner/name>` when
  another repo owns that store name (names collide: `DE0CH/foo-bar` and `foo/bar`, `my.repo` and `My-Repo`; the owner
  is the repo whose add wrote the store, or after a Recover the bundle's `owners`; finish checks it again); 400 for a
  bad repo or store name (`github-deploy-keys` and `core` aren't allowed).
- `POST deploy-keys/finish {pending, signature, share}`: `signature` = the phone's base64 DER ECDSA over the begin
  document's payload (its signing key from the claim), `share` = x(p·E) of the token store sealed to `t` exactly as
  an unlock's share (HKDF info `"jarvis2/unlock-share"`); the shell makes both under one Face ID. One try per
  pending. The core opens `github-deploy-keys` for this call only (it never joins the unlocked set) and reads
  `GITHUB_DEPLOY_KEYS_TOKEN`; it deletes the repo's keys titled `jarvis2 <store>` on GitHub (`GET/DELETE
  /repos/{repo}/keys`), then — add — adds the app's public key (`POST /repos/{repo}/keys`, `read_only: false`) and
  stores exactly the app's blob (writer `core`) →
  `{"kind":"deploy-key-added", pending, repo, store, sensitive, title, publicKey, keyId}`; or —
  remove — deletes the store → `{"kind":"deploy-key-removed", pending, repo, store, deleted}`. 403 for a wrong
  signature or share; 502 `github: HTTP <status>: <GitHub's words>` when GitHub refuses (the router's
  `/api/repos/key/finish` turns a 403/404 into what the token needs: Repository "Administration: read and write").
- `POST store-key {phone}` → the core's signed `{"kind":"store-key", phone, storeKey}`: `storeKey` = P + K (X9.63
  base64) for that phone agreement key P. Open, also on an empty core: what the app wraps a data key to (one-off e,
  HKDF-SHA256 of x(e·storeKey) with info `"jarvis2/store-data-key"`, AES-256-GCM nonce‖ciphertext), since CryptoKit
  can't add points: a deploy key's store, and every store of a Recover's bundle (`claim`, above).

## Actions (`/actions/*`, `router/actions.go`)

The actions key (Deyao, 2026-10-13): the Access app `jarvis2.deyaochen.com/actions` admits one service token,
`jarvis2-actions` (`infra/cloudflare.py --actions`), whose id and secret are `JARVIS2_ACTIONS_ID/SECRET` in the
`default` store. The router checks the Access JWT's audience (`ACCESS_ACTIONS_AUD`) and client id
(`ACTIONS_CLIENT_ID`). Only actions that need no signature from Deyao and reach no secret: anyone with the key could
already message any session. Client: claude-env `scripts/jarvis2-actions.py`. Inbox entries name the caller "the
actions key (default store)".

| Route | What |
|---|---|
| `GET /actions/sessions` | `{sessions: [{id, machineId, state, title, error, status?, needsGrant?}]}` |
| `GET /actions/requests` | The Inbox, as `GET /api/requests` |
| `POST /actions/sessions/:id/resume` | Resume a paused session: same image, no prompt, no option changes, so the core answers `approve_by_dead_machine` and the phone isn't asked. A line whose permission mode differs from its cert still gets its `resume-upgrade` approval. 4xx when not paused |
| `POST /actions/sessions/:id/pause` | As the app's pause |
| `POST /actions/sessions/:id/upgrade` | As the app's Upgrade (next size up, `router/memory.go`) → 202 |
| `POST /actions/requests/:id/deny` | An Inbox request leaves; an approval is rejected as the app's Deny |
| `POST /actions/sessions` | Propose a new session (body as `POST /m/api/sessions`, `explanation` required): a `new-session` approval in the Inbox; at most 3 wait |
| `POST /actions/requests/{repo/add,repo/remove,grant,unlock}` | As `/setup/requests/*`: an Inbox request |

## Setup (`/setup/*`)

Every call carries `X-Setup-Time` (unix seconds) and `X-Setup-Sig` = base64 DER ECDSA-P256-SHA256 signature
by the setup key over `"<METHOD> <path> <time> <sha256hex of body>"` (the router's path); the router checks it
against `SETUP_KEY` (`k8s/apps/router.yaml`), within ±2 min, each signature once. Client: `infra/setup.py`.

| Call | Core path |
|---|---|
| `GET /setup/identity` | `/identity` |
| `POST /setup/stores` | `/stores` |
| `POST /setup/stores/create` | `/stores/create` |
| `POST /setup/stores/write` | `/stores/write` |
| `POST /setup/stores/mark-sensitive` | `/stores/mark-sensitive` |
| `POST /setup/fly-token` | `/fly-token {sealed}`: `{"FLY_API_TOKEN"}` sealed to the core's agreement key (HKDF info `"jarvis2/fly-token"`) → the core's signed `{"kind":"fly-token-set"}`; 409 while the core is empty |
| `GET /setup/core-cert` | (the router's own) `{statement, masterSig}` of the claim it kept for the running core (matched by the core's signing key from `/identity`); 404 when none. A core claimed before the router kept claims (the running core until its release) is asked for its own `/core-cert`. |
| `GET /setup/stores/keys` | (the router's own) the store list with key names, as `GET /api/stores` |
| `GET /setup/jarvis1/paused[/{id}]`, `POST /setup/jarvis1/paused/{id}/prepare\|import` | (the router's own) as `/api/jarvis1/…` (Jarvis 1 import, above); the import's caller is `setup`. `infra/setup.py jarvis1 …` |
| `POST /setup/store-keys` | (the router's own) `{name, keys: [names] \| null}` → `{ok}`: records a store's key names (env-var style, ≤ 128 chars, de-duplicated and sorted); `null` forgets them. No values. `infra/setup.py write` sends it after every write; `infra/setup.py keys NAME KEY…` and `infra/store-keys.sh` (every store, from the layout file) record names alone. |

`GET /setup/status` — the router's health: the names of its secrets that are set (values never), the session
image, whether the core answers, and `githubRepos` — `{total, private}` repos the picker's `GITHUB_READ_TOKEN`
sees (or `{error}`; same 5-minute cache as `/api/github/repos`). `private: 0` = the token has no permission picked.
`flyOrgs` — the Machines view's orgs as counts only: `[{org, via, error, apps: [name…], machines, attention}]`.

## The Claude login (`router/claudelogin.go`)

One OAuth pair shared by every Claude session (Jarvis 1's too, which follows it), on the router's volume
(`claude-login.json`, 0600; DECISIONS 115-121). Its `mode`: `own` = the router is the ONLY refresher (when under 30 min
are left), `follow` = it mirrors Jarvis 1's pair every 30 s and never refreshes. A refresh revokes the previous access
token at once, so never two refreshers: the switch is `infra/setup.py claude-login own|follow` (RUNBOOK "The Claude
login").

Everyone who takes the pair long-polls `GET …/claude-login?have=<their expiresAt>&ack=<gen they hold a lock for, 0
none>&wait=<s, ≤ 55>` → `{credentials? (only when it expires later than have), account, expiresAt, gen, preparing,
mode}`. It answers at once when there is a newer pair, when a refresh is being prepared that the caller hasn't
acknowledged, or when the caller still holds a lock for a refresh that is over; else after `wait`. The refresh
protocol (lessons/74 over the network): the router sets `preparing` with a new `gen`; each participant takes the CLI's
refresh lock (`~/.claude/.oauth_refresh.lock`) and polls again with `ack=gen`; the router waits for every participant
seen in the last 2 minutes (at most 10 s), refreshes, writes the answer to its volume first, then answers every poll
with it; a participant writes its credentials file, then releases the lock. A failed refresh answers `preparing:
false` with no newer pair: participants release. A refused refresh (the grant is dead) DMs Deyao once.

`POST …/claude-login {credentials, account?}` offers a pair (a participant whose claude refreshed by itself): stored only
when it expires later and Anthropic's profile endpoint says it is the stored account's (403 otherwise) → `{stored,
expiresAt}`; in mode `follow` it also goes to Jarvis 1.

| Path | Who |
|---|---|
| `GET/POST /m/claude-login` | a session machine whose cert names the store `claude` (403 otherwise); participant `m:<machine>`. `GET/POST /m/api/credentials` (Jarvis 1's session script, through `$JARVIS_URL`) is the same pair and push. |
| `GET/POST /peer/claude-login`, `GET /peer/claude-login/status` | Jarvis 1: Access app `jarvis2.deyaochen.com/peer`, service token `jarvis1-claude-login` only (router env `ACCESS_PEER_AUD`, `JARVIS1_LOGIN_CLIENT_ID`; `infra/cloudflare.py --peer`); participant `jarvis1`. Its push may carry `relogin: true` (a Re-login in Jarvis 1's Settings), which may change the account. |
| `GET /setup/claude-login`, `POST /setup/claude-login/mode {mode}` | the setup session (signed): status, the cutover switch. |
| `/api/claude-login*`, `/api/usage` | the app (above, "Sessions"). |

## Machines (`/m/*`)

Every request carries `X-Machine: <fly machine id>`, `X-Time: <unix seconds>`, `X-Sig: <base64 DER signature
by the machine's signing key over "<method> <path> <time> <sha256 hex of body>">`; the router checks it
against the machine's current key (from `start`, or its latest downgrade) and refuses a time more than 120 s
off.

| Call | Does |
|---|---|
| `GET /m/cert` | `{cert, predecessorCert}` — this machine's latest succession cert and the predecessor's cert when it continues a real machine (the machine checks both against the core key the core put in its Fly config, `JARVIS2_CORE_KEY`). 404 until certified. |
| `GET /m/snapshot` | The predecessor's snapshot: body = tar.gz, header `X-Snapshot-Sig` = base64 signature by the predecessor's signing key over the sha256 of the body. 404 = none. |
| `POST /m/snapshot` | Upload this machine's snapshot (same format), streamed: the router writes the body to its volume while hashing it and checks `X-Sig` against that hash after (up to 32 GB; a machine the router doesn't know is refused before a byte is read). With header `X-Snapshot-None` and no body: nothing to snapshot (the machine is still booting; its agent answers every snapshot command from the first second of its life), and the waiting pause or destroy goes on at once. A pause or destroy doesn't ask a machine that never got past boot (no `/m/status` from it) at all. |
| `GET /m/restore-snapshot` | A restoring session's first machine only: the archived snapshot, same format, signed by the OLD machine named in `JARVIS2_RESTORE_CERT`; for a Jarvis 1 import, the import manifest (JSON). 404 otherwise. Streamed to disk by the machine. |
| `GET /m/import-file/{name}` | A Jarvis 1 import's first machine only: one file the manifest lists, streamed from the Storage Box with `Content-Length` = the manifest's size (the machine checks size and sha256). 404 for any other name or machine. |
| `POST /m/pull-secrets` | The router adds this machine's cert and the line's carried secrets (`snapshots/<machine>.carry`, else its predecessor's) and relays to the core; answers the core's signed `secrets` doc (sealed to the machine's key; its `carry` field, the next blob, is kept by the router). 423 `store X is locked` when no unlock is open to the cert and the blob doesn't hold the store. |
| `GET /m/commands` | Long poll (≤ 50 s): `{commands: ["snapshot"]}` or `{commands: []}`. `"free"` (an Upgrade, before its snapshot): the agent SIGSTOPs the harness and SIGKILLs every other process of the session user but itself, and writes their list to `~/artifacts/jarvis2-upgrade-freed.txt` (`machine/memory.go`; ignored while booting or frozen). |
| `POST /m/memory` | Body `{totalKb, availKb, oomKills, psiFull60, top: [{rssKb, comm}]}` (≤ 10 processes): the machine's RAM, every 10 s once booted (`machine/memory.go`), for the starvation watch (`router/memory.go`). 400 for a malformed sample. |
| `GET /m/stores` | Every store (all of them, not only this session's) with its key names, as `GET /api/stores`, so the session knows which one to ask for. `jarvis2 stores [--json]` prints it, checks the list against the core's signature and marks this session's own stores. |
| `POST /m/add-store` | Body `{store}`: asks Deyao (an `add-store` approval) to add one store to this session. With a reason: `POST /m/api/requests/add-store` (Requests). |
| `POST /m/downgrade` | Body `{stores, newEncryptionKey, newSigningKey}` → `{challenge}`, which the machine signs with its OLD key. |
| `POST /m/downgrade/finish` | Body `{challenge, signature}` → core `approve/by-old-key` → `{cert}`; from now on the router knows the machine by its new key. |
| `GET /m/tunnel-proof` | `{proof, id}`: hex HMAC-SHA256(`JARVIS2_TUNNEL_KEY`, `"jarvis2-tunnel:" + <this machine's session id>`), which the cf-tunnel Worker checks when the `jarvis2-tunnel` token registers that id. The machine puts it in `TUNNEL_AGENT_SECRET` at boot (never in the Fly config). 404 without the key; 403 for a machine with no running session. |
| `GET /m/config` | The values a machine takes from the router alone, each refused by the machine unless it matches its format (DESIGN "Inputs to a machine"): `{sessionId, discordChannel, liveSyncSeconds, taskRun, taskTrigger, tunnelProof}`. Everything else comes from the cert. |
| `GET /m/restore-cert` | `{cert}`: the old line's cert a restoring new line checks (its machine must be the one the cert's config names). 404 without a restore. |
| `POST /m/delivery-result` | `{id, ok, error?}`: the machine's answer to a delivery. Deliveries arrive in `GET /m/commands` as `{deliveries: [{id, kind: wakeup\|cron\|nudge\|continue\|upgraded, request?, run?, minutes?, jobs?, from?, to?, attest}]}` (`upgraded`: a text built into the image from the two sizes, each small, medium or large): a wakeup/cron is the session's own signed request, `attest` the core's input-log entry for it. |
| `GET /m/attachments` | `{files: [{name, size, isImage}], attest: {<name>: <core doc>}}`: the first-prompt attachments bound to this machine's session (404 none), each with the core's input-log entry for it (`/attest` machine, input `attachment`, origin `cert`, the sha256 of the file as it is on the volume; 502 when the core doesn't answer). The machine takes a file only when its bytes match the cert's sha256 + size AND its attestation. `GET /m/attachments/:name` the bytes; `DELETE /m/attachments` drops the router's copy once fetched. |
| `POST /m/task-result` | A task line's machine (harness `task:<template>`, below) after its run: `{run, exitCode, timedOut, error, startedAt, finishedAt, log /* tail ≤ 256 KB */, output /* ≤ 64 KB */}`, store values already redacted by the machine. `run: ""` = a boot with no run (the line's first machine). The router records the run and pauses the line. 403 for a machine that isn't a running task line. |
| `POST /m/status` | Body `{raw, appTitle}`: `raw` = the output of Jarvis 1's registry command (`machine/status.go`), sent by the agent when it changes and at least every 60 s; parsed by the router (`router/registry.go`). `appTitle` = the Claude app's title of the session's Remote Control entry, which the machine reads (at most once a minute) from `api.anthropic.com/v1/code/sessions/cse_<bridge>` with the session's own Claude login (`machine/apptitle.go`); "" keeps the last one. It becomes the session's `serverTitle`, and a resume without a label passes it on as `SESSION_RESUME_TITLE` (Jarvis 1's supervisor names a fresh Remote Control entry with it). |
| `POST /m/live-transcript` | Header `X-Name: <uuid>.jsonl`, body = the whole transcript (≤ 256 MB). The machine sends each conversation under `~/.claude/projects` that changed, every `JARVIS2_LIVE_SYNC_SECONDS` (default 300; router env `LIVE_SYNC_SECONDS` sets it), skipping Jarvis's delivery relays (`machine/livesync.go`). The router PUTs it to `claude-records/.live/<session id>/<name>` with its own Storage Box credentials — Jarvis 1's layout, which transcript search indexes — and records `liveSync` on the session; with no Storage Box (or `RECORDS_OFF=1`) it answers `{ok, stored: false}`. The folder goes when the session is destroyed. 403 for a machine with no running session. |

## The input log (`router/vouch.go`, `core/audit.go`)

`GET /api/input-log?last=N` (Access): the last N (≤ 2000, default 200) core-signed entries, each
`{kind: "input", seq, prev, at, machine, input, origin, sha256}` with `prev` = sha256 of the previous entry's payload.
The router appends each entry to `DATA_DIR/input-log.jsonl` as it arrives: attest's answer is the entry, and each
cert's entry comes beside the cert (`entry`, with the rebound `carry`, next to `payload`/`sig`). A new core's chain
starts again at seq 0. The core before R2 (the running one until its release) kept its entries for reading instead
(`POST /input-log`, `chain_from`): the router reads those while that core runs.

## Wakeups and crons (`router/schedule.go`)

Jarvis 1's shapes. The app calls them under `/api/sessions/:id/…`; the session itself under `/m/api/sessions/:id/…`
(through its machine's local proxy, below). At the due time the router delivers the prompt as a peer message
(holder `scheduler`), resuming a paused session first. A wakeup or cron belongs to its session and ends with it.

| Call | Does |
|---|---|
| `GET …/wakeup` | `{wakeup /* the soonest or null */, wakeups}`; `GET …/wakeups` → `{wakeups}`. Wakeup view `{name, at /* ms */, atIso, prompt}`. |
| `POST …/wakeup` or `…/wakeups` | `{prompt, at? /* ISO or ms */, delaySeconds?, name? /* default "default" */}` → `{ok, wakeup}`. Arming a name again replaces it. ≤ 90 days, prompt ≤ 3500 chars (whitespace collapses). 409 when the session is destroying. |
| `DELETE …/wakeup?name=X` (`?all=1`), `DELETE …/wakeups/:name` | `{ok, cancelled: [names]}` |
| `GET …/crons` | `{crons}`; view `{name, prompt, everySeconds, tz, nextAt, nextAtIso, until, untilIso, armedAtIso, runs, lastFiredIso}` |
| `POST …/crons` | `{name, prompt, everySeconds? /* 900–7776000, default 86400 */, time? "HH:MM" + tz?, at?, delaySeconds?, until?}` → `{ok, cron}` |
| `DELETE …/crons/:name` | `{ok}` |
| `POST …/notify-idle` | `{enabled}` → `{ok, notifyIdle: "on"|"off"}` (kept for the idle DMs) |

Delivery failures: a grant refusal (the session hasn't allowed the scheduler, or holds a sensitive store) DMs
Deyao once and stays pending, retried every 2 min; any other failure backs off and, after 5 attempts, drops a
wakeup (a cron skips that occurrence) with a DM.

## Tasks (`router/tasks.go`, `machine/task.go`, templates in `tasks/`)

Jarvis 1's Tasks and Schedules tabs, same shapes where the meaning is the same (`selfhost/jarvis/lib/tasks.js`). A task
**instance** is a session **line** whose signed harness is `task:<template>` (DECISIONS 32): creating one asks the phone
once (an ordinary `new-session` approval, label `Task: <name>`, stores = the template's + the ones picked in its store
fields). Each **run** resumes that line with no phone (`approve_by_dead_machine`); its machine runs the template from the
session image instead of a harness, reports to `/m/task-result`, and the router pauses the line again. Task lines also
show in `/api/state` `sessions` (harness `task:…`); the autopilot and Discord channels leave them alone.

**Template** (`tasks/<name>/task.json` + its files; the router image has a copy for the forms, the session image the copy
that runs — `/opt/jarvis2/tasks/<name>`, fixed by the line's image digest):

```
{ title, description?, run? /* "run.py" | "run.sh" | "run.js" | an executable; default: the first that exists */,
  prompt? /* "prompt.md": `claude -p` with {{field}} filled in, in the cert's permission mode (needs store claude) */,
  model? /* prompt only */, stores?: [store…], timeoutSeconds? /* 10–21600, default 600 */,
  size? /* small (default) | medium | large */,
  fields: [{ name /* [a-z][a-z0-9_]* */, label?, type: text|textarea|number|select|multiselect|checkbox, required?,
             default?, help?, placeholder?, options?: ["a", {value, label, sub?}], optionsFrom?: stores|sizes|models }] }
```

A (multi)select with `optionsFrom: "stores"` adds the picked store(s) to the line; `options` comes back empty for it —
the app fills the list from the core's store list (`/api/core/stores`). Jarvis 1's `secretKeys`, `image`, `memory` and
hidden values don't exist here (a picked store brings all its keys; secrets live only in stores).

**What a run sees** (machine/task.go): cwd `~/task-work` (fresh each run); env = PATH/HOME/LANG/…, `JARVIS_URL`,
`SESSION_ID`, `LOBSTER_CHANNEL`, the router's `TASK_PARAMS` (all values as JSON), `PARAM_<FIELD>` (lists comma-joined,
booleans `true`/`false`), `TASK_INSTANCE`, `TASK_NAME`, `TASK_RUN`, `TASK_TRIGGER` (manual | schedule), then `TASK_DIR`
(the template's files), `TASK_TEMPLATE`, `TASK_OUTPUT` (a file whose first 64 KB is the run's output in the app),
`TASK_STATE_DIR` (`~/workspace/task-state`, kept between runs by the snapshot), `TASK_WORK`, `TASK_TIMEOUT`, and last the
line's store values (also in `~/.secrets`). Parameters are NOT secret: they are in the machine's Fly config and unsigned,
so a script treats them as data. The log is `~/artifacts/task-runs/<run>.log` (20 kept, archived with the line); store
values of 6+ characters are replaced by `[secret NAME]` in the log and the output before they leave the machine.
A run past `timeoutSeconds` is killed with its process group (`timedOut`).

```
instance = { id, template, name, params, size, stores, session /* the line, null once gone */, createdAt, updatedAt,
             state: approval | ready | running | busy | failed | gone, detail, sessionState, image,
             lastRun /* the newest finished run */, activeRun, queued /* count */, schedules /* count */ }
run      = { id, name /* = id, Jarvis 1's Job name */, instance, instanceName, template, trigger: manual | schedule,
             schedule, slot, upgrade, phase: queued | starting | running | succeeded | failed | timedout | stopped | lost,
             createdAt, resumedAt, startedAt /* machine up, secrets pulled */, ranAt /* script start */, finishedAt, exitCode, reason,
             waiting /* e.g. the phone must approve a newer image */, tail /* last 15 lines */, logBytes, outputBytes,
             machine, image }
schedule = { id, instance, time "HH:MM", tz, enabled, since /* ms */, createdAt, nextAt /* ms or null */ }
```

| Call | Does |
|---|---|
| `GET /api/tasks` | `{sessionImage, templates /* parsed, broken ones with `error`; `source` = the run/prompt file */, instances, schedules}` |
| `POST /api/tasks/instances` | `{template, name, params, size?, requestId?}` → the instance (state `approval`); the phone's approval is in `/api/approvals`. 400 for bad values (`hide` is refused). |
| `PUT /api/tasks/instances/:id` | `{name?, params?, size?}` → the instance. Values that change the line's stores → 400 (make a new task). |
| `DELETE /api/tasks/instances/:id` | Drops it with its schedules and runs; its line is destroyed (archived like any session) or its pending approval rejected. |
| `POST /api/tasks/instances/:id/approve` | A new line (phone approval) for an instance whose line is gone or failed; 409 otherwise. |
| `POST /api/tasks/instances/:id/run` | `{upgrade?}` → `{name, run}` (phase `queued`; it starts once the line is paused). `upgrade: true` resumes on the newest session image, which the phone approves first (`resume-upgrade`) — how a changed template reaches an existing task. 409: waiting for the first approval, line gone, or 3 runs queued. |
| `GET /api/tasks/instances/:id/runs` | `{runs}` newest first (20 finished kept). |
| `GET /api/tasks/runs/:id` | `{run, log, output}`. |
| `POST /api/tasks/runs/:id/stop` | Queued: dropped. Starting/running: `stopped`, the line is paused (a machine already up may have started the script). 409 when finished. |
| `POST /api/tasks/schedules` | `{instance, time, tz? /* default Europe/London */, enabled?}` → schedule. Daily at `time` in `tz`; a change never fires a slot already past; a slot missed by more than 2 h (router down) is skipped. |
| `PUT /api/tasks/schedules/:id` | `{time?, tz?, enabled?}` |
| `DELETE /api/tasks/schedules/:id` | `{ok}` |

DMs (lobster, as Jarvis 1): a scheduled run that failed, timed out or was lost (with the log's tail), and a scheduled
slot that could not start (line gone, waiting for approval, queue full). A run is `lost` when its line stopped (a manual
pause, the budget cap) before the machine reported, and `timedout` by the router when no result came 15 min past the
template's timeout. A run resumes its line with the secrets the line carries (DESIGN "Carried secrets"), no store
unlocked; a line without them (its blob lost, or first started under a core that predates them) waits on its locked
store like any start: a run whose machine isn't up 30 min after the resume (`waiting` says so) fails and the line is
paused.

## Device leases (`router/leases.go`)

Jarvis 1's lib/leases.js and shapes. One holder and a FIFO queue per device; `wechat-phone`, `iphone` and `mac` are
always listed. The session calls the `/m/api` paths through its machine's proxy (`scripts/lease.py`, which the device
helpers call); its path id must be its own. `/api/state` carries `leases` (the list below).

```
lease = { name, holder: null | {sid /* a session id, or "deyao" */, human, purpose, description, describedAt, note, since,
          expiresAt /* ms, null for Deyao */, expiresInSeconds}, queue: [{position, sid, purpose, description, describedAt,
          enqueuedAt, interrupted}], log /* last 20: {at, kind: granted|promoted|returned|force-returned|expired|taken-over|
          handed-back|note, sid, purpose?, note?, interrupted?} */ }
```

| Call | Does |
|---|---|
| `GET /api/leases`, `/m/api/leases` | `{leases}` |
| `GET /api/leases/:name`, `/m/api/leases/:name` | `{lease}` |
| `POST /m/api/sessions/:id/leases/:name` | `{purpose, description?, prompt? /* the wake note */, ttlSeconds? /* 60–21600, default 3600 */, lowPriority?}` → `{status: granted | renewed | queued | busy, position?, lease}`; `busy` (409) only for `lowPriority`. |
| `PUT /m/api/sessions/:id/leases/:name` | Renew (holder only) → `{status: "renewed", lease}`; 409 otherwise, `{takenOver: true}` with Deyao's note while he has it (and the session is told when he hands it back). |
| `PATCH /m/api/sessions/:id/leases/:name` | `{purpose?, description?}` (holder or waiter; no renew) → `{status: holder | queued, lease}` |
| `POST /m/api/sessions/:id/leases/:name/seen` | The session looked at a device Deyao has (lease.py status) → `{takenOver}`; it is told when he hands it back. |
| `DELETE /m/api/sessions/:id/leases/:name` | Return it (holder) or leave the queue → `{returned, left, next /* the woken session or null */}` |
| `POST /api/leases/:name/force-return` | The app: `{returned, previous, next}` |
| `POST /api/leases/:name/take-over` | The app: `{note?}` Deyao takes the device (never expires; agents' actions refused); the holder goes to the front of the queue and is told (`lease-taken`). While he has it, a note only replaces his note. → `{taken, interrupted, noteUpdated}` |
| `POST /api/leases/:name/hand-back` | The app: `{note?}` → `{handedBack, next, notified}`; the next waiter is woken, every other session that found it taken over is told (`lease-back`). |
| `POST /setup/leases/:name/take-over`, `…/hand-back` | The same, by the setup session for Deyao (setup-key signed; `infra/setup.py lease take-over DEVICE --note …`). |

Wake messages are deliveries (`/m/commands`, checked by the machine, attested by the core): `lease-granted` (the
waiter's own signed acquire request: its prompt, and the device in the signed path; `minutes`, `handover`,
`interrupted`), `lease-taken` and `lease-back` (image texts over `device`). A promoted holder that can't be woken is
retried every 30 s (20 tries). A destroyed session's holder or queue place goes at the next sweep.

## Watches (`router/watches.go`, `services/watch`)

Conditional wakeups, Jarvis 1's shapes. The session arms one (its own signed request); the router runs the check on the
watch runner (k8s/apps/watch.yaml: no secrets, public internet only) every `interval`, whether the session runs or is
paused. Exit 0 = met → `watch` delivery (the session's request: `[watch "<name>" met] <prompt>`); exit 3, or
`maxSeconds` past arming = give up → `watch-fail` (`failPrompt`, or a default). Any other exit, or a runner error =
not yet. The machine runs the check once more itself (its own env, 40 s) and appends that output; the runner's output
never reaches the session. A failed delivery backs off and after 5 attempts the watch is dropped with a DM.

```
watch view = { name, prompt, failPrompt, interval, maxSeconds, armedAt, armedAtIso, expiresAtIso, nextCheckIso, runs,
               lastExit /* null before the first run or when the runner failed */, lastRunIso, lastError /* the last stderr
               line, why it couldn't run, or why the delivery failed ("delivery: …") */, lastOutput /* the start of stdout */, outcome /* "" | met | gave-up */ }
```

| Call | Does |
|---|---|
| `POST /m/api/sessions/:id/watches` | `{name, script /* bash, ≤ 32 KB */, prompt, failPrompt?, interval? /* 30–3600 s, default 60 */, maxSeconds? /* ≤ 400 d, default 7 d */}` → `{ok, watch}`; the same name replaces. The app's `POST /api/sessions/:id/watches` → 400 (only the session's own request can be delivered). |
| `GET /api/sessions/:id/watches`, `/m/api/…` | `{watches}` (no script bodies) |
| `DELETE /api/sessions/:id/watches/:name`, `/m/api/…` | `{ok}` |

The runner (`POST http://watch.jarvis2-edge.svc.cluster.local:8095/run {script, name, timeout}` →
`{exit, stdout, stderr, timedOut, ms}`, router env `WATCH_URL`): a check gets PATH, HOME and TMPDIR (a throwaway
directory), LANG and WATCH_NAME; bash, curl, python3, git, openssl, jq; 90 s; stdout capped at 16 KB.

## Content stores (`router/content.go`)

Named folders of files on the Storage Box, `claude-records/.content/<name>/` (Jarvis 1's, used in place), read and
written with the router's own Storage Box credentials. A name is `[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?`; a file path is
relative, `/`-separated, with no empty, `.` or `..` segment; a file is at most 25 MB.

| Path | Does |
|---|---|
| `GET /api/content[?fresh=1]` | `{stores: [{name, files, bytes}]}` (cached a minute; `fresh=1` walks the box). |
| `POST /api/content` | Body `{name}` → `{ok, name}`; 409 when it exists. |
| `DELETE /api/content/:name` | The store and every file in it. |
| `GET /api/content/:name/files` | `{name, files: [{path, size, modified}]}`, sorted by path; 404 for no store. |
| `GET /api/content/:name/file?path=` | The bytes (`application/octet-stream`). Jarvis 1's `x-content-path` header works in place of `path`. |
| `POST /api/content/:name/file?path=` | The raw body becomes that file (parent folders made) → `{path, size}`. |
| `DELETE /api/content/:name/file?path=` | The file, then the folders it leaves empty. |

A session's content stores are the cert's (`options.config.content`, signed with the line: New session's `content: [name…]`,
or a task's `optionsFrom: "content"` fields); `POST /api/sessions` refuses a name with no store. On the machine,
`SESSION_CONTENT` names them and the base image's `content-sync` (pull at every start, `push`, `status`) calls Jarvis 1's
session paths through the local proxy:

| Path (machine-signed, `/m/api/…`) | Does |
|---|---|
| `GET /m/api/sessions/:id/content` | `{ok, stores: {name: [{path, size, modified}]}}` for the cert's stores (a deleted store: `[]`). |
| `GET /m/api/sessions/:id/content/:name/file?path=` | The bytes, with header `X-Jarvis2-Attest`: the core's input-log entry (machine, `content`, origin `router`, sha256); the machine's proxy refuses the file (502) without a matching one. |
| `PUT` / `DELETE /m/api/sessions/:id/content/:name/file?path=` | Write or delete a file of one of the cert's stores; 403 for any other store. |

## Paired apps (`router/devices.go`)

Deyao's builds of the OpenClaw and Paseo apps pair once and then list and start sessions without a login of their own.

| Path | Does |
|---|---|
| `GET /api/devices/pair?state=&name=&model=&app=openclaw\|paseo` | Deyao's own Access login only (the app opens it in the system sign-in sheet). Mints one Access service token for that device (`CF_DEVICE_TOKENS_API`) → `302 openclaw-de0ch://paired?state&id&clientId&clientSecret` (or `paseo-de0ch://…`); an error comes back the same way as `error` + `status` (429 within 30 s of the last pairing). `state` is `[A-Za-z0-9_-]{16,64}`. |
| `GET /api/devices` | `{devices: [{id, name, model, app, createdAt, lastSeenAt}]}` (no token ids). |
| `DELETE /api/devices/:id` | Deletes its service token at Cloudflare and forgets it. |

`/api/remotes` and `/api/sessions/:id/start` are behind the Access app "Jarvis 2 devices" (`ACCESS_DEVICES_AUD`), which admits
Deyao's email or any service token of the account; the router then admits a token only when its client id (the JWT's
`common_name`) is a paired device's.

## Session-facing API (`/m/api/*`)

Jarvis 1's session scripts call `$JARVIS_URL/api/…`. A Jarvis 2 machine gets `JARVIS_URL=http://127.0.0.1:7171`
(plus placeholder `CF_ACCESS_CLIENT_ID/SECRET` and `SESSION_API_TOKEN`, which the scripts insist on; not for
OpenCode/OpenClaw, whose harness scripts read CF_ACCESS_* as "publish the web UI"). There `jarvis2-machine agent`
serves a proxy that drops the scripts' headers and sends `/m/api/<rest>` (query kept, unsigned; the path is
signed as every `/m` call). Any `:id` in the path must be the calling machine's session (403 otherwise).

| Path | Served by |
|---|---|
| `GET /api/sessions/:id/secrets` | The machine itself: `/m/pull-secrets`, opened with its key → `{ok, environment, secrets}` (Jarvis 1's shape). |
| `GET /api/sessions/:id/changes` | The machine itself: `{checked, repos: [{name, uncommitted, unpushed /* -1 no upstream */}], status}`. |
| wakeups, crons, notify-idle | The router (above). Arming also puts holder `scheduler` on the session's allow list (a wakeup: due + 1 h; a cron: max(31 d, 2 periods + 1 h), renewed at each firing by `jarvis2-machine allow-at-least`). |
| `DELETE /api/sessions/:id` | The router: the session retires itself (Destroy) → 202 `{started}`; 409 `{pending}` while it has wakeups, crons or watches. |
| leases, watches | The router (above). |
| search, iCloud index | `GET /m/api/search`, `/m/api/search/context`, `/m/api/search/status`, `POST /m/api/search/reindex` (any running session), `GET /m/api/icloud/search`, `/m/api/icloud/file`, `/m/api/icloud/status`, `POST /m/api/icloud/relist`, `/m/api/icloud/retry` (only a session whose cert holds the `identity` store; otherwise 403 `{error, needsStore: "identity"}`): the box's own services, as for the app. 403 for a machine with no running session. |
| device leases, content stores | The router (`router/leases.go`, `router/content.go`). |
| `GET/POST /api/credentials` | The router's Claude login ("The Claude login" above), for a machine whose cert names the store `claude`. |
| anything else | 404 |

Nothing is forwarded to Jarvis 1.

## Transcript search (`services/search`)

Its own pod (`k8s/apps/search.yaml`, namespace jarvis2-edge), reached only through the router (above). It crawls
`claude-records/` on the Storage Box every 10 minutes (and when the router archives a session): archived sessions of
both Jarvises (`<dir>/transcript-<id>.jsonl`), Jarvis 1's pause snapshots (`.paused/<id>/`), running sessions of both
(`.live/<id>/`) and the text records in archive dirs (`.md .txt .html .log`, the task records). Other dot-dirs
(`.index/`, `.jarvis2-services/`) are skipped. Hybrid keyword (FTS5, 中文 as phrases/bigrams) + semantic
(`qwen/qwen3-embedding-8b` via OpenRouter) retrieval, reranked by `cohere/rerank-4-fast`.

| Call | |
|---|---|
| `GET /api/search?q=` | `&limit=` (1-50, 10), `&kind=msg,tool,doc`, `&after=`/`&before=` (YYYY-MM-DD), `&state=live,paused,archive` (the session's state now), `&archived=1` (only text read from an archive dir), `&session=` (id / dir / title fragment), `&mode=hybrid|keyword|semantic`, `&rerank=0`, `&group=1` (by session), `&full=1` (whole chunk text). `"quoted phrases"` must match. → `{query, mode, reranked, total, tookMs, timing, notes, terms, hits: [{id, score, via, kind, date, ts, title, sid, dir, state, machineId, file, lines, snippet, text?}]}` (or `sessions: [{title, sid, dir, state, machineId, date, score, count, hits}]` with `group=1`). |
| `GET /api/search/context?id=&before=3&after=3` | The chunks around a hit, in file order → `{session, file, chunks: [{id, kind, ts, lineFrom, lineTo, text, hit?}]}`; 404 for an unknown id. |
| `GET /api/search/status` | Counts (`chunks, sessions, files, vectors, kinds, sessions_by_state, span`), models and the indexer's state (`indexer: {state, lastRun, lastError, billing}`). |
| `POST /api/search/reindex` | Crawl now → 202 `{started}`. |

The index is one SQLite file on the pod's volume; a missing one is seeded from `claude-records/.jarvis2-services/search.db.gz`
on the Storage Box, which the pod rewrites daily.

## iCloud index (`services/icloud-index`)

Its own pod (`k8s/apps/icloud-index.yaml`, namespace jarvis2-edge), reached only through the router. It lists Deyao's
iCloud Drive daily (rclone, the saved login in `k8s/secrets/icloud-session.enc.yaml`) and reads each file: text,
OCR of scans and photos, video frames and speech (AI reading capped by `AI_BUDGET_USD`, a lifetime total kept in the
index), then embeds the text.

| Call | |
|---|---|
| `GET /api/icloud/search?q=` | `&limit=` (1-100, 10), `&kind=text,pdf,office,iwork,image,raw,audio,video,archive,other`, `&ext=`, `&under=<folder>`, `&after=`/`&before=`, `&mode=hybrid|keyword|semantic`, `&rerank=0`, `&full=1` → `{query, total, hits: [{path, kind, size, mtime, score, snippet, …}]}`. A hit's `path` is the iCloud path: `rclone copy "icloud:<path>" .` fetches it. |
| `GET /api/icloud/file?path=` | One file's record and all its extracted text, by part; 404 when it isn't indexed. |
| `GET /api/icloud/status` | Counts by state and kind, `aiSpentUsd`/`aiBudgetUsd`, `embedSpentUsd`, the last listing, the file being read, recent errors. |
| `POST /api/icloud/relist` | List iCloud now → 202. |
| `POST /api/icloud/retry` | Give failed files another go → 202. |

Identity-level: sessions reach it only with the `identity` store (above). A missing index is seeded from
`claude-records/.jarvis2-services/icloud-index.db.gz.age` (age-encrypted, rewritten weekly); with no copy the pod refuses
to start (`SEED_REQUIRED=1`), so the budget is never spent twice.
