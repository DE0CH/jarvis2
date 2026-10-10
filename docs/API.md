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
  discordChannel /* the session's Discord channel id */, wakeups: [wakeup view], crons: [cron view] /* below */,
  resumePrompt /* a prompt queued for delivery once started */ }
```

What the router does by itself with a running session (`router/autopilot.go`, every 30 s), from that report:
auto-pause after 1 h plain idle (unless `autoPause` is off, the session is one-shot, or another feature vetoes);
destroy a one-shot session once `oneShotDone` — forcefully (a failed archive doesn't stop it) and with a DM when work
was lost: dirty repos as its final snapshot recorded them, a repo check that couldn't run, or a failed archive
(`router/oneshot.go`, Jarvis 1's finishOneShot); Escape a prompt left `waiting` for 1 h (holder `status`); DM
"needs you" / idle / dead after 5 min in that state (the idle one muted by `notifyIdle` off); DM new safeguard
refusals and the "switch model?" dialog (holder `status` reads the pane); a Jarvis watchdog peer message every
15 min while idle with background jobs; and login repair: when the session's credentials expire before Jarvis
1's shared pair (`JARVIS1_CREDENTIALS_ID/SECRET` in the router's env) or its transcript ends on "Please run
/login", write the pair (holder `login`) and, for the latter, deliver "continue". A command the machine refuses
sets `needsGrant` to that holder and the loop leaves it alone for 10 min.

`state`: `approval` (waiting for the iPhone; no machine yet) → `starting` (the core makes the machine) →
`initialising` → `started` (running) → `pausing` → `paused` (no machine) → `resuming` → … ; `destroying` →
gone (moved to records); `failed` (with `error`).

| Call | Does |
|---|---|
| `GET /api/state` | `{sessions, approvals, core: {up, signingKey, agreementKey}}` |
| `GET /api/sizes` | `{sizes: [{id, label}]}` (small / medium / large) |
| `GET /api/models` | `?harness=` optional → `{models: [{id, label, harness}], default, defaults: {<harness>: id}, harnesses: {<harness>: {label, detail}}}` — Jarvis 1's list (Claude, OpenRouter via OpenCode, Claude via OpenClaw), only harnesses the policy has. In `POST /api/sessions` an empty model or one of another harness becomes the harness's default; an unknown one is refused (400). |
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
| `GET /api/sessions/:id/terminal` | `{screen /* tmux capture-pane -e */, cursor: "x,y,width,height,visible"}` — an exec under holder `terminal`. `POST` `{text?, keys?: [tmux key names]}` types, `{cols, rows}` resizes the window. |
| `GET /api/sessions/:id/tail` | A paused session's conversation end, from its snapshot: `{title, sessionId, messages: [{role, text, at}]}` (409 while it runs, 404 without a snapshot). |
| `GET /api/state` (extra fields) | `budget`: `{month, spentUsd, capUsd, warnUsd, warned, capped, cappedAt, ratePerHour, perMonth, running, volumes, sampledAt}` or null; `fly`: `{apps, app, machines, volumes, other: [{kind, app, id, name, state, region, created, detail}], error, checkedAt}` ("Also on Fly": machines in app jarvis2-sessions that are no running session of the router's, and volumes); `flyApp`. |
| `GET /api/records` | Destroyed sessions `{records: [...]}`; each has `archive: {dir, title, transcripts, artifacts, signer, snapshotAt, last}` when it was archived, `archiveError`, `restored: [{sessionId, at}]`. |
| `POST /api/records` | Index an archive ALREADY on the Storage Box, by hand (Jarvis 1's call): `{archiveDir: "claude-records/<folder>", transcripts: [file…], artifacts?, title?, environment? \| stores?, repos?, permissionMode?, model?, size?, harness?, created?, destroyedAt?}` → `{ok, record}` (id `archive-<the first transcript's uuid prefix>`). The transcripts must exist; nothing is scanned. Such a record has no machine-signed snapshot (`archive.signer` empty), so its tail, Remove and Delete work and Restore is refused (400). |
| `GET /api/records/:id/tail` | The archived conversation's end (a Range read of its newest transcript), same shape as the session tail. |
| `DELETE /api/records/:id` | Off the list and the Storage Box index; `?purge=1` deletes its archive too (the whole dir, or only its own files when another record shares the dir). |
| `POST /api/records/:id/restore` | Body `{requestId?}` → `{id, requestId}`. A NEW session (new line) with the record's options; an approval of kind `new-session` with `options.restore` naming the record. Its first machine restores the archived snapshot (below). |
| `POST /api/sessions/:id/auto-pause` | Body `{on}` (Jarvis 1's `{enabled}` works too) → `{ok, autoPause: "on" | "off"}`; restarts the idle countdown. |
| `POST /api/sessions/:id/notify-idle` | Body `{on}` → `{ok, notifyIdle}`: mutes only the idle DM; "needs you", dead and downgrade DMs still come. |
| `GET /api/sessions/:id/remote` | OpenCode/OpenClaw only (400 otherwise; 409 unless `started`): `{webUrl, harness, pairUrl, relay}` (opencode: the Paseo app's pairing link) or `{webUrl /* …#token= */, harness, url /* wss://<id>-s.deyaochen.com */, token}` (openclaw: the gateway token). Read in the machine as holder `remote` (a grant, standing rule or allow-list entry); refused → 403 `{error, needsGrant: "remote"}`; front end not up → 503 `{error}`. Cached 1 min per machine. `webUrl` = `https://<session id>-s.deyaochen.com/` (suffix: router env `SESSION_TUNNEL_SUFFIX`). |
| `GET /api/remotes?harness=openclaw\|opencode` | Jarvis 1's shape: `{sessions: [{id, title, state, model, + url, token, webUrl (openclaw) \| pairUrl (opencode), or error (+ needsGrant)}]}`; secrets only for a started session. Also admits one Access service token: client id `JARVIS2_REMOTES_CLIENT_ID` (JWT `common_name`), audience the app's or `ACCESS_REMOTES_AUD`. |
| `POST /api/sessions/:id/permission-mode` | Body `{mode: "auto" | "bypass"}`. Running → 202 `{started, inPlace}`: Jarvis 1's `set-permission-mode` under the `terminal` holder (claude relaunches `--resume` in the new mode; nothing else restarts); a refusal sets `needsGrant: "terminal"`. Paused → 200 `{nextStart: true}`. Same mode → `{unchanged: true}`. |
| `POST /api/sessions/:id/restart` | Body `{env?, rollback?: {dropFromMarker}, prompt?, size?, model?, apiProxy?}` → 202. Pause (if running) + resume on the same image. `env`: `{NAME: value}` patch kept for later starts (`""`/null removes); names that look like secrets (TOKEN, SECRET, PASSWORD, API_KEY, `_KEY`, `_API`, AUTH, …) or Jarvis's own (`JARVIS*_`, `SESSION_`, `CLAUDE_`, `ANTHROPIC_`, `CF_ACCESS_`, `LOBSTER_`, `FLY_`, `LD_`, PATH, HOME…) → 400: secrets come only from stores. `rollback`: the next machine, after verifying the paused snapshot, drops every conversation-transcript line from the first containing the marker (env `JARVIS2_ROLLBACK` + `JARVIS2_ROLLBACK_PRED` = the paused machine; ignored by any other start). |
| `POST /api/sessions/:id/env` | Jarvis 1's shape `{env}` = a restart with only `env`. |
| `GET /api/state` (per session) | `busy: {kind: pausing | starting | destroying | mode | restarting, since}` while a lifecycle action holds it (others 409); `wake: {kind, phase, error, startedAt, finishedAt}` for a permission-mode / restart job (kept 10 min after it ends); `apiProxy`, `envKeys`. Top level: `repos`. |
| `POST /api/uploads` | First-prompt attachments: one raw file per request, headers `x-upload-id` (`[A-Za-z0-9_-]{1,64}`, groups a form's files) and `x-upload-name` (URI-encoded; made a safe basename as in Jarvis 1) → `{name, size, isImage}`. ≤ 20 files, 25 MB each (413). Staged on the router's volume; unbound uploads go after 24 h, bound ones with their session. |
| `GET /api/repos` | Deyao's repo list, for Settings → Repos and New session's `repos`: `{repos: [{name, url /* https://github.com/<repo>.git */, repo /* owner/name */, store /* github-<repo> */, sensitive, fingerprint?, keyAt?}]}`. GitHub repos only; an entry is added or removed only by the core's answer to `POST /api/repos/key/finish` (below). |
| `POST /api/repos/key/begin {action: add \| remove, repo: owner/name \| GitHub URL, sensitive?}` | Relayed to the core's `deploy-keys/begin` (the repo normalised to `owner/name`): its signed begin document, which the shell's secure page checks and the phone answers. 400 for a non-GitHub repo or another action; 501 `{error}` from a core older than deploy keys. |
| `POST /api/repos/key/finish {pending, signature, share}` | Relayed to `deploy-keys/finish`; on the core's signed `deploy-key-added` the repo goes on the list (with `sensitive`, `fingerprint`), on `deploy-key-removed` it comes off. The answer is the core's, unchanged. |
| `GET /api/github/repos` | `{repos: [{fullName, url, htmlUrl, private, fork, archived, description, language, pushedAt, owner}], cachedAt, configured}` (5 min cache, `?refresh=1`), listed with `GITHUB_READ_TOKEN` (router env; metadata read only — sessions push with their repos' deploy keys). 503 without it. |
| `GET /api/usage` | Forwarded to Jarvis 1's `/api/usage` (query kept) with the services token: Jarvis 1 holds the Claude login. |
| `GET /api/search`, `/api/search/context`, `/api/search/status`; `GET /api/icloud/search`, `/api/icloud/file`, `/api/icloud/status`; `POST /api/icloud/relist` | The app's Search tab: forwarded to Jarvis 1's transcript search and iCloud index unchanged (path, query, body) with the services token `JARVIS1_SERVICES_ID/SECRET` and no `X-Jarvis2-Session`; Jarvis 1's shapes (its `selfhost/API.md`). 503 without the token. |

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

## Approvals (the shell's secure pages)

```
approval = { id, kind: "new-session" | "resume-upgrade" | "add-store", created, session, machine /* add-store */,
             label, challenge /* the core-signed challenge doc */, options /* the form's fields, for display */ }
```

| Call | Does |
|---|---|
| `GET /api/approvals` | `{approvals: [...]}` |
| `POST /api/approvals/:id/respond` | Body `{signature}` = base64 DER signature by the phone's signing key over **exactly** `challenge.payload`. Router → core `approve/by-phone`. Answers `{answer, session}`: a core-signed `approval` (then the router starts and certifies the machine) or, for `add-store`, the new `succession-cert`. |
| `POST /api/approvals/:id/reject` | Drops it; a new session disappears, a resume-upgrade stays paused. |

The phone may approve anything; it shows exactly what it signs (`request.stores`, `request.sensitive`,
`request.options`, `request.image`, `request.addedStore`).

## The core, relayed (`/api/core/*`)

When the core can't be reached at all (its pod restarting, e.g. after a wipe) every one of these answers 503
`{error: "the core isn't running", coreDown: true}`; the app waits or shows it as a plain note.
Pass-through to the core's own endpoints, answers unchanged (signed): `GET identity`, `POST stores {nonce}`,
`POST stores/create {name}`, `POST stores/mark-sensitive {name}`, `POST stores/write {store}`, `POST unlock/begin
{store}`, `POST unlock/finish {pending, share}`, `POST lock {id}`, `POST unlocked {nonce}`, `POST log {nonce}`, and
— only from the app's device login (the `cf-access-token` header; 403 otherwise) — `POST claim {statement,
masterSig, bundle}` and `POST wipe {statement, masterSig}`. Formats: `docs/DESIGN.md`, `core/core.go`, the app's
`Shell/CoreSetup.swift`, and the reference client `e2e/main.go`.

Setting the core up (Reset and Recover, the app's Reset or recover page):

- `GET identity` → `{signingKey, agreementKey, boxSig, state}`: `boxSig` = the box key's signature over
  `"jarvis2-core-identity <signingKey> <agreementKey>"` (checked against `keys/box.pub` from GitHub); `state` = a
  core-signed doc `{"kind":"core-state","master": <the master public key it was set up with, "" while empty>,
  "phone": {signingKey, agreementKey} | null}`.
- `claim`: `statement` = the JSON text `{"kind":"claim","master","core":{signingKey,agreementKey},"phone":{…},
  "bundleSha256"}`, `masterSig` = that master key's base64 DER ECDSA over it, `bundle` = `{stores:[{name, values}],
  notSensitive:[names]}` sealed to the core's agreement key (ephemeral P-256, HKDF-SHA256 info `"jarvis2/claim"`,
  AES-256-GCM combined) → the core's signed `{"kind":"claimed","stores": n}`; 409 when the core is set up already.
  Reset sends no stores; Recover every store from the backups (the `core` store: `FLY_API_TOKEN`).
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
checks each `sig` against `keys/setup.pub` (from GitHub) and opens each backup with the master key from the kit.

Unlock, phone side: verify `unlock/begin`'s doc (kind `unlock-begin`, fields `pending, store, e, t`); Face
ID → Enclave key agreement of the phone's agreement key with `e` → the 32-byte x-coordinate; seal it to `t`:
ephemeral P-256 key `r`, `x' = x(r·t)`, key = HKDF-SHA256(ikm `x'`, salt empty, info `"jarvis2/unlock-share"`,
32 bytes), AES-256-GCM combined (`nonce‖ciphertext‖tag`) → `share = {e: base64(r.pub x963), data:
base64(combined)}` → `unlock/finish {pending, share}`.

## Deploy keys (the core: `deploy-keys/*`, `core/deploykeys.go`)

- `POST deploy-keys/begin {action: add | remove, repo: owner/name, sensitive}` → the core's signed
  `{"kind":"deploy-key-begin", pending, action, repo, store /* github-<name> for DE0CH, else github-<owner>-<name> */,
  sensitive /* add: asked for, OR DE0CH/jarvis2, OR the store is sensitive already; remove: the store's */, replaces
  /* add: the store exists */, title /* "jarvis2 <store>": the key's title on GitHub */, tokenStore:
  "github-deploy-keys", e /* that store's E */, t /* a one-off key */}`. 404 while `github-deploy-keys` has no
  contents; 409 on an empty core; 400 for a bad repo (or one whose store name would be `github-deploy-keys`).
- `POST deploy-keys/finish {pending, signature, share}`: `signature` = the phone's base64 DER ECDSA over the begin
  document's payload (its signing key from the claim), `share` = x(p·E) of the token store sealed to `t` exactly as
  an unlock's share (HKDF info `"jarvis2/unlock-share"`); the shell makes both under one Face ID. One try per
  pending. The core opens `github-deploy-keys` for this call only (it never joins the unlocked set) and reads
  `GITHUB_DEPLOY_KEYS_TOKEN`; it deletes the repo's keys titled `jarvis2 <store>` on GitHub (`GET/DELETE
  /repos/{repo}/keys`), then — add — makes an ed25519 key pair, adds the public half (`POST /repos/{repo}/keys`,
  `read_only: false`) and writes the store `{GITHUB_DEPLOY_REPO_<SLUG>: "owner/name", GITHUB_DEPLOY_KEY_<SLUG>:
  base64(OpenSSH private key file)}` (`<SLUG>` = `OWNER_NAME`, upper case, other characters `_`) wrapped to P + K →
  `{"kind":"deploy-key-added", pending, repo, store, sensitive, title, fingerprint /* SHA256:… */, keyId}`; or —
  remove — deletes the store → `{"kind":"deploy-key-removed", pending, repo, store, deleted}`. 403 for a wrong
  signature or share; 502 when GitHub refuses (a 403/404 names the permission the token needs: Repository
  "Administration: read and write").

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

`GET /setup/status` — the router's health: the names of its secrets that are set (values never), the session
image, whether the core answers.

## Machines (`/m/*`)

Every request carries `X-Machine: <fly machine id>`, `X-Time: <unix seconds>`, `X-Sig: <base64 DER signature
by the machine's signing key over "<method> <path> <time> <sha256 hex of body>">`; the router checks it
against the machine's current key (from `start`, or its latest downgrade) and refuses a time more than 120 s
off.

| Call | Does |
|---|---|
| `GET /m/cert` | `{cert, predecessorCert}` — this machine's latest succession cert and the predecessor's cert when it continues a real machine (the machine checks both against the core key the core put in its Fly config, `JARVIS2_CORE_KEY`). 404 until certified. |
| `GET /m/snapshot` | The predecessor's snapshot: body = tar.gz, header `X-Snapshot-Sig` = base64 signature by the predecessor's signing key over the sha256 of the body. 404 = none. |
| `POST /m/snapshot` | Upload this machine's snapshot (same format). |
| `GET /m/restore-snapshot` | A restoring session's first machine only: the archived snapshot, same format, signed by the OLD machine named in `JARVIS2_RESTORE_CERT`. 404 otherwise. |
| `POST /m/pull-secrets` | The router adds this machine's cert and relays to the core; answers the core's signed `secrets` doc (sealed to the machine's key). |
| `GET /m/commands` | Long poll (≤ 50 s): `{commands: ["snapshot"]}` or `{commands: []}`. |
| `POST /m/add-store` | Body `{store}`: asks Deyao (an `add-store` approval) to add one store to this session. |
| `POST /m/downgrade` | Body `{stores, newEncryptionKey, newSigningKey}` → `{challenge}`, which the machine signs with its OLD key. |
| `POST /m/downgrade/finish` | Body `{challenge, signature}` → core `approve/by-old-key` → `{cert}`; from now on the router knows the machine by its new key. |
| `GET /m/tunnel-proof` | `{proof, id}`: hex HMAC-SHA256(`JARVIS2_TUNNEL_KEY`, `"jarvis2-tunnel:" + <this machine's session id>`), which the cf-tunnel Worker checks when the `jarvis2-tunnel` token registers that id. The machine puts it in `TUNNEL_AGENT_SECRET` at boot (never in the Fly config). 404 without the key; 403 for a machine with no running session. |
| `GET /m/attachments` | `{files: [{name, size, isImage}]}`: the first-prompt attachments bound to this machine's session (404 none). `GET /m/attachments/:name` the bytes; `DELETE /m/attachments` drops the router's copy once fetched. |
| `POST /m/task-result` | A task line's machine (harness `task:<template>`, below) after its run: `{run, exitCode, timedOut, error, startedAt, finishedAt, log /* tail ≤ 256 KB */, output /* ≤ 64 KB */}`, store values already redacted by the machine. `run: ""` = a boot with no run (the line's first machine). The router records the run and pauses the line. 403 for a machine that isn't a running task line. |
| `POST /m/status` | Body `{raw, appTitle}`: `raw` = the output of Jarvis 1's registry command (`machine/status.go`), sent by the agent when it changes and at least every 60 s; parsed by the router (`router/registry.go`). `appTitle` = the Claude app's title of the session's Remote Control entry, which the machine reads (at most once a minute) from `api.anthropic.com/v1/code/sessions/cse_<bridge>` with the session's own Claude login (`machine/apptitle.go`); "" keeps the last one. It becomes the session's `serverTitle`, and a resume without a label passes it on as `SESSION_RESUME_TITLE` (Jarvis 1's supervisor names a fresh Remote Control entry with it). |
| `POST /m/live-transcript` | Header `X-Name: <uuid>.jsonl`, body = the whole transcript (≤ 256 MB). The machine sends each conversation under `~/.claude/projects` that changed, every `JARVIS2_LIVE_SYNC_SECONDS` (default 300; router env `LIVE_SYNC_SECONDS` sets it), skipping Jarvis's delivery relays (`machine/livesync.go`). The router PUTs it to `claude-records/.live/<session id>/<name>` with its own Storage Box credentials — Jarvis 1's layout, so its transcript search indexes running Jarvis 2 sessions — and records `liveSync` on the session; with no Storage Box (or `RECORDS_OFF=1`) it answers `{ok, stored: false}`. The folder goes when the session is destroyed. 403 for a machine with no running session. |

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
template's timeout. A run needs its line's stores **unlocked** in the core, as any start does: a run whose machine
isn't up 30 min after the resume (a locked store keeps it `initialising`; `waiting` says so) fails and the line is paused.

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
| `DELETE /api/sessions/:id` | The router: the session retires itself (Destroy) → 202 `{started}`; 409 `{pending}` while it has wakeups or crons. |
| `…/watches` | 501: not in Jarvis 2. |
| Jarvis 1's services (below) | Forwarded to `JARVIS1_URL` (default `https://jarvis.deyaochen.com`) with the Access service token `JARVIS1_SERVICES_ID/SECRET` and header `X-Jarvis2-Session: <id>`; path, query, body, Content-Type/Accept/Range unchanged. |
| anything else | 404 |

Forwarded Jarvis 1 paths (what the cf-tunnel Worker must let the services token reach):
`GET /api/search`, `GET /api/search/context`, `GET /api/search/status`, `GET /api/icloud/search`,
`GET /api/icloud/file`, `GET /api/icloud/status`, `POST /api/icloud/relist`, `GET /api/usage` (the app's, without `X-Jarvis2-Session`), `GET /api/leases`,
`GET /api/leases/:name`, `POST|PUT|PATCH|DELETE /api/sessions/:id/leases/:name`,
`POST /api/sessions/:id/leases/:name/seen`, `GET /api/sessions/:id/content`,
`GET|PUT|DELETE /api/sessions/:id/content/:name/file`, `GET|POST /api/credentials`.

The session routes among them carry the Jarvis 2 session id (`s…`) and no Jarvis 1 session token: Jarvis 1 checks
`SESSION_API_TOKEN` against its own machine metadata (`requireSessionToken`, `sessionContentStore`), so until
it accepts the services token + `X-Jarvis2-Session` as the session's identity they answer 401/403.
