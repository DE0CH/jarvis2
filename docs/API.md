# Jarvis 2 — router API

The router (`router/`) is the only thing reachable from outside: `https://jarvis2.deyaochen.com`, through a
Cloudflare Tunnel behind Cloudflare Access. It is untrusted (docs/DESIGN.md "Target design"): it stores, carries and
schedules. Everything security-relevant it relays is a document signed by a kernel part (`core/kernel`: the log notary,
the succession notarizer, the grant mover and merger, the identity and gullible signers, the spawner, secrets), by the
iPhone, or by a machine, and the receiving end checks the signature. Writing secrets is the one thing only the router
protects.

Formats (`core/kernel/README.md`): a signed document is `{"payload": "<JSON text>", "sig": "<base64 DER
ECDSA-P256-SHA256 over the payload bytes>"}`, its ID the hex sha256 of the payload; public keys are base64 of the 65-byte
uncompressed X9.63 point (CryptoKit `x963Representation`). Succession certs, challenges, notarizations, notarized certs,
grants, sets and pairs are the kernel's formats. Errors are JSON `{"error": "..."}` with an HTTP status; errors that come
from a kernel part are relayed as that part's signed error document `{payload, sig}` whose payload is
`{"kind":"error","error":"..."}`. A part the router can't reach: 503 `{error, kernelDown: true}`.

The machine-facing API (`/m/*`, the guard) is `docs/API-grants.md`; this file lists it only by name.

The kernel parts are reached at router env `NOTARY_URL`, `NOTARIZER_URL`, `MOVER_URL`, `MERGER_URL`,
`IDENTITY_SIGNER_URL`, `GULLIBLE_SIGNER_URL`, `SPAWNER_URL`, `SECRETS_URL` (defaults: `http://<part>.jarvis2-kernel.svc.cluster.local:8090`,
`identity-signer` and `gullible-signer` for the signers).

## Who may call what

| Prefix | Caller | Access |
|---|---|---|
| `/api/*`, `/` (web page) | Deyao's app / browser | Access app `jarvis2.deyaochen.com`, Deyao's email only. The iPhone app sends the Access token in the `cf-access-token` header (got once from `/api/auth/start`). The router also verifies the `Cf-Access-Jwt-Assertion` header itself. An `/api/…` GET no route serves answers 404 (not the web page). |
| `/setup/*` | the trusted setup session | Access app `jarvis2.deyaochen.com/setup`, service token `jarvis2-setup` only (kept in Jarvis 1's `default` store, never on a machine). The router then checks the setup key's signature on each call (below). |
| `/m/*` | session machines (the guard) | Not on the public hostname at all: the router serves `/m` on a second port (8081) that only Fly's private network reaches (the box is a WireGuard peer of org `jarvis2-370`). The router checks the machine's own signature on each request, with the signing key its spawn cert names. |

## App sign-in

`GET /api/auth/start?redirect=jarvis2://auth` — Access makes Deyao log in first; the router then redirects to
`<redirect>#token=<the Access JWT>`. Only `jarvis2://` redirects are allowed. The app keeps the token in the
Keychain and sends it as `cf-access-token` on every request; when a request comes back 302/401/403 from
Access (token expired), it runs sign-in again.

## The kernel's documents (`router/docstore.go`, `router/chain.go`)

The router keeps every kernel document it carried, by ID, on its volume (`DATA_DIR/kernel/`), and each session's
**chain**: `sink → source → M1 → source → M2 → … → source → sink`, every step a notarized succession cert, and the grants
the mover and the merger made along it. The app checks all of it against the keys it knows; the router can only withhold.

| Call | Does |
|---|---|
| `GET /api/kernel/docs/:id` | One document (cert, challenge, notarization, grant) by ID; 404 when the router has none. |
| `GET /api/kernel/notarized/:id` | A notarized cert by its cert's ID: `{cert, challenge, notarization}`. |
| `GET /api/sessions/:id/chain` | `{session, steps: [{kind: cert \| grant, id, notarized? \| grant?}], main /* the main grant */, held /* the grant the running machine holds */, addOns: [{id, kind: terminal \| command, grant, merged, until, cmd?, once?, run?, added, grantDoc, mergedDoc}], source /* the current source object */, machine /* the current machine object or null */, origin /* the notarized cert the source came out of */, spawn /* the machine's notarized spawn cert */}`; also for a destroyed session (its record). 404 before the phone signed its first source. |
| `GET /api/kernel/root-grant` | Root's ⊤ on the sink, as the phone gave it (404 before). Every phone-made source's main grant is this grant moved along `(sink, source, P)`. |
| `PUT /api/kernel/root-grant` | Body: the signed grant `{"kind":"grant","by":"root","machine":{"id":"sink"},"allowed":{"except":[]},"conditions":[],"from":[]}` signed with the root key (the app makes it once at setup, behind the root-key warning screen). 400 for any other shape; the mover checks the root key's signature on every use. |
| `GET /api/kernel/roster` | `{parts: {notary, notarizer, mover, merger, identity, gullible, spawner, secrets}}`: each part's signing key as it answers `/identity` ("" when it doesn't). Not trusted: the app checks each part's box signature at `GET /api/kernel/identities`. |
| `GET /api/kernel/identities` | `{<part>: {role, signingKey, agreementKey?, boxSig?} \| null}`: every part's `GET /identity`, unchanged. |

## Sessions

A session's `id` is the router's (`s` + 16 hex), stable for the session's life; it is the start settings' `session` and
every main grant carries the condition `session:<id>`. `machineId` is the machine it is on now (null before the first
start and while paused). Session objects keep the Jarvis 1 shape where a field means the same thing:

```
{ id, machineId, released, name, state, status, created, region, environment /* stores, comma-joined */,
  stores, harness /* claude | opencode | openclaw | task:<template> */, label, model, permissionMode /* fixed for life */,
  guest, pausedAt, error, autoPause /* "on" | "off" */, notifyIdle /* "on" | "off" */, oneShot,
  lastReport /* the machine's last status report */,
  // while started, from the machine's report (fresh within 3 min), as in Jarvis 1:
  status /* busy | idle | waiting | … */, aiTitle, liveName, nameSource, bgTasks, statusUpdatedAt, bridgeSessionId,
  sessionId /* claude's conversation id */, authFailed, credsExpiresAt, sessionsInside, oneShotDone,
  refusals: [{kind: "fallback" | "refusal", at, uuid, from, to, model, category}],
  pauseInMs /* while the auto-pause countdown runs */,
  serverTitle /* the Claude app's own title of its Remote Control entry (the machine reads it; kept while paused) */,
  userTitle /* a name pinned in the CLI */, title /* what the card, channel and archive use: serverTitle → userTitle →
  label → aiTitle → id, Jarvis 1's pickTitle */, liveSync /* {at, files: {<name>: bytes}, stored, error} */,
  discordChannel, waiting /* what a pause or destroy waits on, plain words, or "" */,
  lockedStore /* a store the machine's last pull listed as locked; "" once a pull serves every store */,
  addOns: [{id, kind: terminal | command, until}] /* in force on the running machine */,
  commands: [{approval, cmd, code, stdout, stderr, error?, at}] /* the approved commands' results, newest last, 10 kept */,
  wakeups: [wakeup view], crons: [cron view], watches: [watch view] /* below */ }
```

What the router does by itself with a running session (`router/autopilot.go`, every 30 s), from the status and the
screen its machine pushes (output only; the router runs nothing in a machine unless Deyao opened a terminal): auto-pause
after 1 h plain idle (unless `autoPause` is off, the session is one-shot, or a wakeup or cron is due within 10 min);
destroy a one-shot session once `oneShotDone` — forcefully (a failed archive doesn't stop it) and with a DM when work was
lost (`router/oneshot.go`); DM "needs you" / idle / dead after 5 min in that state (the idle one muted by `notifyIdle`
off); DM new safeguard refusals and the "switch model?" dialog seen on the pushed screen; the `nudge` notice every 15 min
while idle with background jobs.

`state`: `approval` (waiting for the iPhone; no machine yet) → `starting` (the spawner makes the machine) →
`initialising` (spawned, its grant ready; the machine boots) → `started` (its first secrets pull went through) →
`pausing` → `paused` (no machine; the chain ends in a source) → `resuming` → … ; `destroying` → gone (moved to records);
`failed` (with `error`). A spawn the spawner refuses leaves the session `paused` on its unspent source with the error.

While the router drains for a rollout (`router/drain.go`), every call that starts a lifecycle action (`respond`, pause,
resume, destroy, restart, upgrade, and the same calls under `/m/api`, `/setup` and `/m/api/actions`) answers **503
`{error: "router updating, try again shortly"}`**. A session a router crash left mid-action comes back `failed` with
`error` "the … was cut off by a router crash: … again" (a cut-off start that hadn't spawned yet: `paused` with that
error).

| Call | Does |
|---|---|
| `GET /api/state` | `{sessions, approvals, secrets: {up, signingKey, agreementKey}, rootGrant /* bool: the router holds it */, inbox, inboxBatches, leases, repos, budget, …}` |
| `GET /api/sizes` | `{sizes: [{id, label}]}` (small / medium / large) |
| `GET /api/models` | `?harness=` optional → `{models: [{id, label, harness}], default, defaults: {<harness>: id}, harnesses: {<harness>: {label, detail}}}`. In `POST /api/sessions` an empty model or one of another harness becomes the harness's default; an unknown one is refused (400). |
| `GET /api/stores` | Every store, its keys and what each is for (never a value): `{stores: [{name, sensitive, empty, unlocked, about, version, keys: [names], keyInfo: [{name, explanation, at, writer: {by /* setup \| router \| machine \| core */, machine, session, sessionLabel}}]}], signed /* secrets' signed list it was built from */}`. The list, sensitivity, the key names, who wrote each key and when are secrets' (`POST /stores`; a machine writer is named with its session here); `about` and each `explanation` are the router's own record (`store-docs.json`). Same answer at `GET /m/stores` and `GET /setup/stores/keys`. |
| `PUT /api/stores/:store/docs` | `{about?, keys?: {KEY: text}}` → `{ok}`: what the store and its keys are for (plain text, ≤ 2000 characters each; `""` removes a key's explanation). |
| `GET /api/policy` | `{harnesses: {<harness>: {stores: […]}}}` — the stores each harness brings (the router adds them; the app hides them) |
| `POST /api/sessions` | Body `{requestId, label, prompt, model, permissionMode, size, harness, stores: [], repos, content: [], oneShot, autoPause, apiProxy, attachments: {uploadId, files: [{name}]}}`. The router adds the harness's stores, builds the start settings (docs/API-grants.md "Start settings": `session`, `harness`, `permissionMode`, `title` = label, `model`, `repos`, `content`, `oneShot`, `apiProxy`, `prompt`, `attachments` by sha256 and size) and drafts `(sink, source-x, P)` signed by the phone: source-x = `{id: "source-<32 hex>", image: the current session image, settings}`, P = `({only: ["store:<each store>"]}, ["session:<id>"])`; it asks the log notary for the draft's challenge. The approval (kind `new-session`) is in the Inbox when this answers `{id, requestId}`; a repeat with a `requestId` already on a session answers that session and makes nothing. |
| `POST /api/sessions/:id/pause` | The machine snapshots itself (signed; `snapshot` on its command channel), then the spawner's kill into a fresh source naming the snapshot's sha256, notarized; the main grant is moved onto that source. |
| `POST /api/sessions/:id/resume` | Body `{upgrade?, prompt? /* ≤ 4000 chars */, size?, model?, apiProxy?}`. Nothing that changes the source (no upgrade, prompt or settings change; a size is the spawn's): a spawn from the paused source, its spawn cert notarized and the main grant moved onto the new machine — no phone. Otherwise a new phone-made source: the router drafts `(sink, source-z, P)` with `source-z = {image: the newest session image if upgrade, else the paused one's; settings with the new model/apiProxy and the prompt; snapshot: the paused source's}`; an approval of kind `resume-upgrade` (reject = stays paused). On approval the paused source is burned (gullible `(source, sink)`, notarized) and the session spawns from source-z. |
| `POST /api/sessions/:id/destroy` | A running session is paused first (its final signed snapshot, the kill); the snapshot is archived to the Storage Box (below); then the burn: `(source, sink)` by the gullible signer, notarized — the source is never continued. The session moves to `GET /api/records`. A failed archive leaves the session `paused` with `error: "archive: …"`; `?force=1` destroys anyway (the record keeps `archiveError`). |
| `POST /api/sessions/:id/narrow` | Body `{stores: [names it holds]}` → `{ok, stores}`: the main grant moved along the identity edge `(M, M, ({only: store:<kept>…}, []))` — fewer stores, in place; the machine gets the new grant (and an add-on in force is merged onto it again). 400 for a store the session doesn't hold or a session that isn't running. |
| `GET /api/sessions/:id/changes` | Uncommitted / unpushed work per repo under `~/workspace`: `{checked, paused?, reason?, status?, repos: [{name, uncommitted, unpushed /* -1 = no upstream */}]}`. Running: a shell command, only while a terminal is open (else `checked: false` with the reason); paused: as the last snapshot recorded it. |
| `GET /api/sessions/:id/terminal` | `{screen /* tmux capture-pane -e */, cursor: "x,y,width,height,visible", at?}` — no grant: the pane the machine pushes itself (`POST /m/screen`; `at` = when, fresh for 45 s); with no fresh push, read with a shell command while a terminal is open. `POST` `{text?, keys?: [tmux key names]}` types, `{cols, rows}` resizes the window: shell commands, so only while a terminal is open (403 `{error, needsTerminal: true}` otherwise). |
| `POST /api/sessions/:id/exec` | Body `{cmd, timeout? /* 5–600 s */}` → `{id, code, stdout, stderr, grant, challenge}`: one shell command under the grant the machine holds — only while a terminal is open (403 `needsTerminal` otherwise). |
| `GET /term/:id` | The terminal as a web page (`router/web/terminal.html`): polls the snapshot above, sends keys and text. The iPhone app shows it in a WKWebView and listens on the message handler `jarvis2`: `{action: "terminal"}` (open the app's terminal request: `POST /api/requests/terminal`, Face ID) and `{action: "signin"}`; it calls `window.jarvis2Refresh()` once the terminal is approved or the login renewed. |
| `GET /api/sessions/:id/tail` | A paused session's conversation end, from its snapshot: `{title, sessionId, messages: [{role, text, at}]}` (409 while it runs, 404 without a snapshot). |
| `GET /api/state` (extra fields) | `budget`, `fly`, `flyApp`, `browserbaseBudget` (as before: `router/budget.go`, `router/bbbudget.go`). |
| `GET /api/machines` | The Machines tab (`router/machines.go`), every machine in Fly app jarvis2-sessions and every org, read-only tokens. Each machine: `{id, name, state, region, size, guest, image, created, updated, sessionId, current, routerUrl, test, noDestroy, attention}`. |
| `POST /api/machines/:id/destroy` | Destroy a machine that is no session's current one and that the router holds a notarized spawn cert for (a leftover of a failed pause or start), at least 15 minutes old, re-checked on a fresh Fly list: the spawner's kill with that spawn cert (the spawner alone holds a destroying Fly token, and kills only by a spawn cert). → `{ok, id}`; 409 `{error}` otherwise (e.g. "the router holds no spawn cert for it": Fly's to remove); 400 for an unknown id. |
| `GET /api/records` | Destroyed sessions `{records: [...]}`; each has `archive: {dir, title, transcripts, artifacts, signer, snapshotAt, last}`, `archiveError`, `restored: [{sessionId, at}]`, `chain`. |
| `POST /api/records` | Index an archive ALREADY on the Storage Box, by hand (Jarvis 1's call; `router/records.go`); such a record can't be restored. |
| `GET /api/records/:id/tail` | The archived conversation's end. |
| `DELETE /api/records/:id` | Off the list and the index; `?purge=1` deletes its archive too. |
| `POST /api/records/:id/restore` | Body `{requestId?}` → `{id, requestId}`. The router downloads the archive's snapshot (checking it against the archived spawn cert's machine key), keeps it on its volume by sha256, and makes a NEW session with the record's options whose source names that sha256 (`snapshot`); an approval of kind `new-session` with `options.restore` naming the record. The machine takes exactly those bytes (`GET /m/snapshot`). |
| `POST /api/sessions/:id/auto-pause` | Body `{on}` → `{ok, autoPause}`; restarts the idle countdown. |
| `POST /api/sessions/:id/notify-idle` | Body `{on}` → `{ok, notifyIdle}`. |
| `GET /api/sessions/:id/remote` | OpenCode/OpenClaw only (400 otherwise; 409 unless `started`): `{webUrl, harness, pairUrl, relay}` or `{webUrl, harness, url, token}`. Read with a shell command — only while a terminal is open: 403 `{error, needsTerminal: true}` otherwise; front end not up → 503. Cached 1 min per machine. |
| `GET /api/remotes?harness=openclaw\|opencode` | `{sessions: [{id, title, state, model, + url, token, webUrl \| pairUrl, or error (+ needsTerminal)}]}`. Deyao, or a paired app. |
| `POST /api/sessions/:id/start` | The paired apps' Start of a paused session: a resume with no change (no phone) → 202 `{ok}`. |
| `POST /api/sessions/:id/restart` | Body `{rollback?: {dropFromMarker /* 4–500 chars, one line */}, prompt?, size?, model?, apiProxy?}` → 202. Pause (if running) + resume: with a prompt, a rollback or a settings change, out of a new phone-made source (`resume-upgrade` approval; the settings carry `prompt` and `rollback`, which the guard applies to the snapshot it verified); else from the paused source. |
| `POST /api/sessions/:id/upgrade` | The one tap out of a memory-starvation episode (`router/memory.go`) → 202 `{started, kind: "upgrade", from, to}`: the machine frees memory (word `free`), the usual pause, a resume on the next size (a spawn size: no phone), then the `upgraded` notice. |
| `GET /api/state` (per session) | `busy: {kind: pausing \| starting \| destroying \| restarting \| upgrading, since}`; `wake: {kind, phase, error, startedAt, finishedAt}` for a restart / upgrade job; `apiProxy`; `memory`, `memAlert`. |
| `POST /api/uploads` | First-prompt attachments: one raw file per request, headers `x-upload-id` and `x-upload-name` → `{name, size, isImage}`. ≤ 20 files, 25 MB each (413). Staged on the router's volume; each bound file's sha256 and size go into the new source's settings (`attachments`). |
| `GET /api/sessions/:id/attachments/:name` | The bytes of a file staged for that session (until its machine fetched them): the app's approval page shows it and hashes it against the signed settings. |
| `GET /api/repos` | Deyao's repo list: `{repos: [{name, url, repo, store, sensitive, fingerprint?, keyAt?}]}`; an entry is added or removed only by secrets' answer to `POST /api/repos/key/finish`. |
| `POST /api/repos/key/begin {action, repo, sensitive?, store, title, publicKey?, keys?}` | Relayed to secrets' `deploy-keys/begin` (the repo normalised to `owner/name`). 400 for a non-GitHub repo or another action. |
| `POST /api/repos/key/finish {pending, signature, share}` | Relayed to `deploy-keys/finish`; on secrets' signed `deploy-key-added` the repo goes on the list, on `deploy-key-removed` it comes off. |
| `GET /api/github/repos` | The picker, listed with `GITHUB_READ_TOKEN` (5 min cache, `?refresh=1`); 503 without it. |
| `GET /api/usage` | The Claude quota (Jarvis 1's shape, `router/claudelogin.go`). |
| `GET /api/claude-login` | The Claude login, no secrets: `{hasLogin, expiresAt, expired, email, accountUuid, source, updatedAt, refreshedAt, participants, loginInProgress, preparing, error?, rejected?, needLogin?}`. |
| `POST /api/claude-login/refresh` | Refresh now → `{ok, refreshed, expiresAt}`; 409 / 502 `{error, needLogin}`. |
| `POST /api/claude-login/start` | Re-login, step 1 → `{url}`. |
| `POST /api/claude-login/code` | Re-login, step 2: `{code}` (`code#state`) → stored (any account) and written into the store `claude` → `{ok, email, expiresAt}`. |
| `GET /api/search…`, `GET /api/icloud/…` | The app's Search tab: forwarded to the box's own services (below). |

### Archives (Storage Box, router env `STORAGEBOX_HOST/USER/PASSWORD`)

`claude-records/<yyyy-mm-dd> <title>/` (Jarvis 1's layout; ` 2`, ` 3`… when taken): `transcript-<id>.jsonl`, `artifacts/**`,
`session.json`, `restore-<session id>.json`, and `jarvis2/snapshot.tar.gz` + `snapshot.sig` (the machine's signature over the
sha256 hex) + `spawn.json` (the signer's notarized spawn cert, naming its signing key) + `chain.json` (the session's whole
chain, as `GET /api/sessions/:id/chain`) + `roster.json` (the parts' keys as they answered). Index:
`claude-records/.index/jarvis2-destroyed-sessions.json` (newest first). `RECORDS_OFF=1` (the e2e test) destroys without archiving.
While a session runs, its transcripts are also copied to `claude-records/.live/<session id>/<uuid>.jsonl`
(`POST /m/live-transcript`), deleted on destroy.

Restore trust: the phone signs the new source naming the snapshot's sha256; the guard takes exactly those bytes. The router
checks the archive's signatures first only to refuse a broken archive early.

### Jarvis 1 import (`router/jarvis1import.go`, `machine/jarvis1import.go`)

A paused Jarvis 1 session (`claude-records/.paused/<id>/` on the Storage Box) becomes a NEW session, approved on the phone
like a new session, whose machine restores it and resumes the same conversation.

| Call | Does |
|---|---|
| `GET /api/jarvis1/paused` (`/setup/…` too) | `{sessions: [{id, title, pausedAt, size, model, environment, repos, prepare?, sha256?, sessions: [{id, state}], imported?}]}` |
| `GET /api/jarvis1/paused/{id}` | That one's state: `prepare {state, file, bytesDone, bytesTotal, error, sha256}`, `sha256`, the Jarvis 2 sessions made from it, `imported {session, at}`. |
| `POST /api/jarvis1/paused/{id}/prepare` | 202: the router streams every file once and hashes it, then writes the import manifest `{kind: "jarvis1-import", v: 1, session, files: [{name, sha256, size}]}` and Jarvis 1's record onto its volume. Refused without `manifest.txt`. |
| `POST /api/jarvis1/paused/{id}/import` | Body `{stores: [...], explanation, prompt?, size?}` → `{id, from, approval: true}`: a new session in `approval` whose source's `snapshot` is the manifest's sha256 (the manifest is kept on the volume by that hash); settings: `title` = Jarvis 1's app title, `prompt` = a move notice (or the given one), Jarvis 1's model, permission mode, repos; `options.restore` = "Jarvis 1 session “title” (id, paused date)". The same import again answers the same session. 400 before a prepare. |

The machine whose source names the manifest fetches it (`GET /m/snapshot`), then each file (`GET /m/import-file/{name}`,
streamed from the Storage Box) against the manifest's sha256 and size (`machine/jarvis1import.go`).

## Approvals (the shell's secure pages)

```
approval = { id, kind: "new-session" | "resume-upgrade" | "terminal" | "command" | "add-store", created, session,
             machine /* an add-on: the running machine */, label,
             drafts: [{payload /* the exact succession cert the phone signs */, challenge /* the log notary's, over the payload's sha256 */}],
             source /* new-session, resume-upgrade: the source object the draft makes */, imageSig /* CI's signature over the image, when known */,
             until /* terminal, command */, cmd, once /* command */, store /* add-store */,
             options /* the form's fields, for display */, origin: {caller, call, filing?}, explanation, batch }
```

What each kind's drafts are (all signed by the phone, `signer: "phone"`):

| Kind | Drafts |
|---|---|
| `new-session` | `(sink, source-x, P)`, P = the session's stores on `session:<id>` |
| `resume-upgrade` | `(sink, source-z, P)`, source-z naming the paused source's snapshot (a newer image, a prompt, a rollback, a settings change) |
| `terminal` | `(sink, source-a, ({only: ["shell"]}, ["session:<id>", "until:<T>"]))` and `(source-a, M, ⊤)`; T = filing + minutes (≤ 10) |
| `command` | `(sink, source-a, ({only: ["shell"]}, ["cmd:<sha256 of cmd>", "once:<32 hex>", "session:<id>", "until:<filing + 10 min>"]))` and `(source-a, M, ⊤)` |
| `add-store` | `(sink, source-a, ({only: ["store:<X>"]}, ["session:<id>"]))` and `(source-a, M, ⊤)` |

| Call | Does |
|---|---|
| `GET /api/approvals` | `{approvals: [...]}` |
| `POST /api/approvals/:id/respond` | Body `{signatures: [...]}` = one base64 DER signature by the phone's key over **exactly** each draft's `payload`, in order (one Face ID). The router notarizes each (the notarizer checks the phone's key and the table; a refusal leaves the approval in the Inbox), then: `new-session` / `resume-upgrade` → root's ⊤ moved along the cert is the main grant on the source; the session spawns from it (a resume-upgrade burns the paused source first); `terminal` / `command` → root's ⊤ moved along both certs is the add-on's grant on M; M's main grant is moved along an identity edge `(M, M, (everything, the add-on's conditions))` and merged with it; the machine holds the merged grant until `until` (a command is sent once under it, its result kept on the session, then the main grant is back); `add-store` → the add-on's grant merges straight into a new main grant (its conditions are the main grant's). → `{ok, session}`. 400 for the wrong number of signatures. |
| `POST /api/approvals/:id/reject` | Drops it; a new session disappears, a resume-upgrade stays paused. |

The phone shows exactly what it signs: known strings readably, the source's settings and image, the machine object.

## Requests (the app's Inbox, `router/inbox.go`)

A request asks the phone for something that needs Face ID; it waits in the app's Inbox until Deyao reviews it on the
shell's secure page. The **intent endpoints** are the same under these prefixes, one per kind of caller; the router records
the caller from the credential (never from the body) and the call:

| Prefix | Caller | Credential |
|---|---|---|
| `/api/requests/…` | the web page, or the app (`cf-access-token` header) | Deyao's Access login |
| `/setup/requests/…` | Claude, the setup session | the setup key's signature |
| `/m/api/requests/…` | a session (`$JARVIS_URL/api/requests/…` through the guard's proxy, which adds `X-Jarvis2-Filing`) | the machine key |
| `/m/api/actions/requests/…` | a session's actions | the machine key |

| Intent | Body (`explanation` in every one) | Who | Becomes |
|---|---|---|---|
| `POST …/repo/add` | `{repo, sensitive?}` | anyone | request `repo-key` |
| `POST …/repo/remove` | `{repo}` | not a session | request `repo-key` |
| `POST …/unlock` | `{session}`: the locked stores that session waits on | a session only for itself | request `unlock` |
| `POST …/restore` | `{store, seq}` | not a session; never in a batch | request `restore` |
| `POST …/terminal` | `{session, minutes /* 1–10, default 10; more is refused */}` | a session only for itself (it may leave `session` out) | approval `terminal` |
| `POST …/command` | `{session, cmd /* 1–4000 bytes */}` | a session only for itself | approval `command` |
| `POST …/add-store` | `{session, store}` (not `core` or `github-deploy-keys`; not one it holds) | a session only for itself | approval `add-store` |
| `POST /m/api/sessions` | `POST /api/sessions`'s body without `attachments`, plus `explanation` (required) → `{id, requestId, approval: true}`: a session PROPOSES a new session; at most 3 proposals wait per session (429). | a session | approval `new-session` |

The add-ons answer `{id /* the approval's */, approval: true, expires}`; the rest `{id, duplicate, expires}`.
`explanation`: required from a session, its actions and the setup session (plain text; ≤ 600 characters, ≤ 8 lines). 400
for bad arguments, 403 for what this caller may not ask; at most 20 pending per caller. Everything goes after 10 minutes,
when its session is destroyed, when it is done, or on Deny.

```
item = { id, kind: "repo-key" | "unlock" | "restore" | "api-call" | "new-session" | "resume-upgrade" | "terminal" | "command" | "add-store",
         approval /* bool */, batch, params: {action, repo, sensitive, session, store, seq, method, path, body, contentType},
         session, sessionName, caller: {kind: "web" | "app" | "session" | "setup" | "actions" | "router", session}, callerText,
         call: {method, path, args}, explanation, created, expires, options, open: {kind, options} }
```

| Call | Does |
|---|---|
| `GET /api/requests` | `{requests: [item], batches}`, newest first; also `inbox` in `GET /api/state` |
| `GET /api/requests/:id` | one item (404 when answered, denied or expired) |
| `DELETE /api/requests/:id` | Deny: dropped (an approval is rejected) |
| `POST /api/requests/:id/done` | the shell's page went through: the request leaves the Inbox |
| `POST /api/requests/:id/approve` | an `api-call` request (below, "Actions"): the router runs the call now as Deyao → `{ok, state, status, error}` |
| `GET /setup/requests`, `GET /m/api/requests` | the same list for Claude; a session sees only its own |
| `GET /setup/repos`, `GET /setup/sessions` | the repo list; the sessions and their machines |

### Batches (`router/batches.go`)

| Call | Does |
|---|---|
| `POST …/requests/batch` (`/api`, `/setup`, `/m/api`, `/m/api/actions`) | Body `{summary /* required */, items: [{intent, …that intent's body…}]}`; intents: `repo/add`, `repo/remove`, `unlock`, `terminal`, `command`, `add-store`, `new-session`, `jarvis1-import` (setup and Deyao only). 1–20 items, every one checked first (one bad item, or the same item twice: nothing is filed). → `{id: "b…", expires, items: [{intent, id?, session?, duplicate?, batch?, error?}]}`. A batch counts once toward the caller's 20 waiting requests and, when it proposes a session, once toward the 3 waiting proposals (429). |
| `GET /api/requests/batches/:id` (`/setup/…`; `/m/api/…` its own) | `{batch, items: [item]}` |
| `DELETE /api/requests/batches/:id`, `POST /m/api/actions/requests/batches/:id/deny` | Deny all |

```
batch = { id, summary, caller, callerText, call, created, expires, items: [inbox ids, as filed] }
```

The app signs each item exactly as alone (each approval's drafts, each deploy key's begin), using one LAContext the
batch's Face ID authenticated.

### Outcomes (`router/outcomes.go`, `machine/outcomes.go`)

When an item a **session** filed is decided, the router tells that session with the `request-outcome` notice
(docs/API-grants.md "notices"): `{filing /* the id the guard gave the filing, header X-Jarvis2-Filing */, items: [{item
/* index in a batch, 0 otherwise */, outcome: approved | denied | lapsed | dropped | failed, ref /* the Inbox id; for an
approval the session's id */, status /* an approved API call's HTTP status */}]}`. The guard builds the text from the
filing it kept and texts built into its image. A batch's items go together, once every item is decided or 30 s after the
last decision. A paused session is not started for it; a destroyed session's go with it. A filing without the guard's id
tells nothing.

| Call | Does |
|---|---|
| `GET /m/api/requests/outcomes` | this session's recorded outcomes, newest first: `{outcomes: [{ref, batch?, item, kind, outcome, status?, at, delivered?, error?}]}` |

## Secrets, relayed (`/api/secrets/*`)

Pass-through to secrets' own endpoints (core/kernel/README.md), answers unchanged (signed): `GET identity`, `POST state`,
`POST stores {nonce}`, `POST stores/create {name}`, `POST stores/mark-sensitive {name}`, `POST stores/versions {store,
nonce}`, `POST stores/restore/begin {store, seq}`, `POST unlock/begin {store}`, `POST unlock/finish {pending, shares}` (on
secrets' `unlocked` answer every running machine whose grant names that store gets `pull`), `POST lock {id}`, `POST unlocked
{nonce}`, `POST store-key {phone}`, and — only from the app's device login (the `cf-access-token` header; 403 otherwise) —
`POST claim {statement, masterSig, bundle, deviceKey?, deviceSig?}` (the router keeps the device countersignature for the
setup session and, on 200, the master-signed claim; right after it writes the Claude login into the store `claude`) and
`POST wipe {statement, masterSig}`. An unlock is per store and never locks by itself: it ends with `lock`.

## Store versions and restore (`core/kernel/secrets/history.go`, `router/storerestore.go`)

- `POST /api/secrets/stores/versions {store, nonce}` (relayed; `/setup/stores/versions` the same) → secrets' signed list.
- `POST /api/secrets/stores/restore/begin {store, seq}` (relayed) → secrets' signed begin document.
- `POST /api/stores/restore/finish {pending, signature, shares: {KEY: share}}` (the app, after Face ID): relayed to secrets'
  `/stores/restore/finish`; the router writes secrets' backups to the bucket (`keys/<store>/<key>.json`, writer `restore`
  with secrets' receipt) and only then `/stores/restore/commit {pending}` → `{ok, restored, pulled: [session ids]}` (the
  machines whose grant names the store pull). A backup the router can't write: nothing is committed.

## Backups (`/api/backups`)

`GET /api/backups` → `{bucket, objects: [{key, body}]}`: every object under `stores/` and `sensitive/` in the
versioned bucket `jarvis2-backup-de0ch`, `body` its text unchanged — `stores/<name>.json` = `{doc, sig}` with `doc`
= `{"kind":"store-backup","name","sensitive","sealed":{e,data},"at"}` (the values sealed to the master key, HKDF info
`"jarvis2/backup"`, the store's name as associated data) and `sig` the setup key's ECDSA over `doc`;
`sensitive/<name>.json` = a signed `{"kind":"store-sensitive","name","at"}` marker. The router reads them with its
own read credential (router env `BACKUP_READ_ACCESS_KEY/SECRET_KEY`; `BACKUP_ENDPOINT`, `BACKUP_REGION`,
`BACKUP_BUCKET` default to the production bucket) and answers 503 without it, 502 when the bucket refuses. The app
checks each `sig` against `keys/setup.pub` (from GitHub) and opens each backup with the master key from the kit. A key
backup a restore wrote (`keys/<store>/<key>.json` with `writer: {by: "restore", receipt}`) is checked by its receipt:
secrets' signed `{"kind":"store-restore-approved", pending, store, from, to, put: [{key, e, dataSha256, backupSha256}],
remove, begin, phoneSig, at}`, from a secrets whose identity (`secrets` in the object) the box key signed; it must name this
key's hashes (or list it as removed). Settings → Encrypted backup saves the same answer, checked but unopened, as one file for
`tools/decrypt-backup.py` (RUNBOOK "Offline copy of the stores").

Unlock, phone side: verify `unlock/begin`'s doc (kind `unlock-begin`, fields `pending, store, t, for, version, keys:
[{key, e, writer, dataSha256, backupSha256, at}]`) and every key's writer (`setup`: the setup key's signature over
`"jarvis2-store-key\n" store \n key \n e \n dataSha256 \n backupSha256`; `machine`: the router's word, the app shows
which session wrote the key; `router`: the router itself (the Claude login); `core`: secrets' own); one Face ID → for every key, Enclave key agreement of the phone's agreement key
with its `e` → the 32-byte x-coordinate, sealed to `t`: ephemeral P-256 key `r`, `x' = x(r·t)`, key =
HKDF-SHA256(ikm `x'`, salt empty, info `"jarvis2/unlock-share"`, 32 bytes), AES-256-GCM combined
(`nonce‖ciphertext‖tag`) → `{e: base64(r.pub x963), data: base64(combined)}` → `unlock/finish {pending, shares: {KEY:
share}}` (one share for each key the begin named).

## Deploy keys (secrets: `deploy-keys/*`, `core/kernel/secrets/deploykeys.go`)

- `POST deploy-keys/begin {action: add | remove, repo: owner/name, sensitive, store, title, publicKey, keys}`: the
  app names the store (`github-<name>` for DE0CH, else `github-<owner>-<name>`) and the key's title on GitHub
  (`jarvis2 <store>`), and for an add makes the key pair: `publicKey` ("ssh-ed25519 <base64 wire>") and `keys`, the
  store `{GITHUB_DEPLOY_REPO_<SLUG>: "owner/name", GITHUB_DEPLOY_KEY_<SLUG>: base64(OpenSSH private key file)}`
  (`<SLUG>` = `OWNER_NAME`, upper case, other characters `_`) wrapped to the store key from `POST store-key` →
  secrets' signed `{"kind":"deploy-key-begin", pending, action, repo, store, sensitive /* add: asked for, OR the store
  is sensitive already; remove: the store's */, replaces /* add: the store exists */, title, publicKey, blobE,
  blobSha256 /* add: the blob's E and the sha256 hex of its data */, tokenStore: "github-deploy-keys", tokenWriter,
  tokenDataSha256, e /* that store's E */, t /* a one-off key */}`, so the phone's signature covers the key and the
  blob. The app keeps `DE0CH/jarvis2`'s store sensitive itself (it asks for it, and refuses a begin that isn't).
  400 for an add without the key pair or with a blob for another store, or a title that isn't one short line; 404
  while `github-deploy-keys` has no contents; 409 on an empty secrets; 409 `store github-x belongs to <owner/name>` when
  another repo owns that store name (names collide: `DE0CH/foo-bar` and `foo/bar`, `my.repo` and `My-Repo`; the owner
  is the repo whose add wrote the store, or after a Recover the bundle's `owners`; finish checks it again); 400 for a
  bad repo or store name (`github-deploy-keys` and `core` aren't allowed).
- `POST deploy-keys/finish {pending, signature, share}`: `signature` = the phone's base64 DER ECDSA over the begin
  document's payload (its signing key from the claim), `share` = x(p·E) of the token store sealed to `t` exactly as
  an unlock's share (HKDF info `"jarvis2/unlock-share"`); the shell makes both under one Face ID. One try per
  pending. Secrets opens `github-deploy-keys` for this call only (it never joins the unlocked set) and reads
  `GITHUB_DEPLOY_KEYS_TOKEN`; it deletes the repo's keys titled `jarvis2 <store>` on GitHub (`GET/DELETE
  /repos/{repo}/keys`), then — add — adds the app's public key (`POST /repos/{repo}/keys`, `read_only: false`) and
  stores exactly the app's blob (writer `core`) →
  `{"kind":"deploy-key-added", pending, repo, store, sensitive, title, publicKey, keyId}`; or —
  remove — deletes the store → `{"kind":"deploy-key-removed", pending, repo, store, deleted}`. 403 for a wrong
  signature or share; 502 `github: HTTP <status>: <GitHub's words>` when GitHub refuses (the router's
  `/api/repos/key/finish` turns a 403/404 into what the token needs: Repository "Administration: read and write").
- `POST store-key {phone}` → secrets' signed `{"kind":"store-key", phone, storeKey}`: `storeKey` = P + K (X9.63
  base64) for that phone agreement key P. Open, also on an empty secrets: what the app wraps a data key to (one-off e,
  HKDF-SHA256 of x(e·storeKey) with info `"jarvis2/store-data-key"`, AES-256-GCM nonce‖ciphertext), since CryptoKit
  can't add points: a deploy key's store, and every store of a Recover's bundle (`claim`, above).

## Actions (`/m/api/actions/*`, `router/actions.go`)

A session's actions: what a session may do to Jarvis 2 beyond its own business. Each session's key is its own machine
key (its spawn cert names it), so every action is that session's: Inbox entries name the caller "the actions of session
“title” (id)". The key works only while the session runs (`started`/`initialising`). Client: claude-env
`scripts/jarvis2-actions.py`.

| Route | What |
|---|---|
| `GET /m/api/actions/sessions` | `{sessions: [{id, machineId, state, title, error, image, status?}]}` |
| `GET /m/api/actions/requests` | The Inbox, as `GET /api/requests` |
| `POST /m/api/actions/sessions/:id/resume` | Resume a paused session with no change: a spawn from its paused source, no phone. 4xx when not paused |
| `POST /m/api/actions/sessions/:id/pause`, `…/upgrade`, `…/destroy` | As the app's |
| `POST /m/api/actions/requests/:id/deny` | An Inbox request leaves; an approval is rejected |
| `POST /m/api/actions/sessions` | Propose a new session (as `POST /m/api/sessions`) |
| `POST /m/api/actions/requests/{repo/add,repo/remove,unlock,terminal,command,add-store}` | An Inbox request or add-on approval (a terminal, command or store only for the actions' own session) |
| `POST /m/api/actions/requests/batch`, `…/batches/:id/deny` | A batch; Deny all |
| `POST /m/api/actions/requests/call` | Ask for ANY app API call to be run as Deyao (`router/apicalls.go`): `{method, path, body? \| bodyText? + contentType?, explanation}` → `{id, duplicate, expires}` |
| `GET /m/api/actions/requests/call/:id` | That session's own call: `{state, status, contentType, body, withheld, error, approvedBy, at}` |

Every app route is classified in `router/apicalls.go` `callRules` (`TestEveryAppRouteClassified` fails on one left out):
`callBody`, `callStatus` (the response carries a credential) or `callNo` (the Inbox and approvals, anything that takes a
phone- or root-signed document, and calls that would hand out Deyao's login or can't run on the router).

## Setup (`/setup/*`)

Every call carries `X-Setup-Time` (unix seconds) and `X-Setup-Sig` = base64 DER ECDSA-P256-SHA256 signature by the setup
key over `"<METHOD> <path> <time> <sha256hex of body>"`; the router checks it against `SETUP_KEY`, within ±2 min, each
signature once. Client: `infra/setup.py`.

| Call | Kernel part, path |
|---|---|
| `GET /setup/identity` | secrets `/identity` |
| `POST /setup/stores`, `/setup/stores/create`, `/setup/stores/mark-sensitive`, `/setup/stores/versions` | secrets, the same paths |
| `POST /setup/stores/{store}/keys/{key}` | (the router's own, then secrets `/stores/write-key`, writer `setup` with the setup key's signature over `WriterText`) one key written or deleted, as `POST /m/stores/{store}/keys/{key}` |
| `GET /setup/store-keys` | (the router's own) as `GET /m/store-keys` |
| `POST /setup/store-docs` | (the router's own) `{store, about?, keys}` → `{ok}` |
| `POST /setup/fly-token` | spawner `/fly-token {sealed}`: `{"FLY_API_TOKEN"}` sealed to the spawner's agreement key (HKDF info `"jarvis2/fly-token"`) |
| `GET /setup/secrets-cert` | (the router's own) `{statement, masterSig}` of the claim it kept for the running secrets; 404 when none |
| `GET /setup/claim-device` | (the router's own) the last claims' device countersignatures |
| `GET /setup/stores/keys` | (the router's own) the store list, as `GET /api/stores` |
| `GET /setup/jarvis1/paused[/{id}]`, `POST …/prepare\|import` | (the router's own) as `/api/jarvis1/…` |
| `POST /setup/sessions/{id}/pause`, `/resume`, `/restart` | (the router's own) cancel its wakeups and crons and pause it; resume with no change; restart with no change. 202 |
| `POST /setup/requests/…`, `GET /setup/requests`, `GET /setup/sessions`, `GET /setup/repos` | the Inbox (above) |
| `POST /setup/leases/:name/take-over`, `…/hand-back` | leases (below) |
| `GET /setup/claude-login` | the Claude login's status |

`GET /setup/status` — the router's health: the names of its secrets that are set (values never), the session image, which
kernel parts answer (`kernel: {<part>: bool}`), whether it holds the root grant, `githubRepos`, `flyOrgs`.

## The Claude login (`router/claudelogin.go`)

One OAuth pair shared by every Claude session (Jarvis 1's too while it runs: it follows, `/peer/claude-login`), on the
router's volume (`claude-login.json`, 0600). The router is the ONLY refresher (when under 30 min are left).

Sessions get it through the store `claude` (DESIGN "Secrets"): on every refresh, Re-login, accepted push and right after a
claim, the router writes `CLAUDE_CREDENTIALS` (the exact `~/.claude/.credentials.json`) and `CLAUDE_ACCOUNT` (`{oauthAccount,
userID}`) into `claude` — writer `router`, its backup first, the value sealed to the store key, to the master key and to
secrets' agreement key (`live`, served on the next pull) — then sends `pull` to every running machine whose grant names
`store:claude`.

The refresh protocol (lessons/74): the router sends `claude-prepare:<gen>` to each of those machines (and answers Jarvis 1's
poll with `{preparing, gen}`); each takes the CLI's refresh lock and acks (`POST /m/claude-ack {gen}`; Jarvis 1 polls with
`ack=gen`); the router waits for them (at most 10 s), refreshes, writes the pair to its volume and the store, and sends
`pull`. A refused refresh (the grant is dead) DMs Deyao once.

| Path | Who |
|---|---|
| `POST /m/claude-ack {gen}`, `POST /m/claude-push {credentials}` | a machine whose held grant names `store:claude` (403 otherwise); a push is stored only when it expires later and Anthropic's profile endpoint says it is the stored account's (403 otherwise) → `{stored, expiresAt}` |
| `GET/POST /peer/claude-login`, `GET /peer/claude-login/status` | Jarvis 1 (Access app `jarvis2.deyaochen.com/peer`, service token `jarvis1-claude-login` only): the long poll `?have=&ack=&wait=` → `{credentials?, account, expiresAt, gen, preparing}`, and its push (`relogin: true` may change the account) |
| `GET /setup/claude-login` | the setup session: status |
| `/api/claude-login*`, `/api/usage` | the app (above) |

## Machines (`/m/*`)

The guard's API, every endpoint with its request and response and what the router does behind it: `docs/API-grants.md`.
In short: `GET /m/boot` (the spawn cert and the cert the source came out of, notarized), `GET /m/grant`, `GET /m/config`,
`GET /m/tunnel-proof`, `GET /m/snapshot` (by the sha256 the source names), `POST /m/snapshot`, `GET /m/import-file/{name}`,
`GET /m/attachments/{name}`, `DELETE /m/attachments`, `GET /m/commands` (words, one grant, shell commands, due signals,
notices), `POST /m/challenge`, `POST /m/shell-result`, `POST /m/due-result`, `POST /m/notice-result`, `POST
/m/secrets/pull`, `GET /m/stores`, `GET /m/store-keys`, `POST /m/stores/{store}/keys/{key}`, `POST /m/claude-ack`, `POST
/m/claude-push`; output only: `POST /m/status`, `POST /m/screen`, `POST /m/memory`, `POST /m/live-transcript`, `POST
/m/task-result`.

Output-only endpoints, as the router reads them:

| Call | Does |
|---|---|
| `POST /m/status` | Body `{raw, appTitle}`: `raw` = the output of Jarvis 1's registry command (`machine/status.go`), parsed by the router (`router/registry.go`); `appTitle` = the Claude app's title of the Remote Control entry ("" keeps the last one), the session's `serverTitle`. The first report marks the machine booted. |
| `POST /m/screen` | `{screen, cursor}`: the pane the machine pushes itself; the terminal view and the autopilot's dialog check read it. |
| `POST /m/memory` | `{totalKb, availKb, oomKills, psiFull60, top}`: the starvation watch (`router/memory.go`). |
| `POST /m/live-transcript` | Header `X-Name: <uuid>.jsonl`, body = the whole transcript: PUT to `claude-records/.live/<session id>/<name>`. |
| `POST /m/task-result` | A task session's machine after its run: `{run, exitCode, timedOut, error, startedAt, finishedAt, log, output}`. |

## Wakeups and crons (`router/schedule.go`)

The session arms one through its guard's local API, which keeps the prompt in the guard's records (in the snapshot) and
sends the router the request without it, plus `id` (32 hex, the guard's). At the due time the router sends the machine a
due signal `{kind: wakeup, id}` / `{kind: cron, id, run}` (run numbers count up from 1 per cron), resuming a paused session
first; the guard types its own text by its replay rules. The app lists and cancels them, never arms one (400: there would be
no text on the machine). A wakeup or cron belongs to its session and ends with it.

| Call | Does |
|---|---|
| `GET …/wakeup` | `{wakeup /* the soonest or null */, wakeups}`; `GET …/wakeups` → `{wakeups}`. View `{name, id, at /* ms */, atIso}`. |
| `POST /m/api/sessions/:id/wakeup` or `…/wakeups` | `{id, at? /* ISO or ms */, delaySeconds?, name? /* default "default" */}` (no `prompt`: 400) → `{ok, wakeup}`. Arming a name again replaces it. ≤ 90 days. The app's `POST /api/sessions/:id/wakeup(s)` → 400. |
| `DELETE …/wakeup?name=X` (`?all=1`), `DELETE …/wakeups/:name` | `{ok, cancelled: [names]}` (app and session) |
| `GET …/crons` | `{crons}`; view `{name, id, everySeconds, tz, nextAt, nextAtIso, until, untilIso, armedAtIso, runs, lastFiredIso}` |
| `POST /m/api/sessions/:id/crons` | `{name, id, everySeconds? /* 900–7776000, default 86400 */, time? "HH:MM" + tz?, at?, delaySeconds?, until?}` → `{ok, cron}`. The app's `POST /api/sessions/:id/crons` → 400. |
| `DELETE …/crons/:name` | `{ok}` |
| `POST …/notify-idle` | `{enabled}` → `{ok, notifyIdle}` |

A failed delivery (the guard refused, no answer) backs off and, after 5 attempts, drops a wakeup (a cron skips that
occurrence) with a DM.

## Tasks (`router/tasks.go`, `machine/task.go`, templates in `tasks/`)

Jarvis 1's Tasks and Schedules tabs, same shapes where the meaning is the same (`selfhost/jarvis/lib/tasks.js`). A task
**instance** is a session whose start settings' harness is `task:<template>` and whose `task` carries the instance and
its parameters (DECISIONS 32): creating one asks the phone once (an ordinary `new-session` approval, label `Task:
<name>`, stores = the template's + the ones picked in its store fields). Each **run** resumes that session with no phone (a
spawn from its paused source); its machine runs the template from the session image instead of a harness, reports to
`/m/task-result`, and the router pauses it again. The run's id and trigger reach the machine in `GET /m/config`
(`taskRun`, `taskTrigger`). Task lines also
show in `/api/state` `sessions` (harness `task:…`); the autopilot and Discord channels leave them alone.

**Template** (`tasks/<name>/task.json` + its files; the router image has a copy for the forms, the session image the copy
that runs — `/opt/jarvis2/tasks/<name>`, fixed by the session's image digest):

```
{ title, description?, run? /* "run.py" | "run.sh" | "run.js" | an executable; default: the first that exists */,
  prompt? /* "prompt.md": `claude -p` with {{field}} filled in, in the settings' permission mode (needs store claude) */,
  model? /* prompt only */, stores?: [store…], timeoutSeconds? /* 10–21600, default 600 */,
  size? /* small (default) | medium | large */,
  fields: [{ name /* [a-z][a-z0-9_]* */, label?, type: text|textarea|number|select|multiselect|checkbox, required?,
             default?, help?, placeholder?, options?: ["a", {value, label, sub?}], optionsFrom?: stores|sizes|models }] }
```

A (multi)select with `optionsFrom: "stores"` adds the picked store(s) to the line; `options` comes back empty for it —
the app fills the list from secrets' store list (`/api/secrets/stores`). Jarvis 1's `secretKeys`, `image`, `memory` and
hidden values don't exist here (a picked store brings all its keys; secrets live only in stores).

**What a run sees** (machine/task.go): cwd `~/task-work` (fresh each run); env = PATH/HOME/LANG/…, `JARVIS_URL`,
`SESSION_ID`, `LOBSTER_CHANNEL`, `TASK_PARAMS` (all values as JSON, from the settings' `task`), `PARAM_<FIELD>` (lists
comma-joined, booleans `true`/`false`), `TASK_INSTANCE`, `TASK_NAME`, `TASK_RUN`, `TASK_TRIGGER` (manual | schedule), then `TASK_DIR`
(the template's files), `TASK_TEMPLATE`, `TASK_OUTPUT` (a file whose first 64 KB is the run's output in the app),
`TASK_STATE_DIR` (`~/workspace/task-state`, kept between runs by the snapshot), `TASK_WORK`, `TASK_TIMEOUT`, and last the
session's store values (also in `~/.secrets`). Parameters are NOT secret (they are in the settings the phone saw), so a
script treats them as data. The log is `~/artifacts/task-runs/<run>.log` (20 kept, archived with the line); store
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
| `PUT /api/tasks/instances/:id` | `{name?, params?, size?}` → the instance. Values that change the session's stores → 400 (make a new task). |
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
template's timeout. A run's machine pulls its stores with its main grant; a store that isn't unlocked is listed as
locked and the guard starts after 10 minutes with what was served: a run whose machine isn't up 30 min after the resume
(`waiting` says so) fails and the session is paused.

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
| `POST /m/api/sessions/:id/leases/:name` | `{purpose, description?, ttlSeconds? /* 60–21600, default 3600 */, lowPriority?, id}` (the guard's proxy keeps the wake note, `prompt`, on the machine and adds `id`) → `{status: granted | renewed | queued | busy, position?, lease}`; `busy` (409) only for `lowPriority`. |
| `PUT /m/api/sessions/:id/leases/:name` | Renew (holder only) → `{status: "renewed", lease}`; 409 otherwise, `{takenOver: true}` with Deyao's note while he has it (and the session is told when he hands it back). |
| `PATCH /m/api/sessions/:id/leases/:name` | `{purpose?, description?}` (holder or waiter; no renew) → `{status: holder | queued, lease}` |
| `POST /m/api/sessions/:id/leases/:name/seen` | The session looked at a device Deyao has (lease.py status) → `{takenOver}`; it is told when he hands it back. |
| `DELETE /m/api/sessions/:id/leases/:name` | Return it (holder) or leave the queue → `{returned, left, next /* the woken session or null */}` |
| `POST /api/leases/:name/force-return` | The app: `{returned, previous, next}` |
| `POST /api/leases/:name/take-over` | The app: `{note?}` Deyao takes the device (never expires; agents' actions refused); the holder goes to the front of the queue and is told (`lease-taken`). While he has it, a note only replaces his note. → `{taken, interrupted, noteUpdated}` |
| `POST /api/leases/:name/hand-back` | The app: `{note?}` → `{handedBack, next, notified}`; the next waiter is woken, every other session that found it taken over is told (`lease-back`). |
| `POST /setup/leases/:name/take-over`, `…/hand-back` | The same, by the setup session for Deyao (setup-key signed; `infra/setup.py lease take-over DEVICE --note …`). |

Wake messages are notices (docs/API-grants.md): `lease-granted` (`device`, `minutes`, `handover`, `interrupted`; the note
is the session's own, kept on its machine; a paused waiter is resumed first), `lease-taken` and `lease-back` (`device`). A promoted holder that can't be woken is
retried every 30 s (20 tries). A destroyed session's holder or queue place goes at the next sweep.

## Watches (`router/watches.go`, `services/watch`)

Conditional wakeups, Jarvis 1's shapes. The session arms one through its guard's local API, which keeps the prompts (met,
gave up) in its records and sends the router the check script, the interval, the maximum age and its `id`. The router runs
the check on the watch runner (k8s/apps/watch.yaml: no secrets, public internet only) every `interval`, whether the session
runs or is paused. Exit 0 = met; exit 3, or `maxSeconds` past arming = gave up; any other exit, or a runner error = not
yet. Then a due signal `{kind: watch, id, outcome: met | gave-up}` (the session resumed first when paused); the guard types
its own text. The runner's output never reaches the session. A failed delivery backs off and after 5 attempts the watch is
dropped with a DM.

```
watch view = { name, id, interval, maxSeconds, armedAt, armedAtIso, expiresAtIso, nextCheckIso, runs, lastExit, lastRunIso,
               lastError, lastOutput, outcome /* "" | met | gave-up */ }
```

| Call | Does |
|---|---|
| `POST /m/api/sessions/:id/watches` | `{name, script /* bash, ≤ 32 KB */, id, interval? /* 30–3600 s, default 60 */, maxSeconds? /* ≤ 400 d, default 7 d */}` (no `prompt`/`failPrompt`: 400) → `{ok, watch}`; the same name replaces. The app's `POST /api/sessions/:id/watches` → 400. |
| `GET /api/sessions/:id/watches`, `/m/api/…` | `{watches}` (no script bodies) |
| `DELETE /api/sessions/:id/watches/:name`, `/m/api/…` | `{ok}` |

The runner (`POST http://watch.jarvis2-edge.svc.cluster.local:8095/run {script, name, timeout}` →
`{exit, stdout, stderr, timedOut, ms}`, router env `WATCH_URL`): a check gets PATH, HOME and TMPDIR, LANG and WATCH_NAME;
bash, curl, python3, git, openssl, jq; 90 s; stdout capped at 16 KB.

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

A session's content stores are its source's settings' `content` (New session's `content: [name…]`, or a task's
`optionsFrom: "content"` fields; the phone signs them); `POST /api/sessions` refuses a name with no store. The base image's
`content-sync` (pull at every start, `push`, `status`) calls Jarvis 1's session paths through the local proxy:

| Path (machine-signed, `/m/api/…`) | Does |
|---|---|
| `GET /m/api/sessions/:id/content` | `{ok, stores: {name: [{path, size, modified}]}}` for the settings' stores (a deleted store: `[]`). |
| `GET /m/api/sessions/:id/content/:name/file?path=` | The bytes, with header `X-Jarvis2-Challenge`: the log notary's challenge (a signed document) over the bytes' sha256, `about: "content"`; the guard's proxy refuses the file (502) without a matching one. |
| `PUT` / `DELETE /m/api/sessions/:id/content/:name/file?path=` | Write or delete a file of one of the settings' stores; 403 for any other store. |

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

Jarvis 1's session scripts call `$JARVIS_URL/api/…`; on a Jarvis 2 machine that is the guard's local proxy
(`http://127.0.0.1:7171`), which drops the scripts' headers and sends `/m/api/<rest>` signed with the machine key
(docs/API-grants.md "The session-facing API": what it keeps on the machine). Any `:id` in the path must be the calling
machine's session (403 otherwise).

| Path | Served by |
|---|---|
| `GET /api/sessions/:id/secrets`, `GET /api/sessions/:id/changes` | The guard itself. |
| wakeups, crons, watches, notify-idle | The router (above): ids, never texts. |
| `POST /api/sessions/:id/narrow {stores}` | The router: the session drops stores it no longer needs (the identity edge, as the app's). |
| `GET /api/sessions/:id/commands` | The router: the results of the commands Deyao approved for this session `{commands: [...]}`. |
| `DELETE /api/sessions/:id` | The router: the session retires itself (Destroy) → 202 `{started}`; 409 `{pending}` while it has wakeups, crons or watches. |
| requests, batches, outcomes, `POST /api/sessions` | The router: the Inbox (above); the proxy adds `X-Jarvis2-Filing`. |
| leases, content stores | The router (above). |
| search, iCloud index | The box's own services, as for the app; the iCloud index only for a session whose held grant names `store:identity` (otherwise 403 `{error, needsStore: "identity"}`). |
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

Identity-level: sessions reach it only while their held grant names `store:identity` (above). A missing index is seeded from
`claude-records/.jarvis2-services/icloud-index.db.gz.age` (age-encrypted, rewritten weekly); with no copy the pod refuses
to start (`SEED_REQUIRED=1`), so the budget is never spent twice.
