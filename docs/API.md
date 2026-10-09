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
  stores, harness /* claude | opencode */, label, model, permissionMode, guest, pausedAt, error,
  autoPause /* "on" | "off" */, notifyIdle /* "on" | "off" */, oneShot, needsGrant /* a holder the machine refused */,
  lastReport /* the machine's last status report */,
  // while started, from the machine's report (fresh within 3 min), as in Jarvis 1:
  status /* busy | idle | waiting | … */, aiTitle, liveName, nameSource, bgTasks, statusUpdatedAt, bridgeSessionId,
  sessionId /* claude's conversation id */, authFailed, credsExpiresAt, sessionsInside, oneShotDone,
  refusals: [{kind: "fallback" | "refusal", at, uuid, from, to, model, category}],
  pauseInMs /* while the auto-pause countdown runs */ }
```

What the router does by itself with a running session (`router/autopilot.go`, every 30 s), from that report:
auto-pause after 1 h plain idle (unless `autoPause` is off, the session is one-shot, or another feature vetoes);
destroy a one-shot session once `oneShotDone`; Escape a prompt left `waiting` for 1 h (holder `status`); DM
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
| `GET /api/models` | `{models: [{id, label}]}` |
| `GET /api/policy` | `{harnesses: {<harness>: {stores: […]}}}` — the stores each harness brings (the router adds them; the app hides them) |
| `POST /api/sessions` | Body `{requestId, label, prompt, model, permissionMode, size, harness, stores: [], oneShot, autoPause}` (`oneShot`: the machine gets `SESSION_ONE_SHOT=1` and the session is destroyed when its prompt is done; `autoPause` defaults to true, false for one-shot; both show in the approval's `options`). The router adds the harness's stores and asks the core for a challenge (`succession(null, …)`, before any machine); the approval (kind `new-session`) appears at once. Answers `{id: null, requestId}`. |
| `POST /api/sessions/:id/pause` | The machine snapshots itself (signed), then the core kills it. |
| `POST /api/sessions/:id/resume` | Optional `prompt` (≤ 4000 chars): delivered into the session as a peer message once it is `started` again (dropped if the start fails or is rejected). Body `{upgrade: false}`: the same image, `approve_by_dead_machine`, then start + certify — no approval. `{upgrade: true}`: the newest session image; an approval of kind `resume-upgrade` first (reject = stays paused), then start + certify. |
| `POST /api/sessions/:id/destroy` | Kill (if running), then a burn: a succession to the null image, approved by the dead-machine rule and certified. The session moves to `GET /api/records`. |
| `GET /api/records` | Destroyed sessions `{records: [...]}` |
| `POST /api/sessions/:id/auto-pause` | Body `{on}` (Jarvis 1's `{enabled}` works too) → `{ok, autoPause: "on" | "off"}`; restarts the idle countdown. |
| `POST /api/sessions/:id/notify-idle` | Body `{on}` → `{ok, notifyIdle}`: mutes only the idle DM; "needs you", dead and downgrade DMs still come. |

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

Pass-through to the core's own endpoints, answers unchanged (signed): `GET identity`, `GET core-cert`,
`POST recover {statement, masterSig, bundle}`, `POST stores {nonce}`, `POST stores/create {name}`, `POST
stores/mark-sensitive {name}`, `POST stores/write {store}`, `POST unlock/begin {store}`, `POST unlock/finish
{pending, share}`, `POST lock {id}`, `POST unlocked {nonce}`, `POST log {nonce}`. Formats: `docs/DESIGN.md`,
`core/core.go`, and the reference client `e2e/main.go`.

Unlock, phone side: verify `unlock/begin`'s doc (kind `unlock-begin`, fields `pending, store, e, t`); Face
ID → Enclave key agreement of the phone's agreement key with `e` → the 32-byte x-coordinate; seal it to `t`:
ephemeral P-256 key `r`, `x' = x(r·t)`, key = HKDF-SHA256(ikm `x'`, salt empty, info `"jarvis2/unlock-share"`,
32 bytes), AES-256-GCM combined (`nonce‖ciphertext‖tag`) → `share = {e: base64(r.pub x963), data:
base64(combined)}` → `unlock/finish {pending, share}`.

## Setup (`/setup/*`)

Every call carries `X-Setup-Time` (unix seconds) and `X-Setup-Sig` = base64 DER ECDSA-P256-SHA256 signature
by the setup key over `"<METHOD> <path> <time> <sha256hex of body>"` (the router's path); the router checks it
against `SETUP_KEY` (`k8s/apps/router.yaml`), within ±2 min, each signature once. Client: `infra/setup.py`.

| Call | Core path |
|---|---|
| `GET /setup/identity` | `/identity` |
| `GET /setup/core-cert` | `/core-cert` |
| `POST /setup/stores` | `/stores` |
| `POST /setup/stores/create` | `/stores/create` |
| `POST /setup/stores/write` | `/stores/write` |
| `POST /setup/stores/mark-sensitive` | `/stores/mark-sensitive` |

## Machines (`/m/*`)

Every request carries `X-Machine: <fly machine id>`, `X-Time: <unix seconds>`, `X-Sig: <base64 DER signature
by the machine's signing key over "<method> <path> <time> <sha256 hex of body>">`; the router checks it
against the machine's current key (from `start`, or its latest downgrade) and refuses a time more than 120 s
off.

| Call | Does |
|---|---|
| `GET /m/cert` | `{cert, predecessorCert, coreCert}` — this machine's latest succession cert, the predecessor's cert when it continues a real machine, and the master-signed recovery statement naming the core's key (the machine checks it against the master key built into its image). 404 until certified. |
| `GET /m/snapshot` | The predecessor's snapshot: body = tar.gz, header `X-Snapshot-Sig` = base64 signature by the predecessor's signing key over the sha256 of the body. 404 = none. |
| `POST /m/snapshot` | Upload this machine's snapshot (same format). |
| `POST /m/pull-secrets` | The router adds this machine's cert and relays to the core; answers the core's signed `secrets` doc (sealed to the machine's key). |
| `GET /m/commands` | Long poll (≤ 50 s): `{commands: ["snapshot"]}` or `{commands: []}`. |
| `POST /m/add-store` | Body `{store}`: asks Deyao (an `add-store` approval) to add one store to this session. |
| `POST /m/downgrade` | Body `{stores, newEncryptionKey, newSigningKey}` → `{challenge}`, which the machine signs with its OLD key. |
| `POST /m/downgrade/finish` | Body `{challenge, signature}` → core `approve/by-old-key` → `{cert}`; from now on the router knows the machine by its new key. |
| `POST /m/status` | Body `{raw}`: the output of Jarvis 1's registry command (`machine/status.go`), sent by the agent when it changes and at least every 60 s; parsed by the router (`router/registry.go`). |

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
`GET /api/icloud/file`, `GET /api/icloud/status`, `POST /api/icloud/relist`, `GET /api/leases`,
`GET /api/leases/:name`, `POST|PUT|PATCH|DELETE /api/sessions/:id/leases/:name`,
`POST /api/sessions/:id/leases/:name/seen`, `GET /api/sessions/:id/content`,
`GET|PUT|DELETE /api/sessions/:id/content/:name/file`, `GET|POST /api/credentials`.

The session routes among them carry the Jarvis 2 session id (`s…`) and no Jarvis 1 session token: Jarvis 1 checks
`SESSION_API_TOKEN` against its own machine metadata (`requireSessionToken`, `sessionContentStore`), so until
it accepts the services token + `X-Jarvis2-Session` as the session's identity they answer 401/403.
