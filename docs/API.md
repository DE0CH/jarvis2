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
| `/setup/*` | the trusted setup session | Access app `jarvis2.deyaochen.com/setup`, service token `jarvis2-setup` only (kept in Jarvis 1's `default` store, never on a machine). The core then checks the setup key's signature on each call (below). |
| `/m/*` | session machines | Not on the public hostname at all: the router serves `/m` on a second port (8081) that only Fly's private network reaches (the box is a WireGuard peer of org `jarvis2-370`). The router checks the machine's own signature on each request. |

## App sign-in

`GET /api/auth/start?redirect=jarvis2://auth` — Access makes Deyao log in first; the router then redirects to
`<redirect>#token=<the Access JWT>`. Only `jarvis2://` redirects are allowed. The app keeps the token in the
Keychain and sends it as `cf-access-token` on every request; when a request comes back 302/401/403 from
Access (token expired), it runs sign-in again.

## Sessions

A session's `id` is stable: its first machine's Fly id. `machineId` is the machine it is on now (null while
paused). Session objects keep the Jarvis 1 shape where a field means the same thing:

```
{ id, machineId, released, name, state, status, created, region, environment /* stores, comma-joined */,
  harness /* claude | opencode */, label, model, permissionMode, guest, pausedAt, error }
```

`state`: `starting` (core is creating the machine) → `approval` (waiting for the iPhone) → `initialising`
→ `started` (running) → `pausing` → `paused` (no machine) → `resuming` → … ; `destroying` → gone (moved to
records); `failed` (with `error`).

| Call | Does |
|---|---|
| `GET /api/state` | `{sessions, approvals, core: {up, signingKey, agreementKey}}` |
| `GET /api/sizes` | `{sizes: [{id, label}]}` (small / medium / large) |
| `GET /api/models` | `{models: [{id, label}]}` |
| `POST /api/sessions` | Body `{requestId, label, prompt, model, permissionMode, size, harness, stores: []}`. Starts the machine through the core and asks for a new line (`Succession(null → machine)`); answers at once `{id: null, requestId}`; the approval appears in `approvals` (kind `new-session`) once the machine is up (20–60 s). With `"wait": true` it holds the request until the challenge exists (≤ 55 s) and answers `{approval}`. |
| `POST /api/sessions/:id/pause` | Machine snapshots itself (signed), then the core kills it. |
| `POST /api/sessions/:id/resume` | Body `{upgrade: false}`: a new machine on the **same image**, answered by the core's dead-machine responder — no approval. `{upgrade: true}`: newest session image; burns the old machine and creates an approval of kind `resume-upgrade` (carries the burn cert). |
| `POST /api/sessions/:id/destroy` | Kill (if running) + burn; the session moves to `GET /api/records`. |
| `GET /api/records` | Destroyed sessions `{records: [...]}` |

## Approvals (the shell's secure pages)

```
approval = { id, kind: "new-session" | "resume-upgrade" | "add-store", created, session /* id or null */,
             label, challenge /* the core-signed challenge doc */, burnCert /* resume-upgrade only */,
             options /* the normal-mode form's fields, for display */ }
```

| Call | Does |
|---|---|
| `GET /api/approvals` | `{approvals: [...]}` |
| `POST /api/approvals/:id/respond` | Body `{signature}` = base64 DER signature by the phone's signing key over **exactly** `challenge.payload`. Router → core `respond/phone` → cert → core `init`. Answers `{cert, session}`. |
| `POST /api/approvals/:id/reject` | Drops it; a new session's machine is killed and burned. |

The shell checks before signing: the challenge is core-signed; `request.machine` is present; `request.stores`
and `request.options.harness` are exactly what Deyao picked on the secure page; for `resume-upgrade` the burn
cert is core-signed, a `burn-cert` and names `request.predecessorId`; for `add-store`, `request.addedStore` is
the one store shown.

## The core, relayed (`/api/core/*`)

Pass-through to the core's own endpoints, answers unchanged (signed): `GET key`, `POST stores {nonce}`, `POST
sensitive {nonce}`, `POST mark-sensitive {name}`, `POST unlock/begin {store}`, `POST unlock/finish {pending,
share}`, `POST lock {id}`, `POST unlocked {nonce}`, `POST log {nonce}`.

Unlock, phone side: verify `unlock/begin`'s doc (kind `unlock-begin`, fields `pending, store, e, t`); Face
ID → Enclave key agreement of the phone's agreement key with `e` → the 32-byte x-coordinate; seal it to `t`:
ephemeral P-256 key `r`, `x' = x(r·t)`, key = HKDF-SHA256(ikm `x'`, salt empty, info `"jarvis2/unlock-share"`,
32 bytes), AES-256-GCM combined (`nonce‖ciphertext‖tag`) → `share = {e: base64(r.pub x963), data:
base64(combined)}` → `unlock/finish {pending, share}`.

## Setup (`/setup/*`)

The setup session initialises a fresh core through the router. The router relays these calls to the core
unchanged; the core trusts them only because of the setup key, so the router can neither forge, replay nor
read them.

- **Signature:** headers `X-Setup-Time` (unix seconds) and `X-Setup-Sig` = base64 DER ECDSA-P256-SHA256
  signature by the setup key over `"<METHOD> <path> <time> <sha256hex of body>"`, where `<path>` is the
  core's path (`/setup/phone`, `/setup/store`). The core takes the setup key's public half from `SETUP_KEY`
  (base64 x963, set in git in `k8s/apps/core.yaml`), accepts a time within ±2 min, and each signature once.
- **Sealed secrets:** a store's values travel as `Sealed{e, data}` to the core's agreement key: ephemeral
  P-256 `e`, `data` = AES-256-GCM (nonce‖ciphertext‖tag) under HKDF-SHA256(x(e·K), salt empty,
  info `"jarvis2/setup"`) of the JSON object of values.

| Call | Core path | Does |
|---|---|---|
| `GET /setup/key` | `/key` | The core's `{signingKey, agreementKey}` (no signature needed). |
| `POST /setup/phone` | `/setup/phone` | Body `{signingKey, agreementKey}`: the phone's keys, once per core. |
| `POST /setup/store` | `/setup/store` | Body `{name, values: Sealed, sensitive}`: a new store (never replaced). |
| `POST /setup/stores` | `/stores` | Body `{nonce}`: the core's signed store list. |

**The `core` store** holds the core's own secrets, `FLY_API_TOKEN` and `FLY_APP`. It is seeded and unlocked
like any other store; while it is unlocked the core can start and stop machines, and when its last unlock
is locked the core forgets the Fly token. It never goes to a session (the core refuses it in `succession`).

## Machines (`/m/*`)

Every request carries `X-Machine: <fly machine id>`, `X-Time: <unix seconds>`, `X-Sig: <base64 DER signature
by the machine's signing key over "<method> <path> <time> <sha256 hex of body>">`; the router checks it
against the key the core reported at `start` and refuses a time more than 120 s off.

| Call | Does |
|---|---|
| `GET /m/cert` | `{cert, predecessorCert}` — this machine's succession cert and, when it continues a real machine, that machine's cert (core-signed; the machine takes the predecessor's signing key from it). 404 until approved. |
| `GET /m/snapshot` | The predecessor's snapshot: body = tar.gz, header `X-Snapshot-Sig` = base64 signature by the predecessor's signing key over the sha256 of the body. 404 = none. |
| `POST /m/snapshot` | Upload this machine's snapshot (same format). |
| `POST /m/pull-secrets` | Body `{apiKey}`; the router adds this machine's cert and relays to the core; answers the core's signed `secrets` doc. |
| `GET /m/commands` | Long poll (≤ 50 s): `{commands: ["snapshot"]}` or `{commands: []}`. |
| `POST /m/add-store` | Body `{store}`: asks Deyao (an `add-store` approval) to add one store to this session. |
| `POST /m/status` | Body `{status, title}` — idle/busy and the conversation's title, for the app. |
