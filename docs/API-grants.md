# The guard's router API (`/m/*`, target design)

The machine-facing router API that the guard (`machine/`, branch `grants`) uses. It is written for the router side to
be built against: every endpoint the guard calls, with its request and response JSON, what the router must do behind
it, and the old endpoints that go. The design is DESIGN "Target design: succession certs, grants and the kernel" and
DECISIONS 163; the kernel's formats and endpoints are `core/kernel/README.md`. The guard's tests run against an
in-repo fake of this API (`machine/helpers_test.go`), which is the quickest way to see each call answered.

The router stays untrusted: it carries, stores and schedules. Everything that shapes the machine is checked by the
guard against the kernel roster (below); the router can deny service, never grant anything.

## The machine's Fly config (set by the spawner)

| Env | Value |
|---|---|
| `JARVIS2_SPAWNER_KEY` | the spawner's signing key (base64 of the 65-byte P-256 point) |
| `JARVIS2_ROSTER` | the JSON of `kernel.Roster`: `{notary, notarizer, mover, merger, spawner, identity, gullible, secrets, phone, root}`, each a key as above. Its `spawner` must equal `JARVIS2_SPAWNER_KEY`, every key must be a point, unknown fields refuse it. |
| `JARVIS2_URL` | the router's address on Fly's private network (`http://host[:port]`) |

Only the spawner's Fly token creates machines in the app, so the guard takes these as the spawner's word, as the old
machine took the core's key (`core/kernel/spawner`: `RosterEnv`). Everything else in the config is dropped at boot
(`machine/settings.go cleanEnv`). The guard writes the roster to `/run/jarvis2/roster.json` for its CLI subcommands.

## Signing

Unchanged: every request carries `X-Machine: <fly machine id>`, `X-Time: <unix seconds>`, `X-Sig: <base64 DER ECDSA
by the machine's signing key over "<METHOD> <decoded path> <time> <hex sha256 of body>">`. The query string is not
signed. The router checks it against the machine's signing key from its spawn cert (`(source, M, ⊤)`, the spawner's
`/init` answer) and refuses a time more than 120 s off. There is one key pair per machine for its whole life (no
downgrade, no key change).

## Start settings (a source's `settings`)

The exact JSON the phone signs inside the source object of `(sink, source-x, P)`; the spawner copies it into every
source a kill makes, so it is fixed for the session's life. The kernel never reads it. The guard reads it strictly:
an unknown field, a missing `session`, `harness` or `permissionMode`, or a malformed value refuses the boot.

```json
{"v":1,
 "session":"s4f…",                    // the router's session id, [a-z0-9][a-z0-9-]{0,63}; session:<id> conditions compare with it
 "harness":"claude",                  // claude | opencode | openclaw | task:<template>
 "permissionMode":"auto",             // auto | bypass — fixed for the session's life; nothing switches it
 "title":"…", "model":"claude-opus-5-5",
 "repos":["DE0CH/claude-env"],        // owner/name or GitHub URLs; none = the repos of the deploy-key stores served
 "content":["notes"],                 // content stores
 "oneShot":false, "apiProxy":false,
 "prompt":"first prompt",             // typed at the start of a source the PHONE made (out of the sink)
 "attachments":[{"name":"a.png","sha256":"…","size":123}],   // with that prompt, when the source has no snapshot
 "rollback":"marker",                 // a phone-made source with a snapshot: transcript lines from the first holding it go
 "task":{"instance":"…","name":"…","params":{}}}
```

A source made by a kill (the spawner's `(M, source-y, ⊤)`) carries the same settings, but its `prompt`, `attachments`
and `rollback` are not applied again. A restart with a new prompt, a rollback or a restore of a destroyed session is a
new phone-made source `(sink, source-z)` whose `snapshot` names the snapshot to start from and whose settings carry the
prompt/rollback; the router keeps the session id in `session`.

## Endpoints

All JSON unless marked. "Refused" answers are any non-200 status with `{"error": "…"}`; the guard logs and retries
where noted.

### Boot

| Call | Request | Response |
|---|---|---|
| `GET /m/boot` | — | `{"spawn": NotarizedCert, "source": NotarizedCert}` — `spawn` is this machine's spawn cert `(source-x, M, ⊤)` signed by the spawner (from `/init`) with its challenge and notarization; `source` is the notarized cert source-x came out of: `(sink, source-x, P)` signed by the phone (or root), or `(M_prev, source-x, ⊤)` signed by the spawner (a kill). 404 until both exist (the guard polls every 2 s for 10 minutes). |
| `GET /m/config` | — | `{"discordChannel": "123…", "liveSyncSeconds": 300, "taskRun": "…", "taskTrigger": "cron", "tunnelProof": "…"}` — the values the router gives on its own; each is dropped unless it matches its strict format. Anything else is ignored (there is no `sessionId` any more: it is in the settings). |
| `GET /m/tunnel-proof` | — | `{"proof"}` (unchanged; used when `/m/config` has no `tunnelProof`) |
| `GET /m/snapshot` | — | Body: the bytes whose sha256 the machine's source names (`source.snapshot`), streamed. The router keeps snapshots by sha256: a pause's upload, a destroyed session's archive, or a Jarvis 1 import manifest. 404 when it has none. The guard refuses any other bytes. No signature header is needed (the hash is the spawner's or the phone's). |
| `GET /m/import-file/{name}` | — | A Jarvis 1 import: one file the manifest lists (unchanged). |
| `GET /m/grant` | — | `{"grant": SignedDoc \| null}` — the grant the router holds for this machine: made by the mover or the merger, naming this machine with its keys. At boot the guard polls until it takes one. |
| `GET /m/attachments/{name}`, `DELETE /m/attachments` | — | The first-prompt files (bytes), checked against the settings' sha256 and size; the router's copy dropped once fetched. No listing call and no attestation any more. |

What the router does to boot a session: on New session the phone signs `(sink, source-x, P)`; the router notarizes it
(notary `/challenge` + notarizer `/notarize`), moves root's ⊤ along it (mover `/move` → a grant on source-x), spawns
(spawner `/spawn`, then `/init` until it answers the spawn cert), notarizes the spawn cert and moves the source's grant
along it (→ the grant on M, served at `/m/grant`). A resume: the kill's `(M_prev, source-y, ⊤)` is notarized, M_prev's
last grant is moved along it onto source-y, then along source-y's spawn cert onto the new machine.

### The command channel

`GET /m/commands` — a long poll (≤ 50 s; `{}` when nothing happened). One object, decoded strictly: an unknown field,
a second JSON value, or a list where one value goes refuses the WHOLE answer and nothing in it is taken. Every field is
optional.

```json
{"commands": ["snapshot"],
 "grant":    SignedDoc,                                   // ONE grant; it replaces the one the guard holds
 "shell":    [{"id": "c1", "cmd": "tmux send-keys -t claude 'hi' Enter", "timeoutSeconds": 60}],
 "due":      [{"kind": "wakeup", "id": "<32 hex>"}, {"kind": "cron", "id": "…", "run": 7}, {"kind": "watch", "id": "…", "outcome": "met"}],
 "notices":  [{"kind": "nudge", "minutes": 20, "jobs": 2}]}
```

Until the guard has checked the boot chain only `"snapshot"` is answered (with "nothing to snapshot"); a grant, shell
commands, due signals and notices sent that early are dropped (the guard takes its first grant from `/m/grant`).

**`commands`** — content-free words with fixed behaviour; any other word is refused:

| Word | The guard |
|---|---|
| `snapshot` | while booting: `POST /m/snapshot` with `X-Snapshot-None: booting`; once booted: stops every process of the session (SIGSTOP), takes, signs and uploads its one final snapshot (a later `snapshot` sends the same one again). |
| `free` | an Upgrade before its snapshot: SIGSTOPs the harness, SIGKILLs every other process of the user, lists them in `~/artifacts/jarvis2-upgrade-freed.txt`. |
| `pull` | pulls the secrets again with the grant it holds (send it after an unlock or a key write of a store the machine's grant names, and after writing the Claude login). |
| `claude-prepare:<gen>` | `<gen>` decimal: takes the Claude CLI's refresh lock and answers `POST /m/claude-ack {"gen"}` (below). |

**`grant`** — a grant document (kernel `Grant`, by `mover` or `merger`). The guard takes it only when the mover's or the
merger's roster key signed it, its `machine` is this machine with both its keys (the whole object), every condition is
one it knows, and it holds right now: `until:<RFC 3339>` not passed (`until:2026-10-14T12:10Z` and full RFC 3339 both
parse; several: the earliest), every `session:<id>` equal to the settings' session, no `once:<id>` already used;
`cmd:<64 hex>` is kept for the commands. Any other condition (or a malformed one) refuses the grant. A taken grant
replaces the held one whole and the guard pulls the secrets with it. A refused grant leaves the held one in force. The
router decides which grant a machine holds: e.g. while a terminal is open the merged grant, after its `until` the main
grant again (send it in `grant`).

**`shell`** — commands under the held grant. Each runs only when the grant allows `shell` (a finite set naming it, or a
cofinite set not leaving it out), its conditions hold, and every `cmd:` condition is the command's sha256. Then the guard
asks the log notary for a challenge over the command (`POST /m/challenge`), judges the grant again, records every
`once:` id of the grant (in the snapshot) and runs `bash -lc <cmd>` (timeout 1–600 s, default 600). `id`:
`[A-Za-z0-9_-]{1,64}`. Typing into the terminal, Escape, a command Deyao approved: all are shell commands.

**`due`** — "X is due" / "X fired" for the session's own wakeups, crons and watches, naming only the id the guard gave
it when the session armed it (below), a cron's run number, a watch's outcome (`met` | `gave-up`). The guard looks up the
text in its records (kept in the snapshot) and types it into the harness, by its own rules: a wakeup once; a watch once
(met or gave up); a cron run only with a run number above the last and at least half its period (min 15 min) after the
last, and never after its `until`. An unknown id is refused. The router: run numbers count up from 1 per cron; after a
resume send what came due while paused; the app can't arm a wakeup, cron or watch for a session (there is no text on
the machine to deliver: refuse it, as watches already are).

**`notices`** — texts built into the image; the router names only these strictly formatted values:

| `kind` | Fields |
|---|---|
| `nudge` | `minutes` (1–100000), `jobs` (0–10000) |
| `upgraded` | `from`, `to`: `small` \| `medium` \| `large` |
| `lease-granted` | `device` (a lease name), `minutes` (1–360), `handover`, `interrupted` (bools); the note is the session's own, from its acquire request (kept on the machine) |
| `lease-taken`, `lease-back` | `device` |
| `request-outcome` | `filing` (the id the guard gave the Inbox filing: header `X-Jarvis2-Filing`, below), `items: [{item, outcome: approved\|denied\|lapsed\|dropped\|failed, ref /* Inbox or session id */, status /* HTTP, a call's */}]`; each item once |
| `continue` | — (the text "continue") |

There are no peer messages: nothing delivers another session's text into a machine.

### Answers from the machine

| Call | Body |
|---|---|
| `POST /m/challenge` | `{"subject": "<64 hex>", "about": "shell"}` → the log notary's challenge (`SignedDoc`, kernel `Challenge`): forward to the notary's `/challenge` unchanged and log it. The guard checks the notary's key, the subject and word, and that `at` is within 5 minutes of its clock. |
| `POST /m/shell-result` | `{"id", "code", "stdout", "stderr", "error"?, "grant" /* the grant's ID */, "challenge" /* the challenge's ID */}`; `code` -1 + `error` when refused. Output capped at 1 MiB each. |
| `POST /m/due-result` | `{"kind", "id", "ok", "error"?}` |
| `POST /m/notice-result` | `{"kind", "ok", "error"?}` |
| `POST /m/snapshot` | Unchanged: the tar.gz streamed, `X-Snapshot-Sig` = base64 DER signature by the machine's key over the hex sha256 of the body; or `X-Snapshot-None: booting`, no body. The router passes `{sha256, sig}` to the spawner's `/kill` (it checks the signature with M's key from the spawn cert) and keeps the bytes by sha256 for `GET /m/snapshot`. |

### Secrets

| Call | Request | Response |
|---|---|---|
| `POST /m/secrets/pull` | `{"grant": SignedDoc}` (the grant the guard holds) | The secrets component's signed answer, unchanged: forward `{grant}` to secrets' `/pull`. The guard takes it only when secrets' roster key signed it, `grant` is this grant's ID, `machine` is this machine, and `sealed` opens with its key (info `jarvis2/secrets`) → `{store: {key: value}}`. Locked stores are listed (`locked`); the guard starts after 10 minutes with what was served, and the router's `pull` brings the rest once unlocked. |
| `GET /m/stores` | — | `{"stores": [router rows as today], "signed": <secrets' signed /stores answer>}`; the CLI (`jarvis2 stores`) checks names, sensitivity and key names against secrets' key and marks the stores the held grant names. |
| `GET /m/store-keys` | — | `{"state": <secrets /state>, "storeKey": <secrets /store-key for the state's phone agreement key>, "agreementKey": "<secrets' agreement key from its /identity>"}`. The machine checks both documents with secrets' key and that phone + agreementKey is the signed store key. |
| `POST /m/stores/{store}/keys/{key}` | `{"delete", "explanation", "wrapped": {"e","wrapped"}, "data", "live": Sealed, "backup": {"e","data"}, "backupSha256", "writerText"}` — the value sealed to the store key (data key info `jarvis2/store-data-key`, value AES-GCM with AAD `store\nkey`), to secrets' agreement key (`live`, info `jarvis2/live-key\n<store>\n<key>`), and to the master key for its backup (info `jarvis2/backup`, AAD `store\nkey`); `writerText` = secrets' `WriterText` (informational). A delete has only `delete` and `explanation`. | The router writes the backup first, then forwards to secrets' `/stores/write-key` with `writer: "machine"`, `machine: <id>` (its word), keeps the explanation, and sends `pull` to every running machine whose held grant names `store:<store>` → `{"ok", "receipt" /* secrets' key-written doc */, "pulled": [session ids]}`. |

### The Claude login (the `claude` store)

The router writes the shared OAuth pair into the store `claude` as two keys (writer `router`, with a backup and the
`live` seal), right after a claim, on every refresh, Re-login and accepted push, then sends `pull` to every running
machine whose grant names `store:claude`:

- `CLAUDE_CREDENTIALS`: the exact `~/.claude/.credentials.json` (`{"claudeAiOauth":{…,"expiresAt":<ms>}}`);
- `CLAUDE_ACCOUNT`: the account record (`{"oauthAccount":{…},"userID":…}`).

| Call | Body | The router |
|---|---|---|
| `POST /m/claude-ack` | `{"gen": "<decimal>"}` | the machine holds the CLI lock for refresh `gen` (sent `claude-prepare:<gen>`); once every running Claude machine acked (or a timeout), refresh, write the store, send `pull`. The guard releases the lock when the new pair arrives, or after 45 s. |
| `POST /m/claude-push` | `{"credentials": "<the file>"}` | a pair the CLI on the machine refreshed by itself (output only): the router decides whether to write it to the store. |

The guard takes a pair of the same account only when it expires later than the one on disk; another account's always,
handing the account record to the supervisor and restarting the idle claude host.

### Output only (unchanged)

`POST /m/status`, `POST /m/screen`, `POST /m/memory`, `POST /m/live-transcript`, `POST /m/task-result`: as in
docs/API.md "Machines". The repos' state goes in the snapshot (`~/.jarvis2-changes.txt`) and through
`GET /api/sessions/:id/changes` on the machine.

### The session-facing API (`/m/api/*`, through the machine's local proxy)

The proxy forwards `$JARVIS_URL/api/<rest>` as `/m/api/<rest>`, signed, as today, except:

| Path | The proxy |
|---|---|
| `GET /api/sessions/:id/secrets` | answers itself: a fresh `/m/secrets/pull` → `{ok, environment /* stores served, comma-joined */, locked, secrets}` |
| `GET /api/sessions/:id/changes` | answers itself |
| `POST /api/sessions/:id/wakeup` \| `/wakeups` \| `/crons` \| `/watches` | keeps `prompt` (and a watch's `failPrompt`) in the guard's records and forwards the body without them, plus `"id": "<32 hex>"` (the id `due` names). Wakeup: `{name?, at?, delaySeconds?, id}`; cron: `{name?, everySeconds, time?, tz?, at?, delaySeconds?, until?, id}`; watch: `{name, script, interval?, maxSeconds?, id}` (the script stays: the router's runner runs it). A non-2xx answer takes the record back. Arming a wakeup name again replaces it on both sides. |
| `POST /api/sessions/:id/leases/:device` | keeps `prompt` (the wake note) by device and forwards the body without it, plus `id` |
| `POST /api/requests/…`, `/api/actions/requests/…`, `POST /api/sessions` | keeps the filing (path + body) under a fresh filing id and forwards it unchanged with header `X-Jarvis2-Filing: <32 hex>`; the router keeps that id with the Inbox item and names it in the `request-outcome` notice |
| `GET /api/sessions/:id/content/:name/file` | takes the bytes only with header `X-Jarvis2-Challenge`: a log-notary challenge (JSON SignedDoc) with `about: "content"` and `subject` = the body's sha256 (instead of the core's attestation) |

A session's own paths (`:id`) must be its settings' session (or its machine id). Store-gated session APIs (the iCloud
index needs `identity`) now ask whether the machine's held grant names `store:<name>`. New Inbox intents for a session:
`POST /m/api/requests/terminal {minutes, explanation}` (the phone signs `(sink, source-x, ({shell}, {session:S,
until:T}))` and `(source-x, M, ⊤)`; the router moves and merges as DESIGN "Adding to a running machine") and
`POST /m/api/requests/command {cmd, explanation}` (the same with `{shell}`, `{session:S, cmd:<sha256>, once:<id>,
until:T}`). `add-store` becomes a phone-signed `(sink, source-x, ({store:X}, {session:S}))` plus `(source-x, M, ⊤)`,
moved and merged onto the machine's main grant (equal conditions), then an unlock of X; the merged grant reaches the
machine in `grant`.

## Gone

`GET /m/cert`, `POST /m/pull-secrets`, `POST /m/exec-result`, `GET /m/holders`, `POST /m/delivery-result`,
`GET`/`POST /m/claude-login`, `GET`/`POST /m/api/credentials`, `POST /m/add-store`, `POST /m/downgrade`,
`POST /m/downgrade/finish`, `GET /m/restore-cert`, `GET /m/restore-snapshot` (one `GET /m/snapshot` by hash),
`GET /m/store-key` (now `/m/store-keys`), `GET /m/attachments` (the listing and its attestations); the `execs`,
`deliveries` and `refresh-secrets` of `/m/commands`; the holders, standing rules, the session's allow list
(`jarvis2-machine allow`, `allow-at-least`), `jarvis2-machine add-store`, `await-store`, `downgrade`, `agent`,
`creds-sync`; `set-permission-mode` and `~/.claude/.permission-mode`.
