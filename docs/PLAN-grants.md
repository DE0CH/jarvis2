# PLAN: grants, the notary, the succession signer, secrets and the guard

Status: plan only. Nothing here is built. Sources: DESIGN "Target design" (docs/DESIGN.md:635-701) and DECISIONS 163 (docs/DECISIONS.md:1225-1254). Deyao has since decided six more things (2026-10-14). The plan treats them as fixed:

- **D1.** A key written to ANY store reaches the next pull without a new phone unlock. The "stale" rule goes.
- **D2.** Secrets never locks by itself. No release after a pull, no 30-minute `scopedUnlockTTL`.
- **D3.** The permission mode is fixed for the whole life of a session.
- **D4.** The Claude login rides the `claude` store. The router writes the pair as store keys; the guard pulls it again.
- **D5.** There is no revocation.
- **D6.** Grants signed by a machine follow the same steps as phone grants (notary challenge, logged). A phone-signed grant (the start grant) says which other signers the guard accepts, and for which text types.


**Decided 2026-10-14 (Deyao), supersedes `pending` everywhere below:** each New session gets its own logical **source
machine** with a fresh random id (`source-<32 hex>`: 128 random bits, so it can't clash with a Fly id). The phone binds the start and secrets grants to it and signs the succession challenge naming it as the
predecessor. A source counts as killed from birth, with no snapshot; certify's one-successor-per-predecessor rule
uses it up. Grants reach the first machine by an ordinary exchange through the cert whose predecessor is that source. No `pending` field, no special exchange form. A burn is an ordinary succession onto the fixed machine **`sink`**: the old machine is used up as usual, and
the signer refuses any succession whose predecessor is `sink`, so nothing continues an ended session (`sink` is neither
a Fly id nor a source). The burn cert and the null image go. Sessions are paths from one of many sources into the one sink. **Structure, not branches:** the signer keeps one machine table and one
succession path with the same two rules for everything: a predecessor must be killed and unused (using it marks it
used), and a target must be a known machine. A source is a row inserted killed and unused (no snapshot, no keys), so it
gets exactly one successor; the sink is one permanent row that is never killed, so nothing succeeds it, and as a target
it binds no keys, so any number of machines succeed into it. No "new line" or "burn" branches, no burn-cert kind, no
null image: a new session is a succession from a source, an ended one a succession into the sink. One cert per real
machine follows from Start being single-shot. Also decided: a `grants` branch (§4); terminal grants at most
10 minutes (Q9); a secrets grant covers every key of its stores, current and future, whoever writes them (Q5: secrets
are not code and the model never reads them, so a written key can't be a prompt injection).

---

## 0. Summary of the recommendations

| Question | Recommendation |
|---|---|
| Packaging | One Go module (`core/`) building **three binaries and three images**, run as **three Deployments** in `jarvis2-core`. A small shared internal package holds crypto, identity and signed errors. |
| Setup | Only **secrets** is claimed (Reset/Recover, master key). The **succession signer** gets the Fly token sealed to it and reads the phone key from secrets' box-signed state. The **notary** needs no setup. |
| New-session UX | Grants may be bound to the approval challenge the machine will be certified from (`machine: {pending: <nonce>}`). The signer swaps them onto the certified machine in `certify`. One Face ID before any machine exists, as today. (Question Q1.) |
| Unlock scope | An unlock opens a store **for one session**, named by the `session` field of the secrets grant's text. Standing unlocks go. (Q4.) |
| D1 mechanism | Every write also carries the value sealed to secrets' own agreement key (`live`). Secrets uses it only to update unlocks that are open, then drops it. (Q5.) |
| The held core (6fc20f8 + ad17fec) | **Fold it into this release.** It never goes live on its own; its code becomes `secrets`. One Recover, one session wipe. |
| How to ship before the go | Only work that is inert or safe on the live core goes to main. Router v2, guard v2, the app and the web page live on a branch `grants`, tested on throwaway rehearsal and replica boxes. They merge in one commit on Deyao's go. No dual-stack code. |

---

## 1. Component boundaries

### 1.1 Where today's `core/` code goes

| Today (file:line) | Goes to | Notes |
|---|---|---|
| `core/crypto.go` (Signer, SealTo/OpenSealed, gcm, AddPoints, UnwrapWithShares) | `core/internal/sig` (shared) | Each binary uses only what it needs. `go list -deps ./cmd/X` must stay small; add a CI check listing the files each binary uses. |
| `core/identity.go` (box key PEM), `IdentityText` (core.go:271) | `core/internal/sig` | Every component signs `"jarvis2-<role>-identity <signingKey> <agreementKey>"` with the box key when it starts. The prefix includes the role, so one component's identity can't pass as another's. |
| `writeErr` / the handler helper (main.go:47-235) | `core/internal/sig` | "Errors leave signed too" stays. |
| `audit.go` (the input log: `appendAudit`, `Attest`) | **notary** | Becomes `challenge(subject, about)`. Each challenge is the log entry (hash chain: seq, prev). CloudWatch later (DESIGN Open). |
| `fly.go`, `realfly.go`, `fakefly.go` | **succession** | The Fly token lives only here. |
| `Start` / `Init` / `KillWithSnapshot` (core.go:572-725) | **succession** | Unchanged in substance: single-shot, digest check, snapshot hash. |
| `vouch.go` image regex, `imageDigest`, `reportedDigest`, `machineURL`, `machineEnv`, `SnapshotClaim` (vouch.go:213-279) | **succession** | `coreKeyEnv` becomes `JARVIS2_SUCCESSION_KEY`. |
| `Succession`, `answer`, `ApproveByPhone`, `ApproveByDeadMachine`, `Certify`, the null-image burn (core.go:733-1030, 631-680) | **succession** (simplified) | Options, stores, add-store, downgrade and `approve_by_old_key` all go (see §3). New: `exchange`. |
| `SetFlyToken` (core.go:452-474) | **succession** | Sealed to the signer's own agreement key. |
| `Claim`, `Wipe`, `StoreKey`, `Identity` state (master, phone) (core.go:265-489) | **secrets** | The claim bundle no longer carries `flyToken`. |
| `keys.go` (KeyEntry, WriteKey, WriterText, storeVersion) | **secrets** | Adds the `live` seal. The machine-cert check on writes goes (DESIGN: "no component checks who writes"; Q5). |
| `history.go` (versions, restore begin/finish/commit) | **secrets** | `restore_commit` also updates open unlocks (D1). |
| `deploykeys.go`, `github.go` | **secrets** | `delete(c.unlocked, p.store)` (deploykeys.go:247, 275) changes: with D1, the app's new blob can be served live if the app adds a `live` seal. |
| `CreateStore`, `MarkSensitive`, `Stores` (core.go:505-559) | **secrets** | The `unlocked` column becomes "open unlocks per session". |
| `UnlockBegin`/`UnlockFinish`/`Lock`/`ListUnlocked` (core.go:1061-1181) | **secrets** | `for` becomes the session id. No TTL. |
| `PullSecrets` (core.go:1191-1241) | **secrets** | Its input becomes a `secrets` grant (plus the cert of its machine). No carry, no `stale`, no `releaseFor`. |
| `carry.go` (all 192 lines) | **deleted** | Unlocks never release, and a resume shows a swapped grant whose text names the same session, so nothing needs to be carried. |
| `Options`, `persistentOptions`, `maxConfig`/`maxOnce` (core.go:48-59, vouch.go:262-271) | **deleted** | Their content moves into the start grant and prompt grants. |
| `Cert.Phone/Sensitive/Line/PredCert/Options/Stores` (core.go:88-108) | replaced | By the new cert in §2.4. |
| `signCert` (vouch.go:284-307) | **succession** | No audit entry, no carry. |
| Tests: `core_test.go`, `r1_test.go`, `addstore_test.go`, `carry_test.go`, `vouch_test.go`, `keys_test.go`, `history_test.go`, `deploykeys*_test.go` | split per binary | Add/downgrade/carry tests go. The R1 "forbidden input" tests are kept wherever their rule survives. |

### 1.2 One binary with roles, or three binaries in three pods

**Recommendation: three binaries, three pods.** Layout:

- `core/cmd/notary`
- `core/cmd/succession`
- `core/cmd/secrets`
- `core/internal/sig`

That is one `go.mod` (only stdlib plus `filippo.io/nistec`) and one `go test ./...`. The images are `jarvis2-notary`, `jarvis2-succession` and `jarvis2-secrets`.

How this serves the "small, analysable" goal:

1. **Each binary can be read alone.** The notary is about 200 lines, the signer about 900, secrets about 2,000. Each has one job and a closed list of endpoints.
2. **Each pod holds less.** Store plaintext lives only in the secrets pod. The Fly token lives only in the signer pod. The notary holds no secret except its own key. A memory-safety or logic bug in one cannot read another's memory, which one binary with roles could not promise.
3. **Network policy per pod.**
   - notary: no egress at all (until CloudWatch).
   - succession: egress 443 to the internet for `api.machines.dev`, plus DNS.
   - secrets: egress 443 to the internet for `api.github.com` (deploy keys), plus DNS.
   - All three: ingress only from the router pod.
4. **Each can restart without the others.** Today any change to `core/` means a Recover and the death of every session.
   - A **notary** restart loses only its log head; a new chain starts.
   - A **secrets** restart means a Recover, but running sessions keep their `~/.secrets`. Paused lines resume once Deyao unlocks their stores again (the existing "Waiting for store X" path).
   - A **signer** restart ends every line, as a core restart does today. It does **not** need a Recover: the setup session sends the Fly token again (`infra/setup.py backup-core`).
5. **Holds and pins per component.** Each Deployment carries its own `jarvis2/core-pin: hold` annotation. The pin job moves a component only when `core/cmd/<role>` or `core/internal` changed.

Cost: three box-signed identities for the app, `setup.py` and the guard to check, and three manifests. Small.

### 1.3 Keys and trust distribution

- **Box key.** All three pods mount `core-box-key`, and each signs its own fresh identity with it.
- **Machine to signer.** The signer sets `JARVIS2_SUCCESSION_KEY` (its own signing key) and `JARVIS2_URL` in each machine's Fly config, as the core does now. The guard pins that key for certs and swapped grants.
- **Machine to notary and secrets.** Each cert carries `box` (the box public key; proposed field, Q3). The guard accepts any notary or secrets identity signed by that key, fetched through the router. This is why a notary or secrets restart does not break running lines.
- **Secrets to signer and notary.** Secrets accepts swapped grants signed by a box-vouched signer identity, and challenges from a box-vouched notary identity. It derives the box public key from its own mounted private key.
- **Signer to phone key.** On each `approve_by_phone`, the router passes secrets' signed state (box-vouched identity + `core-state` with the phone keys). The signer reads the phone key from it. The signer is never claimed.
- **App.** It checks all three identities against `keys/box.pub` from GitHub. It claims and wipes secrets only. It seals the Fly token (from the `core` store backup at Recover) to the signer's agreement key.

---

## 2. Document formats

All signed things keep today's envelope: `SignedDoc{payload, sig}`, P-256 ECDSA over sha256(payload), base64 DER signature. `ID(d) = hex(sha256(d.payload))`.

### 2.1 Notary challenge

```go
// POST /challenge {"subject": "<64 hex>", "about": "grant"|"content"|"attachment"|"notice"|"terminal-cmd"}
type Challenge struct {
    Kind    string `json:"kind"`    // "challenge"
    Notary  string `json:"notary"`  // the notary's signing key (find its box-signed identity)
    Seq     int64  `json:"seq"`     // place in this notary's log
    Prev    string `json:"prev"`    // sha256 of the previous challenge's payload ("" = first)
    At      string `json:"at"`      // RFC3339Nano UTC, the notary's clock
    Subject string `json:"subject"` // sha256 hex of what will be signed or delivered
    About   string `json:"about"`   // a word, recorded as given
    Nonce   string `json:"nonce"`   // 16 random bytes, hex
}
```

`challenge` replaces `attest` (audit.go:354). The notary keeps only `seq` and `prev`. The router keeps every answer in `DATA_DIR/notary-log.jsonl`, which replaces `input-log.jsonl` (router/vouch.go:452-667).

### 2.2 Grant

```go
type GrantMachine struct {
    ID            string `json:"id,omitempty"`
    SigningKey    string `json:"signingKey,omitempty"`
    EncryptionKey string `json:"encryptionKey,omitempty"`
    Pending       string `json:"pending,omitempty"` // the nonce of the succession challenge whose cert the grant is for (Q1)
}
type Grant struct {
    Kind      string       `json:"kind"`               // "grant"
    SignedBy  string       `json:"signedBy"`           // "phone" | "machine" | "succession"
    Text      string       `json:"text"`               // exact bytes; JSON of a known type (§2.6)
    Machine   GrantMachine `json:"machine"`
    Challenge *SignedDoc   `json:"challenge,omitempty"` // phone, machine: a notary Challenge with Subject = GrantSubject(...)
    From      string       `json:"from,omitempty"`      // succession: ID of the grant it replaces
    Signer    string       `json:"signer,omitempty"`    // machine: ID of the signing machine's succession cert (proposed, Q3)
}

// what the notary challenge's Subject is the sha256 of (fixed text, no JSON canonicalisation needed in Swift and Go)
func GrantSubject(signedBy string, m GrantMachine, text string) string {
    return "jarvis2-grant\n" + signedBy + "\n" + m.ID + "\n" + m.SigningKey + "\n" + m.EncryptionKey + "\n" + m.Pending + "\n" + text
}
```

Who signs:

- **phone:** the Secure Enclave key, over the payload. The router writes the draft; the app renders `text`, checks it, and signs.
- **machine:** the machine's signing key.
- **succession:** the signer's key.

Rules:

- A `phone` or `machine` grant must carry a challenge with `about == "grant"`.
- A `succession` grant must carry `from` and no challenge.

### 2.3 Swaps (succession signer)

`POST /exchange {grant, fromCert, toCert, signerCert?, phoneState?}` returns a `succession` grant `{text: same, machine: toCert.machine, from: ID(grant)}`.

The signer checks, accept or reject:

1. `toCert` was signed by itself and is not a burn.
2. Either:
   - (a) `grant.machine` has an id and equals `fromCert.machine`, `fromCert` was signed by itself, and `toCert.predecessor == ID(fromCert)`; or
   - (b) `grant.machine.pending == toCert.nonce` (the first swap onto the certified machine).
3. The grant's signature:
   - `phone`: by `fromCert.phone`, or for (b) by `toCert.phone`. Its challenge is signed by a box-vouched notary and its subject matches.
   - `machine`: `signerCert` was signed by itself, `ID(signerCert) == grant.signer`, and the signature verifies with `signerCert.machine.signingKey`. Challenge as above.
   - `succession`: its own signature.
4. It never reads `text`. A test swaps a non-JSON text unchanged.

The output is deterministic, so the same inputs may be swapped again harmlessly. A line can't fork, because `certify` already allows one successor per predecessor and one cert per approval nonce.

### 2.4 Succession cert, challenge, burn

```go
type CertMachine struct{ ID, Image, SigningKey, EncryptionKey string } // image = ref@digest Fly reported

type SuccessionChallenge struct {           // POST /succession {predecessor *SignedDoc|null, image, salt}
    Kind        string `json:"kind"`        // "challenge"
    Nonce       string `json:"nonce"`       // MAC of the request (as now)
    Predecessor string `json:"predecessor"` // ID of the predecessor's cert, "" = new line
    PredMachine string `json:"predecessorMachine,omitempty"`
    Line        string `json:"line,omitempty"`
    Image       string `json:"image"`       // pinned digest, or "null" (burn)
    Salt        string `json:"salt,omitempty"`
}
type SuccessionCert struct {
    Kind        string      `json:"kind"`        // "succession-cert"
    Machine     CertMachine `json:"machine"`
    Line        string      `json:"line"`        // first machine's id; inherited (proposed, Q3)
    Predecessor string      `json:"predecessor,omitempty"`
    Snapshot    string      `json:"snapshot,omitempty"`
    Phone       string      `json:"phone"`
    Box         string      `json:"box"`         // proposed, Q3
    ApprovedBy  string      `json:"approvedBy"`  // "phone" | "dead-machine"
    Nonce       string      `json:"nonce"`
    IssuedAt    string      `json:"issuedAt"`
}
type BurnCert struct{ Kind /* "burn-cert" */, Predecessor, Nonce, IssuedAt string }
```

How a cert is approved:

- **Dead machine** (`approve_by_dead_machine`): the predecessor is killed (Fly-confirmed) and unused, the image is identical, the phone key is copied. Never a new line.
- **Phone** (`approve_by_phone`): a new line, or a resume onto another image. The phone key comes from the `phoneState` it is given.
- **Burns:** as today.

Stores, harness, mode, config and once are **not** in the cert.

### 2.5 The secrets answer, writes, unlocks

- **Pull.** `POST /pull {grant, cert}` answers `{"kind":"secrets","machine":id,"grant":ID(grant),"session":S,"stores":[…],"sealed":Sealed,"at":…}`, signed. `cert` is the signer-signed cert of `grant.machine` (an extra check on top of the phone's check). The grant must be a `phone` or `succession` grant of type `secrets`. A `machine` grant is refused.
- **Write.** `WriteKeyInput` gains `Live Sealed`: the value sealed to secrets' agreement key, with info `"jarvis2/live-key"` and associated data `store\nkey`. If an unlock of that store is open, secrets opens `live` and updates the value in every open unlock of that store. It never stores `live`.
- **Unlock.** `unlock_begin(store, session)`, where `session` matches `^s[0-9a-f]{8,64}$`. `unlocked[store][session]` holds the plaintext until `lock(id)`.
- **The signed unlocked list:** `{id, store, session, since}`.

### 2.6 Grant texts (strict JSON; unknown fields refuse the grant)

Every text has `"type"`, `"v":1` and `"session"`. `session` is the router's session id. It now arrives through a signature instead of as a format exception.

**start** (phone, bound to the first machine or `pending`):

```json
{"type":"start","v":1,"session":"s4f…",
 "harness":"claude","permissionMode":"auto","title":"…","model":"claude-opus-…",
 "repos":["DE0CH/claude-env"],"content":["notes"],"oneShot":false,"apiProxy":false,
 "prompt":"first prompt","attachments":[{"name":"a.png","sha256":"…","size":123}],
 "restore":{"machine":"e28…","sha256":"…"},
 "task":{"instance":"…","name":"…","params":{}},
 "accept":[
   {"from":"own","type":"prompt","kinds":["wakeup","cron","watch","lease"]},
   {"from":{"line":"e286…"},"type":"prompt","kinds":["peer"]}
 ]}
```

`accept` is the list of other signers this start grant vouches for. `"own"` means a machine whose cert has the same `line` as this machine. `{"line": L}` means any machine whose signer-signed cert has `line == L` (the app shows L as that session's title).

**secrets** (phone): `{"type":"secrets","v":1,"session":"s…","stores":["claude","tunnel"]}`. An add-store is a new secrets grant with the full list.

**terminal** (phone, bound to a running machine): `{"type":"terminal","v":1,"session":"s…","until":"2026-10-14T12:10:00Z"}`.

**command** (phone): `{"type":"command","v":1,"session":"s…","id":"<16 hex>","cmd":"…","timeoutSeconds":600,"notAfter":"…"}`.

**prompt** (one type, several kinds):

| kind | signed by | extra fields |
|---|---|---|
| `resume` | phone, bound to `pending` | `after` (ID of the predecessor's cert), `text`, optional `rollback` (Q8) |
| `message` | phone (Deyao typing into a running session, the web/app "resume prompt") | `id`, `text`, `notAfter` |
| `wakeup` | own machine, or the phone when armed from the app or web | `id`, `name`, `at`, `text` |
| `cron` | own machine or phone | `id`, `name`, `everySeconds`, `tz`, `time?`, `until`, `text` |
| `watch` | own machine or phone | `id`, `name`, `script`, `text`, `failText`, `until` |
| `peer` | a machine of a line the start grant accepts | `id`, `fromLine`, `text` (and `session` = the recipient) |
| `lease` | own machine (its acquire note) | `id`, `device`, `text` |

### 2.7 How the guard judges, and where its records live

**Checking a chain** (pure function, `machine/grants.go` rewritten):

- **leaf:** `machine == {me, my keys}`.
- **Walk `from`:** each `succession` step is signed by `JARVIS2_SUCCESSION_KEY`. The router supplies the parents and the certs of each bound machine. Each step's certs must link through `predecessor`, or through `pending == nonce`.
- **root:**
  - `phone`: verified against the `phone` of the cert of the machine the root was bound to.
  - `machine`: verified with `signer`'s cert. That machine must be certified for the text's type and kind by this line's start grant.
  - Either way, the challenge is notary-signed under `cert.box` and its subject matches.
- **Result:** `(root, rootAt = challenge.at)`.

**What each type requires:**

| type | rule |
|---|---|
| `start` | Exactly **one**: the root must be bound to the line's first machine (root machine id == `cert.line`, or the pending nonce of that machine's cert). Two different start roots: refuse to boot. The start ID is recorded; any other start grant is refused for good. This is how the mode stays fixed. |
| `secrets` | Any number; the newest by `rootAt` is used. Minus the stores in the guard's `dropped` set (Q6). |
| `terminal` | `now < until`, `until - rootAt <= cap` (cap: Q9), and `rootAt <= now + 2 min`. Each command arrives as `{grant ID, id, cmd, timeout}` with a notary challenge `about:"terminal-cmd"` whose subject is sha256(cmd). That logs every command and closes the "exec bypasses the input log" open item. |
| `command` | Refused if `now > notAfter` or `id` is already executed. Otherwise recorded **before** it runs. |
| `prompt/resume` | Applies only if `after == my cert.predecessor`. Applied at boot. |
| `message`, `wakeup`, `watch`, `peer`, `lease` | Once per `id`. A wakeup is refused before `at - 1 min`. |
| `cron` | At most once per half period (deliver.go:131-147 rules). Not after `until`. |

**Records** go in `~/.jarvis2-grants.json`:

```
{start: ID, executed: {"<kind>:<id>": {at, run}}, dropped: [stores]}
```

It is added to `snapshotPaths` and replaces `allowFile`, `lineKeysFile` and `deliveredFile` (machine/main.go:478-480). So it travels in the signed snapshot whose hash the next cert names. Known limit: a machine that dies without a snapshot leaves its successor with no records. `notAfter`, `until` and the wakeup's `at` bound the window for replays; see §6.

---

## 3. What to delete or replace

### 3.1 Holders and router "features with a shell"

| Mechanism | file:line | Becomes |
|---|---|---|
| Holder keys, drafts, stored grants, `Exec`/`ExecPhone`/`execWith`, exec queue | router/grants.go:1-356 (holderNames :27) | Deleted. Replaced by a grant store: `router/grantstore.go` (every grant and cert by ID, chain serving) |
| Grant/exec/terminal routes | router/http.go:276-360 | `POST /api/grants/draft`, `POST /api/grants`, `GET /api/sessions/{id}/grants`; terminal commands under a `terminal` grant |
| `/m/commands` execs + deliveries, `/m/exec-result`, `/m/holders` | router/http.go:588-619 | `/m/commands` carries `{commands:[content-free words], grants:[chains], notices:[…]}` |
| Terminal (holder `terminal`) | router/terminal.go:4,50,82,90 | `terminal` grant (typing, resize, Escape) |
| Escape on a stale prompt, dialog fallback (holder `status`) | router/autopilot.go:8, 440-493, 610-646 | The pushed pane only. Escape becomes a content-free `escape-stale` command the guard obeys only when its own status has been `waiting` for ≥ 1 h (Q7) |
| Remote info (holder `remote`) | router/remote.go:10,36,54,111 | Output: the guard pushes `/m/remote` (Paseo offer / OpenClaw token) when booted and on a content-free `remote` command |
| Archive's repo check (holder `archive`) | router/archive.go:532 | Output: the guard pushes `changes` with its status and at the snapshot (`writeChanges`, machine/restore.go:~40) |
| Peer messages / resume prompt over a `scheduler` exec | router/peer.go:1-218 (deliverPeer :184), router/schedule.go:846-918 | `prompt` grants (`message`, `peer`); `sendToHarness` stays in the image (machine/deliver.go:362-438) |
| Wakeup/cron/watch deliveries (signed request + core attest) | router/schedule.go:783-845, router/watches.go:336-386, router/vouch.go:257-450 | Machine-signed `prompt` grants, armed through the local API proxy |
| `noteRefusal`/`execAs`/`grantRetry`/`NeedsGrant` | router/autopilot.go:35-60, 682-715; sessionops.go markRefused | Deleted |
| Holder-based Inbox intent `grant` | router/inbox.go:35,107,180,468,578,597; batches.go:244; session-image/bin/jarvis2-request:7,22-25,206-212 | Intents `terminal {minutes}` and `command {cmd}` (a session only for itself) |
| Machine exec path | machine/grants.go:1-280 (whole file) | Rewritten as the chain checker and judge (§2.7) |
| `refresh-secrets` | machine/main.go:717-720; machine/putkey.go:207 | Content-free `pull` |

### 3.2 Standing rules, the allow list, sensitive-session special cases

- Standing rules: machine/grants.go:172-182; router/grants.go (`kind "rule"`); iOS GrantReviewView/GrantsView; web `lib/grants.ts`. **Deleted.**
- Allow list:
  - `allowCmd` (machine/grants.go:228-280)
  - `allow`/`allow-at-least` subcommands (machine/main.go:141-144)
  - `extendAllow`/`allowAtLeastCmd` (machine/apiproxy.go:259-330)
  - the comment at machine/apiproxy.go:12-15
  - `allowFile` in snapshotPaths (main.go:480)

  **Deleted.** The proxy now signs a `prompt` grant when the session arms a wakeup, cron or watch.
- `Cert.Sensitive` and its uses: core/core.go:99,112-115; machine/grants.go:148,176; machine/apiproxy.go:275-276; machine/restore.go:102; router/schedule.go:883,943-966; iOS `SignedAction.session` :89; GrantReviewView refusal. **Deleted.** Sensitivity stays a store property only: it is in secrets' signed list, the app warns about it, and it is never pre-selected.

### 3.3 Permission mode (D3)

| file:line | |
|---|---|
| session-image/base/set-permission-mode (whole); Dockerfile:152,186 | delete |
| session-supervisor.sh:78-92 (reads `~/.claude/.permission-mode`), :311 comment | read `SESSION_PERMISSION_MODE` only |
| harness-opencode.sh:19,46,233-238; harness-openclaw.sh:36,192-197 | same |
| router/sessionops.go:5-6, 241, 255-310, 611 (`POST …/permission-mode`) | delete |
| router/flows.go:751-769 (resume in another mode → phone) | delete (mode fixed) |
| router/apicalls.go:370 | delete the entry |
| iOS Model/AppModel+Actions.swift:129-170; web app/src/views/Sessions.tsx:92,166-203 | delete the switch UI |
| machine/main.go:1434-1441 `certMode` | mode from the start grant |

### 3.4 Claude login (D4)

- **Delete:**
  - machine/claudelogin.go `fetchLogin`, `sessionClaudeLogin`, the `credsSync` long poll (machine/claudelogin.go:109-160, 274-372)
  - `creds-sync` (machine/main.go:139-140)
  - `CLAUDE_ACCOUNT` injection (main.go:352-356)
  - router `GET /m/claude-login`, `GET /m/api/credentials` (router/claudelogin.go:909-942)
  - the poll/ack participant tracking in `loginHub.poll`/`waitAcks` (:405-551)
  - router/relogin.go (whole)
  - autopilot login repair (autopilot.go:12-13, 474-475, 670-680)
  - `Delivery{Kind:"continue"}`
- **Keep in the guard:** the CLI lock helpers (`takeLock`/`releaseLock`, :222-272) and `restartHostWhenIdle` (:398-426). The guard writes `~/.claude/.credentials.json` and the account switch file from the `claude` store keys `CLAUDE_CREDENTIALS` and `CLAUDE_ACCOUNT` after each pull.
- **New in the router:** on every refresh, Re-login, accepted push, and right after a claim, it writes both keys to `claude` (writer `router`, with backup and `live` seal). Then it sends `pull` to every running machine whose newest secrets grant names `claude`. The refresh handshake becomes content-free commands: `claude-prepare <gen>`, then the guard takes the CLI lock and acks with `POST /m/claude-ack {gen}`, then the router refreshes, writes and sends `pull` (Q10).
- **Keep:** the machine's push of a pair its CLI refreshed by itself (`POST /m/claude-login` → `/m/claude-push`, output), and Jarvis 1's `/peer/claude-login`.

### 3.5 Inputs, deliveries, attestation, Options

- `Options.Config`/`Options.Once`:
  - core/core.go:48-59
  - machine/vouch.go:138-239 (`SessionConfig`, `OnceInputs`, `vouch`)
  - router/vouch.go:77-209 (`certOptions`, `sessionConfig`, `lineConfig`, `resumeOnce`, `onceTaken`)

  These become drafts of start, resume and secrets grants. `harnessEnv` (machine/vouch.go:333-393) takes the start grant.
- **Deliveries:** machine/deliver.go:39-359 (`lineKeys`, `notReplayed`, `SignedRequest`, `Delivery`, `deliveryText`, `checkAttest`, `deliver`) become `machine/prompts.go`. The texts for `nudge`, `upgraded`, `lease-taken`/`lease-back` and `request-outcome` stay as **notices** built in the image. Their router-given parameters are format-checked, and each carries a notary challenge over sha256(parameters) with `about:"notice"` (Q7).
- **Attestation of attachments and content:**
  - machine/attachments.go:67,91: the attachment's sha256 is checked against the start grant; no attestation.
  - machine/apiproxy.go:80,340-351 and the router content path: a notary challenge with `about:"content"`.
- **Format exceptions** (machine/vouch.go:277-327): drop `sessionId` (now in the start grant). Keep Discord channel, live-sync seconds, task run/trigger and tunnel proof.
- **Archived restore** (machine/restore.go:47-112): the hash in the start grant is enough. `checkRestoreCert` and the old-core cert route `/m/restore-cert` (router/vouch.go) go. Q11 covers the sensitive→non-sensitive rule.
- **Rollback** (machine/rollback.go; main.go:314-316): from the `resume` prompt's `rollback`.
- **Outcome proofs** (machine/outcomes.go:160-250): grant → a phone-signed `terminal`/`command` grant; add-store → a phone-signed `secrets` grant naming the store; new-session → a phone-signed `start` grant with the proposed title and prompt; repo → secrets' deploy-key answer.

### 3.6 Succession features that go

- Add-store by self-succession: core addOnto (core.go:933-979); router/flows.go:547-640, 898-928; `/m/add-store` (http.go:620); machine `addStore`/`awaitStore` (main.go:829-912). This becomes the Inbox `add-store` intent: a phone-signed secrets grant for the running machine plus an unlock of the added store, under one Face ID.
- Downgrade: core ApproveByOldKey (core.go:1032-1053); router/flows.go:930-982, http.go:631-660; machine/main.go:960-1101; the `downgrade-secrets` skill. This becomes the guard's local `dropped` set plus the router locking that session's unlock (Q6).
- `approvalsUsed` for self-succession, `latest` per machine. There is one cert per machine now.

### 3.7 Locks, carry, stale

| file:line | Becomes |
|---|---|
| core/carry.go (all); router/carry.go (all, 142 lines); router/http.go:567-575 carry | deleted |
| `scopedUnlockTTL`, `expireScoped` (core/carry.go:31,45-58), `releaseFor` (:87-102), `passUnlocks` (:108-129) | deleted (D2) |
| `stale` in PullSecrets (core.go:1207, 1219-1221, 1240) | deleted (D1) |
| router/storedocs.go:441-525 (`refreshHolders`, `fileRefresh`, `refreshAfterPull`, `unlockArrived`) | deleted. A write sends `pull` to holders of that store instead |
| router/storedocs.go:527+ (key names recorded for a core from before keys.go) and every "until the held core is live" branch in the router and iOS (e.g. ios CoreCrypto.swift:177-205, 355, 405, 688; SetupView.swift:259, 303; CoreSetup.swift:213, 270-340; RouterClient.swift:182-204) | deleted (the held core is folded in) |
| router/corechange.go | watches three identities. A signer change marks lines `oldCore`; a secrets change files unlock requests per running session; a notary change does nothing |

### 3.8 iOS and web

**iOS:**

| file:line | Change |
|---|---|
| Review/GrantReviewView.swift (whole) | `GrantReviewView` v2: renders any grant text. Known types as labelled rows, unknown JSON pretty-printed, anything else raw. Checks: the chain's machine against the session's signer-signed cert and LinePins; the notary challenge signature and subject. |
| Sessions/GrantsView.swift (whole) | "Access": terminal for N minutes, run a command once, the grants in force (Forget = the router stops delivering) |
| Review/BatchReviewView.swift:71-97 | Batch items carry grant drafts |
| Review/ApprovalView.swift | Kinds new-line / continue-on-new-image; the start grant's facts from the text; `addStore` becomes a secrets grant |
| Review/NewSessionView.swift | Signs, under one Face ID: the succession challenge, the start grant, the secrets grant (both `pending`), and the unlocks for `session` |
| Security/SignedAction.swift:51-83 (inputs from config/once), 93-127 (approval kinds, mode), 129-151 (unlock scope: "Locked again: when you lock it or the session ends"), 153-167 (grant) | Rewritten |
| Security/CoreCrypto.swift:147-169, 246-349, 434-497 | Rewritten |
| Model/Fmt.swift:78 `Holder` | Deleted |
| Shapes.swift:28; SessionsView.swift:143; SessionDetailView.swift:35,79; RemoteView.swift:14-67 (`needsGrant`) | Deleted |
| Security/CoreSetup.swift | Three identities; claim to secrets; Fly token sealed to the signer |
| `ios/interop` copies (SignedAction, CoreCrypto, CoreSetup, StoreRestore) | Same changes |
| UITests (ReplicaUITests: terminal grant review, Grants standing rule, Inbox grant requests, batch of two grants) | Rewritten to: terminal grant, command once, add-store, Lock an open unlock |

**Web:** app/src/lib/grants.ts, app/src/pages/Grants, app/src/app/grants.tsx, lib/api.ts:148,171-172,241-245,274-283, lib/shell.ts:6,12, ui/page.tsx:19. Holder vocabulary out; terminal/command intents in.

### 3.9 Output only (no grant, nothing goes into the machine)

- screen (`/m/screen`)
- status (`/m/status`)
- memory (`/m/memory`)
- repo changes (new, with status and at the snapshot)
- remote info (new `/m/remote`)
- live transcript sync (`/m/live-transcript`)
- task results (`/m/task-result`)
- the signed snapshot (`/m/snapshot`; a `snapshot` command only makes the machine produce it)
- app-title reads

Content-free commands the image obeys with fixed behaviour: `snapshot`, `free` (DECISIONS 99), `pull`, `remote`, `escape-stale`, `claude-prepare <gen>`.

### 3.10 Docs that change

DESIGN:

- "Grants" (606-633): replaced.
- "Inputs to a machine" table (509-530): rewritten for grants.
- "Carried secrets" (387-426): deleted.
- "Writing stores" (153-166): D1.
- Flows add-store/downgrade (365-374).
- Guarantees (592-597): "until locked", not 30 min.
- Open (707-711): two items resolved.

DECISIONS superseded: 24, 30, 69-74, 81, 83, 89, 90, 94, 116 (partly), 118, 126.

Also API.md, RUNBOOK ("Releasing the held core", replica core image), PARITY.

---

## 4. Shipping: the held core, and pushing to main before the go

**Fold the held core into this release.**

- Both need a Recover and destroy every session. Two back-to-back releases cost Deyao two Recovers and two session wipes.
- The held core's code (keys, history, restore, deploy keys) *is* the secrets component. Shipping it first would mean a third compatibility layer in the router and app (live core / held core / grants).
- Cost: the restore feature waits for this release. The whole-store-write footgun it fixes is already guarded at both ends (DECISIONS 162).

**Why the router, image and app can't be partly on main.**

- New sessions take the newest pinned image at once (images.yml:172-176). A v2 guard can't run on a cert from the live core, and a v1 image can't run on v2 grants.
- A router or image that dispatches on the running core's identity would carry two full implementations of every flow. That is a shim, against the hard-cut rule.
- Holding the router and image pins (Option 3) would freeze every unrelated router or image fix for the length of the build.

**Recommended path:**

1. **To main (inert, or safe on the live core):**
   - the docs;
   - stage 1 (permission mode fixed);
   - the three new binaries, their images, tests and golden vectors. They are built but not deployed: no manifest is in `k8s/apps/kustomization.yaml`.
   - behaviour-neutral refactors that shrink later conflicts (split machine/main.go into boot.go, agent.go, snapshot.go, secrets.go; move `sendToHarness` out of deliver.go).
2. **On branch `grants` (rebased on main every day):** router v2, machine guard v2, session-image script changes, iOS, web, e2e, infra and k8s manifests. Images are built by `gh workflow run images --ref grants` (they build, never pin: images.yml:149).
3. **Staging:** throwaway boxes.
   - `infra/rehearse-recover.sh` and `infra/phone-replica.sh` with `REHEARSAL_REF=<branch sha>` and `REPLICA_REF=grants`.
   - New overrides beside `REHEARSAL_CORE_IMAGE` (rehearsal-box.sh:231-247): `REHEARSAL_ROUTER_IMAGE`, `REHEARSAL_SESSION_IMAGE`, and one image override per component.
   - A throwaway CI image key put on the keys branch, so the replica's router can sign the branch's session image for the app (`keys/ci.pub` on `rehearsal-keys-<run>`).
4. **The go (held):** run in the order of §5 stage 13.

**Rollback:** re-pin the held core image (already built) and restore `core.yaml` (the reverted merge). The old core comes up empty. Deyao reinstalls the current TestFlight build (it reads key backups) and Recovers. v2 writes key backups in the same bucket format, so nothing is lost but sessions.

---

## 5. Build order

Every stage compiles and passes `go vet` and `go test` in each module. ✱ marks forbidden-input tests: each tries the input and expects a refusal.

| # | Where | Stage | Tests |
|---|---|---|---|
| 0 | main | Docs: this plan; DESIGN/DECISIONS for D1-D6 and the answers to §6 | none |
| 1 | main (live, image + router + app; app after the replica) | Permission mode fixed (§3.3) on today's system | ✱ supervisor and harness scripts ignore a planted `~/.claude/.permission-mode` (a shell test run in `images.yml` test). ✱ `POST …/permission-mode` → 404. ✱ resume never asks for a mode change. Replica updated. |
| 2 | main (inert) | `core/internal/sig`: identity per role, box signing, errors. Golden vectors in `core/testdata/grants/` (grants, chains, certs, challenges, texts, valid and invalid) | Vectors also run by router/machine tests (`../core/testdata`) and by iOS interop |
| 3 | main (inert, image built) | `core/cmd/notary`: `/identity`, `/challenge` | ✱ bad subject, bad about, any other path. Chain continuity. Signatures checked against the box identity. |
| 4 | main (inert) | `core/cmd/succession`: identity, fly-token, start/init/kill, succession/approve/certify/burn, exchange | ✱ cert for a machine it didn't create. ✱ digest mismatch. ✱ predecessor not killed or used twice (fork). ✱ dead-machine approval with another image or for a new line. ✱ phone approval with a state not box-signed or a wrong phone signature. ✱ swap: grant's machine ≠ fromCert's; toCert's predecessor ≠ ID(fromCert); pending ≠ toCert.nonce; second cert for one approval; forged phone, machine or signer signature; challenge from an unvouched notary; subject mismatch; swap into a burn. Text never parsed. |
| 5 | main (inert) | `core/cmd/secrets`: claim/wipe/store-key/create/mark/write(+live)/stores/versions/restore/deploy keys/unlock(session)/lock/unlocked/pull(grant) | ✱ a machine-signed secrets grant. ✱ type ≠ secrets. ✱ phone grant without or with a bad challenge. ✱ succession grant by an unvouched signer. ✱ cert for another machine. ✱ store unlocked for session A pulled by session B (423). ✱ `github-deploy-keys` and `core` never served. ✱ `live` ignored with no unlock open. D1: write, then the next pull has the new value. D2: clock +1 year, still served. Lock ends it. Restore updates open unlocks. All held-core tests carried over. |
| 6 | main (inert) | images.yml builds notary/succession/secrets; pin job pins each only without a hold, and only when `core/cmd/<role>` or `core/internal` changed. Manifests in `k8s/apps-next/` (not in kustomization) | CI only |
| 7 | branch | Router v2, part 1: clients for the three components; grant store and chain serving; `/api/grants/draft`, `/api/grants`, `/m/grants/draft`, `/m/grants`, `/m/boot`; New session, resume, pause, destroy with pending grants and swaps; burns lock the session's unlocks | Flows against fake components (the existing fakefly pattern). ✱ no route for holders, exec, permission-mode, `/m/claude-login` GET, add-store succession, downgrade (404). |
| 8 | branch | Router v2, part 2: wakeups, crons, watches, peer as prompt grants; notices; terminal/command; Inbox intents; outcome proofs; Claude login into the `claude` store with the prepare/ack commands; corechange for three identities; output endpoints (remote, changes) | Schedule/watch/lease/outcome tests rewritten. Login: refresh writes the store and sends `pull`. |
| 9 | branch | Guard v2 (machine/): boot through `/m/boot`, chain checker and judge, start grant into env, resume/rollback at boot, secrets pull, one long-lived guard process (boot becomes the agent; harness entrypoint as a child, not `exec`), creds from the store, local API proxy signs prompt grants, notices, terminal/command, records file in the snapshot | ✱ start not rooted at the phone. ✱ start for another machine. ✱ two start roots. ✱ a second start grant with another mode. ✱ broken `from` chain. ✱ prompt from another line not in `accept`. ✱ own machine sending a kind not accepted. ✱ machine-signed terminal, command, secrets or start. ✱ terminal expired or longer than the cap. ✱ command replay. ✱ command after `notAfter`. ✱ resume on the wrong occasion. ✱ unknown type or field. ✱ challenge unsigned or subject mismatch. ✱ old exec format ignored. ✱ allow-list file ignored. ✱ planted env (cleanEnv tests kept). |
| 10 | branch | Session image: base scripts (§3.3); `jarvis2-request` intents; drop `allow`, `creds-sync`, `downgrade`, `add-store` subcommands | Image build size checks (images.yml:122-139) |
| 11 | branch | iOS + interop + UI tests; web page | Unit tests for SignedAction (each type, unknown JSON, raw). Interop against the real components. |
| 12 | branch | infra: setup.py (three identities, Fly token to the signer, `live` seal on writes, pins from secrets' state), setup_*_test.py, e2e v2 (e2e/main.go:302-320, 497, 541-558 rewritten), rehearsal/replica overrides; k8s: three Deployments + NetworkPolicies, router egress to the three, `core.yaml` deleted | `infra/e2e.sh` on real Fly; `rehearse-recover.sh`; `phone-replica.sh` from the branch: all pass |
| 13 | **HELD release** | 1. Deyao pauses every session (they are destroyed after the go anyway; a running v1 machine loses its login once `/m/claude-login` is gone). 2. On Deyao's go: rebase, run the final replica with `ios/` frozen on main. 3. Merge to main with the components' manifests moved into `k8s/apps/` without holds. 4. `gh workflow run images`: the router, session image and three components pin together, and Flux deletes the old core. 5. The router drains (≤ 30 min). 6. `ios` workflow `only=testflight` (the gate is met by the branch replica on the same tree). 7. Deyao installs, then Recovers. 8. The router writes the `claude` store. 9. The setup session checks `setup.py identity`, `versions default`, and runs `backup-core` if the signer has no Fly token. 10. v1 sessions are archived as records (the snapshot command and upload keep their v1 wire format). | Post-release smoke: New session, wakeup, terminal, add-store, Re-login reaching a running session |

---

## 6. Risks and questions for Deyao

**Questions** (each has a recommended answer):

1. **Q1. Binding at New session.** A grant needs `machine`, but the phone signs before any machine exists.
   - (a) Start the machine first, then one Face ID. That is a 30-90 s wait for an ~8 GB image before Face ID.
   - (b) **Recommended:** bind to `{pending: <succession challenge nonce>}`; `certify` then swaps it onto the machine. This adds one swap form to the design. The same form serves resume-with-prompt.
2. **Q2. Two signatures under one Face ID** for a new line: the succession challenge (`approvedBy: phone`) plus the start and secrets grants. OK? The signer can't take the start grant as approval, because it never reads text.
3. **Q3. Fields beyond the design's minimum.**
   - `line` in the cert, so "own machines" is one comparison instead of walking the chain.
   - `box` in the cert, so a notary or secrets restart doesn't break running lines.
   - `signer` in machine grants (which cert signed it).
4. **Q4. Unlocks keyed by the text's `session`;** standing unlocks (the Stores page's Unlock, open to every session) removed. OK? Paused sessions keep their plaintext in secrets until destroyed. That is D2 working as designed; the phone shows it.
5. **Q5. D1 and its cost.** D1 is implemented with a second seal of each written value to secrets' key (`live`); the value is served only to sessions that already have the store unlocked. Also: should values written by a **session** reach *other* sessions without the phone? Under D1 a low-privilege session can change a key a high-privilege session pulls next (for example `CLAUDE_CREDENTIALS` or a token). The option is to serve only setup- and router-written keys live and leave session writes for the next unlock. Recommended: as D1 says, but ask. Also confirm that the machine-cert check on writes (keys.go:376-394) goes, since the design says no component checks writers. The writer would become the router's word plus the setup signature.
6. **Q6. Downgrade.** With no revocation and no self-succession, recommended: the guard drops stores locally (`dropped`, in the snapshot), rewrites `~/.secrets`, and the router locks that session's unlock. The old key rotation and shredding go. OK?
7. **Q7. Inputs the design doesn't name.** Recommended: the watchdog nudge, "upgraded", lease taken/back and Inbox outcomes stay image-built notices without grants, notary-logged. The stale-prompt Escape becomes a content-free command the guard checks itself, or is dropped. OK?
8. **Q8. Rollback** rides the `resume` prompt (`rollback` field). Or should it be its own type?
9. **Q9. Caps.** Today a phone grant lasts at most 10 minutes. The terminal grant's longest life: 10 min / 60 min / free? The longest `notAfter` for `command`: 1 h?
10. **Q10. The Claude refresh lock.** Keep lessons/74's prepare/ack as content-free commands? Without it, a CLI that refreshes by itself rotates the shared refresh token. Keep the machine's push of a self-refreshed pair (output, then the router writes the store)?
11. **Q11. Archived restore.** Drop the old cert and "sensitive stays sensitive" check (machine/restore.go:102) and rely on the phone-signed hash plus a warning in the app?
12. **Q12. Peers.** How does Deyao pick "accept peer messages from session X" on New session? Recommended: a picker of live sessions, rendered from their start grants, signed as `{"line": …}`.
13. **Q13. Image change on resume** still needs the phone (`approvedBy: phone`); size changes (Upgrade) don't. OK?
14. **Q14. The plan here:** fold the held core in; branch-staged flip; v1 sessions archived at the go.

**Risks:**

- **The guard is no boundary against the agent itself.** The agent runs as user `claude`, which has `sudo -n`, and can read `/run/jarvis2/private.json`. "Mode fixed for life" and "only certified signers" protect against the router, k8s and leaked keys, not against the session. The agent can still sign its own wakeups and peer messages to sessions that accept it. That is intended, but say so in DESIGN.
- **Records lost without a snapshot.** If a machine dies without a snapshot, its successor has no `executed` records. `notAfter`, `until` and wakeup `at` bound the window for replays. Crons and watches could fire one extra time.
- **Unlocks never lapse.** If the router fails to lock at destroy, the plaintext stays in secrets until a restart. The phone's unlocked list is the only check.
- **The release is large.** Many rules and four images change at once. Mitigations: e2e, rehearsal and replica on the branch, the rollback to the held core, and the fact that sessions are already lost in any core release.
- **Branch drift.** Daily main work in router/machine/ios conflicts with the branch. Mitigations: land the refactors early, rebase daily, and keep other sessions off large router/machine refactors while the branch is open.
- **Formats in four languages and places** (Go components, router, machine, Swift and interop). Mitigation: the shared golden vectors in `core/testdata/grants/`.
- **Inconsistencies in today's docs and code the plan resolves:**
  - The `claude` store is created empty (RUNBOOK "After a Reset"), but secrets refuses to unlock an empty store (core.go:786-790, :1068). So the router must write the pair right after the claim, before any Claude session can start.
  - DESIGN 160-166 ("a written key reaches sessions only with the phone") is reversed by D1.
  - DESIGN 592-597 ("at most 30 minutes") is reversed by D2.
  - The design's "secrets holds … the unlocks (the phone's shares)": shares can't open new writes. Secrets holds plaintext plus the `live` seal (§2.5).

### Critical Files for Implementation
- /home/claude/workspace/jarvis2/core/core.go
- /home/claude/workspace/jarvis2/machine/main.go
- /home/claude/workspace/jarvis2/machine/grants.go
- /home/claude/workspace/jarvis2/router/flows.go
- /home/claude/workspace/jarvis2/router/grants.go
