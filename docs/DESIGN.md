# Secrets controller — design

Design agreed between Deyao and Claude, 2026-10-03 → 10-09 (what is built is in PLAN.md). Goal: every
unencrypted secret is touched only by a very small core, and a key store only ever reaches the machine
Deyao chose — never, by bug or attack, a machine of a different privilege level.

## Trust boundary

| | Status |
|---|---|
| Providers we use (GitHub, Apple, Hetzner, Cloudflare, Fly, Anthropic, Discord, AWS if added) | **Trusted** to uphold their explicit contract (only the holder of the right credential/key controls an endpoint; the service does what it documents). If we don't trust a provider on those terms, we don't use it. |
| Provider infrastructure breach, rogue staff, legal compulsion | **Out of scope** |
| Languages, compilers, standard libraries, static-analysis tools | **Trusted** |
| Crypto libraries we use (CryptoKit, Go `crypto`, age, …) | **Trusted**, and preferred over our own code: if a library function exists, use it |
| iOS and iPhone hardware (kernel, process isolation, Keychain, Secure Enclave, Face ID) | **Trusted**; kernel/hardware bugs out of scope |
| Linux kernel and container isolation | **Trusted**; kernel bugs and container escapes out of scope |
| The Hetzner box as a whole (k3s, Flux, permissions, Jarvis, manifests) | **Not trusted** (much customisation = room for bugs) |
| Our own code (memory-safety and logic bugs) | **Not trusted** |
| Our use/configuration of providers and libraries (wrong endpoint, over-broad token, wrong parameters) | **Not trusted**; verified by tests that attempt the forbidden action and expect it to fail |
| All other open-source code (sops, Expo, React Native, npm/pods trees, …) | **Not trusted**; the core never depends on it |

Consequences for our code: no single point (one bug must not expose a secret), memory-safe languages, as
little hand-written crypto as possible (tested against independent implementations), fail closed, small
surface. The core has no branching other than accept/reject, so it is easy to analyse statically; all
conditional logic lives outside it, where a bug can only make things fail, never do something dangerous.

Defence layers: (1) **visibility** — every behaviour change reaches the phone or the backend only from a
visible commit through CI; (2) **a small core** that can be read and analysed; (3) **prevention** against
changes nobody can see — no single compromised component is enough.

## Parts

- **Core (secrets controller):** the only holder of plaintext key stores. Runs in its own pod on the box with
  minimal network surface. Generates its own key pairs (signing, agreement) when it starts; their private
  halves never leave it. Holds the Fly API token in memory for its whole life (it must start machines
  unattended, e.g. a scheduled resume); the token comes from the special store `core`, never goes to a
  session and is never locked.
- **Router/manager (outside the core):** chains core primitives into useful actions and exposes them as an
  API; decides whether a challenge goes to the iPhone or to an automatic approval. Untrusted: a bug can only
  fail or crash.
- **iPhone:** the highest privilege: approves any challenge after Deyao's click on a hardened path; sets the core
  up (Reset or Recover).
- **Session machine (Fly):** its image generates at boot an **encryption key pair** and a **signing key pair**;
  private halves never leave the machine. It trusts the core that created it: the core puts its signing key in
  the machine's Fly config.
- **Box key:** made by the trusted setup session when it creates the box and delivered in Hetzner user-data
  (the only channel into the box we already trust); its public half is in git. On the box it is a secret only
  the core's namespace reads, and the core signs its fresh public keys with it, so its identity can travel as
  plain text through anything untrusted. (Hetzner keeps serving user-data from the metadata address; every pod
  is blocked from it.)
- **Master key pair:** made by the app at **Reset**. Its private half exists only inside the **recovery kit**,
  the one string Deyao saves in his password manager (the one Jarvis 1 already uses); the app holds it in memory
  only while it sets the core up (Reset, Recover, or ending a set-up core). Its public half goes to the empty core
  in a claim the master key signs, and the core keeps it until it ends. It is the key the backups are encrypted to,
  and what the app checks a core against: a core set up with another master key is refused. A new master key
  (Reset) means a new core, empty stores filled again, and a new kit. Nothing in git, the core's manifest or the
  session image names it.

## Records

- **Store** — kept in the core's memory: a name and its contents (the values under a data key, the name as
  associated data, the data key wrapped to the combined key `P + K`). Contents written under one name never
  decrypt under another, so moving them can't change what they are.
- **Non-sensitive set** — the only sensitivity state: the names of the stores that are not sensitive. Every
  other store is sensitive, including one the core never created. Nothing puts a name back into the set.
- **Approval** — a succession challenge (predecessor, store names, options, image) that one of the
  `approve_by_*` primitives approved. Certifies exactly one machine.
- **Started machine** — (Fly machine id, image, public encryption key, public signing key). The core creates it
  on anyone's request and reads its public keys from the output of the image's init command through Fly, so
  their trust chains to Fly. A started machine without a cert gets nothing.
- **Succession cert** — (predecessor → machine, store names, options): the machine's permission document.
  The core keeps no record of which cert is a machine's latest; an older cert still pulls, sealed to the keys
  it names.
- **Null machine / null image** — a new line is a succession **from** null (never consumed). A succession to
  the **null image** (a predecessor, no stores, no options) **burns** the predecessor: certify takes no
  machine, only marks it used (a **burn cert**), so it can never be continued.
- **A machine succeeding itself** — from one of its certs: one more store (approved by the phone), or a
  **downgrade**: a subset of its stores and a new key pair (approved by the old key).

## Core primitives

The core trusts itself: it does what it signs. It doesn't care who calls or why — the router decides that.
Its Fly token is narrowed (a Fly macaroon caveat) to app `jarvis2-sessions`: create, read, stop and destroy
machines, and run exactly one command inside a machine, `/usr/local/bin/jarvis2-init` with no arguments.

| Primitive | Does |
|---|---|
| `identity()` | Its public keys, signed with the box key, and its own signed state: the master public key it was set up with (none while empty) and the phone's keys. |
| `claim(statement, masterSig, bundle)` | Once per core, on an empty core: Reset and Recover. The statement names a master public key, this core and the phone's keys, and that master key signs it; the core keeps both keys for its life. The bundle (sealed to the core) carries the stores — none for a Reset; for a Recover every store from the backups, each wrapped to `P + K` at once (no plaintext kept), the store named `core`, whose Fly token the core keeps for its whole life (never a session's store), and the names of the stores that are not sensitive. Who may claim is the router's business (Deyao's app only). |
| `wipe(statement, masterSig)` | The current master key's signature over a statement naming this core: the core answers and exits; Kubernetes starts a new, empty core. Nothing else empties a set-up core except a restart from git. |
| `set_fly_token(sealed)` | The Fly token, sealed to the core (the setup session, after a Reset). Open: the core calls Fly only for its own app, fixed in its code, so a wrong token can only fail. |
| `create_store(name)` | Once per name: an empty, non-sensitive store. Open. |
| `mark_sensitive(name)` | The one-way upgrade: the name leaves the non-sensitive set. Open. |
| `write_store(contents)` | New contents for a store, already wrapped to `P + K` by the writer. Open (the router guards it). |
| `stores(nonce)` | The signed list: each store, sensitive or not, empty, unlocked. |
| `succession(predecessor or null, stores, options, image)` | A signed challenge, before any machine exists; it lists which stores are sensitive. |
| `approve_by_phone(challenge, sig)` | The phone is the highest privilege: any challenge it signs is approved. |
| `approve_by_dead_machine(challenge)` | Automatic: the predecessor is killed (Fly-confirmed) and not used, and the stores, image and options are identical — or it is a burn. Never a new line, never a machine succeeding itself. |
| `approve_by_old_key(challenge, sig)` | Automatic: a downgrade (same machine, a subset of its stores, a new key pair) signed with the signing key in the cert it continues. |
| `start(image)` | Open (normally the router, which guards it; it can't lead to a secret): Fly create → `jarvis2-init` (its output: the machine's keys) → a started machine. If init fails, the core destroys the machine. |
| `certify(approval, machine)` | The approval and a started machine running the approved image → the succession cert. One machine per approval, one line per machine, one successor per predecessor (killed and not used). The null image: no machine, a burn cert. For a machine succeeding itself the approval is the new cert at once. |
| `kill(machine)` | Fly destroy, confirmed by Fly → killed. |
| `unlock_begin(name)` / `unlock_finish(pending, phone share)` | The split-key unlock; the plaintext stays in memory until locked. |
| `lock(unlock id)` / `list_unlocked(nonce)` | Release; the signed list of open unlocks. |
| `pull_secrets(cert)` | The cert's stores, while unlocked, sealed to that machine's encryption key — so no other proof is needed. |
| `deploy_key_begin(action, repo, sensitive)` / `deploy_key_finish(pending, phone sig, phone share)` | A repo's deploy key, added or removed (below, "Deploy keys"): the signed request, then the phone's signature over it and its share of `github-deploy-keys`; the core uses that store's GitHub token for this one call and writes or deletes the store `github-<repo>`. |
| `log(nonce)` | Its signed log. |

A succession from null is approved only by the phone: every new line starts with Deyao's click.

**State, in memory only:** its own key pairs, the master and phone public keys (from the claim), the Fly token,
the stores, the non-sensitive set, the unlocked stores' plaintext, the pending unlocks and deploy-key requests, and append-only sets — **killed**
(Fly-confirmed), **used** (predecessors continued or burnt), **spent** approvals, **certified** machines. What
it **trusts** about others (the phone's and the master's public keys, the box key's signature) needs no
secrecy; what it uses to **prove itself** (its private keys, the Fly token) never leaves it.

**Restart = a new, empty core,** set up again from the iPhone (Reset or Recover). Nothing is reloaded from the
box's disk.

## Writing stores and their backups

A store is written **outside the core** by a trusted writer (the setup session today, later the app): the
values under a fresh data key, the key wrapped to `P + K` (the phone's and the core's public agreement keys,
from the core's signed state, its keys checked against the box key), handed to the core's open `write_store`.
The router decides who may write. The writer also writes the backup: the values encrypted to the **master public
key** the core was set up with (from the same signed state) and signed by the writer,
in Deyao's Hetzner Object Storage, bucket `jarvis2-backup-de0ch`, **versioned** (an overwrite or a delete keeps
every old version; no true wipe is designed — if one is ever needed, Deyao deletes versions in S3 by hand),
plus a signed marker for every store made sensitive.

## Setting a core up: Reset and Recover (on the iPhone)

Two paths, nothing else, and neither needs Claude or waits on anything Claude does (Deyao, 2026-10-10). Both
live on one secure page of the shell ("Reset or recover"), which first checks the core itself: the box key
(`keys/box.pub`, fetched from GitHub, never from the router) signed its keys, and the core signed its state. The
page says only what Deyao acts on; errors are one plain sentence with the details folded away.

- **Reset (make new):** the app makes a master key pair in memory and shows the **recovery kit**
  `jarvis2-kit:2:<master private key>` with Copy and "I've saved it". On that, it signs a claim naming the
  master public key, the core's keys and its own, with an empty bundle, and the empty core takes it. The stores
  start empty; the setup session fills them later by normal writes (`infra/setup.py write`, which learns the
  master public key from the core's signed state) and sends the core its Fly token (`backup-core`).
- **Recover:** Deyao pastes his kit. The app fetches the backups through the router (which holds the bucket's
  read credential and passes the objects on as they are), checks each writer's signature (`keys/setup.pub`
  from GitHub), decrypts them with the master key, and claims the empty core with the same statement and a
  bundle of every store (the `core` store with the Fly token, the names that aren't sensitive), sealed to the
  core. The core wraps every store to `P + K` at once; plaintext lives on the phone and in that one call, well
  inside a 10-minute cap.

Either way the app pins the core's keys and its own master public key, then forgets the master private key. From
then on it refuses a core set up with another master key, or for another phone. Stores are locked; Deyao unlocks
them as usual.

**A core that is already set up** takes neither path: Reset or Recover first asks for the kit it was set up with
and sends `wipe` signed by that master key; the core exits and a new, empty one takes its place. Without that kit
(a lost kit, or a core someone else claimed first) the core is emptied only by a restart from git (the
`jarvis2/restart` annotation in `k8s/apps/core.yaml`).

**The router's part** is to admit a claim or a wipe only from the app's device login and to serve the backups.
It can withhold a backup or serve an older signed version (the bucket is versioned), never read, change or forge
one: each is sealed to the master key and signed by the setup key. The bucket's read credential is the router's
own (a Hetzner S3 credential narrowed to reads of the backup bucket by bucket policies), set once with the box.

## The box

It takes changes only from git: no SSH, no reachable k8s API, no inbound port; everything arrives through
Flux from the public repo. A box git can't fix is replaced, then set up again as above (Recover). Session machines reach
the router over Fly's private network (the box is a WireGuard peer of the org), not through Cloudflare, so no
credential on a machine opens anything on the edge.

## The path between iPhone and core

The network path is ordinary for everything (the router, the tunnel) — no hardened channel. Integrity
comes from signatures at both ends. **Rule: everything that leaves the core is signed by the core** — every
challenge, cert and answer (including lists and errors), with the caller's nonce where freshness matters.

- **Core → iPhone:** every challenge (and the store list, burn certs, `list_unlocked` answers) is signed by the
  core. The phone verifies the core's signature against the core key it pinned when it set the core up.
- **iPhone → core:** every response is signed by the phone's Secure Enclave key under Face ID. The core
  verifies it against the phone's public key from the claim.

So the router can delay, drop or replay messages, but can't forge or alter one without the signature check
failing.

## Sensitive stores

Sensitivity lives in the core and only grows: `create_store` makes the only non-sensitive stores (besides
a Recover), `mark_sensitive` takes one out of the set for good, a store the core never created is sensitive.
The core marks sensitive stores in every challenge it signs, so the phone learns them from the core, never
from the router: a sensitive store is never pre-selected by the normal-mode UI or the web, is chosen by Deyao
himself on the secure page, and any approval that includes one shows an obvious warning before Face ID.
Which stores a harness brings is the router's business (`policy/stores.json`); the app hides them.

## Unlocking a store (split key agreement)

Each store's key is encrypted to the **combined public key** `P + K`: `P = p·G` is the iPhone's Secure Enclave
key, `K = k·G` the core's. Writing a store picks a fresh one-off `e` and stores `E = e·G`; the shared secret is
`e·(P + K)`. It's Diffie–Hellman with the recipient split in two: `p·E + k·E = (p + k)·E = e·(P + K)`.

1. `unlock_begin(store)` → core returns (store, `E`, one-off `T`), signed.
2. iPhone checks the signature, shows "Unlock <store>?", and on Face ID the Enclave computes its share `p·E`.
   The phone encrypts the share to `T`, so the router relaying it never sees it.
3. `unlock_finish` → core decrypts the share, deletes the one-off key, adds `k·E`, decrypts the store.

Neither side ever learns the other's private key: the core gets `p·E`, never `p` (recovering `p` from it is the
discrete-log problem). A share opens only the store written with that `E`, and every write picks a fresh `e`.
The Enclave returns only the x-coordinate of `p·E`, so the core tries both points with that x and keeps the
one that decrypts.

## Deploy keys (a repo's push access)

Each GitHub repo Deyao adds in the app's Settings gets its own store, `github-<repo>`, holding an SSH key that GitHub
accepts for that one repo, read and push, with no expiry: a **deploy key** (Deyao, 2026-10-10). The key is made
by the core, approved by the phone; the box alone can never make one, and no AI is in the path.

- **The token** that may manage deploy keys lives only in its own sensitive store, `github-deploy-keys`: a
  fine-grained GitHub token on all of Deyao's repositories with Repository "Administration: read and write" and
  nothing else (it can't read or write code). No other store is opened by this flow.
- **Add:** the app asks for the repo; `deploy_key_begin` answers, signed, exactly what will happen: the repo, the
  store's name, whether it is sensitive (asked for, or always for `DE0CH/jarvis2`, whose push reaches the core; a
  store that is sensitive stays so), whether it replaces an existing store, the key's title on GitHub (`jarvis2
  <store>`), and the token store's `E` with a one-off `T`, as an unlock. The shell's secure page shows it; under one
  Face ID the phone signs that document and computes its share of the token store, sealed to `T`.
  `deploy_key_finish` checks the signature against the phone key from the claim, opens the token store with the
  share for this call only (it never joins the unlocked set; the plaintext goes when the call returns), deletes
  that repo's keys titled `jarvis2 <store>`, makes an ed25519 key pair, adds the public half to the repo through
  GitHub's API (api.github.com, fixed in the core), and writes the store — the repo's name and the OpenSSH private
  key — wrapped to `P + K` itself. Its signed answer carries the key's fingerprint.
- **Remove:** the same request and approval; the core deletes the titled keys on GitHub and the store.
- **Sessions:** a session that includes `github-<repo>` gets the key with its other secrets; the machine writes it
  with an SSH host alias that uses only that key and pins GitHub's host keys, and git rewrites that repo's URLs to
  the alias, so clone, pull and push work with no setup, and no other repo is reachable with it.
- **The router** keeps the repo list, adding or removing an entry only from the core's answer; it holds no token
  that can push or manage keys. The repos' stores have no backup (the core can't write one): after a Recover each
  repo is made again with one Face ID, which also deletes the old key on GitHub.

## Flows (router, outside the core)

- **New session:** the router adds the harness's stores (policy) → `succession(null, …)` ← iPhone approval →
  `start(image)` → `certify(approval, machine)` → succession cert. (The router may start the machine while
  Deyao is still deciding, and destroy it on a reject.)
- **Pause:** the machine signs its snapshot (artefacts + transcript) with its signing key and uploads it →
  `kill`. Skipped/failed snapshot = nothing to resume; no secret moves.
- **Resume, nothing changed (also unattended, e.g. scheduled):** `succession(old, …)` ← approve_by_dead_machine
  → `start` → `certify` → succession cert.
- **Resume with a change (e.g. newer image), approved:** `succession(old, …)` ← iPhone (shows the difference,
  Deyao clicks) → `start` → `certify`. Rejecting leaves the session paused as it was.
- **Add a store to a running session:** the session asks through the router (signed with its machine key) for
  one more store → `succession(machine → same machine, set + store)` → `approve_by_phone` → new cert → the
  machine pulls its secrets again.
- **Downgrade in place:** the machine makes a new key pair → `succession(machine → same machine, a subset, new
  keys)` → the machine signs the challenge with its old key → `approve_by_old_key` → new cert → only then the
  machine shreds its old keys and the dropped stores' secrets, and re-pulls with the new keys.
- **End a session:** `kill`, then burn: `succession(old, no stores, no options, null image)` ← respond by
  dead machine → `certify(approval, none)` → burn cert.

## Machine side (in the image)

Boot makes the machine's keys and waits. `jarvis2-init` (run by the core through Fly, no arguments) prints the
public keys and lets boot go on: it takes the core's key from its own Fly config (the core sets it when it creates
the machine; only the core's token, and the setup session's org token, can create or change machines in the app,
the router's is read-only), fetches its core-signed succession cert through the router, checks it against the
core key and that it names its own keys; if the predecessor is a real machine it fetches the snapshot and checks
it against the predecessor's signing key from the cert. Then it starts the harness from the cert's options and
pulls its secrets. Any failed check → start nothing.

## iPhone approval screen

Show only what Deyao understands; what he clicks is exactly the challenge string. The phone translates each
challenge field and refuses anything it can't: store names; "Claude" / "opencode"; the image as "latest CI
build" / "CI build from <date>" (verified via a GitHub-signed build attestation, never trusting the box);
machine ids and public keys are signed but not shown.

## iOS app structure: a trusted shell with two modes

There is no separate confirmation page: the **New session sheet itself** is hardened, so its text and taps
can't be hijacked. That needs a process boundary, because the untrusted stack (React Native, Hermes, pods)
can rewrite anything in its own process.

- **The app's main process is a small native Swift shell (the "compositor").** It owns the window, the Secure
  Enclave keys (Keychain group only it can read) and the secure sheets (New session, unlock, approvals). Apple
  frameworks + the core only.
- **Everything else in Jarvis (React Native, the terminal, all dependencies) runs in a bundled ExtensionKit
  extension, in its own process** (iOS 26+), displayed by the shell through `EXHostViewController`.
- **Normal mode:** the shell shows the extension's view full-screen; the app looks and feels as before.
- **Secure mode:** the shell removes the extension's view and shows its own sheet. The extension can only draw
  inside the area the shell gives it — none — so it can't overlay or redirect taps. The sheet shows only
  trusted data (core-signed store list, built-in harness choices, the image as "latest CI build" via GitHub's
  build attestation); on Create, the shell checks the returned challenge contains exactly those choices, then
  signs under one Face ID. (Face ID shows no custom text, so the sheet, not the system prompt, is what must be
  trustworthy.)
- **Web:** the web page only creates a pending request; approval happens in the app's secure mode.

Test build (2026-10-05, simulator; DE0CH/ios-shell-spike, lessons/73): React Native runs inside the extension
in its own process (taps, typing, a WebView, XPC both ways, background/resume); secure mode removes the
extension's view and only the shell exits it; the extension and its React Native state survive secure mode;
the switch is seamless (shell-owned snapshot, sheet animated in and out, no flash); the pairing sign-in sheet
(ASWebAuthenticationSession) works from the extension. Keyboard avoidance must come from the shell resizing
the extension's area (React Native sees height 0). Still to measure on a real iPhone: the extension's memory
limit and start-up time.

## Guarantees

- A key store reaches a machine only through a succession: from null (Deyao's click), or from a killed,
  never-used predecessor (exact match automatically, or with Deyao's click when something changed).
- Plaintext stores exist only in the core's memory: unlocked ones until locked, during a Recover for at most
  10 minutes, and `github-deploy-keys` for the length of one phone-approved deploy-key call. The Fly token is the one
  secret the core keeps in memory for its whole life.
- A deploy key is made or deleted only on a phone-approved request; the core uses the GitHub token for nothing else.
- A session's line can't fork: each predecessor is used at most once (succession and burn both consume it).
- A bug or compromise outside the core (router, Jarvis, the box) can block or fail actions, never move a store
  to a machine not approved for it.

## Grants (shell access for router features, checked by the machine)

Features outside the core (terminal, scheduler, status, login repair, archive) need a shell in a session, as
Jarvis 1 got through Fly exec. The core's Fly token can exec only `jarvis2-init`, so the machine itself decides
(Deyao, 2026-10-09); the core only adds three fields to every succession cert: the phone's signing key, whether
any of the line's stores is sensitive, and the **line id** (the line's first machine; a successor inherits it).

- Each feature is a **holder** with its own key pair on the router's volume (`router/grants.go`).
- A holder's request (`{id, session: line, holder, cmd, timeout, at}`) is signed by its key and reaches the
  machine through `/m/commands`; the result goes back signed by the machine (`/m/exec-result`).
- The machine runs it (`bash -lc` as the session user) when one of these allows it:
  - a **phone grant**: the phone signs `{kind "grant", holder, session, scope "shell", issued, expires}`,
    at most 10 minutes long;
  - a **standing rule**: the phone signs `{kind "rule", …, until}` once, for things that happen while Deyao is
    away (wakeups, crons, auto-pause);
  - the session's **own allow list** (`jarvis2-machine allow <holder> <duration>`, kept in the snapshot): the
    machine approving for itself.
- A session holding a **sensitive** store accepts only a fresh phone grant.
- Grants name the line, which the machine reads from its core-signed cert, so the router can't make one line's
  grant open another line's machine. Request ids are single-use and at most 2 minutes old.
- Re-pairing the phone: running machines trust the old phone key until their line's next cert.

## Open

- Where the core's log lives. Plan: AWS CloudWatch Logs (append-only: no API deletes a single event; only a whole stream/group; the core's credential gets append rights only; free tier 5 GB/month covers it), added AFTER the core is running. Until then the log is local to the core.
- The secure sheets' exact design.
- Free text (prompts, wakeups) into high-privilege machines.
- Layer 1 hardening (CI-only builds and deploys) — see `SECURITY.md` PENDING 5–6.
