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
- **iPhone:** the highest privilege: approves any challenge after Deyao's click on a hardened path; runs recovery.
- **Session machine (Fly):** its image generates at boot an **encryption key pair** and a **signing key pair**;
  private halves never leave the machine. The image has the **master public key** built in.
- **Box key:** made by the trusted setup session when it creates the box and delivered in Hetzner user-data
  (the only channel into the box we already trust); its public half is in git. On the box it is a secret only
  the core's namespace reads, and the core signs its fresh public keys with it, so its identity can travel as
  plain text through anything untrusted. (Hetzner keeps serving user-data from the metadata address; every pod
  is blocked from it.)
- **Master key pair:** never expected to change. Private half in Deyao's password manager (the one Jarvis 1
  already uses), used only on the iPhone during recovery; public half in git and in the session image. It is
  the root of trust for machines (a core is trusted when the master key has signed its keys) and the key the
  backups are encrypted to.

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
| `identity()` | Its public keys, signed with the box key. |
| `recover(statement, masterSig, bundle)` | Once per core. The master key's signature over a statement naming this core and the phone's keys; the bundle (sealed to the core) carries every store — each wrapped to `P + K` at once, no plaintext kept — the store named `core`, whose Fly token the core keeps for its whole life (never a session's store), and the names of the stores that are not sensitive. |
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
| `log(nonce)` | Its signed log. |

A succession from null is approved only by the phone: every new line starts with Deyao's click.

**State, in memory only:** its own key pairs, the phone's public keys, the Fly token, the stores, the
non-sensitive set, the unlocked stores' plaintext, the pending unlocks, and append-only sets — **killed**
(Fly-confirmed), **used** (predecessors continued or burnt), **spent** approvals, **certified** machines. What
it **trusts** about others (the phone's and the master's public keys, the box key's signature) needs no
secrecy; what it uses to **prove itself** (its private keys, the Fly token) never leaves it.

**Restart = a new core,** brought back by recovery. Nothing is reloaded from the box's disk.

## Writing stores and their backups

A store is written **outside the core** by a trusted writer (the setup session today, later the app): the
values under a fresh data key, the key wrapped to `P + K` (the phone's and the core's public agreement keys,
from the master-signed core cert), handed to the core's open `write_store`. The router decides who may write.
The writer also writes the backup: the values encrypted to the **master public key** and signed by the writer,
in Deyao's Hetzner Object Storage, bucket `jarvis2-backup-de0ch`, **versioned** (an overwrite or a delete keeps
every old version; no true wipe is designed — if one is ever needed, Deyao deletes versions in S3 by hand),
plus a signed marker for every store made sensitive.

## Recovery (a fresh core, on the iPhone)

1. The new core makes its keys and signs its public keys with the box key.
2. The app's **recovery page** fetches that statement (through the router), checks the box-key signature
   against `keys/box.pub` from GitHub, and shows the core's identity as **8 words** (BIP39 English list over
   the SHA-256 of its public keys). Nothing goes on unless the signature checks.
3. Deyao pastes the **master private key** and the backup bucket's read keys from his password manager.
4. The phone reads the backups, checks their writers' signatures, decrypts them with the master key, signs a
   statement naming the core's keys, its own keys and the bundle's hash with the master key, and sends the
   bundle (every store, the `core` store with the Fly token, the names that aren't sensitive) sealed to the
   core. The core wraps every store to `P + K` at once; plaintext lives on the phone and in that one call, well
   inside a 10-minute cap (the phone may drop offline).
5. The phone forgets the master key. Stores are locked; Deyao unlocks them as usual. Machines and the app now
   trust that core through the master key's signature.

The first setup is a recovery from empty backups plus the `core` store.

## The box

It takes changes only from git: no SSH, no reachable k8s API, no inbound port; everything arrives through
Flux from the public repo. A box git can't fix is replaced, then recovered as above. Session machines reach
the router over Fly's private network (the box is a WireGuard peer of the org), not through Cloudflare, so no
credential on a machine opens anything on the edge.

## The path between iPhone and core

The network path is ordinary for everything (the router, the tunnel) — no hardened channel. Integrity
comes from signatures at both ends. **Rule: everything that leaves the core is signed by the core** — every
challenge, cert and answer (including lists and errors), with the caller's nonce where freshness matters.

- **Core → iPhone:** every challenge (and the store list, burn certs, `list_unlocked` answers) is signed by the
  core. The phone verifies the core's signature against the core key it signed in recovery.
- **iPhone → core:** every response is signed by the phone's Secure Enclave key under Face ID. The core
  verifies it against the phone's public key from recovery.

So the router can delay, drop or replay messages, but can't forge or alter one without the signature check
failing.

## Sensitive stores

Sensitivity lives in the core and only grows: `create_store` makes the only non-sensitive stores (besides
recovery), `mark_sensitive` takes one out of the set for good, a store the core never created is sensitive.
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
public keys and lets boot go on: it fetches its core-signed succession cert and the master-signed core key
through the router, checks the core key against the built-in master public key, the cert against the core key
and that the cert names its own keys; if the predecessor is a real machine it fetches the snapshot and checks
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
- Plaintext stores exist only in the core's memory: unlocked ones until locked, and during recovery for at most
  10 minutes. The Fly token is the one secret the core keeps in memory for its whole life.
- A session's line can't fork: each predecessor is used at most once (succession and burn both consume it).
- A bug or compromise outside the core (router, Jarvis, the box) can block or fail actions, never move a store
  to a machine not approved for it.

## Open

- Where the core's log lives. Plan: AWS CloudWatch Logs (append-only: no API deletes a single event; only a whole stream/group; the core's credential gets append rights only; free tier 5 GB/month covers it), added AFTER the core is running. Until then the log is local to the core.
- The secure sheets' exact design.
- Free text (prompts, wakeups) into high-privilege machines.
- Layer 1 hardening (CI-only builds and deploys) — see `SECURITY.md` PENDING 5–6.
