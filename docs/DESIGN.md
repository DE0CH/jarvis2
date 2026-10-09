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
  API; decides whether a challenge goes to the iPhone or to an automatic responder. Untrusted: a bug can only
  fail or crash.
- **iPhone:** answers challenges after Deyao's click on a hardened path; runs recovery.
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

- **Approval** — a succession challenge (predecessor, key-store set, start options, image) answered by a
  responder. Used by exactly one machine.
- **Started machine** — (Fly machine id, image, public encryption key, public signing key). The core creates it
  from an approval and reads its public keys from the output of the image's init command through Fly, so their
  trust chains to Fly.
- **Succession cert** — (predecessor → started machine, **key-store set**, **start options**): the started
  machine continues the predecessor and may run with that store set and those options (which harness). It is
  the machine's only permission document.
- **Null machine** — the special endpoint of every succession line; nothing associated with it is valid.
  - A new machine is a **succession from null**. Null is never consumed (it can start any number of lines).
  - A succession **to** null **burns** a machine so it can never have another successor (a **burn cert**).
- **Adding a store** — a machine can succeed **itself**: succession(machine → the same live machine, its store
  set plus exactly one store, same options). The new cert supersedes the old one for that machine; nothing is
  consumed, so the line stays one machine long.

## Core primitives

The core trusts itself: it does what it signs and needs no checks against itself. Its Fly token is narrowed
(a Fly macaroon caveat) to app `jarvis2-sessions`: create, read, stop and destroy machines, and run exactly one
command inside a machine, `/usr/local/bin/jarvis2-init` with no arguments. A leaked token can start or destroy
machines but never read a session's secrets (a machine without a cert gets none).

| Primitive | Does |
|---|---|
| `Succession(predecessor, store set, options, image)` | Issues a challenge (signed by the core) **before any machine exists**; a valid response → an approval. For adding a store the "predecessor" is the running machine itself and the answer is directly a new cert. |
| `start(approval)` | Creates the Fly machine with the approved image, runs `jarvis2-init` (the machine prints its public keys and goes on), binds the machine to the approval → succession cert. Consumes the approval; if Fly fails, the core destroys what it made and the router asks again. |
| `kill(machine)` | Rejects null. Destroys the machine through Fly, immediately, no cleanup; once Fly confirms it destroyed that existing machine, reports it to respond by dead machine (which records it killed). A "not found" from Fly is not a confirmation. |
| `unlock_begin(store)` | Makes a one-off key pair for this unlock (private half kept in memory) → returns (store, the store's `E`, one-off public key `T`), signed by the core |
| `unlock_finish(pending id, encrypted share)` | Decrypts the iPhone's share with the one-off private key and deletes that key; adds its own share `k·E`, recovers the store key, decrypts the store into memory → unlock id. A wrong share just fails to decrypt. |
| `lock(unlock id)` | Releases that id. A store's plaintext is deleted from memory only when no unlock id for it remains. No automatic lock. |
| `list_unlocked(nonce)` | Read-only: every open unlock id with its store and unlock time (never values), signed with the caller's nonce. |
| `Pull secrets(cert)` | Only while each store in its set is unlocked. Returns the store set's current values encrypted to the machine's public encryption key named in a valid succession cert — so nobody else can open them and no other authentication is needed. Refreshes need no approval. |
| `add_store(sealed store)` | A new store, created outside the core (below): its values sealed to the core, signed by its creator; the core wraps it to `P + K` at once and keeps no plaintext. Stores are never replaced. |

**`Succession` accepts any valid signature over its challenge from a recognised responder; the responders check
the conditions.**

| Responder | Checks before signing |
|---|---|
| iPhone approval | Deyao's click on a plain-language summary; for a predecessor that is a real machine, a core-signed **burn cert** of it (none needed from null). For adding a store, no burn cert: the screen shows the session and the one added store. |
| Respond by dead machine (core, automatic) | Predecessor is recorded killed (Fly-confirmed) and not recorded used; store set + image + options identical. On signing, records the predecessor used. Never answers an add-a-store. |

Null is never in the list of killed machines, so a succession from null can only be answered by the iPhone:
every new line starts with Deyao's click. Every cert is signed by the core, so every cert originates from the
core and is logged. Since the approval comes before the machine, Deyao approves at once; the machine starts
afterwards (its first image pull can take minutes).

**State.** All the state the core depends on lives **in memory only**: respond by dead machine's two
append-only sets (**killed**, **used**), the approvals not yet started, the unlock table, the known stores with
their sensitive marks (each wrapped to `P + K`), the phone's public keys, the Fly token and the core's own
keys. Two kinds of things: what it **trusts** about others (the phone's and the master's public keys, the box
key's signature on itself) needs no secrecy; what it uses to **prove itself** (its private keys, the Fly
token) never leaves it.

**Restart = a new core.** A restarted core has new keys and knows nothing; it is brought back by **recovery**
(below). Nothing is reloaded from the box's disk, so nothing on the untrusted box can feed it altered state.

**Known stores.** The core only acts on key stores it knows (learned in recovery, or added with `add_store`).
A store it doesn't know is rejected, so a restarted core can't be led to believe a sensitive store is not
sensitive. Sensitive marks arrive with the stores, or are added later with `mark_sensitive`.

## Stores outside the core: creation and backup

A store is created **outside the core** by a trusted creator (the setup session today, later the app). The
creator encrypts it twice: to the **master public key**, as the backup, and sealed to the core, for
`add_store`. It signs both. The backup goes to Deyao's Hetzner Object Storage, bucket `jarvis2-backup-de0ch`,
**versioned**: an overwrite or a delete keeps every old version. No true wipe is designed; if one is ever
needed, Deyao deletes versions in S3 by hand.

## Recovery (a fresh core, on the iPhone)

1. The new core makes its keys and signs its public keys with the box key.
2. The app's **recovery page** fetches that statement (through the router), checks the box-key signature
   against the box's public key in git, and shows the core's identity as **8 words** (a fixed word list over
   the SHA-256 of its public keys). Nothing goes on unless the signature checks.
3. Deyao pastes the **master private key** from his password manager.
4. The phone signs the core's public keys with the master key (machines and the app now trust that core), gets
   the latest backup from S3, checks its creator's signature, decrypts it with the master key and re-encrypts
   the whole key store to the core, together with the phone's own public keys.
5. The core holds the plaintext key store **for at most 10 minutes** (the phone may drop offline at any time):
   it wraps every store to `P + K` with the phone, keeps the `core` store's Fly token in memory, and wipes the
   rest. If the split isn't done in 10 minutes it wipes everything and recovery starts again.
6. The phone forgets the master key. Stores are locked; Deyao unlocks them as usual.

The first setup is a recovery from an empty backup plus the `core` store.

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

A key store can carry a **sensitive** mark.

- `list_sensitive(nonce)` returns every store carrying the mark, signed by the core together with the caller's
  nonce (genuine, complete, fresh).
- `mark_sensitive(store)` is a core primitive anyone may call (it only adds protection). There is **no**
  primitive to remove the mark. The only way to have the same secrets unmarked is to create a new store with
  them.
- The mark is part of the core-signed store list, so the iPhone learns it from the core, never from the
  router.
- **Entering secure mode with options:** anything (the normal-mode UI, the web) may ask for secure mode with
  pre-selected options, and may freely pre-select non-sensitive stores. A sensitive store must be chosen by
  Deyao himself inside the secure sheet. (Open: never pre-selectable, or pre-selectable but only with the
  warning below.)
- **Approving a request that came from the web:** if it includes a sensitive store, the approval shows an
  obvious warning before Face ID.

The mark is part of the core's in-memory known-stores list; it only grows (see State).

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

- **New session:** `Succession(null, …)` ← iPhone approval → `start(approval)` → succession cert.
- **Pause:** the machine signs its snapshot (artefacts + transcript) with its signing key and uploads it →
  `kill`. Skipped/failed snapshot = nothing to resume; no secret moves.
- **Resume, nothing changed (also unattended, e.g. scheduled):** `Succession(old, …)` ← respond by dead machine
  → `start` → succession cert.
- **Resume with a change (e.g. newer image), approved:** `Succession(old, …)` ← iPhone (shows the difference,
  Deyao clicks) → burn (`Succession(old → null)` ← respond by dead machine) → `start`. Rejecting leaves the
  session paused as it was.
- **Add a store to a running session:** the session asks through the router (signed with its machine key) for
  one more store → `Succession(machine → same machine, set + store)` → iPhone approval → new cert → the
  machine pulls its secrets again.
- **End a session:** `kill`, then burn.

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
