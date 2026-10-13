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
| All other open-source code (sops, Expo and the web page's npm tree, …) | **Not trusted**; the core and the iOS app never depend on it |

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
  The core keeps each certified machine's **newest** cert nonce: a cert an add-store or a downgrade replaced is
  superseded and pulls, continues and succeeds to nothing (R1 audit, 2026-10-11: an older cert must not undo a
  downgrade).
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
| `claim(statement, masterSig, bundle)` | Once per core, on an empty core: Reset and Recover. The statement names a master public key, this core and the phone's keys, and that master key signs it; the core keeps both keys for its life. The bundle (sealed to the core) carries the stores — none for a Reset; for a Recover every store from the backups, each already wrapped by the app to `P + K` (the core's signed store key), so the core never sees their plaintext; the `core` store's Fly token, which the core keeps for its whole life (never a session's store); each deploy-key store's repo; and the names of the stores that are not sensitive. Who may claim is the router's business (Deyao's app only). |
| `wipe(statement, masterSig)` | The current master key's signature over a statement naming this core: the core answers and exits; Kubernetes starts a new, empty core. Nothing else empties a set-up core except a restart from git. |
| `set_fly_token(sealed)` | The Fly token, sealed to the core (the setup session, after a Reset). Open: the core calls Fly only for its own app, fixed in its code, so a wrong token can only fail. |
| `create_store(name)` | Once per name, on a set-up core: an empty, non-sensitive store. Open; the writer checks the core's word against its own list and marks a store sensitive before writing it (an empty store goes into no session). Never `github-deploy-keys`. |
| `mark_sensitive(name)` | The one-way upgrade: the name leaves the non-sensitive set. Open. |
| `write_store(contents)` | New contents for a store, already wrapped to `P + K` by the writer, with the writer's signature (the setup key) over its name, `E` and data hash. Open, on a set-up core; the core passes the signature on in `unlock_begin`, and the phone checks it before its share. |
| `stores(nonce)` | The signed list: each store, sensitive or not, empty, unlocked. |
| `succession(predecessor or null, stores, options, image, salt)` | A signed challenge, before any machine exists (the phone shows each store's sensitivity from the signed store list). Exact values only (the router fills in defaults): a harness, permission mode `auto` or `bypass`, stores sorted and each once, and for a new line the caller's random salt (a repeated salt only gets its second approval refused). `options` = harness, permission mode, the session's settings (`config`) and one machine's one-time inputs (`once`): below, "Inputs to a machine". |
| `approve_by_phone(challenge, sig)` | The phone is the highest privilege: any challenge it signs is approved. |
| `approve_by_dead_machine(challenge)` | Automatic: the predecessor is killed (Fly-confirmed) and not used, and the stores, image and options are identical (the predecessor's `once` left out; this challenge has none) — or it is a burn. Never a new line, never a machine succeeding itself. |
| `approve_by_old_key(challenge, sig)` | Automatic: a downgrade (same machine, a subset of its stores, a new key pair) signed with the signing key in the cert it continues. |
| `start(image, region, size)` | Open (normally the router, which guards it; it can't lead to a secret): one Fly create → a created machine. The image is `ghcr.io/de0ch/jarvis2-session` pinned by digest; `size` is small, medium or large (anything else is refused); the machine's Fly config gets only what the core sets (its key, the router's address). |
| `init(machine)` | One try, for a machine this core created: Fly must report it started, then one run of `jarvis2-init` (its output: the machine's keys) → the signed `started` document. 409 while it isn't up; the router retries and kills a machine that never comes up. |
| `certify(approval, started, carry?)` | The approval and a started machine (init's signed document) running the approved image (the digest Fly reports is the approval's) → the succession cert, naming the snapshot the predecessor signed at its kill. One machine per approval, one line per machine, one successor per predecessor (killed and not used). The null image: no machine, a burn cert. For a machine succeeding itself the approval is the new cert at once. Given the line's carry blob, certify (and an add-store's or downgrade's answer) answers it rebound to the new cert beside it, keeping only that cert's stores. |
| `kill(machine, snapshot?)` | One Fly destroy, then Fly must report the machine destroyed → killed (409 before: the router asks again). `snapshot` = the sha256 of the machine's last snapshot and its signature over it with its current key: kept as what its successor restores. |
| `attest(machine, input, origin, sha256)` | The input log: sign and append to a hash chain (no parsing); the answer is the entry. Certs are appended by the core itself, each cert's entry answered beside it. The core keeps only the head and the length; the router keeps the entries. |
| `unlock_begin(name, for)` / `unlock_finish(pending, phone share)` | The split-key unlock. `for` = the nonce of the one challenge or cert it is for (a Start, an add-store, a waiting session): only that cert reads it and its pull locks it again (below, "Carried secrets"); no `for` = a standing unlock, open until locked. |
| `lock(unlock id)` / `list_unlocked(nonce)` | Release; the signed list of open unlocks (each with what it is for). |
| `pull_secrets(cert, carry)` | The cert's stores sealed to that machine's encryption key — so no other proof is needed — each from an unlock open to that cert, else from the line's carried secrets; answers the next carry blob for that machine. |
| `deploy_key_begin(action, repo, sensitive, store, title, publicKey, blob)` / `deploy_key_finish(pending, phone sig, phone share)` | A repo's deploy key, added or removed (below, "Deploy keys"): the signed request (naming the app's public key and its store blob's hash), then the phone's signature over it and its share of `github-deploy-keys`; the core uses that store's GitHub token for this one call to add exactly that public key, and stores exactly that blob or deletes the store. |
| `store_key(phone)` | Open: the signed store key P + K for that phone key, which the app wraps store data keys to (it can't add points). |

A succession from null is approved only by the phone: every new line starts with Deyao's click.

**State, in memory only:** its own key pairs, the carry key, the master and phone public keys (from the claim), the Fly token,
the stores, the non-sensitive set, the machines it created and not yet initialised (with the image asked for), each
initialised live machine's current signing key, the unlocked stores' plaintext (each unlock standing or for one cert), the pending unlocks and deploy-key requests, and append-only sets — **killed**
(Fly-confirmed), **used** (predecessors continued or burnt), **spent** approvals, and per certified machine the nonce of
its **newest** cert. What
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
live on one page of the iOS app ("Reset or recover"), which first checks the core itself: the box key
(`keys/box.pub`, fetched from GitHub, never from the router) signed its keys, and the core signed its state. The
page says only what Deyao acts on; errors are one plain sentence with the details folded away.

- **Reset (make new):** the app makes a master key pair in memory and shows the **recovery kit**
  `jarvis2-kit:2:<master private key>` with Copy and "I've saved it". On that, it signs a claim naming the
  master public key, the core's keys and its own, with an empty bundle, and the empty core takes it. The stores
  start empty; the setup session fills them later by normal writes (`infra/setup.py write`, which learns the
  master public key from the core's signed state) and sends the core its Fly token (`backup-core`).
- **Recover:** Deyao pastes his kit. The app fetches the backups through the router (which holds the bucket's
  read credential and passes the objects on as they are), checks each writer's signature (`keys/setup.pub`
  from GitHub), decrypts them with the master key, wraps each store to `P + K` (the store key the core signs for
  this phone: CryptoKit can't add points), and claims the empty core with the same statement and a bundle of those
  blobs (the `core` store's Fly token on its own, the names that aren't sensitive, each deploy-key store's repo),
  sealed to the core. The plaintext lives only on the phone, well inside a 10-minute cap; the core never sees it.

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

- **The metadata address** (169.254.169.254, which keeps serving the user-data with the box key): NetworkPolicies keep
  the core, the router and cloudflared from it, and a box built from 2026-10-11 on drops every pod's packets to it in
  the raw table at each boot (`jarvis2-no-metadata.service`), whatever a namespace's policy says.
- **GitHub (layer 1, R1 audit 2026-10-11):** a ruleset on `main` lets only repo admins (Deyao's token) and deploy keys
  update it (no deletion, no force push); a workflow's GITHUB_TOKEN can't. The environment `release` (refs/heads/main
  only) holds the App Store Connect key, the CI image key and the images pin job's deploy key, so a branch with a
  rewritten workflow gets none of them. k8s pins the router, the session image and (from its next release) the core by
  digest, so a tag pushed again from anywhere changes nothing that runs.

**The setup session trusts only Deyao's core** (R1 audit, 2026-10-11: claim is first-come, so a router or box that
claims an emptied core first would otherwise receive every store `fill-stores` writes, and every backup sealed to its
master). `infra/setup.py` writes, backs up and sends nothing until the core's master key is the one pinned in the bucket
(`pins.json`, signed by the setup key), or the core's claim names the pinned **device key** — the app's long-lived
Secure Enclave key, kept across Reset and Recover — inside the master-signed statement and the router kept that
device's signature over the statement (`deviceKey`/`deviceSig` on POST /api/core/claim). A claim under the pinned master
pins the device key it names; a claim countersigned by the pinned device key moves the master pin (a Reset).

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

1. `unlock_begin(store)` → core returns (store, `E`, one-off `T`, the blob's **writer**: the setup key's signature over
   name, `E` and the data's sha256, or "core" for a blob the core vouches for: a Recover's or a deploy key's, which the
   phone or the master key signed for), signed.
2. iPhone checks the signature and the writer (`keys/setup.pub` from GitHub; refused without one when the core's store
   list says `writers`), shows "Unlock <store>?", and on Face ID the Enclave computes its share `p·E`.
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
- **Add:** the app makes an ed25519 key pair and wraps the store holding the repo's name and the OpenSSH private
  key to the core's store key (`P + K`, signed by the core), so the core never sees the private key; it asks for the
  repo with that public key and blob. `deploy_key_begin` answers, signed, exactly what will happen: the repo, the
  store's name, whether it is sensitive (asked for, and a store that is sensitive stays so; the app always asks for
  `DE0CH/jarvis2`, whose push reaches the core, and refuses an answer that isn't), whether it replaces an existing
  store, the key's title on GitHub (`jarvis2 <store>`), the public key and the blob it will store, and the token
  store's `E` with a one-off `T`, as an unlock. The app's review page shows it; under one
  Face ID the phone signs that document and computes its share of the token store, sealed to `T`.
  `deploy_key_finish` checks the signature against the phone key from the claim, opens the token store with the
  share for this call only (it never joins the unlocked set; the plaintext goes when the call returns), deletes
  that repo's keys titled `jarvis2 <store>`, adds the app's public key to the repo through GitHub's API
  (api.github.com, fixed in the core), and keeps the app's blob as the store. Its signed answer carries the public
  key.
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
- **Pause:** the machine stops every process of the session (SIGSTOP), signs its snapshot (artefacts + transcript)
  with its signing key and uploads it; it signs only this one in its life and answers any later snapshot command with
  the same one, so the router holds no earlier signed state to roll a successor back to →
  `kill(machine, snapshot hash + its signature)`: the successor's cert names that snapshot and no other. Its carried secrets (sealed by the core at its last pull) are already next to the snapshot. Skipped/failed
  snapshot = nothing to resume; no secret moves.
- **Resume, nothing changed (also unattended, e.g. scheduled):** `succession(old, …)` ← approve_by_dead_machine
  → `start` → `certify` (with the line's carry) → succession cert + the carry rebound → the machine pulls its secrets from the carried blob,
  no store unlocked, no Face ID.
- **Resume with a change (e.g. newer image), approved:** `succession(old, …)` ← iPhone (shows the difference,
  Deyao clicks) → `start` → `certify`. Rejecting leaves the session paused as it was.
- **Add a store to a running session:** the session finds the store holding the key it needs (`jarvis2 stores`:
  every store's key names, never values — the router's record, kept by the setup session's writes; repo stores'
  names follow from the repo), then asks through the router (signed with its machine key) for
  one more store → `succession(machine → same machine, set + store)` → `approve_by_phone` (the same Face ID unlocks
  the added store for that challenge only, if it is locked) → new cert + its carry rebound → the machine pulls its
  secrets again (its stores from the carried blob, the added one from its unlock, locked again by that pull).
- **Downgrade in place:** the machine makes a new key pair → `succession(machine → same machine, a subset, new
  keys)` → the machine signs the challenge with its old key → `approve_by_old_key` → new cert + its carry rebound (the
  dropped stores leave the carried blob) → only then the machine shreds its old keys and the dropped stores'
  secrets, and re-pulls with the new keys.
- **End a session:** `kill`, then burn: `succession(old, no stores, no options, null image)` ← respond by
  dead machine → `certify(approval, none)` → burn cert. The router deletes the carried blob with the snapshots;
  burnt, it could open for nothing anyway (no successor can be certified, the killed machine's certs read none).

## Carried secrets (Deyao, 2026-10-11)

"After a session is started, there's no reason to keep the store unlocked in the core. So just lock it then." For
unattended resumes (a wakeup, a cron, a task run with nobody there) he chose: **the session carries its secrets**.

- **Unlocks are for one session.** The phone's unlock names what it is for: `unlock_begin(store, for)` with the nonce
  of the Start's challenge (New session, an approval of a new line), of an add-store's challenge, or of a waiting
  session's cert (Unlock…, an Inbox unlock request). The core signs `for` into the begin document, only the cert with
  that nonce reads the plaintext, and that cert's first pull that goes through locks it again; one its cert never
  pulls with lapses after 30 minutes. Start stays one Face ID that unlocks what the session needs (Deyao,
  2026-10-10). A **standing** unlock (no `for`: the Stores page's Unlock) stays what it was, open to every session
  until locked; it is the only kind the store list calls unlocked.
- **The carry blob.** Every pull that goes through also answers the values it sealed, per store, under the core's
  **carry key** (AES-256-GCM), bound to that machine. The router keeps it next to the machine's snapshot
  (`snapshots/<machine>.carry` on its volume) and sends it with the machine's next pull. The blob names the cert it was
  sealed for; the core reads a store from it only when no unlock is open to the cert, only for the machine's newest
  cert whose blob was sealed for that cert or the one it directly continues (the same machine's previous cert, or the
  predecessor's newest), so a blob from before a downgrade opens for nothing after it,
  only while that machine isn't killed, and only the stores that cert names. The call that makes a new cert rebinds it
  and answers it beside the cert: a successor's certify (so one that dies before pulling doesn't break the line), an
  add-store's or a downgrade's answer (the dropped stores leave it at once).
- **The carry key** is 32 random bytes the core makes when it starts, in memory only: sealed to the running core
  and nothing else — no backup, no setup step, no new trust path. Nothing else (the router, the Storage Box, a
  machine, another session, another core) can open or forge a blob.
- **A new core destroys the earlier core's sessions** (Deyao, 2026-10-11: "They are just automatically destroyed.
  Core restart is infrequent enough. No need to engineer around it."). A new core (restart, `core/` deploy, box
  rebuild; empty, Reset or Recovered) can open none of the earlier blobs, and the earlier lines can't continue on it
  (their certs are the earlier core's; its killed/used sets are gone). The router watches the core's identity
  (`router/corechange.go`, every 30 s; the key must sign its own state document): when it changes, every session
  with a line is marked `oldCore`, and each is destroyed the normal way once it is paused — archived as a record in
  Previous, its snapshots and blob deleted, its machine and Discord channel cleaned up (a running one goes when it next
  pauses). Restoring one from Previous is an ordinary new line approved on the phone.
- **What still needs the phone:** a new line (Start, a restore, a task's first line), a store added, a changed image
  or permission mode on resume — as before. A paused session whose blob is gone (lost by the router, a session
  paused under a core that predates carried secrets) waits on its locked store as before ("Waiting for store X",
  Unlock… or an Inbox unlock request), now unlocked for that session's cert only.
- **Values are the session's own.** A resume gets the values its line last pulled. A store rewritten since reaches
  the line at its next pull with an unlock open to it (Unlock… for that session, or a standing unlock).
- Grants are unchanged: they open a shell on a machine, not a store; a standing rule still serves the unattended
  features, which now also find their stores without anything left unlocked.

## Requests: the Inbox (Deyao, 2026-10-11)

Anything that needs the phone's Face ID and is asked for somewhere other than the phone itself — by a session, the
web page or the setup session (Claude) — waits in the app's **Inbox** tab (a badge counts it; no push, no Discord).
A caller calls an **intent endpoint** on the router (`…/requests/repo/add`, `repo/remove`, `grant`, `unlock`; a
session also `add-store`) with the intent's arguments and its own explanation. The router keeps the request
(persisted, deduplicated by kind + arguments, gone after 10 minutes, at most 20 per caller) with **who called**, worked out
from the credential the call carried — the machine key (a session), the setup key (Claude), Deyao's Access login
(the web page, or the app when its device token is sent) — never from what the caller says about itself, and the
exact call it made. The router's own approvals (new session, resume on the latest image, add a store) are listed in
the same Inbox with their caller and call recorded when they were made, and also go after 10 minutes (rejected like a Deny).

Opening one shows the app's review page for it (the same review stop the app's own buttons use) with three
read-only fields on top, in **decreasing trust and increasing level of explanation**:

1. **What you sign (exact)** — fully trusted. Rendered by the app from the very content the phone signs (the core's
   signed begin document, the core-signed challenge, the session's core-signed cert and the checked grant), never
   from router prose (`Shell/SignedAction.swift`): the lowest level, what happens mechanically. Drawn strongest; the
   one that matters.
2. **Requested via (router)** — as trustworthy as the router: the caller and the endpoint with its arguments. The
   intent.
3. **Reason given by <caller> (unverified)** — the caller's own words: plain text (control and format characters
   dropped, at most 600 characters and 8 lines), shown as theirs and never as instructions or markup. The why.

**Allow** is the page's own action, unchanged (one Face ID over what field 1 shows); **Deny** drops the request (an
approval is rejected). Nothing a non-phone caller does can approve anything: a request is only a pointer to a secure
page, and the phone's signature over the exact content stays the only approval. Requests made in the app itself keep
their direct flow (no Inbox detour). What a caller may ask for: a session only for itself (a grant, an unlock, a
store) and for a repo to be added (a new key in its own store, which no session holds until Deyao picks it); not
removing a repo or anything about another session. The web page, the app and the setup session may ask for any kind.

**Batches** (Deyao, 2026-10-13): a caller may file several items as one batch, through the API, with a **summary** of
its own. The Inbox shows the batch as one entry; its review page shows the summary as the caller's unverified words,
then every item with its own three fields as above (each item's "What you sign (exact)" rendered from that item's
signed content), and **Allow all** asks for ONE Face ID: the app evaluates Face ID once on an LAContext and signs every
item with the Secure Enclave key on that context (the simulator: one stand-in check), each exactly as it would be signed
alone and sent on its own, so the core and the grant store verify each item unchanged. Nothing about what a signature
covers changes; a batch is only the router's grouping. Any kind may be in a batch; Deny drops it whole (an item can be
denied or allowed alone); it goes after 10 minutes like any request; an item that fails is shown failed while the
others stand, and Retry reads it again and asks for another Face ID.

## Machine side (in the image)

Boot makes the machine's keys and waits. `jarvis2-init` (run by the core through Fly, no arguments) prints the
public keys and lets boot go on: it takes the core's key from its own Fly config (the core sets it when it creates
the machine; only the core's token, and the setup session's org token, can create or change machines in the app,
the router's is read-only), fetches its core-signed succession cert through the router, checks it against the
core key and that it names its own keys; if the predecessor is a real machine it fetches the snapshot and checks
it against the hash the cert names and the predecessor's signing key from the cert. Then it starts the harness from
the cert's options and pulls its secrets. Any failed check → start nothing. Everything else it takes: below.

## Inputs to a machine (Deyao, 2026-10-11)

Deyao's question: once a session is certified (new or an unattended resume), can the machine that receives its
secrets run another image, another entry point, or anything carrying state other than the certified transcript?
The rule: **every input our infrastructure delivers into a machine that holds secrets — at start, resume, restore,
and later (wakeups, nudges, attachments, an added store) — is vouched for by one of**

- **(a) the cert**: what the phone approved, or what an unattended resume carried over unchanged;
- **(b) the predecessor's signature**: its snapshot, whose hash the cert names (the core took it from the signed kill);
- **(c) the line's own signature**: what a machine of this line asked for itself (a wakeup, a cron), kept by the router
  exactly as signed and checked against the line's signing keys, which travel in the signed snapshot;
- **(d) a trusted provider over an authenticated channel**: GitHub over SSH with the repo's deploy key (or HTTPS for a
  public repo the cert names), the GitHub release a runtime bundle is pinned to by sha256.

Router-only data never reaches a program or the agent, **except values whose strict format can't carry an
instruction** (listed below). "Data" is no exemption: a prompt, a title, a transcript all steer the agent. This
guards the **entry points** only: it establishes a chain of trust from Deyao's approval to the running agent that
the router or box can't break. What the session itself chooses to read afterwards (the web, email, files it fetches,
Deyao telling it to) is outside it, and so are shell grants (below, "Grants"): a phone grant or standing rule is
Deyao handing a feature a shell, and the session's own allow list is the session's choice.

| Input | Who vouches |
|---|---|
| The image | (a) the approval names `ghcr.io/de0ch/jarvis2-session` pinned by its linux/amd64 digest; certify refuses a machine whose Fly-reported digest differs. A resume runs the predecessor's digest. |
| The entry point | the image (Fly config has no init/cmd, no files, mounts or services; only the core's token can create or change machines) |
| The env | none needed: the core sets only `JARVIS2_CORE_KEY` and `JARVIS2_URL` (from its own deployment); the machine also throws away anything else at boot (keeps the image's own ENV, recorded at build, and Fly's `FLY_*`) |
| Title, first prompt, model, repos, one-shot, API proxy, attachments (by sha256), a restore (machine + snapshot sha256), task parameters | (a) `Options.Config`, fixed for the line; the first prompt and attachments only for its first machine; each attachment also carries the core's attestation (input log) and is taken only when its bytes match |
| A resume's prompt, a rollback | (a) `Options.Once`: only the phone approves one; never carried over |
| The predecessor's state (transcripts, workspace, artifacts, `~/artifacts/on-start`, `.claude` settings and hooks, the allow list, the line keys) | (b) the one snapshot the cert names, signed by the predecessor |
| An archived snapshot (restore) | (a) its sha256 in the config, plus the old cert (core-signed) and its machine's signature |
| Repo contents (CLAUDE.md, hooks, skills) | (d) GitHub, for exactly the repos the cert names (a cert whose config names none: the repos of the deploy-key stores in the cert) |
| Secrets | the cert's stores, sealed to the machine by the core; written to `~/.secrets` only under env-name keys |
| The Claude login | (d) Anthropic: the router hands the pair over `/m/claude-login` (machine-signed, only to a cert with the store `claude`), and the machine writes it only when Anthropic's profile endpoint names the account the store vouches for (`CLAUDE_ACCOUNT_UUID`; on a resume whose carried store predates it, the account in the snapshot's `~/.claude.json`); taken at boot, kept in step by a long poll with the router's refresh protocol (`machine/claudelogin.go`, `router/claudelogin.go`); no router write, no grant |
| Wakeups, crons | (c) the session's own signed request + the core's attestation; the line records what it delivered (in the snapshot): a wakeup once, a cron once per run and at most every half period |
| The watchdog's nudge, "continue" after a re-login, "upgraded" after an Upgrade | the image: texts built into it; the router picks when, never what (numbers, or a size: small, medium or large) |
| An added store | (a) the new cert, phone-approved |
| The OpenClaw runtime | (d) the GitHub release, pinned by sha256 in the image |
| Jarvis 1's restore-snapshot (would fetch unsigned state from the Storage Box when a store holds its credentials) | disabled in the image |

**Format exceptions** (the router's word alone, `GET /m/config`, each refused unless it matches): the session id
(`[a-z0-9-]`), the Discord channel id (digits), the live-sync interval (5–86400 s), a task run's id and its trigger
(a word), the tunnel proof (a token, `[A-Za-z0-9._~+/=-]`).

**The input log** (the record, beside the voucher): every input delivered after a machine started carries the core's
attestation over (machine, input hash, kind, origin) and the machine refuses one without it. The core appends each,
and every cert it issues, to a hash chain of core-signed entries; the router persists them to its volume
(`input-log.jsonl`, `GET /api/input-log`) from the answers that carry them; a new core's chain starts again at seq 0
(the router's file shows where one core's ends). The core keeps only the head and the length; it only
hashes, signs and appends.

## iPhone approval screen

Show only what Deyao understands; what he clicks is exactly the challenge string. The phone translates each
challenge field and refuses anything it can't: store names; "Claude" / "opencode"; the image as "latest CI
build" / "CI build from <date>" (verified with CI's signature over the image, `keys/ci.pub` from GitHub: the key
exists only in the GitHub environment `release`, which admits refs/heads/main only; the router passes it on as the
approval's `imageSig` and can only withhold it; every image CI ever pinned keeps its signature in
`k8s/apps/session-image-sigs.txt`, so a resume on a session's own older image is still a CI build);
machine ids and public keys are signed but not shown.

## iOS app structure: one native app (Deyao, 2026-10-11)

The iPhone and iPad app is one native SwiftUI app (`ios/`), built from Apple's frameworks and our own Swift only: no
React Native, no third-party packages, no extension process. The whole app is therefore trusted code, and a page where
Deyao signs is an ordinary sheet of it; no process boundary is needed to keep its text and taps honest. What makes a
signature safe stays the same:

- **What is signed is rendered from the signed content.** Every review page (New session, an approval, a grant, an
  unlock, a repo key, and the Inbox's "What you sign (exact)") draws its text from the core's signed documents, checked
  against the core key pinned at Reset/Recover, or, for a grant, from the session's core-signed cert. The session a page
  acts on is named from signed content too: an approval from its predecessor's cert, a grant or unlock from the
  session's cert (title and first prompt from a core that vouches, its line, machine and sensitivity); the router's
  label shows only as unverified. The app remembers each session id's line and refuses a cert naming another.
- **Face ID for every signature**: the phone's two Secure Enclave keys are bound to the faces enrolled now
  (`.biometryCurrentSet`) and made fresh at every Reset/Recover; a long-lived device key (Face ID or passcode) countersigns
  claims and wipes, so the setup session can tell this iPhone's claims from the router's.
- **Nothing the router says decides what is signed**: the stores a harness brings are pinned in the app from git
  (`policy/stores.json`); Start refuses a store that wasn't picked and isn't the harness's, and a sensitive one it didn't
  pick. The image must carry CI's signature (`keys/ci.pub`).
- **New session is one page** (Deyao, 2026-10-10): prompt, title, stores, harness, repos, permission mode, model and the
  other options; its **Start** signs the session and, under the same Face ID, unlocks every store the session gets that is
  locked, for that session only. An approval made elsewhere (the web page, a restore, a task) and an add-store do the same
  under their one Face ID. A request from elsewhere (a session, the web page, Claude's setup session) waits in the Inbox
  and opens the same review page, with **Allow** (Face ID) and **Deny**.
- **No prose assembled by code** (Deyao, 2026-10-12): the app and the web page show facts as UI, not sentences pieced
  together from fields. A review page is labelled rows and lists (Action, Repo, Store, Session, Until; a store list, a
  Sensitive badge), a status is a short label or badge, an action is a button; no "What is being signed: you allow X to
  Y until Z" paragraphs and no template strings with a field dropped in. Fixed strings stay short (a section title, a
  one-line hint, a button). Prose appears only when an LLM wrote it (a caller's reason, a session's title or summary),
  shown as that author's text. Follow Apple's HIG / standard platform controls (Form, LabeledContent, List, badges).
- **The terminal is a web page**: the router serves it (`/term/{id}`) and the app shows it in a `WKWebView` with its
  Access login; WebKit runs it in its own process. The machine still runs its commands only under a grant, which the
  page asks the app for.
- **Web:** the web page (`app/`) only files requests; approval happens in the app.
- **A session waiting on a locked store says so:** the router notes the core's 423 on the machine's secrets pull
  (`lockedStore`); the session's page and the terminal show "Waiting for store X to be unlocked" with Unlock…, a review
  that unlocks exactly the locked stores of the session's core-signed cert, for that cert only. The machine retries every
  2 s.

## Guarantees

- A key store reaches a machine only through a succession: from null (Deyao's click), or from a killed,
  never-used predecessor (exact match automatically, or with Deyao's click when something changed).
- Plaintext stores exist only in the core's memory: an unlock for one session until that session's machine has
  pulled (at most 30 minutes), a standing unlock until locked, during a Recover for at most 10 minutes, and
  `github-deploy-keys` for the length of one phone-approved deploy-key call. Elsewhere a store's values exist only
  sealed: to a machine's key (its pull), or under the core's carry key, bound to that machine (its carried secrets). The Fly token is the one
  secret the core keeps in memory for its whole life.
- A deploy key is made or deleted only on a phone-approved request; the core uses the GitHub token for nothing else.
- A session's line can't fork: each predecessor is used at most once (succession and burn both consume it).
- A bug or compromise outside the core (router, Jarvis, the box) can block or fail actions, never move a store
  to a machine not approved for it.
- A machine that holds secrets runs only the approved image's own entry point, and takes at its entry points only
  inputs the cert, its predecessor's signature, its own line's signature or a trusted provider vouches for, each
  later input recorded in the core's input log ("Inputs to a machine").

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
- **Viewing the terminal needs no grant** (Deyao, 2026-10-12): the machine pushes its own capture of the harness's
  pane to the router (`/m/screen`, every 2 s when it changed, 30 s heartbeat), as it pushes its status. Nothing goes
  into the machine for it. Typing, resizing and the Escape on a stale prompt stay behind the `terminal` / `status`
  grants; the "switch model?" dialog check reads the pushed pane.
- Grants name the line, which the machine reads from its core-signed cert, so the router can't make one line's
  grant open another line's machine. Request ids are single-use and at most 2 minutes old.
- Re-pairing the phone: running machines trust the old phone key until their line's next cert.
- **Asking for one** (Deyao, 2026-10-10): the app's Grants page (feature; 1–10 minutes or a standing rule until a
  date) or a one-tap button where a feature was turned away builds the whole request; the app's grant review only
  reviews it (Allow with Face ID, or Deny).

## Open

- Where the core's log lives. Plan: AWS CloudWatch Logs (append-only: no API deletes a single event; only a whole stream/group; the core's credential gets append rights only; free tier 5 GB/month covers it), added AFTER the core is running. Until then the log is local to the core.
- The secure pages' exact design (New session one page, review stops: 2026-10-10).
- Free text into high-privilege machines: the first prompt, a resume prompt and the session's own wakeups are vouched
  for ("Inputs to a machine"); wakeups made from the app or web (not by the session) and peer messages from other
  sessions are not delivered to a machine whose cert vouches, until the phone can sign them.
- Shell grants: a standing rule hands a feature (the router) a shell for its length; every exec under one bypasses
  the input log. Narrowing each holder to fixed commands is not done.
- Layer 1 hardening (CI-only builds and deploys) — see `SECURITY.md` PENDING 5–6.
