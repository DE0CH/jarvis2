# Decisions made while building milestone 1 (for Deyao to review)

The design itself is `docs/DESIGN.md` (decided with Deyao, 2026-10-03 → 10-09). These are the choices Claude
made around it; the app's own list is `app/DECISIONS.md`.

## Shape

1. **One Go module per part** (`core/`, `router/`, `machine/`, `e2e/`), no shared code; the machine and the
   tests re-implement the few crypto calls they need in the core's formats.
2. **The router is new code** (~1,200 lines of Go), not Jarvis 1's backend. Not in M1: tasks, schedules,
   wakeups, terminal, transcript search, content stores, repo picker, Discord channels, the Fly budget cap,
   auto-pause on idle.
3. **The session image is Jarvis 1's image (pinned by digest)** with `jarvis2-machine` in front: keys, wait for
   `jarvis2-init`, take the core's key from the Fly config, check the cert, restore the snapshot, pull the secrets,
   then Jarvis 1's unchanged entrypoint. One image serves production and the end-to-end test (it names no master
   key).

## Security-relevant

4. **Session machines reach the router over Fly's private network**, not through Cloudflare: the box is a
   WireGuard peer of org `jarvis2-370` (`fly wireguard create`), run inside the router in userspace
   (wireguard-go + netstack, no privileges); `/m` exists only on that listener. Reason: Jarvis 1's Access apps
   admit any service token of the account, so a token on every machine would have opened Jarvis 1.
5. **The setup session** reaches `/setup/*` through its own Access app and service token `jarvis2-setup`, and
   the router checks the setup key's signature on every call (method, path, time, body; once, within 2 min).
6. **The app signs in by carrying the Access JWT** (`/api/auth/start` → `jarvis2://auth#token=…`, sent as
   `cf-access-token`); the router verifies it too. Access sessions last 30 days.
7. **Pause snapshots sit on the router's volume**, signed by the machine, not encrypted at rest.
8. **The Fly token is narrowed** (`infra/fly-token.sh`): app jarvis2-sessions only, read/write/create/delete/
   control (Fly refuses to create a machine without write), and exec of exactly `/usr/local/bin/jarvis2-init`
   with no arguments. Tested on a real machine: create and destroy allowed, `cat` refused, `jarvis2-init` with an
   argument refused. Write also lets a holder change a running machine's config; the machine then restarts
   without its keys and, with no cert, gets nothing.
9. **The core waits up to 10 min for a machine to start** (the image's first pull on a Fly host is slow) and
   destroys a machine whose init fails.
10. **A CI-only fake Fly** (`go build -tags fakefly`) lets the app's CI run the real core and router.
11. **The app checks a core's identity itself** (Deyao, 2026-10-10: no words to compare): the box key's signature
    over `"jarvis2-core-identity <signingKey> <agreementKey>"` against `keys/box.pub` from GitHub, then the core's own
    signature on its state.
12. **The recovery kit is one password-manager item, the master private key only** (`jarvis2-kit:2:…`, items
    46–55).
13. **Backups:** `stores/<name>.json` (values sealed to the master key, the name as associated data; sensitive
    flag; signed by the setup key) and `sensitive/<name>.json` markers, in the versioned bucket
    `jarvis2-backup-de0ch`. A store is not sensitive after a Recover only if its backup says so and no marker exists.
14. **The box changes only through git:** no SSH (sshd off, a throwaway key so Hetzner mails no root
    password), no k8s API from outside, a Hetzner firewall with no inbound rules. Flux applies as a limited
    identity (admin in the three Jarvis 2 namespaces only). Secrets (tunnel token, WireGuard peer, box key)
    arrive once in user-data; Hetzner keeps serving user-data from the metadata address, which every pod's
    network policy blocks.
15. **The core restarts only when `core/` changes** (CI pins its image separately), because a restart means a
    new, empty core that Deyao sets up again.

## Infra

16. **Box**: Hetzner cx23 (2 vCPU, 4 GB, 40 GB) in fsn1, EUR 6.588/month gross, IPv6-only (DECISIONS 156), in the
    `jarvis2-mock` project (renaming a Hetzner project needs the console).
17. **Fly**: app `jarvis2-sessions` in org `jarvis2-370`, region `lhr`, sizes small/medium/large = 2/4/8 shared
    CPUs with 2/4/8 GB, then every doubling past large, named by its memory (16gb, 32gb, …; DECISIONS 167). The router's budget cap (Jarvis 1's: DM at USD 25, pause all at USD 30) reads the app with a
    read-only Fly token (`infra/fly-read-token.sh`).
18. **Images** on GHCR (public, like the repo), with GitHub build attestations (the phone doesn't check them
    yet).
19. **Repos for a session** are cloned by the machine over SSH with each repo's deploy key from its store (items
    58–66); a repo without one is cloned anonymously over HTTPS.
20. **Harness stores** (`policy/stores.json`, baked into the router image): `claude` brings the store `claude`,
    `opencode` brings `openrouter` + `tunnel`, `openclaw` brings `claude` + `tunnel` (`tunnel` = the confined Access
    service token `jarvis2-tunnel` for the web UI's cf-tunnel agent: a store, not the router's machine env, so the
    router never holds it and it never sits in a Fly machine config; the per-id proof comes over `/m`).
21. **Stores that can reach a code push are sensitive** (Deyao, 2026-10-09). Each repo's push access is its own
    deploy-key store `github-<repo>` (items 58–66): `github-jarvis2` is sensitive (Jarvis 2's own push path),
    every other repo's store isn't unless Deyao picks it so (he asked for non-sensitive repo stores). claude-env
    holds no Jarvis 2 code or design.
22. **The Claude login is shared with Jarvis 1** (Deyao, 2026-10-09). The store `claude` holds an Access service
    token (`jarvis2-claude-credentials`, keys `JARVIS1_CREDENTIALS_ID/SECRET`) that Jarvis 1's Worker lets
    reach only `GET/POST jarvis.deyaochen.com/api/credentials`; tested: 403 on any other path and on session
    hosts. The machine takes the pair at boot and every 30 s pushes its own refreshed copy and takes Jarvis 1's
    when that expires later (`machine/claudelogin.go`). Holding the store gives the Claude login and nothing
    else in Jarvis 1. Not sensitive.
23. **Jarvis 1 stays a push path into jarvis2** (Deyao, 2026-10-09, "leave it"): Jarvis 1's `default` store holds
    the account-wide GitHub token, so whoever can start a Jarvis 1 session can push Jarvis 2's code.
24. **Grants** (Deyao, 2026-10-09; DESIGN "Grants"): router features get a shell in a session through a phone
    grant (≤ 10 min), a standing rule, or the session's own allow list; the machine checks them against its
    core-signed cert. Holders are per feature. Shell is arbitrary (as Fly exec was in Jarvis 1). A session with a
    sensitive store accepts only a phone grant.
25. **The router's secrets live in git, SOPS-encrypted to the box's age key** (`k8s/secrets`, `infra/router-secrets.py`):
    lobster's token, the Storage Box keys, a read-only Fly token, a GitHub token that only lists repos, and the
    Jarvis 1 tokens the cf-tunnel Worker confines (`CONFINED_TOKENS`): `jarvis2-claude-credentials`,
    `jarvis2-services` (credentials, search, iCloud, usage), `jarvis2-tunnel` (Jarvis 2 tunnel agents, per-id proof).
26. **Discord**: lobster (shared with Jarvis 1, Deyao's answer), channels under a "Jarvis 2" category.
27. **Archives** go to the Storage Box in Jarvis 1's layout (`claude-records/<date> <title>/`), so Jarvis 1's
    transcript search indexes them, with the machine-signed snapshot and its cert chain under `jarvis2/`; Jarvis 2's
    own index is `.index/jarvis2-destroyed-sessions.json`.
28. **Restore of a destroyed session** is a new line (phone approval) whose first machine restores the archived
    snapshot after checking it against the old core-signed cert. Which snapshot is the router's choice, not
    signed; the router already holds every snapshot, so a wrong choice exposes nothing new.
29. **Tasks are one-shot sessions** (Deyao, 2026-10-09): a task is a session line approved once; each run resumes
    it (approve_by_dead_machine, no phone), runs, and pauses again. Its secrets come from stores.
30. **Only raising to bypass needs the phone** (Deyao, 2026-10-09): permission mode is a signed option (a resume
    that changes it needs the phone), and switching a running session to bypass needs a fresh phone grant. Size,
    model, one-shot, auto-pause and the API proxy stay unsigned.
31. **Env patches on restart** are allowed for non-secret-looking names only (a name filter, not a guarantee).
    **Rollback** is the router's unsigned word, applied by the new machine after it verified the snapshot.


## Tasks (2026-10-09)

32. **A task's code is fixed by its cert** (building on 29): the instance's line has harness `task:<template>` (the
    core signs the harness string as it is), and the template is baked into the session image (`/opt/jarvis2/tasks`),
    whose digest the cert pins. The machine runs that template instead of a harness. So the router can't change what
    runs (cloning templates at run time would have let it, through the unsigned repo list), and a changed template
    reaches an existing task only through `run {upgrade: true}`, which the phone approves.
33. **Script mode, no delivery**: a run is a resume whose machine runs the script by itself at boot and reports to
    `/m/task-result`; nothing is delivered into a harness and no holder needs a grant. A line holding a sensitive store
    therefore runs unattended like any other: the rule "a sensitive session accepts only a phone grant" guards the
    router's shell, and here no router-chosen command runs. Prompt templates (`prompt.md`) are the same with
    `claude -p` as the script. What still needs Deyao: the line's stores must be unlocked in the core when it runs
    (a locked store fails the run after 30 min, with a DM for a scheduled one).
34. **Task parameters are unsigned, non-secret env** (`TASK_PARAMS`, `PARAM_<FIELD>`): the router could change them, so
    scripts treat them as data; the script's env is built by the machine (no router `LD_PRELOAD`, `BASH_ENV` …) with
    the store values last. Secrets only in stores; Jarvis 1's hidden values are refused. A picked store joins the line
    at creation; changing it needs a new task (a new approval).
35. **Task schedules are the router's own daily tick**, not the scheduler's crons: a cron delivers a prompt through the
    `scheduler` grant, which a script line has no harness for and a sensitive line refuses. Same shape and rules as
    Jarvis 1 (HH:MM in a zone, `since`, 2 h grace), one firing per slot.
36. **One machine per task at a time**: runs queue (at most 3) and start when the line is paused; the router pauses the
    line once the machine reports, after 15 min on a started line with no run, or 15 min past the timeout with no
    result. Results (log tail, output, exit code) live in the router (`<data>/task-runs/`, 20 per task); the run's log
    also sits in `~/artifacts/task-runs`, archived with the line. Store values are redacted on the machine.
37. **Task lines have no Discord channel and skip the autopilot** (no harness to watch: no "dead" DMs, no auto-pause);
    failure DMs follow Jarvis 1 (scheduled runs only).

## Parity, 2026-10-10

38. **Live transcript sync needs no grant: the machine pushes, the router writes.** Each machine sends its changed
    transcripts to `POST /m/live-transcript` every 5 minutes and the router PUTs them to `claude-records/.live/<session
    id>/` with its own Storage Box credentials (Jarvis 1's layout, so Jarvis 1's search indexes them). No holder runs a
    command in the session, so the grant rules don't come into it, a sensitive session included: the router already
    receives the same transcripts in every pause snapshot (and archives them on destroy), so this moves nothing new to
    anyone; the Storage Box credentials stay on the router (writing is the router's, never a machine's). The copy stays
    while a session is paused (Jarvis 1's search then shows it as "running" until the next resume or the destroy) and
    goes on destroy. The router keeps no copy itself.
39. **The Claude app's title is read by the machine, with its own Claude login**, not by the router: the router holds
    no Claude token (Jarvis 1's box did), and the machine already holds the session's. It sends only the title with its
    status report. As in Jarvis 1 it beats every other name (a rename in the Claude app wins over the label), it is
    kept while paused, and a resume without a label passes it as `SESSION_RESUME_TITLE`. Jarvis 1's "rename the new
    Remote Control entry back after a Start" (`keepAppTitle`, a PUT with the token) isn't ported: the title passed at
    launch covers the common case.
40. **One-shot sessions are destroyed with force** (Jarvis 1's finishOneShot): a failed archive no longer leaves them
    paused; the repos' state comes from the final snapshot (the machine records it just before tarring), so no `archive`
    grant is needed; Deyao gets a DM only when work was lost (dirty repos, an unchecked state, a failed archive).
41. **Indexing an archive by hand** (`POST /api/records`, Jarvis 1's) puts a folder already on the Storage Box on the
    Previous list (tail, Remove, Delete). It can't be restored in Jarvis 2: restore trusts only a machine-signed
    snapshot with its core-signed cert, which such a folder doesn't have.
42. **Search and the iCloud index were forwarded to Jarvis 1** until they moved to the Jarvis 2 box (2026-10-13, entries
    106-111).
43. **When the core can't be reached the router answers 503 `{coreDown}`** (it said 502 "core unreachable"): while
    its pod restarts (after a wipe) that is the normal state, and the app waits or shows it as a plain note.
44. **Lease pills**: superseded by 113 (leases are the router's own and listed in `/api/state`).
45. **A new line's challenge carries a random salt** (`Request.salt`, core.go Succession): the nonce is the request's
    MAC and an approval nonce is used once, so two new sessions with the same stores, harness, mode and image used to
    get the same nonce and the second failed with "this approval was already used". Fixed before the first recovery
    (a core change restarts the core). Successors don't need it: each predecessor is succeeded once.

## Reset and Recover, 2026-10-10

Deyao: "There are two paths, one is reset/make new, and the other is recover, an ai shouldnt be involved in either
path." His four answers: an empty core takes the master public key from the logged-in app; the router holds the
backup bucket's read credential and the kit is just the master key; no words to compare; Reset starts with empty
stores, filled later by normal writes.

46. **A core starts empty and is claimed once** (`claim`): a statement naming a master public key, the core and
    the phone, signed by that master key, with a bundle sealed to the core (none for Reset, the backups for
    Recover). One primitive serves both paths. The core keeps that master key for its life and shows it in its
    signed state. **Trade-off:** an empty core takes the first valid claim. The router admits claims only from the
    app's device login (Deyao's Access login, carried as `cf-access-token`, which no browser tab sends), and the
    app refuses a core set up with another master key; such a core can hold none of Deyao's stores (the backups
    are sealed to his master key, and every approval needs his phone), and a restart from git empties it.
47. **A set-up core ends only with its own master key** (`wipe`, the safe default asked for): the core answers,
    then exits, and Kubernetes starts a new, empty core: the same as an infra restart, with no partial wipe to get
    wrong (the used/killed sets, certs and unlocks all go with the process). Reset and Recover on a set-up core
    both ask for its kit first. Not chosen: letting the phone pinned at the claim end the core without the kit
    (that would make a Reset possible from the phone alone; change: accept the claim's phone key in `Wipe`).
    Without the kit, the `jarvis2/restart` annotation in `k8s/apps/core.yaml` empties the core (a commit).
48. **Machines trust the core that creates them**: the core puts its signing key in the machine's Fly config
    (`JARVIS2_CORE_KEY`, overriding anything the router sends), and the machine checks every cert against it.
    Only the core's narrowed token and the setup session's org token can create or change machines in the app;
    the router's is read-only. This replaces the master key built into the image and the master-signed core cert
    the machine used to check, so there is one session image (no test image) and no master key in git or
    `core.yaml`.
49. **The Fly token**: the Fly app is a constant in the core (`FlyApp`), so a token can only ever act on Deyao's
    app; it comes in a Recover bundle (the `core` store's `FLY_API_TOKEN`) or sealed to the core by the setup
    session (`/setup/fly-token`, `setup.py backup-core`, which also writes the backup). The core's
    `set_fly_token` is open, like `write_store`: a wrong token (even the router's read-only one) can only make
    starts fail, which the router can do anyway.
50. **The router serves the backups** (`GET /api/backups`) with its own read credential (`jarvis2-backup-read`, a
    second SOPS Secret `router-secrets-backup`, so it can be set without re-entering the other router secrets).
    **Trade-off:** the router can withhold a backup or serve an older signed version (the bucket is versioned).
    It can't read, change or forge one. The one effect beyond a stale or missing store: dropping a
    `sensitive/<name>` marker (or serving a store's backup from before it was marked) brings that store back not
    sensitive. Accepted as Deyao chose this split; the app's Stores page shows each store's sensitivity, and
    marking one again is one tap.
51. **The kit is `jarvis2-kit:2:<master private key, base64 PKCS#8 DER>`**; a version-1 kit is refused with "This
    recovery kit is from an older Jarvis 2 and doesn't work any more." The master private key lives only in the
    setup page's memory: Reset shows the kit first and claims only on "I've saved it" (a failed claim keeps the
    same kit for a retry; leaving the page before claiming means nothing was claimed, and the next Reset shows a
    new kit). A pasted kit is forgotten when the page goes or after 10 minutes; Copy puts the kit on this device's
    clipboard only, for 2 minutes.
52. **What the app pins**: at the claim, the core's keys and its own master public key (Keychain, this device only).
    The page names the core's state from the signed state: empty, set up on this iPhone, set up with this kit for
    another iPhone (e.g. after a reinstall), or set up with a different kit. A core set up here but never pinned
    (the app ended between the claim and the pin) is pinned on the next visit.
53. **The setup session needs a set-up core**: `infra/setup.py` learns the master public key and the phone's keys
    from the core's signed state (box key first) and writes nothing to an empty core; `infra/fill-stores.sh` fills
    every store after a Reset (core and backup, tokens minted or rotated). `setup.py recovery-keys`,
    `/setup|/api/recovery-keys`, the sealed blob and `keys/master.pub` are gone; the blob an earlier router kept
    on its volume (`recovery-keys.json`) is unread.
54. **The earlier build's held master key is deleted** from the iPhone's Keychain at launch (it went into the
    version-1 kit; no core trusts it).
55. **Settings has one entry**: "Jarvis 2" (running or not) with "Reset or recover…"; the core's keys are no longer
    shown. The app opens the page by itself when it isn't set up from this iPhone or the core has changed.
56. **This change restarted the production core** (a `core/` change): it held no stores, and it is now empty, waiting
    for Reset. The backups sealed to the previous master key stay in the versioned bucket; the next
    `fill-stores.sh` re-mints or rotates every Jarvis 2 token in them. A new read credential `jarvis2-backup-read`
    is in the router's secrets (both bucket policies moved to it, the permission test passed, the previous one
    deleted in the Console, no local copy kept).
57. **The setup session is fully trusted** (Deyao, 2026-10-10: "I don't really care what the setup person can do"). It
    holds every key's plaintext, so it can put any key in any store, and its signed backups set each store's
    sensitivity at the next Recover. Sensitivity protects against sessions and the router, not against it.

## Deploy keys, 2026-10-10

Deyao: "i want each github git (e.g. claude-env or china-train) to be associated with a non sensitive key store that
contains a github key that can read and push to the repo. It should be minted automatically (without using ai) when
i add the repo in setting page." His answers: phone-approved (Face ID; the box alone can never make a key) and a
deploy key (SSH, one repo, read + push, no expiry, through GitHub's API). Then: "Should belong in its own [store],
shouldnt unlock the whole infra [store] for that one task."

58. **The minting token has a store of its own**: `github-deploy-keys`, sensitive, key `GITHUB_DEPLOY_KEYS_TOKEN` = the
    fine-grained PAT `jarvis2-deploy-keys` on DE0CH: **all repositories** (so a new repo works), **Repository
    permission "Administration: read and write" and nothing else** (Metadata read comes with every token), no
    expiry. Deploy keys need Administration (GitHub has no narrower permission); it also lets the token change a repo's
    settings, collaborators, branch protection, and delete repos, but it can't read or write contents or refs (tested:
    contents write and ref create 403, keys list/add/delete 200/201/204, on a repo made after the token). A deploy
    key on jarvis2 is a push path, hence sensitive. The add/remove flow opens only this store, never `infra`.
    Minted by `infra/fill-stores.sh` (claude-env's `github-web pat-create-all jarvis2-deploy-keys … Administration=write`).
59. **Core primitives `deploy_key_begin` / `deploy_key_finish`** (core/deploykeys.go, DESIGN "Deploy keys"): the
    begin document (repo, store, sensitivity, add/remove, replaces, the key's title, the token store's E, a one-off T)
    is signed; the phone signs that document and sends its share of the token store under ONE Face ID (one LAContext
    for both Enclave keys). The core checks the signature, opens the token store for this call only (it never joins
    the unlocked set; the plaintext leaves with the call), talks to GitHub at the fixed host api.github.com, and
    writes or deletes the repo's store itself (the app's blob, wrapped to P + K; item 93). Both proofs, not just the
    share: the share binds the request too (it is sealed to the pending's T), but the signature is what makes the
    approval explicit and checkable.
60. **The repo's store**: `github-<name>` for DE0CH's repos, `github-<owner>-<name>` otherwise (lower case,
    `[a-z0-9-]`); contents `GITHUB_DEPLOY_REPO_<SLUG>` = `owner/name` and `GITHUB_DEPLOY_KEY_<SLUG>` = base64 of the
    OpenSSH private key file (ed25519, made by the app since R2, item 93; checked against `ssh-keygen` in the tests).
    Not sensitive unless picked on the secure page; **`DE0CH/jarvis2` is always sensitive** (the app asks for it and
    refuses a begin that isn't, since R2; the router can't lower it), and a store that is sensitive stays so on a re-add.
61. **Re-adding a repo rotates its key**: the core deletes every key titled `jarvis2 <store>` on that repo, adds the
    new one and replaces the store (the begin document says "replaces"; any unlocked plaintext of the old key is
    dropped). Keys with other titles are never touched. Remove deletes the titled keys and the store.
62. **No backups of repo stores**: the core has no way to write a backup (the router reads the bucket only). After a
    Recover the repo list says "No key" for each and **Make key** (one Face ID) makes a new one. Change: a core-signed
    backup the app checks on Recover.
63. **The repo list is the router's, but follows the core**: an entry appears only from the core's `deploy-key-added`
    answer and goes with `deploy-key-removed`; GitHub repos only (Jarvis 1's "any git URL" is gone, and an older
    non-GitHub entry is left off the list). Removing needs Face ID too, since it deletes the key on GitHub.
64. **Sessions get the repo by SSH, set up by the machine** (machine/deploykeys.go): each key in
    `~/.ssh/jarvis2-deploy/`, a host alias `github.com-jarvis2-<slug>` with that key only (`IdentitiesOnly`) and
    GitHub's published host keys pinned (`StrictHostKeyChecking`, its own known_hosts), and git `insteadOf` rewrites of
    the repo's `.git` URLs (https, `git@`, `ssh://`; as stored and lower case) to the alias. Only the `.git` forms:
    a rewrite is a prefix match, so `…/claude-env` would also catch `…/claude-env-x`. Rewritten whole at boot and after
    add-store / downgrade. No `GITHUB_TOKEN` is used for cloning any more (a plain `GITHUB_TOKEN` in a store is just an
    env var).
65. **New session pre-selects a picked repo's store** when it isn't sensitive; a sensitive one (github-jarvis2) is
    ticked on the secure page, as every sensitive store. The web page adds a picked repo's store either way and marks a
    sensitive one (164).
66. **The production core is held, not restarted** (`jarvis2/core-pin: hold` on the core Deployment; `images.yml` builds
    the core image but doesn't pin it while the annotation is there). A restart would empty the core and only Deyao's
    Recover brings the stores back, so the deploy-key core waits for his go: remove the annotation (a commit), run the
    `images` workflow (it pins the core), Flux restarts it, Deyao recovers, then adds claude-env and jarvis2 in Settings → Repos.
    Until then the router and app ship (the router answers 501 "the running core predates deploy keys") and sessions
    have no push access to any repo: the old per-repo PATs (`jarvis2-sessions-*-push`) are deleted and their store
    backups removed (delete markers; the versions stay in the versioned bucket).
67. **Requests (the Inbox), Claude's choices** (Deyao, 2026-10-11 asked for the Inbox and the three fields; the rest is
    Claude's): a request, and an approval shown in the Inbox, goes after **10 minutes** (Deyao, 2026-10-12; an expired
    approval is rejected like a Deny, and the caller asks again), at most **20
    pending per caller** (a looping session can't flood the Inbox), and the same kind + arguments pending already
    answer that request instead of a second one (the first reason is kept). **A session may ask only for itself**
    (a grant, an unlock, a store) **and for a repo to be added** — harmless: the key goes into a new store of its own,
    which no session holds until Deyao picks it in New session; it may not ask to remove a repo or for anything about
    another session. The web page, the app and the setup session may ask for any kind. A reason is **required** from a
    session and from the setup session, optional from Deyao's own web page. **Who called** is the router's word, from
    the credential (machine key, setup key, Access login; the app vs. the web page by the device token header) — the
    router is the one recording it, so it is shown as "Requested via (router)", below what is signed. The setup
    session gets `GET /setup/repos` (the router's repo list) so it checks before asking for a repo. Unlock requests
    name a session (the stores it waits on), as the shell's unlock page does; no "unlock store X" with no session.
68. **Store key names come from the router's own record, not the core** (Deyao, 2026-10-11: "the names of the keys
    should be visible through the api"; names from data we own, behind TLS and the push path, are trustworthy
    enough, no core assertion needed). The core can't name a locked store's keys, so the router keeps
    `store-keys.json` in its data volume, written only by the setup session's signed `POST /setup/store-keys` (every
    `infra/setup.py write` sends it; `infra/store-keys.sh` fills it from the layout file after a new box). A repo store's
    two names follow from the repo. The store list itself stays the core's signed list (passed on as `signed`, and
    checked by `jarvis2 stores`), and a store whose names were never recorded shows `keys: null`, never a guess.
    Every session sees every store's names (not only its own), since that is what it needs to pick one to add.

## Carried secrets, 2026-10-11

Deyao: "after a session is started, there's no reason to keep the store unlocked in the core. So just lock it then";
for unattended resumes he chose "the session carries its secrets" (DESIGN "Carried secrets").

69. **The carry key is the running core's own, made at start, never backed up; a new core destroys the earlier
    core's sessions** (Deyao, 2026-10-11: "They are just automatically destroyed. Core restart is infrequent enough.
    No need to engineer around it."). The router notices a new core identity (its key signing its own state) and
    destroys each session that had a line once it is paused (archive kept in Previous; blob, snapshots, machine and
    channel gone); the first identity a router sees is taken as the sessions' own core. A destroy whose archive
    fails is tried again 10 minutes later.
70. **Unlocks name what they are for** (`for` = a challenge or cert nonce), signed into the begin document; the core
    locks them at that cert's first pull that goes through, and an unused one lapses after **30 min** (the machine
    retries a locked pull for 10). **Standing unlocks stay** for the Stores page (open until locked); the store
    list's `unlocked` means standing only, so the app never skips a store that is open only for another session.
    Change: drop standing unlocks altogether (the Stores page would only lock).
71. **The core seals the blob at every pull, not at pause.** The machine doesn't take part (no machine or image
    change), the blob is authentic by construction (AES-GCM under the core's key), and a pause, a crash or a lost
    snapshot leaves the last pull's blob. The router keeps it with the snapshot on its volume and forwards it right
    after certify, an add-store and a downgrade.
72. **Sensitive stores are carried too.** An unattended resume is what approve_by_dead_machine already certifies (same
    stores, image, options); before, it only needed the store left unlocked. Change: leave sensitive stores out of
    the blob, so a sensitive session's resume waits for an Unlock… each time.
73. **A resume gets the values its line last pulled**; an unlock open to the cert wins (fresh values). A store
    written since reaches it only with a new unlock, which the router asks the phone for (163).
74. **Approvals made outside the app also unlock under their one Face ID** (the web page's new session, a restore, a
    task's first line, an add-store), for that session only, as New session does; a resume on a new image or mode
    unlocks nothing (it carries its secrets). With a core that predates scoped unlocks (the held core) these pages
    unlock nothing, as before, and New session's Start unlocks as before (standing).

## Inputs to a machine, 2026-10-11

Deyao asked whether a certified session's machine could be made to run another image, another entry point, or
take state other than its certified transcript; then set the rule (DESIGN "Inputs to a machine"): the image pulls
its options and data and checks them against the cert; every input at an entry point is vouched for by the cert,
the predecessor's signature, the line's own signature or a trusted provider; router-only data reaches nothing
except strict-format values; every later input is attested by the core into a hash-chained log; the guard covers
entry points only ("if I decide to break it later then it's fine").

75. **The core sets the machine's whole env** (its key, and `JARVIS2_URL` from the core's own `MACHINE_URL`, with no
    default: a core without it starts no machine, so a test core can never make a machine that reaches production's
    router — an e2e run on the first version, which defaulted to production, made one, 08010e6c7e6138, 06:47 UTC);
    `start`'s `env` is ignored. Production's `MACHINE_URL` goes into `k8s/apps/core.yaml` with the release (a change
    to the core's template restarts it, so not before). The machine also re-execs with a clean env at boot, so it
    holds with the held core too. Change: the URL baked into the image instead.
76. **Settings travel as one opaque JSON string (`Options.Config`)**, not core fields: the core stays trivial (it
    compares it for an unattended resume, never reads it); the machine reads it strictly (an unknown key refuses
    the cert) and the shell refuses a key it can't show. One-time inputs (`Options.Once`: a resume prompt, a
    rollback) are a second string the dead-machine approval requires empty and ignores in the predecessor.
77. **The first prompt, attachments and a restore live in the line's config** and are used only by its first machine
    (a successor never re-sends them); the title, model, repos, one-shot, API proxy and task parameters hold for the
    line. A rename later doesn't reach the machine; the resumed title comes from the transcript (signed), not the
    app's title (`SESSION_RESUME_TITLE` dropped).
78. **Attachments are vouched by sha256 + size in the config**, computed by the router when the session is made; the
    phone shows names and hash prefixes. The shell doesn't hash the files itself (it never holds them), so this
    binds what the phone approved, not what Deyao uploaded. Change: the shell fetches and hashes them.
79. **Env settings (`/api/sessions/:id/env`) no longer reach a machine whose cert vouches**: arbitrary names are
    exactly the hole (`LD_PRELOAD`, `ANTHROPIC_BASE_URL`, …). The router still stores and sends them (an old image on
    the held core uses them); the new machine drops them.
80. **The snapshot hash comes from the kill**: the router passes the machine's signed snapshot claim with `kill`; the
    core checks it against the machine's current key (updated on a downgrade) and keeps the first one. A kill without
    a valid claim = the successor starts with no predecessor state (withholding was always possible; swapping in an
    older snapshot of the same machine is not).
81. **Wakeups and crons are the session's own signed request** (c), delivered by the machine itself (inbox socket or
    harness-send) with the core's attestation; the line's signing keys travel in the snapshot. A machine whose cert
    vouches no longer puts the scheduler on its allow list when it arms one. Wakeups made from the app/web, the
    router's free-text `Deliver`, and peer messages from other sessions are refused for such a machine (nothing
    vouches for them). Change: phone-signed wakeups from the app.
82. **The watchdog nudge and "continue" are texts built into the image**; the router sends only the kind and two
    numbers. Delivering one to a sensitive line needs no grant now (it carries nothing chosen by the router).
83. **The input log is persisted by the router** (`DATA_DIR/input-log.jsonl`, `GET /api/input-log`) from the core's
    answers (R2: the core keeps only head and length). The router can drop entries from its copy; it can't forge or
    reorder them (core-signed, hash-chained). Change: CloudWatch (DESIGN "Open").
84. **Images are pinned by the linux/amd64 manifest digest** (what Fly reports; the index digest `docker push` prints
    never matches): `infra/image-digest.sh`, run by `images.yml` when it pins `router.yaml`. The core refuses any other
    repository and any unpinned reference.
85. **Repos of a cert whose config names none = the deploy-key stores in the cert** (their `GITHUB_DEPLOY_REPO_*`
    value), never the router's list.
86. **The OpenClaw runtime bundle is pinned by sha256** in the image (`session-image/openclaw-runtime.json`), and
    Jarvis 1's `restore-snapshot` is a no-op in the Jarvis 2 image.
87. **A pause right after a start waits up to 90 s for the machine to finish booting** when it already has its
    secrets (it is seconds from booted): its successor's cert names only the snapshot this machine signs, so a kill
    mid-boot would leave the line with no state at all. A machine still waiting on a locked store isn't waited for.
88. **Orphan machines are destroyed through the core's existing kill** (Machines tab, 2026-10-11): the kill already takes
    any machine of the app, so no core change or restart; the router offers it only for a machine it never started, with
    no session mapping or cert, at least 15 minutes old. No separate destroy token for the router (one more credential
    that could destroy session machines). A machine is "test" when its JARVIS2_URL host isn't `jarvis2-box._peer.internal`.
89. **A session logs into Claude by itself** (Deyao, 2026-10-11: no grant, no Face ID). Decision 22's boot step was
    written (`machine/claudelogin.go`) but never called for sessions, so every session's first login was the
    router's `login` exec — which a vouching machine refuses without a grant: after the core release every new
    session asked for "login repair". Now boot takes Jarvis 1's pair over the `claude` store's confined token
    before the harness starts (a pair already here that expires later, a resume's, is kept), passes Jarvis 1's
    account record as `CLAUDE_ACCOUNT`, and runs `credsSync` as its own process for the machine's life. Trusted
    provider path (DESIGN "Inputs to a machine" (d)), not router input. The router writes nothing into a session
    holding `claude` (no grant asked for); it falls back to the old write only when such a session stays behind
    Jarvis 1 for 5 minutes (a machine from before this), and a stuck one gets "continue" once its own pair is in
    step. The store may name another endpoint (`JARVIS1_CREDENTIALS_URL`, https only): the end-to-end test's
    stand-in, a fake pair in `e2e/testdata`.
90. **A phone grant clears the refusal back-off** (2026-10-11): the loop backed off 10 minutes after a refusal and
    a saved grant didn't reset it, so a 10-minute grant usually ran out before the next try and the "Allow" button
    looked dead. `AddGrant` now clears `needsGrant` and the back-off for that holder; the next tick (30 s) uses it.
91. **A repo's store belongs to one repo** (2026-10-11, decided while Deyao was away): store names collide
    (`DE0CH/foo-bar` and `foo/bar` both make `github-foo-bar`; `my.repo`, `my_repo`, `My-Repo` all make
    `github-my-repo`), and a second repo's add used to replace the first's store silently, orphaning its key on
    GitHub. The core knows each deploy-key store's owner without new kept state: the add that wrote it, or, on a
    Recover, the store's own `GITHUB_DEPLOY_REPO_*` value. begin and finish refuse another repo with 409 "store
    github-x belongs to owner/name"; the owner (any case) re-adds and removes as before. An add that loses a race to
    a colliding add while GitHub is called takes its new key back off GitHub.
92. **R1 audit fixes outside the app** (2026-10-11, decided while Deyao was away; ~/artifacts/away/audit/r1rest.json).
    Each finding re-checked on main, fixed at the cause, with a test that attempts the forbidden thing:
    - *A machine's newest cert* (core, HELD): the core keeps, per certified machine, its newest cert nonce (it replaces
      the `certified` set, so no new structure). Succession, approve_by_dead_machine, certify, pull and the carry rebinding
      take only the newest; an add-store or downgrade answer needs the challenge to continue the newest and then
      supersedes it, so a saved challenge answered again gets nothing. Carry blobs name their cert; one opens only for
      that cert or the cert that directly continues it (`Cert.PredCert`). Smallest state that makes "dropped stores
      leave" true: without it any older cert of a killed machine resumes.
    - *Sensitivity and the writer* (core HELD + setup.py live): create/write refused on an empty core, the claim sets
      the non-sensitive set to exactly the bundle's, an empty store goes into no session; the writer (setup.py) keeps
      its own list of not-sensitive stores (`NOT_SENSITIVE`, a visible commit) and marks any other store sensitive before
      writing when the core says otherwise. Not a writer-signed create_store: that needs the core to know the writer key.
    - *Who the core belongs to* (setup.py + router live; app sends it): pins in the bucket (`pins.json`, setup-signed)
      plus the app's long-lived device key countersigning its claim (named inside the master-signed statement, so the
      router can't swap its own in). The production master was pinned on first use (`pin-master`, 2026-10-11): that core
      holds every store from the backups, which only the kit opens.
    - *Writer of a store blob* (core HELD + setup.py live; app checks): `unlock_begin`/`deploy_key_begin` carry the
      writer (setup key signature over name, E, data sha256, or "core"); the phone refuses a missing/bad one once the
      core's store list says `writers: true`. The core can't check it (it holds no writer key) and doesn't need to.
      The machine also writes only env-name keys into `~/.secrets`.
    - *github-deploy-keys* (core HELD + router live): never in a succession, never unlocked, never created not sensitive.
    - *Downgrade* (machine live): the old key signs only a challenge keeping exactly the asked stores.
    - *Snapshot rollback* (machine live, no core state): the machine signs one snapshot in its life, after stopping the
      session (SIGSTOP of every process it may signal), and repeats that one. Chosen over a core sequence number (new
      core state per machine) — the router asks for a snapshot only to pause or destroy.
    - *Wakeup/cron replay* (machine live): a delivered record per signed request in the snapshot.
    - *GitHub* (live): ruleset on main (admins + deploy keys only); environment `release` (main only) with ASC_*, the CI
      image key and the pin job's deploy key; images.yml pins only commits on main and pins router/session/core by
      digest; the phone's image check is CI's signature (`keys/ci.pub`), not a Sigstore bundle (no Sigstore verifier in
      the shell; the key's secrecy rests on GitHub's environment rules, a provider contract). Probed: a branch workflow's
      push to main is refused (GH013) and its job can't enter `release`.
    - *Metadata* (live for cloudflared; next box for the rest): edge NetworkPolicy; a raw-table drop in cloud-init. No
      NetworkPolicy for flux-system/kube-system: a mistake there would cut the box's only change path (git), so the
      host-level drop on the next box covers them.
    - *The core's tag* stays mutable until the core's next release (pinning its digest now would restart it).

93. **R2: the core as small and as stateless as it can be** (2026-10-11, decided while Deyao was away;
    ~/artifacts/away/audit/r2.json, 18 findings). R1 stays: every refusal R1 needs is still the core's, tested in
    core/r1_test.go and the rest.
    - *Fly*: the core makes single calls (create; init = one look at the state and one jarvis2-init; kill = one destroy
      and one look); the router waits, retries and kills a machine that never comes up. The core keeps the image a
      created machine was asked for and each live machine's current signing key; everything else is in its signed
      `started` document, which certify takes. A size that isn't one of the ladder's (small, medium, large, 16gb, 32gb, …) is refused, not defaulted.
    - *Logs*: no free-text log; the input log leaves in the answers (attest's; beside each cert) and the router keeps it.
      The core keeps head and length. A new core starts its chain at seq 0 instead of `chain_from` (the router's file
      shows the seam; the router's word either way).
    - *One route per fact*: no `/key` (use `/identity`), no `/core-cert` (the router keeps the claim it relayed), no
      `/carry/forward` (certify and the add-store/downgrade answers rebind the carry beside the cert). One map for
      killed machines and their snapshots.
    - *No defaults or compatibility markers in the core*: succession refuses a missing harness, a mode outside auto/bypass,
      unsorted stores, and a new line without the caller's salt (the router fills them in); no `scopedUnlocks`, no
      `vouch: 2`, no `request.sensitive` (the app reads sensitivity from the signed store list), no StartRequest.Env.
      The machine's pre-vouch path (legacy.go) is gone: every core in use vouches.
    - *Keys the app makes*: the app makes a deploy key's pair and wraps its store, and brings a Recover's stores already
      wrapped, so the core never sees those plaintexts. CryptoKit can't add points, so the core gives the store key P + K
      signed (`store_key`). The core's older forms (it made the pair; the plaintext Recover bundle) are gone now that
      the app has moved: a begin without the app's store, title and key pair is 400, and so is a bundle that isn't
      "blobs". GitHub's refusal is the core's status and words; the router adds the hint.
    - *Kept*: the scoped-unlock TTL sweep (finding 8: moving the check into openFor alone would keep lapsed plaintext in
      memory longer, the opposite of stateless); the three-size table (refusing unknown sizes, no default) rather than a
      guest spec from the router with a bound. (The always-sensitive DE0CH/jarvis2 check left the core once the app's
      own check shipped: Checks.deployKeyBegin.)
    - *Router compatibility*: while the running (held) core is the one from before R2, the router still reads its
      `/input-log`, its `/core-cert`, its `/carry/forward`, and its waiting `/start` and `/kill`. These fallbacks go
      when that core is released.

## Image attachments on New session, 2026-10-12

Deyao asked for images attached with the first prompt on New session (app and web), reaching the machine as vouched
inputs under the input guard. The router's uploads and the config's `attachments` (77, 78) already existed; these
fill the gaps (decided while Deyao was away, ~/artifacts/away/decisions.md).

94. **Each attachment is in the input log**: the machine's listing (`GET /m/attachments`) carries the core's attestation
    of each file as it is on the volume (`/attest` machine, input `attachment`, origin `cert`; every core in use has
    `/attest`), and the machine takes a file only when its bytes hash to the cert's sha256 + size AND the attestation
    names that hash, this machine and `attachment` (machine/attachments.go). One file failing refuses them all and the
    session starts without them (as before). A swapped file is attested under its own hash, so the swap shows in the log.
95. **The web page takes images only** (PNG, JPEG, GIF, WebP, as they are: no conversion in the browser), from a file
    picker or pasted into the page, up to 20 per session, 25 MB each (the router's limits). It uploads them, then files
    the request; the phone approves it in the Inbox.

## The hk-news-stream PoC, 2026-10-12

96. *(Removed 2026-10-15: Deyao ended the proof of concept; its manifest, Secret, tunnel route, Access app and DNS
    record are gone.)*

## Image attachments in the app, 2026-10-12

97. **The phone hashes the bytes, not only the names** (replaces 78's "binds what the phone approved, not what Deyao
    uploaded"): the app's New session uploads each image, hashes it itself and Start refuses unless the signed config's
    `attachments` are exactly those files (the router's safe name, sha256, size, in order). The approval page (a session
    made on the web) reads each staged file back (`GET /api/sessions/:id/attachments/:name`) and shows its thumbnail
    only when the bytes hash to the signed value. Photos and camera shots go as JPEG (quality 0.85, longest side at most
    4096 px; HEIC never leaves the phone); PNG, JPEG, GIF and WebP from Files or the clipboard go as they are; any other
    image type is made a JPEG (app/DECISIONS.md 47-49).

## Read-only terminal without a grant, 2026-10-12

Deyao asked for a read-only terminal that needs no grant. The machine pushes its pane (as it pushes status), so no input
reaches the machine and the input guard is untouched. Every session pushes, sensitive ones included: the router already
holds each session's conversation (live sync, snapshot tails), so the pane adds little it couldn't see. The push runs
every 2 s only when the pane changed; the router keeps the latest one in memory. Change: make the push a signed New
session setting (`Checks.configKeys`) if a session should keep its screen from the router.

## Memory alert and Upgrade, 2026-10-12

98. **Jarvis 1's memory-starvation watch and one-tap Upgrade, ported** (Deyao, 2026-10-12, after the YYC AI megathread
    session went "Can't reach your computer"; he picked "alert + Upgrade"). The machine reports its RAM itself
    (`POST /m/memory`, every 10 s) because the router has no exec of its own; a machine that stops reporting while short
    is counted as starving, as Jarvis 1 counted one that stopped answering its exec. The watch lives in the router's
    memory only (a restart starts it afresh). Each Upgrade doubles the memory, with no last size (DECISIONS 167).
99. **`free` is a router command the machine obeys without a voucher.** It is not an input to the agent: it only stops
    processes, which the router can already do more bluntly by pausing or destroying the machine, and the snapshot that
    follows is still the machine's own, signed. The harness (the machine's main process) is SIGSTOPped, not killed, so
    the Fly machine stays up for the snapshot. The list of what was stopped is written inside the snapshot, and the
    successor reads it, so the router's word never reaches the agent; the `upgraded` message itself is an image text
    over two sizes. Change: make Upgrade phone-approved if Deyao wants a Face ID on it.

## The session image's base moves into Jarvis 2, 2026-10-13

100. **The base is its own image, rebuilt only when `session-image/base/` changes** (not one combined Dockerfile). It is
    ~7 GB and takes 20-30 min to build, so rebuilding it for every `machine/` or `tasks/` push would slow every deploy.
    It goes to the existing public package `jarvis2-session` as tag `base-sha-<12>` (a new GHCR package would start
    private), and `session-image/Dockerfile` names it by digest in `ARG BASE`, which the pin job moves in the same commit
    as the k8s pins: moving the base stays a visible commit, as it was when it pointed at Jarvis 1's
    `claude-sessions`. The session image built in that run stands on the new base (`--build-arg BASE`). Change: fold
    the two Dockerfiles into one if the build cache makes a full build cheap.
101. **Carried over as it was; only the Dockerfile's comments were rewritten.** The scripts are byte-for-byte Jarvis 1's
    (`selfhost/session-image/` at claude-env 32e9a0f, the base of Jarvis 1's last image sha-32e9a0f7c8c6) plus the
    cf-tunnel agent (`cf-tunnel-agent.js`, was a second build context); every Dockerfile command is the same. The
    comments had notes about other projects and private workflows, now generic. Jarvis 1 code paths stay where they are
    inert or harmless in a Jarvis 2 machine, so the move is mechanical: `restore-snapshot` (replaced by a no-op in the
    session layer), the kubeconfig the entrypoint writes only when a store carries KUBE_SERVER + KUBE_TOKEN, the
    `jarvis.deyaochen.com` default of `JARVIS_URL` in pull-secrets / content-sync / push-claude-credentials (never used:
    jarvis2-machine always sets `JARVIS_URL` to its local proxy), `sync-live-transcripts` (runs only when a store carries
    STORAGEBOX_*; goes with the transcript-search port), and the entrypoint's handling of SESSION_SECRETS_JSON and
    CLAUDE_* (jarvis2-machine relies on it). The forks' builds are pinned here by `fork-pin.yml`
    (entry 156).
102. **The image checks moved with it**: the build job fails, so nothing pins, when the session image isn't anonymously
    pullable or needs more than 8.0e9 bytes on disk unpacked (Jarvis 1's limit and script, `infra/image-unpacked-size.py`).
    A too-big session image therefore also holds back a router or core pin in the same run, which is louder than Jarvis
    1's (it skipped only the session pin). Change: split the check into its own job if that blocks deploys.

## An offline copy of the stores, 2026-10-13

Deyao (2026-10-13): "build a thing that allows me to download a copy of the encrypted key store so I can use the master
key to decrypt it offline"; the download in the iPhone app, the decryptor a command-line script.

103. **The app's file is the backups exactly as served**, not re-encoded: `{format: "jarvis2-backup-export", version 1,
    bucket, fetchedAt, setupKey, setupKeySource, objects: [{key, body}]}`, each `body` the bucket object's text
    unchanged, so the decryptor checks the setup key's signature over the very bytes `infra/setup.py` signed. The app
    checks every signature (the same checks as Recover minus opening) and still lets Deyao save a file with a failed
    one, listed in red: it is still only ciphertext, and the decryptor refuses it again. It keeps only the latest copy
    in its temporary folder (complete file protection); the share sheet is the way out. No router or core change.
104. **The decryptor is Python with `cryptography`** (`tools/decrypt-backup.py`), not a Go binary: it reuses the exact
    primitives `infra/setup.py` seals with, is one readable file Deyao can audit on the Mac, and needs no build or
    release pipeline; the cost is a one-time `pip install cryptography` (in a venv) while online. It trusts the setup key
    inside the file only together with `--setup-pub` (a file whose key and signatures were both swapped would pass on its
    own, so the RUNBOOK command always passes `keys/setup.pub` from a clone). The kit is read from a file, stdin or a
    no-echo prompt, never argv. Output is mode 0600, never over an existing file, values on the terminal only with
    `--stdout`. Change: a static Go binary if Deyao would rather not keep Python on the Mac.
105. **Tested with the public TEST master key only**: `tools/decrypt_backup_test.py` seals with `infra/setup.py`'s own
    `backup`/`mark_sensitive_backup` and a throwaway setup key, and reads a committed vector
    (`tools/testdata/backup-export-v1.json`) so a later format change must keep reading v1 files; `ios.yml`'s interop job
    decrypts the file the app's Swift code made from the router's stand-in bucket; the phone replica downloads the copy
    in the Release build and the runner opens the saved file with that run's throwaway kit. The production master key
    is never used (no session has it).

## Transcript search and the iCloud index move to the Jarvis 2 box, 2026-10-13

106. **Transcript search and the iCloud index run on the Jarvis 2 box, in jarvis2-edge** (`services/search`,
    `services/icloud-index`, ported from Jarvis 1 with the same API shapes, so the app and session scripts change only
    their base URL). They read untrusted content (transcripts, PDFs, images through ffmpeg), so they sit next to the
    news pod rather than the router or the core, and their NetworkPolicies admit only the router's pod: they have no
    login of their own, and the router forwards behind Access (the app) or the machine signature (any running session,
    `router/searchsvc.go`). Change: give them a namespace of their own if more services join.
107. **Fixes came along with the port**: Jarvis 1's iCloud pod had restarted 623 times (OOMKilled at 1536Mi). Loading
    its ~750k vectors with `fetchall()` held the blob list next to the matrix at every start and every reload; they now
    stream into a preallocated matrix and later loads add only new vectors (limit 2 GiB). A file now counts a try
    BEFORE it is read and is given up after 3 (`error: not read: stopped the indexer N times`), and images over 40
    megapixels are decoded at a reduced scale (JPEG) or skipped with that reason. The AI budget ledger is carried as
    it was: no new AI spend beyond USD 25 without Deyao.
108. **The databases were copied, not rebuilt** (the embeddings and the iCloud AI-budget ledger are paid for). The setup
    session's Jarvis 1 token can read logs but not exec into Jarvis 1's pods, so a temporary read-only Job in
    claude-env (`selfhost/k8s/jarvis2-export`, Flux-applied next to the running pods, which it doesn't touch) took
    SQLite online backups of both and put them on the Storage Box. At the copy: search 45,460 chunks / 44,067 vectors
    (386 MB); iCloud 781,864 files / 1,696,050 chunks / 746,995 vectors (8.0 GB), `ai_spent` USD 25.00 of the USD 25
    budget, so AI reading was already paused at its cap.
109. **The Storage Box copy doubles as the seed and the backup**: `claude-records/.jarvis2-services/<db>.gz`, rewritten
    daily (search) or weekly (iCloud: each backup stages 8 GB plus its gzip on the volume). A pod with no database
    seeds from it. The iCloud index refuses to start without one (`SEED_REQUIRED=1`), because an empty index would
    forget the ledger and spend the budget again. Change: drop the backups if the Storage Box traffic matters.
110. **Their credentials**: the Storage Box account Jarvis 1's services used (its main login, read and write: the
    backups go there too) and the same OpenRouter key, in their own SOPS parts (`search`, `icloud-index`). The iCloud
    login is the Jarvis 1 pod's own rclone file (rclone keeps its cookies fresh there; the `identity` store's copy is
    older), encrypted to the box key by the export Job, so no session saw it: part `icloud-session`, mounted as a file.
    It can't reach a code push, so it sits with the box's other secrets, as it did on Jarvis 1's box. Change: a
    Storage Box sub-account limited to `claude-records/` if Deyao wants the services narrower.
111. **Until Jarvis 1's freeze both indexes run**: they share the budget ledger only by having copied it, but the budget
    was already used up, so neither reads with AI; both still embed new text (not capped) and list iCloud daily. Scale
    Jarvis 1's `search` and `icloud-index` Deployments to 0 at the freeze. The box is a cx23 (4 GB RAM, 40 GB disk):
    the iCloud database alone is 8 GB and its pod may use 1.5 GB, so watch the box's disk and memory; a bigger box is
    `infra/create.sh` with `SERVER_TYPE`.
112. **The iCloud index is identity-level** (Deyao, 2026-10-13: "the index should be guarded by key identity store"). A
    session reaches `/m/api/icloud/*` only while its cert holds the `identity` store (where the iCloud login lives):
    the router checks the session's cert stores (`Session.Stores`, which follow add-store and downgrade) and answers
    any other session 403 `{error: "… jarvis2-request add-store identity …", needsStore: "identity"}`. Deyao's app
    keeps `/api/icloud/*`. Transcript search stays open to every running session. On the box the index keeps its own
    SOPS parts (`icloud-index`, `icloud-session`), its pod admits only the router, and its Storage Box copy is
    age-encrypted (`icloud-index.db.gz.age`) to a key whose private half is only in that pod's SOPS part and, for a
    box rebuild, in the new sensitive store `icloud-backup` (`ICLOUD_BACKUP_AGE_KEY`). The plain copy from the Jarvis 1
    import is read once (`SEED_PLAIN_OK=1`) and deleted by the first encrypted backup. Change: keep that key in the
    `identity` store itself instead (a full rewrite of that store, so Deyao's or the orchestrator's call).

## Device leases and watches in Jarvis 2, 2026-10-13

113. **Device leases are the router's own** (Jarvis 1's lib/leases.js ported to `router/leases.go`; nothing forwarded
    to Jarvis 1). Same rules and request shapes: one holder and a FIFO queue per device (`wechat-phone`, `iphone`,
    `mac` always listed), acquire / renew / describe / return, `lowPriority` never queued, a 1 h renewable lease, expiry
    and gone sessions swept every 30 s, Deyao's take-over / hand-back and force return. The state is in the router's
    `state.json`. The holder is the calling machine's own session (its path id must be its own, as for every `/m/api`
    call). **Jarvis 1's lease table is separate and not consulted**: while both run, a Jarvis 1 session and a Jarvis 2
    session could each hold the same device; after the cutover Jarvis 2 is the only authority. Change: a one-way check
    of Jarvis 1's table before granting, if Deyao wants the overlap closed while both run.
    - **Wake messages are deliveries the machine checks**, never router text: `lease-granted` carries the waiter's own
      signed acquire request (its prompt, and the device in the signed path; the machine refuses a device that isn't
      the one its request named) plus two flags and the lease's minutes; `lease-taken` and `lease-back` are texts built
      into the image over the device name (a lease-name word). Deyao's notes (take-over, hand-back) never go into a
      session: nothing vouches for them. The session reads them with `lease.py status` (its own choice to read).
    - **Scripts that drive a device by themselves** (tunnel button pages, pay buttons) run inside a session and take
      the lease as that session through `$JARVIS_URL` (`lease.holding`), so no separate lease token exists; the
      `shopping` store's `JARVIS1_LEASE_ACCESS_ID/SECRET` (Jarvis 1's Worker-confined token) is no longer used by
      Jarvis 2 sessions. A Jarvis 2 session is queued and woken like a Jarvis 1 session was (Jarvis 1 could only answer
      it "busy").
    - The app's take-over, hand-back and force return are Deyao's Access login (no Face ID): they only move a lease,
      never a secret. Change: phone-signed if he wants it.
    - **Deyao's Jarvis 1 take-overs were carried over** (2026-10-13, by the setup session through
      `/setup/leases/:name/take-over`): `iphone` with his note "Unavailable to agents long term …" and `mac`, both
      held by him in Jarvis 1, are held by "deyao" in Jarvis 2 too, so a Jarvis 2 session can't take them. He hands
      them back in the web page's Devices tab (or `infra/setup.py lease hand-back`).
114. **Watches run on the box, with no secrets** (`router/watches.go`, `services/watch`, `k8s/apps/watch.yaml`).
    Jarvis 1 ran each check on its box with the session's store plaintext; Jarvis 2's box never holds store plaintext,
    and a watch must fire while its session is paused (no machine). So the router runs each due check on a **watch
    runner** pod in `jarvis2-edge` that holds nothing: no secrets, no service account token, no volume; its
    NetworkPolicy admits only the router and lets it reach only DNS and public addresses on 80/443/993 (never a
    private range: not the router, the core, the search pods or the metadata address). A check gets a clean env
    (PATH, HOME/TMPDIR = a throwaway dir, LANG, WATCH_NAME), 90 s, capped output, and its process group is killed;
    while no check runs every other process in the runner is killed too. The checks of different sessions share the
    runner: one could disturb another's (a false "met" delivers only that session's own signed prompt; a missed check
    runs again). Considered and not chosen: running the check on the session's machine (impossible while paused, and
    a resume per check costs a Fly start each interval), a task line per watch (a new line needs the phone).
    - **What a check can't do**: use a store's secret (Gmail, a private repo's token). Such a condition needs a
      public signal, or the session waits running and checks itself. Change: a check that needs a secret could run
      as a task-style resume of the session's line every N minutes (no phone, carried secrets), at the cost of a
      machine start each time.
    - **Delivery is the session's own signed request** (`watch` when met, `watch-fail` on exit 3 or past `maxSeconds`),
      attested by the core and checked by the machine against its line's keys, like a wakeup; one of the two, once
      (`.jarvis2-delivered.json`). The runner's output never reaches the agent (the router keeps its last line and the
      start of its stdout for the app only); instead the machine runs the check once more itself, with the session's
      own env, within 40 s, and appends that output, as Jarvis 1 appended the check's stdout.
    - Arming is the session's own (`POST /m/api/sessions/:id/watches`, Jarvis 1's body); the app can list and cancel,
      not arm (nothing would vouch for the delivery). A watch keeps its session (`PendingSchedule`: no self-retire,
      no automatic destroy) until it fires, gives up, or is cancelled. Script limit 32 KB (Jarvis 1's 4000 characters
      was a Fly metadata limit).

## The Claude login moves into Jarvis 2, 2026-10-13

Jarvis 2 stops depending on Jarvis 1 for the shared Claude login (PLAN "Before Jarvis 1 retires"). Replaces 22 and the
Jarvis 1 half of 89.

115. **The router holds the Claude login**, on its volume (`claude-login.json`, 0600), not in the core and not in a
     store. The pair rotates every 8 hours with nobody there and goes to every Claude session: in the core that is
     state changing without Deyao and branching beyond accept/reject (DESIGN "Trust boundary"); a store's value is
     fixed until the setup session rewrites it. The router already reached the pair (its login repair used Jarvis 1's
     confined token), and Jarvis 1 kept it in an untrusted box too, so nothing is exposed that wasn't. A box rebuild
     loses it: one Re-login in the app (Settings → Claude account). A rollout waits for a refresh in flight (SIGTERM
     drains it), and the answer reaches the volume before anything else. Change: a pod of its own if router rollouts
     ever cut a refresh short.
116. **Machines take the router's Claude login whatever its account** (Deyao, 2026-10-14: "Your Re-login is enough").
     Until then every pair was checked against `CLAUDE_ACCOUNT_UUID` in the store `claude`, which a running session
     only gets with a Face ID unlock: the Re-login to another account on 2026-10-14 left every running session refusing
     the new login. Now a Re-login to any account reaches every running and new session within a minute. A pair for
     another account replaces the one on the machine even when it expires sooner, and the claude host is restarted
     (`--resume`) once it is idle so its Remote Control comes up under the new account. The router writes no login into
     a session any more (login repair and the `login` holder went), and `CLAUDE_ACCOUNT_UUID` is gone. The router
     still refuses a pushed pair for another account than the one it holds (only a Re-login switches it). Cost: the
     router alone picks which Claude account sessions use.
117. **One refresher, chosen by a switch**: the file's `mode` is `follow` (mirror Jarvis 1's pair every 30 s, never
     refresh; the default, so a new router can't start a second refresher) or `own` (the router is the only
     refresher), set only by the setup session (`infra/setup.py claude-login own|follow`). Cutover order: Jarvis 1
     becomes a follower first (its Secret `jarvis-claude-login`; then both follow and nobody refreshes, harmless for
     hours since a pair lives 8 h), then `own` here. Never `own` while Jarvis 1 still refreshes.
118. **lessons/74's refresh lock, over the network**: every taker long-polls the router; before refreshing, the router
     announces it (`preparing`, a generation number), each participant takes its CLI refresh lock and acknowledges, the
     router waits for every participant seen in the last 2 minutes (at most 10 s), refreshes, and answers every poll
     with the new pair; a participant writes it and then releases the lock (released after 45 s regardless). Jarvis 1
     is one participant for all its sessions (it locks them through Fly exec, as before). Replaces Jarvis 1's exec-based
     guard for Jarvis 2 sessions, which had none (they polled Jarvis 1 every 30 s).
119. **Re-login is the CLI's OAuth flow in Go** (`router/claudelogin.go`), not a PTY around `claude auth login`
     (lessons/39 drove the real CLI): the router image is distroless with no CLI, and a pending sign-in kept on the volume
     (the PKCE verifier, 15 minutes) survives a rollout, which Jarvis 1 needed a separate broker for. The parameters
     (authorize URL, client id, scopes, manual redirect, token endpoint, the `code#state` paste) are read from claude
     2.1.296; after a CLI upgrade that changes them, update the vars at the top of the file.
120. **Jarvis 1 reads the login from Jarvis 2** (`/peer/claude-login`): a path-scoped Access app
     `jarvis2.deyaochen.com/peer` admitting one service token, `jarvis1-claude-login` (router env `ACCESS_PEER_AUD`,
     `JARVIS1_LOGIN_CLIENT_ID`; its secret only in Jarvis 1's Secret `jarvis-claude-login`). Jarvis 1 stores each newer
     pair in its own Secret, so its sessions, its `/api/credentials` (still used by Jarvis 2 sessions on older images)
     and its usage card keep working unchanged; it pushes its sessions' own refreshes and its Settings Re-login
     (`relogin: true`, which may change the account) to Jarvis 2. The token reaches nothing else on the router.
121. **A refused refresh DMs once and isn't retried**: only a newer pair (a Re-login or a push) clears it, as in
     Jarvis 1. Usage is read with the stored access token and cached a minute.

## Importing paused Jarvis 1 sessions, 2026-10-13

Deyao: move every paused Jarvis 1 session to Jarvis 2, so each continues there as the same conversation with its working
tree; Face ID is unavoidable, the approval burden should be small.

122. **An import is a new line whose cert's `restore` names the Jarvis 1 session id and the sha256 of an import
     manifest** (`router/jarvis1import.go`): at prepare the router streams every file of `.paused/<id>/` once and records
     `{name, sha256, size}` for each; Deyao's Face ID signs the manifest's hash, so it vouches for every byte (DESIGN
     "Inputs to a machine" (a)). It reuses the `restore` key the app already shows ("Restores machine <id>", the hash;
     a Jarvis 1 id is its first machine's id), so no app release is needed. The machine tells the two kinds apart by the
     bytes the cert names (an import manifest is JSON naming that id; anything else must be a signed Jarvis 2
     snapshot), so the router can't switch one for the other. Change: a separate `import` config key the app labels
     "Imports Jarvis 1 session" (an app release through the phone replica).
123. **Which bytes are hashed is the router's choice** (as with attachments, 78): the phone binds what the router read
     from the Storage Box (ours, over TLS) at prepare. The machine fetches each file through the router, streamed (it
     holds no Storage Box credential), and refuses any whose sha256 or size differs. There is no sensitivity rule to
     carry over (Jarvis 1 had none): Deyao sees the stores in the approval.
124. **(Superseded by 140: imports may be filed as one batch, allowed under one Face ID.) One Face ID per imported session, no batch approval.** The phone's signature covers one core challenge. Signing a
     list safely needs either a core primitive that approves N challenges from one signature (a core change, so a
     Recover) or the app signing N challenges under one Face ID (an app release through the replica). For a one-off,
     N Inbox approvals (Allow + Face ID each) is the smaller change. The 3-waiting-proposals limit is a session's (it
     guards against a session flooding the Inbox); the import is filed by the setup session (caller `setup`), whose
     calls the router already trusts to ask for anything, so no limit is raised or bypassed. Change: a batch approval in
     the app if imports or restores become routine.
125. **What the first machine restores** (as Jarvis 1's restore-snapshot + entrypoint did): workspace, artifacts and the
     harness tarball (`.paseo`, `.openclaw`, `.local/share/opencode`) extracted into a staging dir while hashed, moved into
     place only after the hash matched, entries outside those roots or through a symlink skipped, files' mtimes kept (git's
     index stays valid); the transcripts under the working dir's project slug after the repos are cloned (Jarvis 1's
     rule: the single repo in `~/workspace`, else `~/workspace`); `~/.claude.json` without `oauthAccount` and `userID`
     (the machine ID stays, so the Claude app's Remote Control entry can reattach); GitHub remotes without embedded
     credentials and ending in `.git`, so the line's deploy-key rewrites take them. Not taken: `changes.txt` (written
     again at the next pause) and `artifacts-manifest.txt` (the plain-file artifacts of a Jarvis 1 Previous-restore,
     used only when no artifacts tarball exists).
126. **Wakeups and crons are re-armed by the machine as the line's own signed requests** ((c), so later deliveries
     need no new voucher): a wakeup whose time passed while paused fires 5 minutes after boot; a cron keeps its period,
     time zone and end and runs next at its first occurrence after now (its time of day kept), and a run that fell
     while paused fires once 5 minutes after boot as the wakeup `missed-<name>`; a cron past its end isn't armed;
     Jarvis 1 watches are noted, not armed (their check scripts aren't in the record). The list goes to
     `~/artifacts/jarvis1-import/rearmed.txt`.
127. **The first prompt is a move notice** (signed with the line, shown on the phone) typed into the resumed
     conversation: the environment changed, the stores it now has, Jarvis 1's API is going away, reply in one line and
     wait. One short turn per session; the reply also shows in the transcript that the resume worked.
128. **Settings carried over**: label = Jarvis 1's app title (else its label), which names the Remote Control entry;
     model, permission mode, repos and auto-pause as in Jarvis 1; size `xlarge` → `large` (Jarvis 2's largest; the core
     refuses others).
129. **Snapshots stream** (a session can be several GB): the machine writes its final snapshot to disk while hashing it
     and uploads it streamed, the signature over that hash; the router streams the body onto its volume while hashing
     and checks the signature after (it read up to 4 GB into a pod with 1 GiB of memory); a restore (predecessor or
     archive) streams to disk and unpacks from the file. A file that shrinks while the snapshot is taken is padded
     instead of failing the whole snapshot.
130. **Disk**: Jarvis 2 machines get Fly's default 8 GB root disk (the core's create sets no size; Jarvis 1 set 16 GB).
     The largest paused Jarvis 1 session unpacks to 4.3 GB; with its pause snapshot (about 1.8 GB compressed) it fits, with
     little room. Change: `rootfs: {size_gb: 16}` in the core's create, with the next core release (a core change).
131. **A new core destroys imported lines like any other** (once paused, archived in Previous; Restore is a new line).
     Imports made before a pending core release are destroyed at that release; the import manifest stays on the router's
     volume (`jarvis1-imports/<id>/`) and Jarvis 1's records are only read, so an import can be asked for again.

## Content stores, paired apps, Browserbase and Fly personal leave Jarvis 1, 2026-10-13

Deyao is retiring Jarvis 1 (2026-10-13); these were the last pieces Jarvis 2 took from it besides the login, search, the
iCloud index and leases (decided while Deyao was away; the safe, reversible default each time).

132. **Content stores: the pick is signed, the router serves the files.** A session's content stores are a field of its
     config (`content`, `SessionConfig` on both sides and the shell's `Checks`), so the phone approves them with the line
     and an unattended resume keeps exactly them. The machine holds no Storage Box credential: content-sync's calls go
     through its local proxy to `/m/api/sessions/:id/content…`, and the router reads and writes Jarvis 1's
     `claude-records/.content/<name>/` folders in place with its own credentials, only for the stores the calling
     machine's cert names. Each file a machine downloads carries the core's attestation (input `content`, origin `router`)
     and the proxy refuses one without it, so every content file a machine took is in the input log. Change: per-store
     Storage Box sub-accounts in key stores would let the machine fetch directly (DESIGN (d)), at the cost of a store per
     content store and the Hetzner admin key for each one made.
133. **The bytes are the router's word.** A content store is shared, mutable data that other sessions and Deyao write, so
     nothing can sign its contents ahead of time; it is treated like the web a session reads: kept in `~/content/<name>/`
     (never the cwd, so no CLAUDE.md, hooks or skills load from it; nothing runs it), recorded in the input log. Pushes are
     the session's own act and need no voucher. A store deleted since the line began reads as empty. Change: sign each
     push with the line's key and have the reader check it, if a store should only ever hold what sessions wrote.
134. **Jarvis 1's task templates: the content ones are ported, nothing is scheduled.** `encrypt-to-content`,
     `paraphrase-to-content` and `proton-send` read and write content stores through the local API (`content.py`) and take
     `AES_KEY` from a key store picked in a `optionsFrom: "stores"` field (Jarvis 1's `secretKeys` has no Jarvis 2 form: the
     whole picked store reaches the task, as every store does). `new-session` is not ported: a scheduled new line would
     need the phone each day; a session proposes one instead (`jarvis2-request new-session`). Jarvis 1's five instances
     and three schedules (all disabled since 2026-10-04) are not recreated: each instance is a new line approved on the
     phone, and no Jarvis 2 store holds the `AES_KEY` they use. Change: Deyao makes them from the Tasks tab when he wants
     them.
135. **Paired apps: Jarvis 2 mints their tokens itself.** Jarvis 1's design (its `/api/remotes` appending Jarvis 2's list)
     dies with Jarvis 1, so the router answers pairing as Jarvis 1 did: one Access service token per app, minted with a
     Cloudflare token that can manage Access service tokens and nothing else (`jarvis2-device-tokens`, router SOPS part
     `devices`; it can't change an Access app, policy, DNS or Worker). The Access app "Jarvis 2 devices" covers only
     `/api/remotes` and `/api/sessions/*/start` and admits any service token of the account, and the router admits a token
     only when its client id is a paired device's; pairing itself needs Deyao's email login. Trade-off: that Cloudflare
     token can also delete or mint any service token of the account (a broken router could revoke the setup or tunnel
     tokens, or mint one that passes Access wherever any service token passes: Jarvis 1's apps, the session hosts
     `<id>-s.deyaochen.com`); the router could already read the session hosts' secrets through the `remote` holder.
     `JARVIS2_REMOTES_CLIENT_ID` / `ACCESS_REMOTES_AUD` are gone. Change: one shared device token handed to every app
     (no Cloudflare token on the box, no per-device revoke).
136. **Start from a paired app is a resume with no phone step** (`POST /api/sessions/:id/start`, 202): the same image and
     stores (approve_by_dead_machine), as the app's own Resume without a prompt. A resume that needs the phone (a newer
     image, a store added) is not reachable from these apps.
137. **The Browserbase DM moves as it is** (`router/bbbudget.go`): the same re-pricing, USD 10 cap and USD 8 warn line
     (router env), DM only. The month's flags are the router's, so until Jarvis 1 is frozen both Jarvises may send the
     same DM once each.
138. **Org personal is read with a read-only token of its own** (`FLY_PERSONAL_READ_TOKEN`, part `flypersonal`): the
     personal org token attenuated offline to the caveat Organization `{id, mask "r"}` (`infra/fly-personal-read-token.sh`;
     a check that it lists apps and can't create a machine). Fly has no caveat narrower than read for machine listings,
     and a read returns each machine's whole config: the router could read the Fly env of Jarvis 1's session machines
     (their stores) and of KAMYEE's Jarvis 3 sessions in that org. Unavoidable for listing them; today both apps have no
     machines, and Jarvis 1's go when it is frozen. Only the fields `router/flyorgs.go` copies leave the router. Change:
     an Apps caveat leaving out `de0ch-claude-sessions` (Jarvis 1's machines then don't show).
139. **The apps' server URL changes at retirement, not now.** Both forks name jarvis.deyaochen.com in one constant; moving
     them now would cut Deyao's apps off Jarvis 1's sessions while he still uses it. At the freeze: change the constant,
     ship each through its TestFlight workflow, pair each app once (RUNBOOK "Paired apps").
140. **A start waits out Fly's org machine limit** (up to 3 hours, a try a minute; `router/flows.go` startMachine):
     the limit counts every machine object (lessons/58: 20 in Jarvis 1's org), and the import starts 16 lines at once
     next to the running ones. A refused create made nothing and the phone's approval isn't spent until certify, so
     the router keeps it and tries again as sessions pause, instead of failing a line Deyao already approved (which
     would cost him another Face ID). The session shows `starting` meanwhile. Change: ask Fly to raise the org's limit.
141. **A successor with no snapshot takes the line's Jarvis 1 import again** (2026-10-13: the imported sessions' Fly
     machines were stopped by hand right after boot, so their rootfs and keys were gone and no snapshot could be signed;
     their kills named none). A successor whose cert names no snapshot, on a line whose signed config names a restore that
     is a Jarvis 1 import, fetches that manifest and its files again and checks them as the first machine did
     (`machine/restore.go` reimportJarvis1; the router serves them to such a successor). The cost: a router that withholds
     a later snapshot can bring the line back to the imported state instead of an empty one; both were already in its power
     (withholding, and the import's bytes are what Deyao signed). A destroyed Jarvis 2 session's archive is not taken again.
142. **`/setup/sessions/{id}/pause` cancels the session's wakeups and crons first** (they would resume it by themselves);
     the imports' re-armed ones are armed again by the re-import at the next resume.

## Batch approvals in the Inbox, 2026-10-13

Deyao: several actions approved together with ONE Face ID; the caller groups them through the API and gives a summary
(its unverified words, shown above every item's signed details); nothing excluded; Deny works on the whole batch.

143. **One Face ID, every item signed as alone; no core change** (supersedes 124). The app evaluates Face ID once
     (`PhoneKeys.authorize`: `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`) and passes that context
     to every Secure Enclave use of the batch (`SecureEnclave.P256…PrivateKey(dataRepresentation:authenticationContext:)`),
     so the Enclave asks no second time; the keys stay `.biometryCurrentSet`. Each item is then signed and sent exactly as
     from its own page (approvals' core challenges, grant texts, deploy-key begin documents, unlocks' shares), so the core
     verifies each one unchanged. The simulator does its Face ID stand-in once per batch. The replica proves the one-Face-ID
     path on the simulator (software keys) only; on Deyao's iPhone the evaluated context opened the keys for every item
     (172: batch b986f9a3177e8d687, two deploy keys signed 1.3 s apart under one Face ID). 0e1f12f's guess that it
     opened them for the first item only was wrong and is reverted (172). Change: a core primitive approving N
     challenges from one signature (a Recover).
144. **Items are read and checked before Face ID; each is signed and sent in order after it.** A batch page reads every
     item as its own page would (the same Checks: the core key, line pins, the session's cert, CI's image signature, the
     grant's draft checked field for field before signing) and offers Allow all only when every item is readable and
     signable and no approval is still being made. An item that fails mid-batch is shown failed; the ones before it went
     through and left the Inbox (approvals leave when answered, requests on `done`), so Retry is idempotent: it reads only
     what is left and asks for one more Face ID. Grants and deploy keys draft/begin again on Retry.
145. **Deny: the whole batch, or one item.** Deny all drops every request and rejects every approval (a new session
     disappears); an item can also be denied (or allowed) on its own, which takes it out of the batch. The web page shows
     batches and denies them; approving stays on the phone.
146. **Limits count a batch once.** A batch is one of the caller's 20 waiting requests and, when it proposes any new
     session, one of its 3 waiting proposals (a session or the actions key); a batch holds at most 20 items. So a session
     can have at most 3 proposal entries in the Inbox, as before, each still needing Deyao's Face ID per entry. The setup
     session's imports, as before, aren't limited beyond the 20 items per batch.
147. **The batch is checked whole before anything is filed** (an item the caller may not ask for, a bad argument, the same
     item twice: 400/403 and nothing filed). Filing itself can still fail per item (the core refusing a challenge): that
     item is reported with its error and the others stand, since undoing filed approvals would be a Deny the caller didn't
     ask for. A request already waiting alone joins the batch; one already in another batch stays there. Per-item
     explanations are optional in a batch (the summary is required).
148. **The whole batch expires 10 minutes after filing** (its requests carry the batch's end; an approval goes at the
     sooner of its own 10 minutes and the batch's). Imports and proposed sessions come in a moment after filing (the core's
     challenge); the batch shows them as `preparing` and the phone waits for them before Allow all.

149. **Router rollouts drain; nothing is redone after a crash** (Deyao, 2026-10-13: drain on SIGTERM, remove the
     save-to-disk-and-redo). Tracking lives in the lifecycle lock (`lock` begins a tracked action, its unlock ends it) plus
     the approval answer (`Respond`); a restart or upgrade job is tracked as a whole and its own pause/resume steps still
     begin during a drain, so a drain between its steps doesn't leave the session paused half way. Creating a session
     (only an approval, no machine) is not refused; the phone's answer is, before the core uses the approval up, so it
     stays in the Inbox. Preparing a Jarvis 1 import (hashing, no machine) isn't tracked.
150. **A drain doesn't wait out Fly's machine limit.** A start in the limit wait (up to 3 h) when the drain begins, or one
     that would begin it during a drain, ends `failed` with "the Fly org is at its machine limit and the router is
     updating: start it again". Change: let it wait in the next pod (it would need the saved state we just removed).
151. **Grace 30 min, not 15.** `terminationGracePeriodSeconds: 1800`, `DRAIN_SECONDS` 1740: the longest tracked job is a
     restart/upgrade (a pause's 600 s snapshot wait + the kill, then a resume's machine init, up to 12 min). Flux applies
     with `wait: false` and no workflow waits on the rollout, so the long grace delays only the new pod. A drain past it is
     cut off like a crash.
152. **After a crash: `paused` for a cut-off resume, `failed` otherwise.** A resume cut off before certify keeps its line
     (the core marks the predecessor used only at certify), so the session goes back to `paused` with the reason and a
     plain Resume works. A new line's start (its phone approval is spent), a pause and a destroy become `failed` with the
     reason; Pause and Destroy both run from `failed`. The cut-off start's machine, if the core had made one, isn't known
     any more: it holds no secret (never certified) and the Machines tab flags it as having no session. Old state.json's
     `pendingStart` is dropped on load.

153. **The router's default secret part keeps four dead Jarvis 1 keys until its next rewrite.** The router no longer reads
     `JARVIS1_CREDENTIALS_*` / `JARVIS1_SERVICES_*` (nor the stale `GITHUB_READ_TOKEN`), but `router.enc.yaml` is rewritten
     whole and nobody can read `JARVIS2_TUNNEL_KEY` back: dropping them now means a new tunnel key on the Worker and the
     router at once, and every running OpenCode/OpenClaw session's web UI would fail on its next reconnect until it
     restarts. The values are inert (no code reads them); their Access service tokens can be revoked on Cloudflare when
     Jarvis 1 goes to 0, which kills them for good. Change: rotate the tunnel key in a quiet moment and rewrite the part
     (RUNBOOK "The router's secrets").
154. **A paused Claude session on a pre-router-login image resumes on the newest image.** Images pinned before
     `sha-c5427052a542` (2026-10-13 01:39) fetched the Claude login from Jarvis 1 with the store `claude`'s
     `JARVIS1_CREDENTIALS_*`; those keys leave the store, so such a line would boot logged out. The router's Resume (the
     app, the actions key, a wakeup, a lease or watch wake) of a line with the store `claude` whose image comes before that
     pin in `session-image-sigs.txt` (or isn't listed at all) asks for the newest image instead: a `resume-upgrade`
     approval in the Inbox, so the phone approves it; nothing boots before. A wakeup that resumes such a line waits on
     that approval (and lapses with it after 10 minutes, leaving the line paused). (The old-image route through the
     router's login repair went with DECISIONS 116's 2026-10-14 change.)
155. **The end-to-end test runs with Jarvis 1 unreachable, always.** The router runs in its own mount namespace (`sudo
     unshare`) whose /etc/hosts sends jarvis.deyaochen.com to 127.0.0.2, where a root listener logs every connection; any
     line fails the test. Each session machine gets `0.0.0.0 jarvis.deyaochen.com` in /etc/hosts through Fly exec as soon
     as Fly lists it started; the machine boots on its own, so the first boot can finish before that (the test logs
     "before boot"/"after boot" per machine); every later step runs blackholed. Search, the watch runner and the Storage
     Box (for content stores) are local stand-ins (an in-memory WebDAV over TLS, trusted through the router's
     SSL_CERT_FILE); the watch stand-in doesn't run scripts (the real runner kills every other process in its
     container). The router's own refresh against Anthropic isn't run (it would need a real login); the test covers a
     newer pair reaching a running machine by itself.
156. **The forks pin their builds with a `workflow_dispatch`, not a `repository_dispatch`.** DE0CH/claw-code and
     DE0CH/openclaw run `gh workflow run fork-pin.yml -R DE0CH/jarvis2` with a fine-grained token that has only
     Actions write on this repo (`JARVIS2_DISPATCH_TOKEN` in each fork). A `repository_dispatch` needs Contents write,
     which as Deyao's token (an admin, whom main's ruleset lets through) could push main from a fork's CI. The workflow
     checks every input (the URL must be the fork's own `de0ch-<sha12>` release asset for a commit on the fork's main,
     never older than the current pin), downloads it and pins it with its sha256: claw in `session-image/base/forks.json`
     (baked into the base, checked at build), OpenClaw in `session-image/openclaw-runtime.json` (so an OpenClaw pin builds
     only the outer image; the base's own `openclaw` wrapper and forks.json's `openclaw` entry are gone). It pushes with
     its own deploy key `FORK_PIN_DEPLOY_KEY` (environment `release`, main only), and that push starts `images.yml`.
     Change: a GitHub App for the dispatch.

## Two add-stores pending for one session, 2026-10-13

157. **An add-store is always answered onto the machine's newest cert** (Deyao, 2026-10-13: "The race shouldn't happen.
     Fix the root issue."). What happened: a session filed `jarvis2-request add-store identity` and, 20 minutes later,
     `… yyc`; Deyao approved both close together (the waiters logged "added yyc" 05:29:47, "added identity" 05:29:59
     UTC) and the session ended with identity only. Each challenge is made from the cert the machine has when it is
     filed (`stores = s.Stores + X`), so both continued the same cert. The live core (sha-06ab2452f8ad, from before R1)
     answers a challenge exactly as made: the second answer rebuilt the cert from the cert both were filed against, the
     router stored it, and the first store left. R1's core refuses the second instead (409 "isn't the newest"), the same
     loss the other way. Reproduced by core/addstore_test.go `TestTwoPendingAddStoresBothApprovedEndWithBoth` (fails
     against either of those cores) and router/addstore_test.go (with a stand-in of the live core).
     *The root cause* is that the phone signed a snapshot (the whole store set at filing time) when what it approves is
     a change ("add X to this machine"). *The fix, in the core* (`answer` + `addOnto`): every add-store is answered by
     one rule, with no fresh/stale branch (Deyao, 2026-10-13: the core doesn't decide; a call made wrong is refused):
     the caller sends the machine's newest cert as `current`, the core takes it only when it signed it, it names the
     challenge's machine and line and its nonce is that machine's newest (the core keeps only the nonce), and answers
     its stores plus X, its keys, its options (which must equal the challenge's). No `current`, a superseded one,
     another machine's, or one that already holds X: refused. Each self-succession challenge is answered once
     (`approvalsUsed`). Approvals thus commute: in any order and timing every approved store ends in the cert. Unlocks
     opened for a cert that is replaced before it pulled go to the cert that replaces it, for the stores it still
     names (`passUnlocks`), exactly as the carry does when the pull came first, so the first store, unlocked for the
     first answer's cert, isn't locked for the second.
     *Why this keeps the security model*: the phone signs "add store X to this running machine" (the review shows the
     store, the session from the signed predecessor, the machine id). Every store in the newest cert was approved for
     this machine before, by the phone (an add-store, the Start) or kept by its own old key (a downgrade), so the answer
     grants exactly one store the phone didn't already grant this machine: X. What a downgrade did stays done: the
     dropped stores aren't in the newest cert, so they don't come back (R1's concern), and its new key pair is the one
     the answer names (the challenge's old keys are never used again). A replayed challenge gets nothing. The router
     can't widen an answer: `current` must be the core's own newest cert for that machine, so the router can only pick
     the one cert the core would pick itself. The phone's "Stores after" row is "Stores when asked", and the app checks
     the answer for the same machine id holding X rather than the challenge's whole machine (after a downgrade its keys
     are the new ones).
     *Not chosen*: re-making every pending add-store challenge when a cert changes and having the app fetch again before
     signing. A batch signs all its challenges under one Face ID before sending any, so the second would still be stale,
     and a single approval racing an answer would need a second Face ID. Nor a fresh/stale branch in the core (an
     earlier form of this fix): one rule is simpler to check and is the same answer in the fresh case.
     *The router* (`respondAddStore`): one new cert per machine at a time (`selfSuccessionLock`, also around a downgrade's
     finish), always sends `current` and the carry under that lock, and never stores an answer that loses a store the
     session holds: with the live core (which ignores `current`) the approval is filed again from the newest cert and
     the respond says "approve it again". That path is dead once the held core goes live; delete it then. A 409 for a
     store the session already holds is the approval done.
     *The machine*: `~/.secrets`, the cert file and the deploy keys are written under one flock
     (`~/.jarvis2-secrets.lock`); a waiter pulls inside the lock, after the previous write, so it pulls from the router's
     newest cert at that moment and a slower waiter can't write an older pull over a newer file (machine
     secretslock_test.go). A downgrade holds the same lock and starts again (new key pair) when an add-store made its
     challenge stale. The waiter reads the machine's keys on every poll (a downgrade replaces them).
     *Deploy*: router and machine (session image) go live with the push; the core change waits for Deyao's go (the core
     is held: a new core is a Recover, and destroys the earlier core's sessions once paused, DECISIONS 69).

158. **A session's actions run on its own machine key, and can ask for any app API call** (Deyao, 2026-10-13: "the
     action key can request anything … action keys should be scoped and minted for each session, so i can see and log
     where that comes from … and they should be disabled with each session pausing/destroying").
     *Per session*: the shared Access service token `jarvis2-actions` (in the `default` store) is gone, with its Access
     app and router env. The actions moved to `/m/api/actions/*`, signed by the calling machine's key, which the core
     mints for each machine it starts; the router names the caller `Caller{Kind: "actions", Session}`, shows it in the
     Inbox and logs every non-GET action with its session. A machine key already dies with its machine; the actions
     also refuse a session that is pausing, destroying or paused (`actionsSession`), and its pending call requests
     leave the Inbox, so no action outlives the session's run.
     *Any call*: `POST /m/api/actions/requests/call` files an `api-call` request naming one app route's method, path and
     body. Deyao approves it on its own review sheet (app or web page, 169); the router runs it through its own public mux with
     the approving request's Access headers, so the route checks Deyao exactly as when he calls it, and keeps the
     result 10 min for that session alone. No Face ID for the approval: Face ID signs only what the core verifies, and
     a call that needs it (a switch to bypass needs the terminal grant) asks for that separately.
     *The sweep*: `callRules` classifies every app route. `callNo`: the Inbox and approvals (a request never files or
     approves another), and calls that hand out Deyao's own login or can't run server-side. `callStatus`: allowed, but
     the response carries a credential, so the session gets only the status. Everything else is `callBody`.
     *Not chosen*: replaying with a router-held identity (the call must run as the person who approved it), and a
     per-session Access service token (a machine key is already per session, rotates with each machine and needs no
     Cloudflare state).

## The box is IPv6-only, 2026-10-13

159. **Every Jarvis 2 box is IPv6-only, with Cloudflare's free WARP client for the outgoing IPv4** (Deyao, 2026-10-13:
     every Hetzner server, because the account is at its limit of 10 primary IPs). `infra/create.sh` creates with
     `public_net: {enable_ipv4: false, enable_ipv6: true}`; `infra/warp-host.sh` (ahead of `cloud-init.sh` in the
     user-data) installs WARP from Cloudflare's apt repo (reachable over IPv6), registers, `mode tunnel_only` and
     `tunnel ip add-range ::/0`, so only IPv4 enters the tunnel: GitHub, GHCR, Fly's WireGuard gateways
     (`*.gateway.6pn.dev` have no AAAA) and anything else IPv4-only. Claude's choices around it:
     *tunnel_only, not warp*: mode `warp` puts WARP's DNS proxy (127.0.2.2) in front of systemd-resolved; tunnel_only
     leaves Hetzner's IPv6 resolvers. *IPv6 excluded*: WARP's default captures IPv6 too, which would cut inbound IPv6.
     *k3s stays IPv4*: on a host without a public IPv4 k3s picks the IPv6 address and builds an IPv6-only cluster
     (pods `fd00:42::/56`) whose pods reach no IPv4 at all (tested: SERVFAIL, no GitHub). So the node gets
     `10.254.254.1` on a dummy interface `k3s0` (`node-ip`, `flannel-iface`; 10.0.0.0/8 is outside the tunnel), pods'
     IPv4 is masqueraded out through WARP, and CoreDNS forwards to 1.1.1.1/8.8.8.8 (`resolv-conf`) through WARP; set in
     `/etc/rancher/k3s/config.yaml`. *Not chosen*: dual-stack pods (more change, nothing needs pod IPv6 today); WARP's
     SOCKS proxy mode (every client — containerd, git, Flux, the router's Go code — would need proxy settings);
     wgcf/a hand-made WireGuard to WARP (an unofficial client). WARP's free tier has no SLA: if WARP is down, the box
     loses GitHub/GHCR, the Fly WireGuard peer (machines can't reach the router) and the Cloudflare tunnel (cloudflared runs
     in an IPv4-only pod, so its edge connection goes through WARP too) until it's back; nothing is lost, it reconnects. Tested on throwaway boxes in project runners: curl -4
     api.github.com, git ls-remote, GHCR pulls, Flux, the core through the tunnel, the router through the WireGuard
     peer, a reboot.
160. **The production box keeps its IPv4 (Deyao, 2026-10-13: "no need", a primary IP was free again); if it is ever converted, it converts in place** (`infra/convert-ipv6.sh`): shutdown → the primary IPv4
     unassigned (Hetzner allows it only while the server is off) and deleted → a single-use rescue boot with a
     throwaway SSH key writes `warp-host.sh` and a oneshot unit (before k3s) onto the disk → reboot. The disk keeps the
     box key, age key, Secrets and Flux state, so nothing is re-minted (a rebuild would need every router-secrets part
     again, a new backup read credential and a new tunnel key, and loses paused sessions). Both reboot the box, so the
     core starts empty either way: Deyao Recovers, as after a power failure. A real pre-change box can't be rehearsed (a
     new IPv4 is over the account's limit, which counts IPv6 primaries too), so it was simulated on a runner: a k3s
     cluster on a non-persistent IPv4 node-ip, Flux, WARP removed → convert-ipv6.sh (rescue over IPv6, 60 s) → after
     the reboot WARP installed by the unit, the node Ready on 10.254.254.1, every pod Running, Flux fetching GitHub,
     a new GHCR image pulled and a pod reaching api.github.com.

161. **The apps' server URL moved to Jarvis 2 now, not at retirement** (Deyao, 2026-10-13: "make sure Jarvis 2 runs fully
     without Jarvis 1"; supersedes 139). OpenClaw and Paseo name jarvis2.deyaochen.com from their next TestFlight build;
     Deyao pairs each once. They no longer see Jarvis 1's OpenClaw/OpenCode sessions (Jarvis 1 is frozen). Paseo's CI
     e2e token is a Jarvis 1 device: Jarvis 2 admits only devices paired through `/api/devices/pair` (Deyao's Access
     login), and the setup session can't pair one (giving it that would hand it every OpenClaw gateway token), so the
     fork's simulator test skips its Jarvis checks (a warning) until a paired token is in its secrets. Change: a
     setup-signed device registration for a CI token, or Deyao pairs a "Paseo CI" device once.

## A session hears what became of its Inbox requests, 2026-10-13

162. **The requesting session is told every decision on what it filed** (Deyao, 2026-10-13: "Approving an Inbox
     request should send a message or something to notify the session that requested it"; `router/outcomes.go`,
     `machine/outcomes.go`). Approved, denied, lapsed (10 minutes), dropped (left without a decision) or failed (an
     approved API call that couldn't run), per item, for everything a session files on its machine key (requests,
     add-store, new-session proposals, batches, the actions' filings incl. API calls). Claude's choices:
     *Built like the lease wake*: a delivery kind `request-outcome` whose text the machine builds from the session's
     own signed filing (kept by the router exactly as signed, as for wakeups) and image texts; the router names only
     the outcome word, an id (`[a-z0-9-]`), an HTTP status and a proof per item; the core attests the delivery over
     a canonical record of exactly those; each item is taken once (the delivered file in the snapshot).
     *What vouches for "approved"*: whatever signed trace the approval leaves, checked by the machine, which refuses
     the whole delivery when it doesn't check out: the phone-signed grant for this line (grant; the holder's name to
     key mapping is the router's, so the text says "a grant for this session", not which feature), this machine's new
     core-signed cert naming the store (add-store), the core's approval by the phone of a new line whose config has the
     proposal's label and prompt (new-session; the new session's id is the router's, a format value), the core's signed
     deploy-key answer for the repo (repo add/remove). An **unlock** (the core's unlock answer names no session) and an
     **API call** (approved with Deyao's Access login, no signature) leave nothing signed: the router's word, and the
     text says "this is Jarvis's report".
     *What vouches for denied / lapsed / dropped / failed*: nothing can: they are non-events (Deny is Deyao's Access
     login; a lapse is a clock). The router's word, as a fixed word whose text says so. The harm of a false one is
     bounded: the session doesn't use something it could have, or files again (Deyao sees it again). A false
     "approved" is the one that matters, and that is the one the machine checks where it can.
     *Never Deyao's words*: no note, no free text; a batch's summary in the text is the session's own (signed).
     *Paused session*: no boot. The outcomes wait in the router's state (at most 100 per session) and go in once it
     runs again (the tick delivers only to a started session). Change: a wakeup-style start, if Deyao wants a paused
     session woken by a decision; not chosen because a decision rarely needs action before the session's own next start,
     and a boot costs a machine for a message.
     *A batch is one message*: its items go together once all are decided, or 30 s after the newest decision (an item
     filed as a duplicate into another batch, or never decided, doesn't hold the rest back).
     *Older images*: a machine that answers "unknown delivery kind" is given up on at once (its outcomes stay
     listed); `jarvis2-request outcomes` / `wait ID` read the router's record (`GET /m/api/requests/outcomes`), the
     session's own choice to read, like `lease.py status`.
     *The app's "done"*: `POST /api/requests/:id/done` (Deyao's Access login) is what says an unlock went through, so
     an unlock's "approved" rests on it. A grant or deploy key is told from the signed answer when it is stored, before
     the app's done arrives.

163. **A store is a set of keys; any running session writes one key with no approval; a written key reaches a session
     only through the phone** (Deyao, 2026-10-13: "make sure that writing one key by name is allowed, and it doesn't
     just overwrite the whole key store (with the public half of the key)"; "any session with a valid machine key, this
     is part of the api endpoints they can use, and since writing a key is perfectly safe (has backup, so can't
     overwrite, and also can't read), no approval is needed"; "pulling keys for newly written keys require my approval
     on iphone"; the explanations of each key surfaced on the web and iPhone portal, kept in Jarvis 2).
     *What happened*: after the add-store race (157) the YYC session was restarted (a phone-approved resume to bypass);
     `yyc` had gained keys since its last unlock (`YYC_CLUSTER_SSH_KEY` and others, written by another session with
     `store-put.py`, which rewrote the whole store from its own copy), and the resumed session came back with the old
     copy until an unlock. That is not the race: the core can't open a rewritten store without the phone's share (the
     data key is wrapped to P + K), so the carried copy (73) was the only thing it could give. What was wrong is that
     nothing said the copy was behind, and that writing one key meant reading and rewriting the whole store (a writer
     with an older copy writes old values back).
     *The design* (DESIGN "Writing stores and their backups"): each key is sealed on its own to the store key P + K
     (the public half: anyone can seal, only phone + core open), with the store's and key's names as associated data;
     `write_key` replaces one key and never reads or touches the others. A running session writes with `jarvis2
     put-key` (`POST /m/stores/{store}/keys/{key}`), the setup session with `infra/setup.py write`. The router writes
     the key's backup first (versioned bucket, `keys/<store>/<key>.json`, sealed to the master key) and only then the
     key into the core. Every pull reports the stores whose values are behind (each store's version: a hash of its
     keys' names, E and data hashes, recorded with every unlock and carried copy); after a write, and after any pull
     that comes back behind (a resume), the router files an unlock request for each running session holding the store
     (one batch); the phone's unlock for a running machine's cert makes the router send it `refresh-secrets`, and the
     machine pulls the store as it is now. What each key is for is the router's record (`store-docs.json`), required
     for a new key name, shown in the app, the web page and `jarvis2 stores --keys`, and carried in each key backup.
     *Security reasoning*:
     - Reading: unchanged. A written value is sealed to P + K; only the phone's share plus the core's key open it, and
       the core gives a value only to a cert the phone approved for that store, from an unlock the phone made or the
       line's carried copy. Writing reveals nothing to the writer it didn't already have.
     - Integrity of what sessions get: a session can now put a value Deyao didn't choose under a key name (e.g. its own
       API key in place of the real one, to see what other sessions send). It reaches no other session without the
       phone: running sessions keep their copy until a refresh unlock (Face ID), a resumed session the same, and a new
       session gets it only through its Start's unlock. Each unlock_begin names every key's writer, signed by the core:
       for a machine writer the core checked the signature itself with the signing key in that machine's newest cert
       (a live machine it certified), so the router can't claim a session wrote something it didn't, nor forge a
       write as a session; the phone shows which session wrote which key before Face ID. The setup writer's signature
       is passed on and checked by the phone against keys/setup.pub, as before.
     - Overwriting: the bucket is versioned and the router's credential may only add versions under `keys/` (no
       delete, no policy); every write's backup is written before the core takes the key, so every earlier value
       stays recoverable (Deyao's "has backup, so can't overwrite"). A write to the core with no backup is refused by
       the router; the core can't check the backup (it can't read the value), so the backup's hash is in what the
       writer signs, and the app checks it at Recover.
     - Where machines may not write: the `core` store (the core's Fly token: nobody), `github-deploy-keys` and every
       repo's deploy-key store (their keys come only from a phone-approved deploy-key call; a session overwriting
       `GITHUB_DEPLOY_REPO_*` could otherwise steer which repo a store belongs to at the next Recover), and a store
       that doesn't exist (making stores, and their sensitivity, stays with the setup writer and `create_store`).
     - Recover: a session-written key's backup carries the machine's signature, its core-signed cert and that core's
       identity (signed by the box key), so the app checks the chain box key → core → cert → machine → value; a
       setup-written key carries the setup signature; both cover the backup's hash. A store's whole-store backup (from
       before keys) is the base and its key backups written after it are applied.
     - The core still doesn't decide (157): write_key is one operation that does exactly its job or refuses; the
       refresh is the router's choice, and only an unlock (the phone) changes what a session holds.
     *Restart*: correct behaviour, not part of the race: a resume can't carry anything newer than what the phone last
     released. Now it isn't silent: the resumed session's first pull reports the store behind and the phone is asked.
     A resume that already asks for Face ID (new image or mode) also unlocks the line's stores under that Face ID (the
     app), so it brings the stores as they are now with no second ask.
     *Not chosen*: letting the writer hand the core the new data key so sessions update with no Face ID — the core
     would then read stores without the phone (Deyao kept the phone rule); refreshing on a schedule (a store written
     reaches sessions only when Deyao says).
     *Deploy*: router, machine (session image), app (TestFlight) and web go live with the push and still work with the
     live core (sha-06ab2452f8ad: whole stores; marked "until the held core is live"); the core waits for Deyao's go (a
     new core is a Recover, and it destroys the earlier core's sessions once paused, 69). Before that, the router's
     bucket credential gets PutObject on `keys/*` (infra/backup-read-key.py policies).

164. **The web page picks any store, sensitive ones included** (Deyao, 2026-10-13: "make it so that I can select
     secret stores on web"). *Why it was restricted*: the design kept the choice of a sensitive store with Deyao
     himself on the phone's secure page (DESIGN "Sensitive stores"), since the web page is served by the router and
     is not trusted: a compromised router or page could slip a sensitive store into a request it files. *Lifted*: the
     web page's New session lists every store (each sensitive one with a red "sensitive" badge, never pre-picked; an
     amber "Sensitive" row names every sensitive store the session would get, a picked repo's and the harness's
     included), and picking a repo now adds its store even when that is sensitive (`github-jarvis2`). The task form
     (`optionsFrom: stores`) already offered them. The router never refused a sensitive store from the web, so nothing
     changed there (test `TestWebRequestTakesSensitiveStores`). *What still protects a sensitive store*: the web only
     files a request; nothing starts until Deyao's Face ID on the iPhone, whose review page lists the stores from the
     core-signed challenge, marks each sensitive one (the core's signed store list and the challenge's own marks, never
     the router's word) and shows the orange "Sensitive" warning before Face ID; the store's unlock still happens only
     under that Face ID, for that session only; and a sensitive line still takes only a phone grant. Never offered on
     the web, as before: the core's own store (`core`), the deploy-key token's store (`github-deploy-keys`, the router
     refuses it too) and a harness's stores (they come with the harness). The Restore and Jarvis 1 import flows take
     their stores from the record / the import form and never filtered sensitivity; the web page has no add-store (a
     session asks for one with `jarvis2-request add-store`). The iPhone app needed no change.

## Restoring a store to an earlier version, 2026-10-13

165. **The core keeps each store's last 50 versions; a phone-signed restore puts one back, with no kit and no
     plaintext outside the core** (Deyao, 2026-10-13, after two whole-store writes of 2 keys wiped 24 keys of `identity`
     and `yyc`: "it needs to go through the core and be signed, because I don't want to randomly lose my master key").
     *Built* (DESIGN "Restoring a store"; `core/history.go`, `router/storerestore.go`, the app's Stores → a store →
     Versions → Restore…, the web page's Propose restore): every change to a store makes a version (its `KeyEntry`s,
     sealed to `P + K`); `versions` lists them signed; `restore_begin` signs exactly what changes; the phone signs that
     document and shares the keys put back under one Face ID; `restore_finish` opens them, seals each one's backup to
     the master PUBLIC key and answers a signed receipt; the router writes the backups (writer `restore`) and only then
     `restore_commit` changes the store, if it is still the version the phone saw. The restore is a version too.
     *Security reasoning*: a restore can only put back values the core itself held for that store (the entries keep their
     writers, so the phone sees who wrote each key on the review and at every unlock); the router can't start one (the
     phone's signature over the core's exact document) or change what it puts back (the core reads the version from its
     own memory, never from the caller); the plaintext is in the core for one call, as with a deploy key's token; the
     master key's private half is never needed, so the kit stays in the password manager. The bucket backups stay the
     disaster path, and a Recover takes a restore's key backups: the core's receipt (a core the box key vouched for)
     names each backup's hashes, and carries the phone's signature over the begin.
     *Choices for Deyao to review*:
     - **Kept in the core's memory**, not the router's volume: simplest to reason about (the core moves entries it holds
       itself; no foreign input to verify) and costs little (entries are shared between versions; 50 per store). A
       restart of the core loses the history, like everything else in it; the bucket stays the way back from that.
     - **50 versions per store** (`historyMax`), oldest dropped first. A restore is itself a version.
     - **Backups of the restored keys are made by the core** (it seals each value to the master public key while the
       phone's shares are open in the finish call) rather than copied from older bucket versions: keys that came from a
       Recover or a whole-store backup have no per-key backup to copy, and the core's copy is checked by decrypting. The
       router writes them before the commit; the commit is refused when the store moved on, and a backup the core made
       but never committed only describes a restore Deyao approved.
     - **Not restorable**: a repo's deploy-key store (its key on GitHub is deleted on every re-add, so an old one would
       be dead: make the key again) and the `core` store. `github-deploy-keys` (the PAT) is restorable.
     - **Who may ask**: the app (direct), the web page and the setup session (an Inbox request `restore {store, seq}`);
       never a session (a session can't ask about stores beyond its own add-store, and a restore changes what every later
       unlock of the store releases), never inside a batch (its review needs the begin document and the phone's shares).
     - **The live core's footgun is closed at both ends now**, before the held core ships: `infra/setup.py write` refuses
       a whole-store write that leaves out a key name recorded for the store unless `--replace`, and sends the names; the
       router's `/setup/stores/write` refuses the same (409) unless `replace: true`, and a write naming no keys for a
       store with recorded names (400). On a core made of keys there is no whole-store write and `--replace` is refused.
       The app's and web Stores pages write no values (only explanations, which a write never removes), so they needed
       no guard.
     *Not chosen*: a restore that decrypts the bucket backups in the app with the kit (that is Recover's path and needs the
     master private key out of the password manager, which Deyao ruled out for routine use); the router keeping old
     versions (it would have to prove to the core that a blob was once the core's, adding signed receipts of every write
     for the core to check, for no gain over the core's own memory); a restore without the phone (any session can already
     write keys, but a restore rewrites many at once and Deyao asked for it to be signed).
     *Release*: the core part is behind `jarvis2/core-pin: hold` with 6fc20f8 (stores made of keys); both ship in the
     same release (RUNBOOK "Releasing the held core"). The router, setup.py, the web page and the app work with either
     core (a core without versions answers 404 and the Versions page says so).
166. **Succession certs with permission pairs, grants moved by meet, a kernel of small parts; the guard is the one
     entry point** (Deyao, 2026-10-14; DESIGN "Target design"; build: docs/PLAN-grants.md). Not built yet.
     *Why*: switching the Claude account on 2026-10-14 broke every running session, and the repair took store writes,
     per-session unlocks, login grants, pauses and resumes. Behind it: router features got a general shell on
     secret-holding machines for things that are not shell work, and the permission mode could change on a running
     session without the cert.
     *What*: objects are sources (infinitely many, created by the phone), Fly machines and one sink holding ⊤; every
     object has keys (hash-to-curve for sources and the sink, so a grant there seals to nobody). A succession cert carries
     a permission pair (allowed covariant, conditions contravariant, exact strings, finite or cofinite); the succession
     notarizer checks a policy table and answers the log notary; the grant mover gives the successor G ⊓ P and never
     refuses; the grant merger joins grants with identical conditions; the spawner attests Fly facts with P = ⊤; the
     identity signer signs (M, M, P) for narrowing; the gullible signer ends things; root signs anything. Only a source can
     be burned. Widening only out of the sink. Start settings live in the source, so the permission mode is fixed for life.
     Stores are grant strings; secrets never locks by itself and serves every written key at once; writing secrets is
     protected only by the router. Pause/resume/destroy/end are the router's lifecycles. Peer messages are out of scope.
     *How it was reached*: policy as data over control flow; structure (ideal objects: sources, the sink, identity edges,
     a signer that signs anything) instead of special branches; the kernel checks only ⊆/⊇ and a table, everything
     needing the clock, a hash or memory belongs to the guard.
167. **Upgrade is a ladder with no top: each step doubles the memory** (Deyao, 2026-10-15: "keep tapping Upgrade to go
     to 16 GB, 32 GB and beyond"; no "biggest size", no fixed last rung). Sizes are small (2 GB), medium (4), large (8),
     then `16gb`, `32gb`, `64gb`, … (`router/sizes.go`; the same block is in `core/fly.go`, which makes the guest, and
     `machine/deliver.go`, which names the sizes in the `upgraded` text; `TestSizeBlocksMatch` keeps them equal).
     *Guests* follow Fly's rules (fly.io/docs/machines/guides-examples/machine-sizing: ≤ 2 GB per shared CPU, 2–8 GB per
     performance CPU): up to 16 GB shared (16 GB = 8 shared CPUs, the most a shared guest holds); past it performance,
     keeping large's 8 CPUs, or memory/8 CPUs once the memory needs more. A step never lowers the CPU count, so 32 GB is
     performance-8x rather than the cheaper performance-4x.
     *Prices* in lhr (fly.io/docs/about/pricing, its calculator read 2026-10-15: a vCPU-second shared 8.465e-7 /
     performance 1.2732e-5 with 0.25 / 2 GB included per CPU, a further GB-second 2.316e-6, lhr markup 1.134615385):

     | size | guest | USD/hour | hours to the USD 30 cap |
     |---|---|---|---|
     | small | 2×shared · 2 GB | 0.0211 | 1421 |
     | medium | 4×shared · 4 GB | 0.0422 | 711 |
     | large | 8×shared · 8 GB | 0.0844 | 355 |
     | 16gb | 8×shared · 16 GB | 0.1601 | 187 |
     | 32gb | 8×performance · 32 GB | 0.5674 | 53 |
     | 64gb | 8×performance · 64 GB | 0.8701 | 34 |
     | 128gb | 16×performance · 128 GB | 1.7402 | 17 |
     | 256gb | 32×performance · 256 GB | 3.4805 | 8.6 (Fly's preset list ends at performance-16x; Fly decides) |

     The budget's rates (`router/budget.go`) are now that calculator's, so the cap counts big rungs right.
     *No invented limit*: a size Fly can't make fails at Fly; the Upgrade job then ends with Fly's own error and the
     session resumes on its old size (`resumeBigger`), so it isn't left down (the line's last machine is unused until a
     cert names a successor, so the core answers the second resume as it did the first).
     *Release*: the core's part is behind `jarvis2/core-pin: hold` with the held core (165); until it is live, the
     running core refuses sizes past large ("size: small, medium or large"), and an Upgrade from large ends with that
     error and the session back on large. The `upgraded` text of images from before this names only the three sizes, so a
     session on such an image moved past large gets no `upgraded` message (the router logs the refusal).
     *Not chosen*: a fixed list of rungs; a guest set by the router on a running machine (the core alone holds the Fly
     token and makes machines).

## Resume and API calls, 2026-10-15

168. **A resume the core won't answer by itself becomes the resume-upgrade approval in the Inbox** (Deyao, 2026-10-15:
     "Resume just works with my single tap"). *Root cause*: the core's `approve_by_dead_machine` compares the predecessor
     cert's image string with the challenge's, byte for byte, and a cert names what Fly reported its machine runs
     (`registry/repository@sha256:…`). Since 692658e the router named CI's pinned ref for that digest
     (`…:sha-…@sha256:…`) in every resume, so every same-image resume of a pinned line was refused with "store set,
     image or options differ from the predecessor's" (2026-10-15: "Jarvis Core rebuild" stayed paused). *What*: an
     unattended resume names the cert's own image string (`certImage`); a resume the phone approves (a prompt, a
     rollback, a mode change, a newer image) names CI's pinned ref, whose signature the phone checks. When the core still
     refuses the unattended resume with that 403, the router files the `resume-upgrade` approval on the same image
     itself, so the app's Resume, the web page's, the session actions' and the setup resume all end in one Face ID,
     never a retry or a `{upgrade: true}` call. Any other refusal (a predecessor that isn't a killed, unused machine)
     stays an error on the paused session. The unattended challenge takes its stores, harness, options and image from the
     cert itself, the very things the core compares.
     *From failed too*: a `failed` session with no machine is resumed like a paused one (the core marks a predecessor used
     only at certify, so a start or certify that failed leaves the line where its pause left it); a new line that never
     got a cert gets its `new-session` approval again (`startAgain`, `Approval.Again`: Deny leaves it failed instead of
     removing it). Both apps show Resume for such a session. A failed session that may still have a machine (a pause cut
     off) is not resumed. The 2026-10-15 `/start` failure ("context deadline exceeded (Client.Timeout exceeded while
     awaiting headers)") was the router's 15-minute client timeout: the core's Start is one Fly create bounded by its own
     90 s client and holds no lock across it, so the core process itself didn't answer for 15 minutes: the box, not the
     code (the same day's box incident has its forensics Job in k8s/apps).
     *Not chosen*: matching by digest in the core (a core change behind the
     `core-pin: hold`, and the router-side fix suffices); retrying on the newest image (that changes the image, which
     Deyao didn't ask for). The match is on the core's refusal text; the core's text changes only with a core release.
169. **An API call has its own review sheet, which stays up for the core requests the call brings about** (Deyao,
     2026-10-15). The `api-call` Inbox item opens a sheet (iPhone app `APICallReviewView`, web page `pages/APICall.tsx`)
     with the call (method, path, body), who asked and the reason; Approve runs it (no Face ID, 158). The router links an
     approval to the call that made it: the call runs with its request id in the context (`viaCallKey`), the handler's
     origin carries it (`Origin.ViaCall`), and filing the approval adds it to the call's kept result (`Followups`). A
     handler whose work may file one later (a resume asking the core) says so before the work starts
     (`expectFollowup` → `Awaiting {session, until}`, 1 min); filing the approval or the work ending without one
     (`settleFollowups`) clears it, and a failed call waits for nothing. The sheet reads
     `GET /api/requests/calls/:id` and waits on exactly that, never on a guess: each open follow-up opens its own
     approval page inside the sheet (What you sign (exact), Face ID) and comes back to it. The web page can't sign: it
     shows each follow-up and waits for the iPhone app's Face ID (or denies it). *Not chosen*: the sheet watching the
     Inbox for any approval of the call's session (an unrelated approval would be shown as the call's), and a fixed wait.

## Downgrade names its mode, 2026-10-15

170. **`jarvis2 downgrade` takes `--keep STORE…`, `--drop STORE…` or `--none`; bare store names are refused**
     (Deyao, 2026-10-15). Twice a session meant one of keep/drop and ran the other (the command read its names as
     the keep-set, the claude-env skill's `downgrade.sh` as the drop-set), and the session lost every store it wanted.
     Now the mode is always spelled out, every name must be a store the session's newest cert holds (a typo or a
     store already gone changes nothing), and `--drop` that would leave nothing is refused (that is `--none`). The
     keep-set is worked out from the cert inside each try, so a retry after an add-store uses the new list.
     Session images from before this keep the old reading (names = keep); the claude-env skill's `downgrade.sh` is gone.

## The control plane owns 2 GiB of the box, 2026-10-15

171. **Core, router and cloudflared hold 2 GiB and 0.9 CPU of the box as their own; everything else is capped**
     (Deyao, 2026-10-15, after the box thrashed and took the control plane down with it). Memory requests equal limits
     for the control plane (router 1536 Mi, core 256 Mi, cloudflared 2 × 128 Mi = 2048 Mi), so the scheduler keeps that
     memory free for them and the kernel kills a pod over its request before them; CPU is requested (router 500m, core
     200m, cloudflared 2 × 100m) but not limited, so under contention they get their share and are never throttled.
     Every other service has a hard memory and CPU limit (search 2 × 448 Mi / 500m, watch 2 × 192 Mi / 250m), so a
     runaway job is killed at its cap instead of pushing the node into swapless thrash. icloud-index is off (0
     replicas): at up to 2 GiB with ffmpeg it can't sit beside the control plane on a 4 GiB box. *Not chosen*: a
     PriorityClass or a ResourceQuota for the other services — both need permissions the bootstrap doesn't give Flux
     (admin in the three namespaces only, nothing cluster-scoped; a change means a box rebuild).

## Batch Allow all: every add-store after the first failed, 2026-10-15

172. **A waiting add-store is made again from the session's new cert, and the batch page signs it as it is then**
     (Deyao, 2026-10-15: "batch approval is buggy, sometimes only the first request succeeds signing"). *The cause*,
     from the router's own outcomes: the failed items were add-stores for one session. Batch b820f7dcea03177ee
     (5 add-stores for s9bda92994266c781, 02:11 UTC) went in over several rounds (item 5 alone at 02:11:50; at 02:12:15
     two stores in and three still waiting; all five a few seconds later), and Deyao reported the bug at 02:15;
     ba07c5f9390738c4b (2 add-stores for
     s71b971c6bf7328de) went in 7 s apart (item 2 04:09:14, item 1 04:09:21: a Retry), while b986f9a3177e8d687 (2 deploy
     keys, each a signature and a share) went in 1.3 s apart on one Allow all with the same app, so the Face ID context
     was never it. Every add-store is a challenge the router makes from the session's cert when it is filed
     (`stores = cert's + X`), and the page reads every item before the Face ID. The live core (k8s/apps/core.yaml:
     sha-06ab2452f8ad, the held core waits for Deyao's go) answers a challenge exactly as made, so the second answer
     named the cert both were made from and lacked the first store; `respondAddStore` refuses to store such an answer,
     files the approval again from the newest cert and returns "another store was added to this session while this
     approval waited: approve it again" — the failed item. One store per round, so "only the first" every time a batch
     has two add-stores for one session; batches of other kinds (grants, deploy keys) were unaffected, hence
     "sometimes". Reproduced by router/addstore_test.go `TestABatchOfAddStoresForOneSessionAllGoInAtOnce` (fails with
     exactly that error without the fix). *The fix*: (1) the router: whenever a running machine gets a new cert (an
     add-store answered, a downgrade finished) every other add-store waiting for it is made again from that cert
     (`rebaseAddStores`), keeping the earlier challenges (`earlier`) so a phone that signed one while its page was open
     is still answered (tried after a 403 on the current one); (2) the app's batch page reads an add-store's challenge
     again right before signing it and signs a new one only when it is the same ask (`Checks.sameAddStore`: the same
     store, machine, session line and title, mode, harness and settings, the store's sensitivity, and no store but
     those the reviewed challenge named or this batch just added), once more if the router made it again during the
     signing; an unlock reads the session's cert again for the nonce it is for (an add-store before it gives the
     session a new cert). "What you sign (exact)" shows "Stores when asked" of the challenge reviewed; the one signed
     may also name the stores this batch added before it (the R1 core's addOnto answers so anyway, 157). Works with
     either core. (3) `PhoneKeys.authorize` is `evaluatePolicy` again (0e1f12f reverted: no throwaway signature with the
     phone key). *Not chosen*: an app-only fix that re-signs after the router's "approve it again" — it works, but
     every extra store costs a stale core answer the router throws away; a core release (the held core already answers
     onto the newest cert) needs Deyao's go and a Recover, and the batch must work before it.


## Core continuity: the same kit makes the same core, 2026-10-15

173. **The core's keys come from the master key; its line state comes back at a Recover; the cores hand over to each
     other** (Deyao, 2026-10-15: a hard reset and then a resources change each forced a Recover, and each cut every
     session off; "even the current design allows my iPhone to sign arbitrary certs"; supersedes 69's "a new core
     destroys the earlier core's sessions" for a Recover with the same kit; DESIGN "Core continuity").
     - *Chosen: derive the core's keys from the kit.* The app sends HKDF(master scalar, `jarvis2/core-seed`) in the
       sealed claim bundle; the core derives its signing key, store share K, carry, nonce and line-state keys from it
       (`core/continuity.go`), and the master-signed statement names the derived public keys (`identity`), so a
       derivation mismatch fails at the claim, not later. No machine code changes: `JARVIS2_CORE_KEY` stays right for
       every image, old ones included. Security cost: the kit now also yields the core's private keys. The kit already
       opens every backup, so its loss was already total; the core key adds impersonating a core to machines, which
       gives nothing the backups didn't. The seed exists outside the core only on the phone during a Reset/Recover.
     - *Chosen: a sealed line state the router keeps* (newest cert per machine, created/initialised machines, killed,
       used, spent approvals, the input log's head, the stores as wrapped entries), fetched by the router whenever
       `X-Line-Seq` moves, before the answer goes on (`router/linestate.go`), copied to the bucket every ≤5 min and at
       the drain. The app checks it against the derived key and refuses one older than the newest `lineSeq` it has seen
       in the core's state. A key without its state would be unsafe (superseded certs, burnt lines and used
       predecessors would all be live again); the state without a witness lets the router roll back what happened
       since the app last looked: accepted, bounded, and never more than an earlier point of a line Deyao approved.
     - *Chosen: the deploy-key stores travel in the line state* (wrapped to P + K, no plaintext), so the app keeps its
       Secure Enclave keys across a Recover (Reset still renews them). A Recover on another phone still loses them
       (Make key again). *Not chosen*: a master-sealed backup of each deploy key written by the app (more app and
       router code; worth adding for the lost-phone case).
     - *Chosen: handoff / standby / takeover in the core* (Deyao's blue/green): a serving core seals a FINAL state on
       the router's call and stops; a standby Recover serves only from a final state at least as new as the one it was
       Recovered with. At most one core with these keys serves in a planned move. A crash Recover (no final state
       possible) serves at once: there the old core being gone is the guarantee. The app doesn't offer standby yet; the
       blue/green flow adds it.
     - *Chosen: archives from earlier cores restore through the master key's claim of that core* (`core-cert.json`
       in every archive; the running core's signed state names the master).
     - *Not chosen*: a master-signed chain of core keys that machines accept (every machine image would need the new
       check, and every running session on an old image would still be cut off; the core would still lose its line
       state). *Not chosen*: the phone re-signing live certs at Recover (machines on old images reject the new core
       key anyway; the phone can't tell the newest cert of each line from the router's word; one Face ID per Recover
       per line). *Not chosen*: a monotonic anchor at a provider (the core writing its state head to the bucket or Fly
       metadata with its own credential, which would close the rollback above): a new credential and network path for
       the core; the next step if the rollback bound isn't enough.
     - The sessions running when this was released were made by a random-key core: no later core can sign for them,
       so they end once more at this release's restart. `router/corechange.go` now marks only sessions whose cert the
       running core's key didn't sign, and only once the core is set up.
## The iCloud index rolls out without a gap, 2026-10-15

174. **The iCloud index runs search's pattern: two replicas on one volume, a writer lease in the database** (Deyao,
     2026-10-15: the box redesign brings the index back on the services box, and "deploy" means zero downtime).
     `services/icloud-index/icloud_index/lease.py` is the twin of `services/search/lib/lease.js`: kv `writer`
     {holder, since, until}, renewed every `TICK_S` (5 s) inside BEGIN IMMEDIATE, released on SIGTERM, lapsing 45 s
     after a kill. Both replicas answer searches; only the holder runs the lister, the worker, the embedder and the
     backup. Claude's choices:
     - *Every write and every AI call checks the lease first* (`Indexer.check()`, raising `Stopped`): a replica that
       lost the lease (frozen past the TTL, then back) can't finish a file it had begun and write it, or spend on it.
       *Not chosen*: trusting the threads to notice the stop flag (a file can take minutes: ffmpeg, a download).
     - *A file half read at a clean stop gets its try back*: the 3-try limit is for files that kill the process, and
       a rollout isn't one.
     - *A reader's /relist and /retry are kv requests the writer takes at its next tick* (as search's reindex).
     - *Readers reload their vectors when kv `index_version` moves* (the writer bumps it after each embedding batch).
     - *The backup's rhythm lives in the database* (kv `last_backup`), so a handover doesn't start a new 8 GB staging
       copy; *seeding a missing database takes a file lock* beside it, so two replicas starting on an empty volume
       download the copy once.
## A pause never loses a session's state, 2026-10-15

After session sb8e0273d6c308894 ("k-matrix clone: interactive 5") lost its conversation: its disk was full, the final
snapshot failed with "no space left on device", the machine was destroyed anyway and the resume started empty.

175. **The final snapshot streams to the router; the machine needs no free disk for it** (`machine/snapstream.go`,
     `router/snapstream.go`). The tar.gz is made straight into the request body (`POST /m/snapshot-stream`, signed over
     the marker `stream` because the hash isn't known before the bytes, and checked before the router takes a byte); the
     router answers the hash of what it stored, the machine compares it with its own, signs it and commits. The R1 rule
     stands: one signature per machine, after the session is stopped; a later command commits the same one, and a commit
     that never arrived is redone only if the frozen files hash the same. A failure is reported at once
     (`/m/snapshot-failed`) and, with nothing signed, the session is let go on (SIGCONT) so space can be freed. A router
     without streaming gets the old whole-file upload. *Not chosen*: HTTP trailers for the signature (proxies drop them);
     compressing to a tmpfs (RAM is the next thing to run out).

176. **A machine whose final snapshot fails and that has no volume is kept, never destroyed; Deyao gets a "needs you"
     DM** (`router/snapsafe.go`). Failure = an error the machine reports, no snapshot within `SNAPSHOT_WAIT`, or a booted
     machine silent for 3 min (it can't send one). The session goes `failed` with its machine and `snapshotFailed`; Pause
     again retries, Destroy anyway (`force`) goes on without it. A kill that can't finish (the core's backup or destroy,
     45 min) also keeps the machine and DMs. A machine paused while still booting signs its predecessor's snapshot (its
     cert names it; the machine has no state of its own yet) and the router links that file, so a pause during boot no
     longer leaves the line without a snapshot. *Not chosen*: retrying the snapshot in a loop (a full disk stays full).

177. **Each machine keeps its state on its own Fly volume, and the core backs the volume up at every kill**
     (Deyao, 2026-10-15; `core/volumes.go`, `machine/volume.go`). The core (the only Fly token holder) makes a new, empty
     volume with each machine (`/data`, default 10 GB, encrypted, Fly's daily snapshots on); the machine bind-mounts the
     snapshot's directories from it (paths unchanged, so Claude's project names don't move) and copies the single files
     there every minute. At the kill, after the machine's own snapshot or after it failed or timed out, the core stops the
     machine, takes an on-demand snapshot of the volume, and only once Fly reports it `created` destroys the machine and
     deletes the volume. The kill's signed record names the backup (volume id, snapshot id, retention); the session lists
     it (`backups`, app and web page). **No resume or restore reads a backup** (Deyao, 2026-10-15): a successor gets a
     new empty volume and its state from the predecessor's signed snapshot only, so a volume never carries one line's data
     to another machine; the backup is for recovery by hand. A line whose last kill named no signed snapshot doesn't
     resume (`noSnapshot`: it would start empty): the session says why, Deyao gets a DM naming the backup, and Destroy
     still archives the newest signed snapshot. Fly keeps a deleted volume's snapshots for their retention, reachable by
     the volume id the record keeps. The live volumes and the backup records go in the core's line state
     (DECISIONS 173), so a core that takes the line over still backs up and deletes those machines' volumes. **Retention: 3 days when the machine also signed its own snapshot** (the backup is a
     second copy), **60 days (Fly's longest) when it didn't** (then the backup is the only copy of that state); the
     retention is set on the volume just before the snapshot. *Price* (fly.io/docs/about/pricing, 2026-10: volumes USD
     0.15/GB-month provisioned, snapshots USD 0.08/GB-month stored, the first 10 GB of snapshots free): a 10 GB volume
     costs USD 1.50 per machine-month while it runs, nothing while paused (it is deleted); at about 3 running machines on
     average that is about USD 4.50/month, which `router/budget.go` already counts (it bills provisioned volumes).
     Backups: about 10 pauses a day × 3 days × ~3 GB of state ≈ 90 GB stored → about USD 6/month after the free 10 GB
     (less if Fly's incremental storage shares blocks); each failed-snapshot backup adds ~3 GB × 2 months ≈ USD 0.50
     once. The budget cap counts both (180). Needs the
     held core release (the `core-pin: hold`), and the core's narrowed Fly token must allow volume calls: its caveat is
     `Apps {jarvis2-sessions: rwcdC}` with no per-resource limit, which should cover volumes; check on the first start
     after the release (a refusal shows as `start: fly create: volume: … 403`). *Not chosen*: restoring from the backup
     automatically or from Fly's daily snapshots (Deyao: recovery from them is his decision, by hand); one volume per
     session kept across pauses (it would bill while paused, and a router could then start any machine on it).

178. **Disk is reported like memory, warned about before it fills, and grown with More disk** (`machine/disk.go`,
     `router/disk.go`). Every 30 s the machine reports its root disk and its volume; the volume is the disk that counts
     when there is one. Under 10 % or 1 GB free starts an episode: one DM, `diskAlert` on the session, ending at 20 % and
     2 GB free. More disk (`POST /api/sessions/:id/disk`, a button on the session in the app and web page) has the core
     extend the volume to twice its size (at most 500 GB); the session's `diskGb` keeps the size for every later machine,
     and when Fly says the machine must restart to see it, a pause and resume follow (as Upgrade does). A machine without
     a volume (until the held core is live) can't grow: the alert says so. *Not chosen*: Fly's automatic volume extension
     (`auto_extend_size_*`): a runaway build would grow the bill without anyone seeing it; and a bigger root disk
     (Fly `config.rootfs.size_gb`, the earlier unpushed attempt on branch snapshot-fix): the state must live on a volume
     anyway for the core's outside backup (177), a volume grows in place (often with no restart) where a root disk needs
     a new machine, and one disk to watch and grow is simpler than two. That branch's phone-approved resume fallback
     (newest line snapshot + live transcript) is dropped too: Deyao wants no resume fallback (176, 177).

## The router moves between boxes, its state is backed up, the core flips, 2026-10-15

179. **The router moves to another box by the same handover as a rollout, over the private network; the core moves
     with it as a flip** (Deyao, 2026-10-15: layout A, a box of its own for the control plane, the move with "as little
     downtime as possible"; `router/move.go`). The new box's router is a candidate that proxies to the old one and
     copies `/data` every minute; at `MOVE_AT` the old one drains, freezes and hands over its files and its WireGuard
     peer, and from then on is only a proxy (`/data/router.moved`, for good). Claude's choices: *pull, not push* (the
     new box copies; the old box needs only a listener with a shared bearer key, `MOVE_KEY`, on a port the private
     network reaches); *size + mtime for the pre-copies, and the final delta refetches every file under 1 MB and
     everything touched since the last copy* (a same-size rewrite within one mtime tick, state.json's case, would
     otherwise be missed); *the peer moves in `/data/wg.conf`, which wins over `WG_CONFIG`* (the machines'
     `jarvis2-box._peer.internal` must keep its address, and a new peer of the same name would cut them off until it
     is made); *a trigger in git (`MOVE_AT`)*, not an API call (the box changes only through git); *a failed freeze or
     delta aborts and thaws the old box* (state, peer and drain back); *a refused takeover is not undone* (core
     continuity: a handed-off core stays handed off; the final state is kept for the retry and Deyao is DMed).
     *The flip* (`router/nextcore.go`): every `/api/core/*` relay takes `X-Jarvis2-Core: next` / `?core=next`, the
     state names the serving core (`activeCore`) so a restart keeps it, and `FLIP_AUTO=1` flips once the next core is
     a standby. *The state backup* (`router/backup.go`, Deyao: "router state backed up to the Storage Box"): age to a
     key whose private half is in `infra`, not on the box (the Storage Box is shared with Jarvis 1's sessions); the
     snapshots once each, the rest every 15 min when changed, 48 kept; a rebuilt box restores with `ROUTER_RESTORE=1`.
     *Not chosen*: rsync or a shared volume between boxes (no SSH, no shared storage); a Job that copies through the
     Storage Box at the cut (minutes of downtime).
## The budget cap counts everything Fly bills for the sessions, 2026-10-15

180. **Volume snapshots are in the Fly budget estimate, beside machines and provisioned volumes** (`router/budget.go`).
     Prices from fly.io/docs/about/pricing, read 2026-10-15: started machines per its calculator (unchanged), volumes
     USD 0.15 per provisioned GB-month (already counted), volume snapshots USD 0.08 per stored GB-month with the first
     10 GB free. Every 30 min the router lists the snapshots of each volume Fly still has and of each deleted volume a
     session or record names a backup of while its retention runs (Fly keeps those snapshots, and bills them, after the
     volume is gone); each snapshot is counted once by id, failed ones not at all, and the stored GB past the free 10
     add to the hourly burn the cap sums. The read-only token (`Apps {jarvis2-sessions: r}`) can list snapshots. A
     failed list keeps the last one it got (logged). `GET /api/state` `budget` shows `snapshots` and `snapshotGb`.
     *Not chosen*: Fly's billing API (the org's invoice needs a token that can see billing, more than read on one app);
     counting snapshots at their volume's size (Fly bills the stored, incremental size, which its list reports).


## Failed sessions, repo stores and API calls in a batch, 2026-10-15

181. **A failed session comes back with one tap and can always be destroyed** (Deyao, 2026-10-15). Stuck that day:
     "Jarvis Core rebuild" (start: core /start timed out), "Jarvis 2" (start cut off by a router restart), "Draft reply
     to image" (kill: a Fly destroy timed out), and five sessions whose kill the core refused ("the snapshot isn't signed
     by machine …'s current key": machines certified by the core from before the 2026-10-15 Recover, for which this
     core has no key, so it refuses every snapshot claim). *Resume* takes any failed session: with no machine as 168
     says; with one, it first finishes the pause (the final snapshot, the same one again if the machine took it, then
     the kill) and resumes from it, on the same tap. A kill the core refuses (403) leaves it failed with the error.
     *Kills* that fail on the way (502: Fly's API timing out; the core not answering) are tried again 4 times, 30 s
     apart; refusals are final. *Destroy* never restores anything, so when the core refuses the snapshot claim it kills
     without one: the core still destroys the machine, the router's own copy of the snapshot (checked against the
     machine's key when it arrived) is archived to the Storage Box as usual, and the record (`snapshotNote`,
     `archive.unverified`, `session.json` `snapshotUnverified`) says "from an earlier core, not verified by this core";
     restoring such a record is refused until the core release that carries old lines. (Restored on top of 175-180 after 51b7bbd
     dropped it: the kill path is snapsafe.go's, these fallbacks only on a destroy.) A destroy whose kill still
     fails goes on when Fly (the router's read token) has no such machine; otherwise it is failed with "… (Destroy anyway
     removes the session; the machine is then on the Machines tab)", and Destroy anyway (`?force=1`) destroys it: the
     router stops taking the machine's calls (its `started` key goes) and the Machines tab treats a destroyed session's
     machine as an orphan, whose Destroy tries the kill again. *The /start timeout was ours* (168 said the box): the
     running core (sha-06ab2452f8ad, from before R2) waits inside /start (a create, up to 10 waits for "started", up to
     10 init execs, each Fly call bounded by its own 90 s client: ≈ 34 min at worst) and /kill (≈ 32 min), and the router
     gave up after 15 min, failing a start the core was still carrying out (and leaving any machine it then made unknown
     to anyone). The router now waits 40 min for /start and /kill (`coreCallTimeout`); other calls keep 15 min. The held
     core's start is one Fly call, so this matters only until it is live.
182. **A repo a session asks for lands in that session in the same approval** (Deyao, 2026-10-15: one Face ID). A
     session's `repo/add` (alone or in a batch, through its requests or its actions) names the asking session
     (`params.session`; `noStore: true` opts out, for a repo meant for a proposed session); the Inbox shows it
     (`open.options.into`, `intoLabel`, `store`) and the call's args carry `into`. When the key is finished
     (`POST /api/repos/key/finish?inbox=ID`), the router files an add-store of `github-<repo>` for each running session
     that asked and doesn't hold it, at once (the core makes a challenge only for a store it has), and answers the one
     for the request the phone answered as `followups` beside the core's document. The phone showed it before Face ID
     ("then adds the store to session …"), checks the challenge is exactly that store for that session, and signs it
     under the same Face ID. Other asking sessions' add-stores wait in the Inbox on their own; a session that isn't
     running gets none. The add-store's origin is the request's caller and call without its signed filing (the session
     hears the repo's outcome; `jarvis2-request add-repo` starts the store's waiter). An app from before this signs the
     add-store as a second item, as before.
183. **An API call can be an item of a batch** (`{"intent": "call", "method", "path", "body" | "bodyText"}`), from a
     session's requests or its actions only, checked exactly as a single call request (callRules) before anything is
     filed. It is an `api-call` request in the batch; the phone's Allow all approves it with the others (no Face ID of
     its own, 158) and then shows what the call brought about, each follow-up on its own page with its own Face ID
     (169: it wasn't shown before the batch's Face ID). Its result is read by the session through either of its
     credentials (`GET /m/api/actions/requests/call/:id`), and its outcome arrives as the batch's item.

## The release of core continuity keeps today's sessions, 2026-10-15

184. **An earlier core's sessions are taken over at their kill, not destroyed** (Deyao, 2026-10-15: "he's doing real
     work in his running sessions": no session destroyed by the release, each moves over at its own next pause; DESIGN
     "Core continuity"). `POST /kill` takes `legacy: {cert, coreCert}`: a cert of a core the running core's master key
     claimed (the claim the router kept; it now also keeps the running core's own claim when it has none:
     `keepRunningClaim`), with the snapshot the cert's machine key signed; the core records the kill and answers the
     same cert signed by itself (`adopted`). The router sends it for any machine whose cert the running key didn't sign,
     takes a paused session over at once and a running one at its pause, and never destroys a session whose earlier core
     a kept claim names. The first resume of each waits for one unlock (the earlier core's carry key is gone; nothing but
     the phone opens the stores), which the router files as an Inbox request when the pull first waits (`CarryLost`).
     Proven with `infra/e2e.sh` E2E_ONLY=legacy against production's core of the day (06ab245): a running and a paused
     session on it, the restart to this core, the paused one taken over at once, the running one at its pause, both
     resumed with their snapshots and secrets after one unlock each, and a second pause/resume carrying the secrets as
     usual. *Not chosen*: re-sealing the earlier carry blobs (the earlier core has no such call and can't get one
     without a restart); a standing unlock of every store at the release (opens every store to every session).
     *Trusted to the router*: which earlier cert of a line is the newest (an older one has fewer stores; a downgrade's
     key signs the snapshot) and that an earlier line isn't taken over twice from two of its machines: once per
     machine, for claimed cores only.

## Claude accounts: one Claude key store per account, 2026-10-15

185. **Several Claude accounts, one Claude key store each (`claude-<name>`); a session's account is picked when it is
     made and kept for its life** (Deyao, 2026-10-15: "there should be multiple claude key stores, one per account, so I
     can choose which account a session starts with and the session uses it (refreshed automatically), and I can manage
     the accounts in the dashboard"). Replaces 116's "the router alone picks which Claude account sessions use".
     *Built* (`router/claudeaccounts.go`, `router/claudelogin.go`, `machine/claudelogin.go`; API "Claude accounts";
     RUNBOOK "The Claude accounts"): one login hub per account, its pair on the router's volume
     (`claude-accounts/<store>.json`), each refreshed by the router alone with the same refresh protocol (115-118), its
     participants the machines of its own sessions. `Session.ClaudeAccount` is set when the session is made (New session
     in the app and web page, `jarvis2-request new-session --account`, a prompt task's instance, a restore: the account
     it ran on, a Jarvis 1 import) — named, else the default one Deyao sets — and a resume keeps it; a running session
     never switches. Harnesses that need one say so in the policy (`claudeAccount`: claude, openclaw). Settings → Claude
     accounts (web and iPhone): each account's login state and usage, Refresh token, Re-login (must be the same Claude
     account; another one is refused, and one account can't be in two stores), Make default, Remove (refused while any
     session uses it, and for the default), Add (a name, then the sign-in).
     *Why the router's stores, not the core's*: the pair rotates every 8 hours with nobody there (115), and the core's
     stores take keys only from the setup session or a session, so the router can't write one; an empty core store can't
     be put in a cert or unlocked. The account is therefore the router's word (Session.ClaudeAccount), like the pair
     itself: Deyao, 2026-10-15, "trust the router", no machine-side account check. Signed in the cert's config
     (`claudeAccount`, shown on the phone's review page and checked against New session's pick) only once the router
     runs with `SIGN_CLAUDE_ACCOUNT=1`: phone app builds before the one that knows the key refuse settings they can't
     show, so the switch is set after that build is on Deyao's phone (until then it is shown beside the approval as
     `options.claudeAccount`). New prompt-task instances on the iPhone pick the account too.
     *A broken login*: no automatic action (Deyao, 2026-10-15): its sessions stop on "Please run /login" when their
     token runs out; the dead-login DM names the account; Deyao re-logs it in, and "continue" follows as before.
     *The clean cut* (CLAUDE.md "Migrations: clean cuts"): every reference to the core's store `claude` changes at once,
     with no alias. The first router with accounts turns `claude-login.json` into `claude-<its email's name>` (the
     default, and the account Jarvis 1 follows) and gives it to every session and record whose cert names `claude`:
     running sessions keep what they have (their machines keep polling and now get that account's pair; nothing is done
     to them), paused ones resume on it. New sessions no longer get `claude` (the policy brings `tunnel` only), the
     router refuses it in `stores` and add-store, and the pickers hide it; the store stays in the core for the older
     lines (a store can't be deleted). Machines ask the router whether their session has an account (404 `noAccount`
     otherwise) instead of looking for the store in their cert. A new box with no account starts sessions logged out.
## Two boxes, logs in Grafana Cloud, 2026-10-15

186. **The control plane gets a box of its own; shared services and experiments get another** (Deyao, 2026-10-15,
     layout A of the redesign, after the thrash: "an unimportant job must never bring down the control plane").
     A cx23 control box and a cx33 services box (EUR 6.588 + 10.188/month gross, Hetzner API), separate k3s and Flux, joined by a Hetzner Network (free).
     DESIGN "The boxes". Claude's choices inside it: *The control box is a cx23* (EUR 6.588/month): cx33 and cx43 were sold out
     in every EU location that day (Hetzner API: available=false), and Deyao chose the cx23 over waiting or a cpx32
     (EUR 42.588). It holds because the router measured small (`/setup/status` → `process`: 48 MB RSS at start, 171 MB
     peak after 40 min, 2026-10-15): ONE router whose rollout surge pod is the standby (no standing standby), 512 Mi
     requested / 1 Gi limit; two cores at 192 Mi; two cloudflared at 128 Mi; only Flux's source and kustomize
     controllers; kubelet reserving 512 Mi with eviction at 200 Mi free; the memory-pressure alert shows if it is tight. *One Flux Kustomization per app*:
     a refused manifest holds back only its app. *The services box's NodePorts on the private address only, plus a
     mangle-table guard at boot*: Hetzner Firewalls don't cover private interfaces. *Search's Role in the bootstrap*:
     Flux's dry-run refuses a RoleBinding to a Role made in the same apply (it did on the services tree too). *Two
     primary-IP and four core slots freed by deleting the old YYC server yyc-stream* (Deyao's OK): the account is at 10
     primary IPs (IPv6 primaries count) and 20 shared cores. *Not chosen*: one cluster with two nodes (shared apiserver and
     Flux: the 2026-10-15 backlog would still land on the control node), one bigger box (shared kernel, disk and reboots).
187. **Logs and metrics go to Grafana Cloud Free (EU Germany), from Alloy on each host, and session machines' logs from
     Fly's log shipper** (Deyao, 2026-10-15). Claude's choices: *Alloy on the host, not a pod*: it must keep shipping when
     the cluster on that box doesn't, and Pod Security "restricted" forbids the hostPaths it reads (rightly: the disk
     holds the user-data with the box key). Its config comes from git (`import.git`), its token from a SOPS Secret a host
     timer copies, so nothing about it changes outside a commit. *Persistent journald*, so a hard reset's last minutes
     still reach Grafana. *Secret shapes replaced before shipping* on the boxes and the Fly shipper. *The Fly shipper
     without Vector's API or metrics port*: it sits in the sessions' org network, and the API's `tap` would stream every
     session's log to any machine there. *The Grafana account is a GitHub login (DE0CH)*: email signup's Turnstile never
     cleared from a session (Browserbase out of credit, IPRoyal's residential balance empty), and DE0CH's GitHub carries
     chendeyao000@gmail.com. *The log read token lives in the new store `jarvis2-ops`, not `infra`* (the decision said
     `infra`): `infra` held keys this session didn't, so the old core's whole-store write would have dropped them, and the
     tokens had to be stored before the core release; `jarvis2-ops` holds all of Jarvis 2's operations credentials
     (Grafana tokens, the alert webhook, the probe token, the router's backup key), written only by the setup path.
     *Alerts to Discord #jarvis2-alerts* through a webhook; rules as code (`infra/grafana.py`). *The external probe on
     `/healthz`* with its own path-scoped Access app and one service token, never past Access.

## Subagents and background jobs on the session card, 2026-10-15

188. **A running session shows how many subagents and background jobs its harness runs now** (Deyao, 2026-10-15: "the
     number of subagents/workers of a session on the dashboard"). Claude's choices: *Claude Code's documented hooks are
     the source* (code.claude.com/docs/en/hooks): Claude Code documents no live list of its tasks from outside (not in
     `claude agents`, the statusline, the registry file or a CLI command; its task output under `/tmp/claude-<uid>/` and
     subagent transcripts stay after they end), but `Stop` and `SubagentStop` carry `background_tasks`, the harness's own
     in-flight list with a type per task (shell, subagent, monitor, workflow, teammate, …). Each such list replaces the
     count; between two of them `SubagentStart` adds the agent and a `PostToolUse` with a `backgroundTaskId` (a background
     Bash, a Monitor) adds the job, so a new one shows within one status report (10 s). A job that ends in the middle of a
     long turn stays counted until the next subagent end or turn end (no hook marks it). *Foreground subagents count too*:
     the list never names them (seen with a logging hook on 2.1.300), so they come from SubagentStart/SubagentStop, and a
     turn's Stop clears any left. *A stopping subagent's own list entry is dropped* (the list still has it as running).
     The harness's internal agents (empty `agent_type`: prompt suggestions, `/btw`) are not counted. *Installed by the
     machine at boot* (`jarvis2-machine workers-hook` in `~/.claude/settings.json`, next to whatever else is there), only
     for the claude harness; the counts live in `~/.claude/jarvis2-workers/<conversation>.json` (ids and types, never a
     command or a description; not in the snapshot; emptied on each boot and on SessionStart startup/resume) and travel
     in the status report (section `__WORKERS__`), not a new endpoint. The router keeps the host conversation's in its
     live state (`workers` in /api/state). *Subagents apart, other jobs by Claude Code's own type label.* *`bgTasks` stays
     as it was* (the process count the autopilot's idle and nudge rules use): changing what auto-pause sees is another
     decision. The hook never fails a turn: any error exits 0 with no output. New sessions only (the session image).

## A handover ends long polls at once and loses no delivery, 2026-10-15

189. **Every handover (rollout or box move) stops deliveries, quiesces the machines' peer and ends the requests in
     flight before the state freezes** (Deyao, 2026-10-15: running sessions keep reaching the router throughout, only
     the seconds of the gap may interrupt, no wakeup dropped; `router/movegate.go`). Claude's choices: *deliveries
     finish before the freeze* (a wakeup delivered and not yet cleared would otherwise fire again on the next leader);
     *the peer drops SYNs rather than refusing them* (the machine binary on running sessions doesn't retry: a refused
     dial is a failed call, a dropped SYN is retried by TCP until the next peer answers); *the next leader's peer comes
     up before it serves, with a handler that holds* (the dials land early, the SYN retry is the first one);
     *an app `exec` waiting for the machine's answer ends with "run it again"* (its answer goes to the next leader, and
     running a command twice by itself is worse); *the scheduler sleeps until the next item is due* (at most its 30 s
     tick), so a wakeup is late by the gap, not by a tick. Measured with `E2E_ONLY=move` on Fly (two runs): 396 ms / 1.36 s gap,
     450–550 probe calls per path (session API, lease, search) with none failed, an exec through `/m/commands` 0.8 s
     after the move, a wakeup due in the gap delivered once, 3.7 s after it was due. *Not chosen*: retries in the machine (running sessions keep their image until a restart).

## Every refusal protects something, or it goes, 2026-10-15

190. **A refusal stays only when it protects against a real threat or failure; the rest are gone, and the action does
     its safe part** (Deyao, 2026-10-15: "what does refusing to destroy even protect?"). The audit lists every refusal of
     the core, the router, the machine and the session tools with what it protects and its class (kept, removed,
     redesigned). What changed in the core (ships with the core at the move):
     *A kill never fails over the snapshot.* A snapshot claim the core can't check (another key's, a machine it doesn't
     know, an earlier core's line whose takeover doesn't check) no longer refuses the kill: the machine is killed, the
     record names no snapshot and says why (`snapshotRefused`), and its successor restores nothing. A destroy needs no
     vouched snapshot; only a resume does. A pause still would rather keep the machine than lose its state, so the
     router's pause asks for that (`snapshot.required`): then the kill is refused (409) with the machine untouched and
     the message says to Destroy instead or pause again. *Answered, not refused, when the outcome already holds*: a
     mark-sensitive of a sensitive store, a lock of an unlock that isn't open, a wipe of an empty core (nothing ends),
     an add-store of a store the cert already holds (the new cert keeps the same stores and reads the add-store's
     unlock, so the session gets the store as it is now). *A session's write may make a store* (sensitive, so it
     reaches no session without the phone); `github-*` names stay reserved for repo deploy keys (squatting one would
     block that repo's key). *The router writes the Claude account stores* (writer `router`, `claude-<name>` only,
     below). Messages of the kept refusals say what to do next.
     *The Claude accounts are core stores* (the coordinator's case, Deyao: "I thought write was free"). DECISIONS 185 kept
     the pairs in the router because the core took keys only from the setup session or a session. That refusal was a
     real protection with the wrong outcome: it keeps every key truthfully attributed, but the router gains nothing by
     being refused (it holds the pair in the clear and hands it to machines anyway). So the core takes writer `router`
     for `claude-<name>` stores only, unsigned and named "router" on every unlock (the phone accepts it for those stores
     only), and the router writes each account's `CLAUDE_CREDENTIALS` and `CLAUDE_ACCOUNT` into its store at every change
     (`router/claudestores.go`, from the login loop; a new core gets them within a minute). Claude's choices: *no bucket
     backup and no Inbox refresh for these writes*: an earlier pair is worthless once rotated, and running machines take
     refreshes from the long poll (an unlock every 8 hours would be the refusal again). *The router keeps its working
     copy*: the core gives a store back only with the phone, and the router must refresh with nobody there. *The cert
     names the account's store only with the router's env `CLAUDE_STORE_IN_CERT=1`*, set once the app that accepts the
     router writer is on Deyao's phone (an older app refuses that unlock, so every Start would fail). Also: Remove of the
     default account makes the next one the default (Remove stays refused while a session uses the account: Deyao's
     decision that a session's account never changes); a removed account's core store loses its keys; a sign-in of another Claude account than the store's is kept as that account's own (its
     store, or a new `claude-<its name>`, and the dashboard says it was added as a new account) instead of thrown away
     after the exchange; Add of an existing name is its
     sign-in; an account named for a harness that takes none is ignored; an add-store of `claude` gives a session with
     no account the default one.
     *Router, the machine and the tools* (each answer in API.md): what was already so is answered, not refused (Pause of
     a paused session, Resume of a running one, a deny or unpair or record delete of something already gone, a content
     store that exists); failed sessions take what paused ones take (permission mode, resume options, restart/env, More
     disk, an Upgrade's next size); a lapsed New session of Deyao's own stays as failed (Start again) instead of
     vanishing; an archive from an earlier core is restorable (the machine checks it, not a blanket refusal); a session
     may ask for anything for another session too (every item still needs Deyao: the "only for itself" rule was already
     bypassed by actions); an approved API call runs although its session paused (it runs as Deyao); a restore in a
     batch is filed beside it; a locked store no longer stops a machine starting (it starts with no secrets and pulls
     them at the unlock: the core seals a cert's stores all or none); `--drop` of a store not held drops the rest; a
     delivery with some items already delivered delivers the others; one bad attachment no longer drops the good ones;
     pull-secrets and content-sync work in a grant shell (the local proxy's address and token are fixed) and print the
     proxy's error; setup.py's delete, mark-sensitive and `--replace` stop demanding what they don't use, and a store
     the core calls not sensitive after a write is marked so and still backed up. Also: a wakeup in the past fires
     at once, wakeups reach 400 days like a cron's until, a cron whose first firing passed takes its next slot; arming
     one from the app is refused at once (it could never be delivered: the machine takes only the session's own signed
     request), not accepted to fail at every firing; a task's change of stores files the new line itself, and a run on
     a gone, waiting or dying line is queued behind its new line; a Jarvis 1 import prepares itself; a machine no session
     names any more can be destroyed from the Machines tab. *Kept, with Deyao's call*: every ask
     carries a reason (`--why`) and every new key an explanation; approvals lapse after 10 minutes, Deyao's own too; a
     session's actions stop once it starts pausing; the Fly budget cap pauses everything with no override.

## A destroy deletes no live copy it hasn't archived, 2026-10-15

191. **The archive takes every `.live` transcript the snapshot doesn't hold, verified, before any `.live` file goes**
     (2026-10-15: destroying sb8e0273d6c308894 deleted its original conversation, which only `.live` still had;
     `router/livearchive.go`). Claude's choices: *byte-identical means the same size and sha256* as the snapshot's file of
     that name; *another version of a conversation the snapshot has is kept beside it* as `transcript-<uuid>.live.jsonl`
     (not dropped as "older": it may hold what the snapshot lost); *each copy is read back from the Storage Box and
     checked* before it counts; *a copy that fails is an archive failure* (the session stays paused, as before), and a
     forced destroy then keeps every `.live` file and says so in the record (`liveKept`); *the clear deletes file by
     file*, only names and sizes the archive accounted for, and the dir only once empty; *no snapshot but live copies =
     a record of those alone* (indexed, not restorable). **A destroy never DMs that a session won't resume** (it isn't a
     resume): its missing snapshot goes into the record (`archive.noSnapshot`, `session.json`). **The memory DM offers only
     a size the running core starts**: the core reports `sizeLadder: 1` in `/identity` (the held core does; the one live
     until the box move doesn't), the router keeps its last answer (refreshed at most once a minute) and offers no Upgrade
     past large without it (`nextSize` null; Upgrade itself refuses with 409). *Not chosen*: a hard-coded "8 GB until the
     move" (it would outlive the move).

192. **The supervisor: its build choices (Deyao's design, 2026-10-16; DESIGN "The supervisor and the guard").** Deyao
     decided the shape (one long-running process with the guard as one component, OOM-protected and restarted, its log
     and the lifecycle log in the app, secrets in RAM only); Claude chose how:
     - **Keeper and worker.** `jarvis2-machine supervisor` is a tiny keeper that only sets `oom_score_adj` -1000 (sudo
       `tee`) and restarts `supervisor --worker` (backoff 1 s → 30 s). The worker inherits the score; what it starts for
       the session goes through `jarvis2-machine unprotected` (raises itself back to 0: no privilege needed). The
       freeze's `kill(-1, SIGSTOP)` stops the keeper too, so the worker SIGCONTs it at once. *Not chosen*: restarting
       the supervisor from the harness launcher (the harness isn't protected, so it could die first).
     - **Pause and resume of the Claude process** stop the launcher, every tmux pane's process and all their children,
       parents first (so the launcher's watchdog can't relaunch a stopped host), and resume children first. The router
       sends them as one-word commands (`POST /api/sessions/:id/harness`); no app button.
     - **The worker count** moved into the supervisor: the hook sends a boiled-down event (ids, types, the event name)
       over `/run/jarvis2/workers.sock` and exits 0 whatever happens; the count lives in the supervisor (and
       `/run/jarvis2/workers.json` for a worker restart). The status report's `__WORKERS__` section is unchanged for
       the router.
     - **Secrets in RAM.** The supervisor alone pulls; boot and the CLI (`await-store`, `downgrade`) ask it to over its
       socket (`pull`, `reload`). A worker restart keeps the values through a **memfd the keeper holds** (fd 3), since a
       new pull may meet a store the core has locked again. Callers are checked by SO_PEERCRED (the session user or
       root); each request is logged with names and pid/comm. The harness's env carries every env-name key (boot builds
       it from the supervisor's answer). The local Jarvis API's old `GET …/secrets` answers 410 (pull-secrets uses the
       socket); `harness-send`, which runs from the supervisor, re-execs itself through `pull-secrets --exec` for a
       direct send. *Not chosen*: a CLI handing the supervisor a pulled map (any process could then plant values).
     - **Deploy keys through the supervisor's ssh-agent** (golang.org/x/crypto/ssh/agent): read-only to callers (no
       add/remove/lock), every signature logged with the repo; `~/.ssh/jarvis2-deploy/*.pub` names which key each
       repo's alias uses (`IdentityFile` + `IdentitiesOnly` + `IdentityAgent`), since GitHub takes the first deploy
       key offered and would then refuse the other repos.
     - **Not covered (Deyao's choice or outside the supervisor):** `~/.claude/.credentials.json`; a file written with
       `pull-secrets --write` (if it is under `~/workspace` or `~/artifacts`, the snapshot takes it); the harnesses' own
       state the snapshot already carried (`.openclaw`, `.paseo`).
     - **The lifecycle log reads Fly with the router's read-only token**: the machine's events (deduplicated: Fly keeps
       only a few) and Fly's logs API without the app's own lines; if the read-only token can't read the logs API, the
       operation says so once and shows events only. Operations end when the machine reports in (boot/resume), the pause
       or destroy finishes, or after 15 min; the API's single-operation read has no cursor (late Fly events can carry
       earlier times), clients re-read it while it runs.

## A handover starts the next machine while the old one stops, 2026-10-19

193. **The next machine starts as soon as the old one has been told to stop; only its cert waits for Fly's
     "destroyed"** (Deyao, 2026-10-19: "you can start a new machine before the old machine has completely shut down, as
     reported by Fly, as long as the stop command has been sent"; `router/handover.go`). Upgrade, Restart, More disk and
     the Resume of a failed session that still has its machine used to run in a row: the final snapshot, the kill until
     Fly reported the old machine destroyed (the serving core: stop, the volume's backup snapshot until Fly reports it
     created, destroy), then the core's start of the new machine (volume and machine create, the image pull, boot,
     init), then its cert. Now the router asks the core for the new machine (a *spare*) the moment the old one is told
     to stop: when the supervisor is sent `snapshot` (it stops the Claude process and freezes the session first), `free`
     for an Upgrade, or the kill itself when no snapshot needs asking for. The spare's create, pull and boot overlap the
     snapshot and the kill; the start after the kill takes it (`startAndCertify`) instead of making another.
     **Kept in a row, and why:**
     - *The cert waits for the kill* (the core's Certify needs the predecessor killed, Fly-confirmed, with the final
       snapshot named). A machine with no cert has no secrets, restores nothing and has no identity: it prints its keys
       and waits. So the new machine always restores the old one's final snapshot, never an older one (the kill names
       it, the cert names the kill's), and by the time it gets its identity (cert, stores, tunnel proof, Remote Control,
       leases, which all follow the cert) the old machine is gone and can't write state or clash with it. Certifying
       once the stop is *sent* would be a core change (Certify, Kill, ApproveByDeadMachine all read "killed" as
       Fly-confirmed destroyed), and a core release needs Deyao's Recover, so it is not part of this change. What a
       handover still waits for is only the part of the snapshot and the kill that outlasts the new machine's boot.
     - *A spare is used only when it is exactly the machine the start asks for* (image, size, disk; "" = medium) and
       only for a resume the core answers by itself (the cert's own image). A resume the phone approves (newer image,
       resume prompt or rollback, another permission mode, the Claude login's legacy image) gets its own machine after
       the approval; a spare already made for it is destroyed.
     - *An unused spare is destroyed in the background*: the pause kept the old machine (its snapshot failed), the
       resume went to the phone or failed, the job failed, or nothing took it within 8 min (`spareMaxAge`: the machine
       asks for its cert for about 10 min, then refuses to start). Fly's org machine cap counts it until then
       (lessons/58), so a spare never waits out the cap: at the cap it gives up and the start after the kill makes the
       machine, as before. The old machine's kill is unchanged (the core's stop, backup, destroy, volume delete), so it is
       always cleaned up; it is not made asynchronous because the cert depends on it.
     - *A router restart mid-handover* loses the spare (in memory): its machine has no cert and no line, and it shows
       on the Machines tab as an orphan after 15 min, as a start cut off by a restart always did.
     - *The resume after the pause tries again on "busy"* (`handoverResume`, Upgrade, Restart, More disk): a pause marks
       the session paused a moment before it lets go of the session's lock, so a resume that comes right away could be
       refused as busy and fail the whole job (it also made `TestNoSnapshotStopsTheResumeAndNamesTheBackup` flaky).
     *Not chosen*: starting the spare at the start of the job, before the stop is sent (a pause that keeps the machine
     would waste it more often, and Deyao's rule names the stop); keeping spares warm ahead of any handover (a machine
     per session, billed and counted toward the cap).
