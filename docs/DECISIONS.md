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
    CPUs with 2/4/8 GB. The router's budget cap (Jarvis 1's: DM at USD 25, pause all at USD 30) reads the app with a
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
    ticked on the secure page, as every sensitive store.
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
    rewritten while a session is paused reaches it at its next pull with an unlock for it.
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
      `started` document, which certify takes. Sizes outside small/medium/large are refused, not defaulted.
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

96. **The hk-news-stream proof of concept runs on the box** (2026-10-12, Deyao asked for it on the Jarvis 2 cluster,
    with OpenRouter for the model and nothing heavy on the box). Code and image in DE0CH/hk-news-stream (public);
    here only `k8s/apps/news.yaml`, its Secret `k8s/secrets/news.enc.yaml` (OPENROUTER_API, `router-secrets.py --part
    news`) and the hostname hknews.deyaochen.com on the production tunnel (`infra/cloudflare.py --news`, Access on
    Deyao's email). It sits in `jarvis2-edge` because the bootstrap gives Flux no other namespace and a new one would
    need a rebuild; the cloudflared policy is narrowed to cloudflared's own pod (it was every pod in the namespace),
    and the news pod's own policy allows only cloudflared in and DNS plus public 80/443 out, so it can't reach the
    router, the core or cloudflared's token. Its image is pinned by digest and changes only by a commit here, so the
    other repo can't change what the box runs. Remove all four pieces together when the PoC ends.

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
    memory only (a restart starts it afresh). The Upgrade goes small → medium → large; there is no xlarge because the
    core's sizes would change, and a core change waits for Deyao (the core holds stores).
99. **`free` is a router command the machine obeys without a voucher.** It is not an input to the agent: it only stops
    processes, which the router can already do more bluntly by pausing or destroying the machine, and the snapshot that
    follows is still the machine's own, signed. The harness (the machine's main process) is SIGSTOPped, not killed, so
    the Fly machine stays up for the snapshot. The list of what was stopped is written inside the snapshot, and the
    successor reads it, so the router's word never reaches the agent; the `upgraded` message itself is an image text
    over two size words. Change: make Upgrade phone-approved if Deyao wants a Face ID on it.

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
    (entry 153).
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
116. **Machines check the account of every pair before writing it** (DESIGN "Inputs to a machine": the login decides
     whose Claude app reaches the session through Remote Control, so the router must not pick it). Anthropic's profile
     endpoint must name the account the store `claude` vouches for (`CLAUDE_ACCOUNT_UUID`, written by the setup session;
     on a resume whose carried store predates it, the account in the `~/.claude.json` the signed snapshot restored).
     The router can only withhold the login. The router checks pushes the same way. Cost: a Re-login to ANOTHER Claude
     account needs `infra/setup.py write claude CLAUDE_ACCOUNT_UUID` (fill-stores.sh reads it from the router), and
     running lines take the new value at their next pull with an unlock. Change: drop the check if Deyao switches
     accounts often.
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
132. **A start waits out Fly's org machine limit** (up to 3 hours, a try a minute; `router/flows.go` startMachine):
     the limit counts every machine object (lessons/58: 20 in Jarvis 1's org), and the import starts 16 lines at once
     next to the running ones. A refused create made nothing and the phone's approval isn't spent until certify, so
     the router keeps it and tries again as sessions pause, instead of failing a line Deyao already approved (which
     would cost him another Face ID). The session shows `starting` meanwhile. Change: ask Fly to raise the org's limit.
133. **A successor with no snapshot takes the line's Jarvis 1 import again** (2026-10-13: the imported sessions' Fly
     machines were stopped by hand right after boot, so their rootfs and keys were gone and no snapshot could be signed;
     their kills named none). A successor whose cert names no snapshot, on a line whose signed config names a restore that
     is a Jarvis 1 import, fetches that manifest and its files again and checks them as the first machine did
     (`machine/restore.go` reimportJarvis1; the router serves them to such a successor). The cost: a router that withholds
     a later snapshot can bring the line back to the imported state instead of an empty one; both were already in its power
     (withholding, and the import's bytes are what Deyao signed). A destroyed Jarvis 2 session's archive is not taken again.
134. **`/setup/sessions/{id}/pause` cancels the session's wakeups and crons first** (they would resume it by themselves);
     the imports' re-armed ones are armed again by the re-import at the next resume.

## Batch approvals in the Inbox, 2026-10-13

Deyao: several actions approved together with ONE Face ID; the caller groups them through the API and gives a summary
(its unverified words, shown above every item's signed details); nothing excluded; Deny works on the whole batch.

140. **One Face ID, every item signed as alone; no core change** (supersedes 124). The app evaluates Face ID once
     (`PhoneKeys.authorize`: `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`) and passes that context
     to every Secure Enclave use of the batch (`SecureEnclave.P256…PrivateKey(dataRepresentation:authenticationContext:)`),
     so the Enclave asks no second time; the keys stay `.biometryCurrentSet`. Each item is then signed and sent exactly as
     from its own page (approvals' core challenges, grant texts, deploy-key begin documents, unlocks' shares), so the core
     verifies each one unchanged. The simulator does its Face ID stand-in once per batch. The replica proves the one-Face-ID
     path on the simulator (software keys); the Enclave's reuse of an evaluated context is Apple's documented behaviour,
     first exercised on Deyao's iPhone. Change: a core primitive approving N challenges from one signature (a Recover).
141. **Items are read and checked before Face ID; each is signed and sent in order after it.** A batch page reads every
     item as its own page would (the same Checks: the core key, line pins, the session's cert, CI's image signature, the
     grant's draft checked field for field before signing) and offers Allow all only when every item is readable and
     signable and no approval is still being made. An item that fails mid-batch is shown failed; the ones before it went
     through and left the Inbox (approvals leave when answered, requests on `done`), so Retry is idempotent: it reads only
     what is left and asks for one more Face ID. Grants and deploy keys draft/begin again on Retry.
142. **Deny: the whole batch, or one item.** Deny all drops every request and rejects every approval (a new session
     disappears); an item can also be denied (or allowed) on its own, which takes it out of the batch. The web page shows
     batches and denies them; approving stays on the phone.
143. **Limits count a batch once.** A batch is one of the caller's 20 waiting requests and, when it proposes any new
     session, one of its 3 waiting proposals (a session or the actions key); a batch holds at most 20 items. So a session
     can have at most 3 proposal entries in the Inbox, as before, each still needing Deyao's Face ID per entry. The setup
     session's imports, as before, aren't limited beyond the 20 items per batch.
144. **The batch is checked whole before anything is filed** (an item the caller may not ask for, a bad argument, the same
     item twice: 400/403 and nothing filed). Filing itself can still fail per item (the core refusing a challenge): that
     item is reported with its error and the others stand, since undoing filed approvals would be a Deny the caller didn't
     ask for. A request already waiting alone joins the batch; one already in another batch stays there. Per-item
     explanations are optional in a batch (the summary is required).
145. **The whole batch expires 10 minutes after filing** (its requests carry the batch's end; an approval goes at the
     sooner of its own 10 minutes and the batch's). Imports and proposed sessions come in a moment after filing (the core's
     challenge); the batch shows them as `preparing` and the phone waits for them before Allow all.

146. **Router rollouts drain; nothing is redone after a crash** (Deyao, 2026-10-13: drain on SIGTERM, remove the
     save-to-disk-and-redo). Tracking lives in the lifecycle lock (`lock` begins a tracked action, its unlock ends it) plus
     the approval answer (`Respond`); a restart or upgrade job is tracked as a whole and its own pause/resume steps still
     begin during a drain, so a drain between its steps doesn't leave the session paused half way. Creating a session
     (only an approval, no machine) is not refused; the phone's answer is, before the core uses the approval up, so it
     stays in the Inbox. Preparing a Jarvis 1 import (hashing, no machine) isn't tracked.
147. **A drain doesn't wait out Fly's machine limit.** A start in the limit wait (up to 3 h) when the drain begins, or one
     that would begin it during a drain, ends `failed` with "the Fly org is at its machine limit and the router is
     updating: start it again". Change: let it wait in the next pod (it would need the saved state we just removed).
148. **Grace 30 min, not 15.** `terminationGracePeriodSeconds: 1800`, `DRAIN_SECONDS` 1740: the longest tracked job is a
     restart/upgrade (a pause's 600 s snapshot wait + the kill, then a resume's machine init, up to 12 min). Flux applies
     with `wait: false` and no workflow waits on the rollout, so the long grace delays only the new pod. A drain past it is
     cut off like a crash.
149. **After a crash: `paused` for a cut-off resume, `failed` otherwise.** A resume cut off before certify keeps its line
     (the core marks the predecessor used only at certify), so the session goes back to `paused` with the reason and a
     plain Resume works. A new line's start (its phone approval is spent), a pause and a destroy become `failed` with the
     reason; Pause and Destroy both run from `failed`. The cut-off start's machine, if the core had made one, isn't known
     any more: it holds no secret (never certified) and the Machines tab flags it as having no session. Old state.json's
     `pendingStart` is dropped on load.

150. **The router's default secret part keeps four dead Jarvis 1 keys until its next rewrite.** The router no longer reads
     `JARVIS1_CREDENTIALS_*` / `JARVIS1_SERVICES_*` (nor the stale `GITHUB_READ_TOKEN`), but `router.enc.yaml` is rewritten
     whole and nobody can read `JARVIS2_TUNNEL_KEY` back: dropping them now means a new tunnel key on the Worker and the
     router at once, and every running OpenCode/OpenClaw session's web UI would fail on its next reconnect until it
     restarts. The values are inert (no code reads them); their Access service tokens can be revoked on Cloudflare when
     Jarvis 1 goes to 0, which kills them for good. Change: rotate the tunnel key in a quiet moment and rewrite the part
     (RUNBOOK "The router's secrets").
151. **A paused Claude session on a pre-router-login image resumes on the newest image.** Images pinned before
     `sha-c5427052a542` (2026-10-13 01:39) fetched the Claude login from Jarvis 1 with the store `claude`'s
     `JARVIS1_CREDENTIALS_*`; those keys leave the store, so such a line would boot logged out. The router's Resume (the
     app, the actions key, a wakeup, a lease or watch wake) of a line with the store `claude` whose image comes before that
     pin in `session-image-sigs.txt` (or isn't listed at all) asks for the newest image instead: a `resume-upgrade`
     approval in the Inbox, so the phone approves it; nothing boots before. A wakeup that resumes such a line waits on
     that approval (and lapses with it after 10 minutes, leaving the line paused). Change: resume on the old image and
     let the router's login repair (holder `login`) copy the pair in.
152. **The end-to-end test runs with Jarvis 1 unreachable, always.** The router runs in its own mount namespace (`sudo
     unshare`) whose /etc/hosts sends jarvis.deyaochen.com to 127.0.0.2, where a root listener logs every connection; any
     line fails the test. Each session machine gets `0.0.0.0 jarvis.deyaochen.com` in /etc/hosts through Fly exec as soon
     as Fly lists it started; the machine boots on its own, so the first boot can finish before that (the test logs
     "before boot"/"after boot" per machine); every later step runs blackholed. Search, the watch runner and the Storage
     Box (for content stores) are local stand-ins (an in-memory WebDAV over TLS, trusted through the router's
     SSL_CERT_FILE); the watch stand-in doesn't run scripts (the real runner kills every other process in its
     container). The router's own refresh against Anthropic isn't run (it would need a real login); the test covers a
     newer pair reaching a running machine by itself.
153. **The forks pin their builds with a `workflow_dispatch`, not a `repository_dispatch`.** DE0CH/claw-code and
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

154. **An add-store is always answered onto the machine's newest cert** (Deyao, 2026-10-13: "The race shouldn't happen.
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

155. **A session's actions run on its own machine key, and can ask for any app API call** (Deyao, 2026-10-13: "the
     action key can request anything … action keys should be scoped and minted for each session, so i can see and log
     where that comes from … and they should be disabled with each session pausing/destroying").
     *Per session*: the shared Access service token `jarvis2-actions` (in the `default` store) is gone, with its Access
     app and router env. The actions moved to `/m/api/actions/*`, signed by the calling machine's key, which the core
     mints for each machine it starts; the router names the caller `Caller{Kind: "actions", Session}`, shows it in the
     Inbox and logs every non-GET action with its session. A machine key already dies with its machine; the actions
     also refuse a session that is pausing, destroying or paused (`actionsSession`), and its pending call requests
     leave the Inbox, so no action outlives the session's run.
     *Any call*: `POST /m/api/actions/requests/call` files an `api-call` request naming one app route's method, path and
     body. Deyao approves it on its Inbox card (app or web page); the router runs it through its own public mux with
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

156. **Every Jarvis 2 box is IPv6-only, with Cloudflare's free WARP client for the outgoing IPv4** (Deyao, 2026-10-13:
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
157. **The production box keeps its IPv4 (Deyao, 2026-10-13: "no need", a primary IP was free again); if it is ever converted, it converts in place** (`infra/convert-ipv6.sh`): shutdown → the primary IPv4
     unassigned (Hetzner allows it only while the server is off) and deleted → a single-use rescue boot with a
     throwaway SSH key writes `warp-host.sh` and a oneshot unit (before k3s) onto the disk → reboot. The disk keeps the
     box key, age key, Secrets and Flux state, so nothing is re-minted (a rebuild would need every router-secrets part
     again, a new backup read credential and a new tunnel key, and loses paused sessions). Both reboot the box, so the
     core starts empty either way: Deyao Recovers, as after a power failure. A real pre-change box can't be rehearsed (a
     new IPv4 is over the account's limit, which counts IPv6 primaries too), so it was simulated on a runner: a k3s
     cluster on a non-persistent IPv4 node-ip, Flux, WARP removed → convert-ipv6.sh (rescue over IPv6, 60 s) → after
     the reboot WARP installed by the unit, the node Ready on 10.254.254.1, every pod Running, Flux fetching GitHub,
     a new GHCR image pulled and a pod reaching api.github.com.

158. **The apps' server URL moved to Jarvis 2 now, not at retirement** (Deyao, 2026-10-13: "make sure Jarvis 2 runs fully
     without Jarvis 1"; supersedes 139). OpenClaw and Paseo name jarvis2.deyaochen.com from their next TestFlight build;
     Deyao pairs each once. They no longer see Jarvis 1's OpenClaw/OpenCode sessions (Jarvis 1 is frozen). Paseo's CI
     e2e token is a Jarvis 1 device: Jarvis 2 admits only devices paired through `/api/devices/pair` (Deyao's Access
     login), and the setup session can't pair one (giving it that would hand it every OpenClaw gateway token), so the
     fork's simulator test skips its Jarvis checks (a warning) until a paired token is in its secrets. Change: a
     setup-signed device registration for a CI token, or Deyao pairs a "Paseo CI" device once.

## A session hears what became of its Inbox requests, 2026-10-13

159. **The requesting session is told every decision on what it filed** (Deyao, 2026-10-13: "Approving an Inbox
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
