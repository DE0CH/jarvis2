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

16. **Box**: Hetzner cx23 (2 vCPU, 4 GB, 40 GB) in fsn1, EUR 6.588/month gross plus its IPv4, in the
    `jarvis2-mock` project (renaming a Hetzner project needs the console).
17. **Fly**: app `jarvis2-sessions` in org `jarvis2-370`, region `lhr`, sizes small/medium/large = 2/4/8 shared
    CPUs with 2/4/8 GB. The router's budget cap (Jarvis 1's: DM at USD 25, pause all at USD 30) reads the app with a
    read-only Fly token (`infra/fly-read-token.sh`).
18. **Images** on GHCR (public, like the repo), with GitHub build attestations (the phone doesn't check them
    yet).
19. **Repos for a session** are cloned by the machine with the session's own `GITHUB_TOKEN`.
20. **Harness stores** (`policy/stores.json`, baked into the router image): `claude` brings the store `claude`,
    `opencode` brings `openrouter` + `tunnel`, `openclaw` brings `claude` + `tunnel` (`tunnel` = the confined Access
    service token `jarvis2-tunnel` for the web UI's cf-tunnel agent: a store, not the router's machine env, so the
    router never holds it and it never sits in a Fly machine config; the per-id proof comes over `/m`).
21. **Stores that can reach a code push are sensitive** (Deyao, 2026-10-09): one GitHub token per repo, each
    limited to its repo (fine-grained, no expiry; contents, workflows, actions) — store `github-claude-env`
    (key `GITHUB_TOKEN_CLAUDE_ENV`, not sensitive) and `github-jarvis2` (key `GITHUB_TOKEN_JARVIS2`,
    sensitive). The machine gives each repo its own token (`GITHUB_TOKEN_<REPO>`), so a session with both keeps
    both. claude-env holds no Jarvis 2 code or design.
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
42. **Search and the iCloud index stay Jarvis 1's** (as PLAN.md "Later" says for retirement): the app's Search tab is
    forwarded with the router's confined `jarvis2-services` token, not reimplemented.
43. **When the core can't be reached the router answers 503 `{coreDown}`** (it said 502 "core unreachable"): while
    its pod restarts (after a wipe) that is the normal state, and the app waits or shows it as a plain note.
44. **Lease pills are not in the app**: leases are forwarded to Jarvis 1, which doesn't accept Jarvis 2 sessions yet
    (PLAN.md "Later"), so no Jarvis 2 session can hold one and the pill would never show.
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
