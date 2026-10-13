# Jarvis 2 — runbook

Everything here runs from a Claude session whose env has Jarvis 1's `default` store (JARVIS2_* keys,
HETZNER_JARVIS2_MOCK_API, HETZNER_S3_*, CF tokens). The box has no SSH and no reachable k8s API: it changes only
through git, and a box git can't fix is replaced.

## Deploying

`git push` to main. The `images` workflow builds the core, router and session images, then pins them by digest in
`k8s/apps/` (and signs the session image for the phone, `SESSION_IMAGE_SIG`); Flux applies within a minute.
The session image stands on its base, `session-image/base/` (every tool, harness, the entrypoint and supervisor: add a
tool a session should always have to `session-image/base/Dockerfile` and push). The workflow's `base` job rebuilds the base
only when that directory changed since the base pinned in `session-image/Dockerfile` (`ARG BASE=…jarvis2-session:base-sha-<12>@sha256:…`),
or on `gh workflow run images -R DE0CH/jarvis2 -f base=true` (newer tools, the latest claude CLI); it takes 20-30 min,
and the pin job then moves `BASE` in the same commit as the k8s pins. Before pinning, the build job checks the session
image is anonymously pullable (Fly pulls without credentials) and needs at most 8.0e9 bytes on disk once unpacked
(`infra/image-unpacked-size.py`): Fly refuses a bigger one (it refused 8.380e9; 8.340e9 booted) and destroys the machine
before it boots, so every new session breaks. A failure there pins nothing. Its pin job
runs only for a commit on main, in the GitHub environment `release`, and pushes with its own deploy key
(`jarvis2-ci-pin`): main's ruleset lets only repo admins and deploy keys update main, so no workflow's GITHUB_TOKEN can.

Deyao's forks pin their builds themselves: on every push to its main, DE0CH/claw-code (`de0ch-latest.yml`) and
DE0CH/openclaw (`de0ch-package.yml`) publish release `de0ch-<sha12>` and run `gh workflow run fork-pin.yml -R
DE0CH/jarvis2 -f name=claw|openclaw -f url=… -f sha=…` with `JARVIS2_DISPATCH_TOKEN` (fine-grained PAT
`jarvis2-fork-dispatch`: Actions write on DE0CH/jarvis2 only). `fork-pin.yml` checks the inputs, pins the asset with its
sha256 (claw: `session-image/base/forks.json`, so the base rebuilds; OpenClaw: `session-image/openclaw-runtime.json`)
and pushes with its deploy key, which runs `images`. By hand: the same `gh workflow run` line (DECISIONS 153).

GitHub settings (R1 audit, 2026-10-11; `gh api`): ruleset "main: only admins and deploy keys update it" (deletion,
non_fast_forward, update; bypass: the admin role and deploy keys); environment `release` (deployment branches: main only)
with secrets ASC_KEY_ID / ASC_ISSUER_ID / ASC_PRIVATE_KEY (ios.yml's TestFlight job), CI_IMAGE_KEY (the private half of
`keys/ci.pub`), PIN_DEPLOY_KEY and FORK_PIN_DEPLOY_KEY (`fork-pin.yml`, deploy key `jarvis2-fork-pin`). A workflow that must push to main gets its own deploy key in `release`, never
`contents: write` on GITHUB_TOKEN. Rotating the CI key: a new P-256 key into CI_IMAGE_KEY and its public half (base64
X9.63) into `keys/ci.pub` in one go, then run `images` so the router gets a fresh signature. The core's tag moves only when `core/` changed (a core restart is a
new, empty core: see "Setting the core up"), and never while the core Deployment in `k8s/apps/core.yaml` carries the
annotation `jarvis2/core-pin: hold`: a core change that waits for Deyao's go (he then Recovers). To roll it out once
he says so, delete the annotation, push, then `gh workflow run images -R DE0CH/jarvis2` (a k8s/ push alone doesn't
run it): it pins the newest core and Flux restarts it. The held core now (2026-10-13) is stores made of keys (6fc20f8) with
store versions and the phone-signed restore (ad17fec): one release. Before it: the router (already live) and an app
build from the same main (TestFlight, after the phone replica) that speaks per-key unlock, the keys-format Recover
and restore-written key backups; after it Deyao Recovers (the bucket has every whole-store backup and every key backup
since, restores' included), every earlier session is destroyed once paused (DESIGN "Carried secrets"), and the setup
session checks `infra/setup.py versions default` answers (the history starts at the Recover). A core from aa0443a on starts no machine without `MACHINE_URL`: in the same commit
add `- { name: MACHINE_URL, value: "http://jarvis2-box._peer.internal:8081" }` to the core container's env (test cores
get their own peer's address from `infra/e2e.sh` / `infra/rehearsal-box.sh`).

A router rollout drains (`router/drain.go`): the old pod refuses new lifecycle actions with 503 "router updating, try
again shortly" and exits once the running ones have finished (its log: `draining: … waiting for N running: [...]`, every
minute `still running`, then `drained`); the new pod starts only then (strategy Recreate), so a deploy during a pause can
take up to the snapshot wait (10 min) to go live, at most 30 min (`terminationGracePeriodSeconds: 1800`, `DRAIN_SECONDS`
1740). Watch it with `kubectl -n jarvis2-router logs deploy/router -f`. A start waiting out Fly's machine limit ends
when the drain begins ("…start it again"). After a crash (OOM, node reboot), sessions cut off mid-action show `failed`
(a resume: `paused`) with "cut off by a router crash" and are started, paused or destroyed again from the app; a
cut-off start may leave an uncertified machine that the Machines tab flags with no session (Destroy it there).

## The keys (`keys/`)

- `box.pub` — written by `infra/create.sh` with each new box; commit it. The app and `setup.py` check a core's
  keys against it.
- `box-age.pub` — the box's age key (SOPS recipient of the router's secrets), also from `infra/create.sh`.
- `setup.pub` — the setup key (private half JARVIS2_SETUP_KEY); also `SETUP_KEY` in `k8s/apps/router.yaml`. It
  signs every `/setup` call, every store backup and every store blob (the writer signature the phone checks).
- `ci.pub` — CI's image key (private half: secret CI_IMAGE_KEY of the environment `release`): the phone shows a session
  image as a CI build only with its signature.

There is no master key in git: Deyao makes it in the app (Reset), and the core learns it from his claim.

## Setting the core up (Deyao, in the app — nothing for Claude to do)

A new core (after any restart, deploy of `core/`, or box rebuild) is empty. Deyao opens the app (it shows
Reset or recover by itself, or Settings → Reset or recover…):

- **Reset** — the app shows a new recovery kit (`jarvis2-kit:2:…`, Copy), he saves it in his password manager,
  taps "I've saved it", and the core is set up with no stores. Then "After a Reset" below.
- **Recover** — he pastes his kit; the app reads the backups through the router and the core is set up with every
  store. Nothing else to do.

`infra/setup.py identity` says whether the core is empty or set up (and with which master public key).

**The setup session's pins** (`pins.json` in the backup bucket, signed by the setup key): the master key the stores
belong to and the app's device key. `setup.py` writes, backs up or sends nothing to a core whose master isn't pinned,
unless its claim names the pinned device key and the app's countersignature is at the router (Deyao's Reset: the pin
moves by itself). A Recover keeps the master; a claim under the pinned master re-pins the device key it names. If
setup.py says REFUSED, the core was claimed by something other than his app: empty it from git ("Emptying the core
without its kit") and let him set it up again. `infra/setup.py pin-master` pins the current core's master by hand; use
it only when the core is known to be his (it holds the stores of a Recover, which only his kit opens) and nothing is
pinned yet (a new bucket, a rehearsal box).

### Store key names

The app, sessions (`jarvis2 stores`) and `infra/setup.py stores` list every store's key names (API.md `GET
/api/stores`). The router keeps them in its data volume; `infra/setup.py write` records them with each write. When
they are missing (a new box, or after a Recover onto a new box) run `infra/store-keys.sh` (names only, from the
layout file; needs only `JARVIS2_SETUP_*`). A new key in a store: add it to the layout file, then write the store
(or `infra/setup.py keys <store> <KEY>…` to record the names alone).

### After a Reset (the setup session)

`infra/fill-stores.sh` — once the core is set up (and trusted: the pins above): creates the non-sensitive stores
(only those in `NOT_SENSITIVE` in `infra/setup.py`; a write marks any other store sensitive first if someone created it), writes every store to the core
and its backup (sealed to the new master key, read from the core's signed state), minting or rotating every token
whose value lived only in the old stores and backups, sends the core its Fly token (`backup-core` with a fresh
`infra/fly-token.sh`), and deletes the local copies. The stores and their keys: Deyao's own stores by kind, `default` (not sensitive), `identity`, `infra`,
`money`, `devices`, `work` and `jarvis1` (sensitive), whose key names are listed in the private claude-env repo
(`.claude/skills/jarvis2/stores.txt`, read by the script; run it under `pull-secrets --exec` so it sees the setup
session's live store values); `github-deploy-keys` (sensitive; GITHUB_DEPLOY_KEYS_TOKEN: a new fine-grained PAT
`jarvis2-deploy-keys`, all repositories, Repository "Administration: read and write" only, minted by `github-web
pat-create-all`, which deletes the same-name token first; its line is in the layout file too); the harness stores
`openrouter` (OPENROUTER_API), `claude` (CLAUDE_ACCOUNT_UUID: the Claude account sessions accept the router's login
for, read from the router's login; not secret), `tunnel` (CF_ACCESS_CLIENT_ID/SECRET: `jarvis2-tunnel`, rotated) and `core` (the Fly token). The narrowed
Fly token in an old `core` backup can't be revoked on its own (an attenuation of JARVIS2_FLY_TOKEN); it stays sealed
to the old master key. Old backup versions stay in the versioned bucket, sealed to their old key. Nothing needs
unlocking ahead (each Start unlocks what its session needs, for that session only); Deyao adds his repos again in
Settings → Repos (the repos' stores aren't backed up, below).

### Offline copy of the stores (Deyao, whenever he wants one)

A copy of the encrypted store backups that Deyao keeps himself and opens with his kit on his Mac, with no network:

1. **Download it in the app**: Settings → Encrypted backup → Download encrypted backup. The app reads every backup
   through the router (`GET /api/backups`), checks each signature against `keys/setup.pub` from GitHub as Recover does
   (any that fail are listed in red), and makes ONE file, `jarvis2-backup-<yyyy-mm-dd-hhmm>.json` (UTC): the objects
   exactly as served, the bucket, the fetch time and the setup public key. Save file… opens the share sheet (Save to
   Files, AirDrop to the Mac). The app never asks for the kit and never opens a backup; the file is as safe as the
   bucket itself (everything in it is sealed to the master key), and only the kit opens it.
2. **Decrypt it offline** with `tools/decrypt-backup.py` from a clone of DE0CH/jarvis2 (Python 3.9+ and
   `cryptography`; set up once, while online: `python3 -m venv ~/.jarvis2-venv && ~/.jarvis2-venv/bin/pip install
   cryptography`):

       ~/.jarvis2-venv/bin/python tools/decrypt-backup.py ~/Downloads/jarvis2-backup-2026-10-13-1015.json --setup-pub keys/setup.pub

   It asks for the kit without echoing it (or `--kit-file FILE`, or `--kit-file -` on stdin; never as an argument, so
   it stays out of the shell history), checks every signature against the file's setup key AND `keys/setup.pub`
   (they must be the same key), opens every store, and writes `jarvis2-stores-<date>.json` (mode 0600; `--out PATH`,
   a path ending in `/` = one `<store>.json` per store in a 0700 directory; never over an existing file without
   `--force`). Values reach the terminal only with `--stdout`. A failed check stops it before anything is written
   (`--skip-bad` leaves the bad objects out and lists them). It also takes the router's raw `/api/backups` answer and a
   single `stores/<name>.json` from the bucket (an older version, for example; both need `--setup-pub`), and a
   version-1 kit's master part.
3. **Keeping it**: the encrypted file can sit anywhere the backups could (Files, iCloud Drive, a USB stick); it is
   only as current as its fetch time. The decrypted `jarvis2-stores-*.json` is every secret in the clear: open it,
   use what's needed, and delete it; never put it in a synced folder (iCloud Drive, Dropbox).

### Carried secrets (DESIGN "Carried secrets")

Stores stay locked: a Start's Face ID unlocks them for that session only, the core locks them again once its machine has
pulled, and a paused session carries its secrets to its next machine (`snapshots/<machine>.carry` in the router's data
volume, sealed under a key only the running core holds). Nothing to operate. A session that says "Waiting for store X"
on a resume has no usable blob (lost, or paused under a core that predates carried secrets): Unlock… on its card, or
`infra/setup.py request unlock SESSION --why "…"` for the Inbox. After a core restart (and Reset or Recover) the
router destroys every earlier session by itself once it is paused (DESIGN "Carried secrets"): each is archived in
Previous, and Restore there starts it as a new line approved on the phone.

## Repos and their deploy keys

Each repo is added in the app (Settings → Repos → Add repo, or "Make key" on a listed repo whose store is missing):
the app makes an ed25519 key, the shell's secure page shows the core's signed request, and one Face ID lets the core
use `github-deploy-keys` for that call to add the key to the repo as a read/write deploy key titled `jarvis2 <store>`
and keep the app-wrapped private half in the store `github-<repo>` (the app keeps `github-jarvis2` sensitive). Nothing
for Claude to do. Remove deletes both. A Recover brings no repo stores back (no backup): "Make key" again, which also
deletes the old key on GitHub. Sessions that include a repo's store clone, pull and push it over SSH
(`machine/deploykeys.go`).

If the picker says "No match." for a repo that exists (a private one), the router's `GITHUB_READ_TOKEN` sees public
repos only: `infra/setup.py status` shows `githubRepos.private: 0`. Mint `jarvis2-repo-list` again with Metadata read
picked and write `--part github` (The router's secrets, below); then "refresh list" in the app.

If the core says the token can't manage a repo's deploy keys, the token in `github-deploy-keys` lacks Repository
"Administration: read and write" on it: mint `jarvis2-deploy-keys` again (`github-web pat-create-all
jarvis2-deploy-keys ~/.jarvis2/gh-deploy-keys.token Administration=write`) and write the store (`setup.py write
github-deploy-keys GITHUB_DEPLOY_KEYS_TOKEN=file:~/.jarvis2/gh-deploy-keys.token`, then shred the file).

Against real GitHub: `JARVIS2_LIVE_GITHUB_TOKEN_FILE=… JARVIS2_LIVE_REPO=<a throwaway repo> JARVIS2_LIVE_OTHER_REPO=<a
private repo> go test -run Live` in `core/` (the phone flow, then `git clone`/`push` over SSH with exactly that key,
the other repo refused, remove).

### Asking Deyao from a session or from the setup session (the Inbox)

Claude never adds a repo or allows anything itself: it files a request and Deyao approves it in the app's Inbox
(docs/API.md "Requests").

- Setup session: `infra/setup.py request add-repo DE0CH/claude-env --why "…"` (also `remove-repo`, `grant SESSION
  HOLDER [--minutes N | --days N]`, `unlock SESSION`); `infra/setup.py requests` lists what waits, `infra/setup.py
  repos` the router's repo list (check it before asking for a repo that may be there already).
- Inside a session: `jarvis2-request add-repo OWNER/NAME --why "…"`, `jarvis2-request grant HOLDER --minutes 5 --why
  "…"`, `jarvis2-request unlock --why "…"`, `jarvis2-request add-store STORE --why "…"`, `jarvis2-request list`
  (`session-image/bin/jarvis2-request`, through the machine's proxy). `add-store` also starts a background
  `jarvis2-machine await-store STORE`, which pulls the store into `~/.secrets` once the approval lands in the cert
  (log `~/.jarvis2-await-STORE.log`); before it did, an approved store stayed unpulled (2026-10-12).

The reason is required, plain text, ≤ 600 characters. A request (and an approval in the Inbox) goes after 10 minutes (Deyao, 2026-10-12): ask again if it lapsed.

**Several at once = one batch** (Deyao, 2026-10-13): when Claude needs more than one thing, it files them as a batch,
so Deyao reviews one Inbox entry and allows everything with ONE Face ID (or denies it whole). `--summary` (required)
says what the batch is for; each item may carry its own `explanation`. Any kind can be in a batch (repo add/remove,
grant, unlock, add-store, new-session, jarvis1-import); at most 20 items; every item is checked before any is filed.

- Setup session: `infra/setup.py request batch --summary "…" --item repo/add,repo=DE0CH/x --item
  grant,session=sID,holder=terminal,minutes=5` (or `--file items.json`, a JSON list of `{"intent": …, …}`);
  several Jarvis 1 imports: `infra/setup.py jarvis1 import ID1 ID2 … --stores a,b --why "…" --summary "…"`.
- Inside a session: `jarvis2-request batch --summary "…" --item grant,holder=scheduler,minutes=5 --item
  add-store,store=gmail` (or `--file`); `--item new-session,label=…,prompt=…,stores=a|b` (lists with `|`; a long
  prompt goes in a `--file` item). A batch counts as one of the session's 3 waiting proposals.
- `infra/setup.py requests` / `jarvis2-request list` show the batches (`b…` ids) after the loose requests.

**The outcome comes back by itself** (Deyao, 2026-10-13): once Deyao decides an item a session filed, that session gets
a message from Jarvis, `[Inbox outcome] … APPROVED / DENIED / LAPSED / DROPPED / FAILED: …` (a batch in one message,
numbered like its items), with what was checked (the phone's grant, the new cert naming the store, the new session's
id). No polling needed; a paused session hears at its next start. `jarvis2-request outcomes` lists them;
`jarvis2-request wait ID` blocks on one (exit 0 approved). An outcome that wasn't delivered shows `not delivered: …` in
`outcomes` (e.g. an image from before outcomes); the router logs `[outcome]` lines.

### Emptying the core without its kit

A set-up core ends from the app only with the kit it was set up with (Reset or Recover asks for it). Without that
kit — a lost kit, or a core someone else claimed first (the app says "set up with a different recovery kit") —
change the `jarvis2/restart` annotation in `k8s/apps/core.yaml` and push: Flux restarts the core, and the new one
is empty.

## Stores

- `infra/setup.py stores` — the core's signed list.
- `infra/setup.py create NAME` — once per name, an empty store that is NOT sensitive. Without it, a store is
  sensitive.
- `infra/setup.py write NAME KEY[=SRC]…` — new contents (values from this session's env, never printed),
  written to the core wrapped to the phone + core key, and backed up to S3 (bucket `jarvis2-backup-de0ch`,
  versioned, encrypted to the master key the core was set up with, signed by the setup key).
- With the live core from before stores were made of keys, `write` REPLACES the whole store with exactly the keys
  given: it refuses (and so does the router, 409) a write that leaves out a key name recorded for the store; name every
  key, or add `--replace` only to drop keys on purpose. A core made of keys writes one key at a time (`delete` removes
  one) and refuses `--replace`.
- `infra/setup.py versions NAME` — the store's earlier versions the core keeps (core made of keys: last 50 each).
- `infra/setup.py request restore NAME VERSION --why TEXT` — asks Deyao (Inbox) to put that version back (below).
- `infra/setup.py mark-sensitive NAME` — the one-way upgrade, in the core and in the backup.
- The Fly token: `infra/fly-token.sh ~/.jarvis2/fly.tok` (narrowed to the app and to `jarvis2-init`), then
  `infra/setup.py backup-core ~/.jarvis2/fly.tok` — sent to the core sealed to its key, and backed up as the
  `core` store (a Recover brings it back).

All of them need a set-up core: they learn the master public key and the phone's keys from the core's signed
state, after checking its keys against `keys/box.pub`.

### Restoring a store to an earlier version (DESIGN "Restoring a store")

Keys lost or overwritten by a write (a session's `put-key`, a delete, a mistaken `write`): no kit, no Recover.

1. `JARVIS2_URL=https://jarvis2.deyaochen.com infra/setup.py versions STORE` — find the version before the mistake (each
   line: number, time, what made it, the key names it held).
2. `infra/setup.py request restore STORE VERSION --why "…"` and Discord Deyao "waiting on you: restore STORE in the
   Inbox". He reviews exactly what the core will put back and remove, and allows it with one Face ID (or does it
   himself: Stores → the store → Versions → Restore…; the web page's Versions → Propose restore files the same request).
3. Check `infra/setup.py versions STORE`: the newest version says `restore of version N` and is current. Sessions holding
   the store get the restored values only after the refresh unlock the router files in his Inbox.

A core restart (a new core) keeps no versions: its first version of each store is what the Recover brought. The bucket
backups (Recover with the kit) stay the way back from anything older or from a lost core. A restore's own backups are in
the bucket like any key write's, so a later Recover brings the restored store back.

## The router's secrets

Non-sensitive only (nothing that can reach a code push), SOPS-encrypted to `keys/box-age.pub`; Flux decrypts them
on the box with the age key the box got in user-data. Four Secrets, each rewritten whole by
`infra/router-secrets.py` (nobody can read the old values back), so name every key of the one you write:

- `infra/router-secrets.py KEY[=SRC]…` → `k8s/secrets/router.enc.yaml`:
  `LOBSTER_TOKEN STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD FLY_READ_TOKEN=file:~/.jarvis2/fly-read.tok
  JARVIS2_TUNNEL_KEY=file:…` (`JARVIS2_TUNNEL_KEY`: the tunnel proof key, the same value as the cf-tunnel Worker's
  secret `JARVIS2_TUNNEL_KEY` — without it no OpenCode/OpenClaw web UI) (the read-only Fly token:
  `infra/fly-read-token.sh`). The file written 2026-10-09 still carries four keys the router no longer reads
  (`JARVIS1_CREDENTIALS_ID/SECRET`, `JARVIS1_SERVICES_ID/SECRET`, Jarvis 1 Access service tokens) and the stale
  `GITHUB_READ_TOKEN` (DECISIONS 150): the next rewrite of this part leaves all five out. That rewrite needs every value
  above, and nobody can read the old `JARVIS2_TUNNEL_KEY` back: mint a new one and set it on the Worker in the same step
  (`wrangler secret put JARVIS2_TUNNEL_KEY` in claude-env `cf-tunnel/`); running OpenCode/OpenClaw sessions keep their
  old proof until they restart.
- `infra/router-secrets.py --part github GITHUB_READ_TOKEN=file:…` → `k8s/secrets/router-github.enc.yaml`: the
  repo picker's list token, the fine-grained PAT `jarvis2-repo-list` (`github-web pat-create-read jarvis2-repo-list
  <out>`: all repositories, no expiry, **Metadata read picked explicitly**). A fine-grained token with NO permission
  picked sees public repos only, even on "All repositories" (0 private; Settings → Repos says "No match." for a
  private repo). Check after a rollout with `infra/setup.py status`: `githubRepos.private` > 0. The default part
  (`router.enc.yaml`, written 2026-10-10) still holds an older public-only `GITHUB_READ_TOKEN` (that token is
  deleted on GitHub); `router-secrets-github` is the LAST `envFrom` in `k8s/apps/router.yaml`, so it wins. The next
  time the default part is rewritten, leave `GITHUB_READ_TOKEN` out of it.
- `infra/router-secrets.py --part backup BACKUP_READ_ACCESS_KEY BACKUP_READ_SECRET_KEY` →
  `k8s/secrets/router-backup.enc.yaml`: the backup bucket's read credential, with which the router serves the
  locked backups to the app's Recover (`infra/backup-read-key.py install` writes it; below).

- `infra/router-secrets.py --part flyorgs FLY_ORG_READ_TOKENS=file:…` → `k8s/secrets/router-flyorgs.enc.yaml`: the
  Machines view's other orgs, JSON `{"jarvis2-370": "<token>", "kamyee": "<token>"}`, each `fly tokens create readonly -o <org>`
  (named "Jarvis 2 Machines tab (read-only)"; revoke with `fly tokens list -o <org>` + `fly tokens revoke`).
- `infra/router-secrets.py --part flypersonal FLY_PERSONAL_READ_TOKEN=file:…` → `k8s/secrets/router-flypersonal.enc.yaml`:
  org personal for the Machines view. `FLY_PERSONAL_ORG_TOKEN=<an org token of personal> infra/fly-personal-read-token.sh OUT`
  attenuates it offline to Organization read (it checks the result lists apps and can't create a machine). It reads every
  machine's config in personal, env included (DECISIONS 138); it dies only with the token it was made from.
- `infra/router-secrets.py --part browserbase BROWSERBASE_API_KEY` → `k8s/secrets/router-browserbase.enc.yaml`: the
  Browserbase spend DM (`router/bbbudget.go`; cap and warn line are `BROWSERBASE_BUDGET_USD` / `_WARN_USD` in
  `k8s/apps/router.yaml`).
- `infra/router-secrets.py --part devices CF_DEVICE_TOKENS_API=file:…` → `k8s/secrets/router-devices.enc.yaml`: the
  Cloudflare token `jarvis2-device-tokens` (Access: Service Tokens read + write on the account, nothing else; minted with
  claude-env's `cloudflare-dash` skill, `cf_token.js jarvis2-device-tokens OUT a1c0fec57cf94af79479a6d827fa518c
  91f7ce32fa614d73b7e1fc8f0e78582b`), with which the router mints and deletes the paired apps' tokens.

The box's services have their own parts (Secrets in jarvis2-edge):

- `infra/router-secrets.py --part search STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD OPENROUTER_API` →
  `k8s/secrets/search.enc.yaml` (transcript search).
- `infra/router-secrets.py --part icloud-index OPENROUTER_API LOBSTER_TOKEN STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD BACKUP_AGE_KEY=env:ICLOUD_BACKUP_AGE_KEY`
  (the last from the store `icloud-backup`)
  → `k8s/secrets/icloud-index.enc.yaml` (the iCloud index; LOBSTER_TOKEN for its DMs: login expired, budget used up).
- `infra/router-secrets.py --part icloud-session ICLOUD_RCLONE_CONF=file:<rclone.conf with the [icloud] section>` →
  `k8s/secrets/icloud-session.enc.yaml`: the saved iCloud login. After a re-login (claude-env `icloud-drive` skill),
  write it again and push; the pod reads the mounted file and switches by itself (no restart needed).

After a box rebuild, re-run all of them (the age key is new).

### The backup bucket's read credential

The router's only way into the bucket; Deyao never sees it. It is the Hetzner S3 credential `jarvis2-backup-read`
in project "Cloud Code" (2827255), which also holds `de0ch-claude-6fdff6`. S3 credentials are project-wide, so
bucket policies narrow this one (principal `arn:aws:iam:::user/p2827255:<access key>`): on `jarvis2-backup-de0ch` a
Deny of every delete, delete-version, ACL, tagging, policy, versioning, lifecycle, CORS, website, logging,
notification, replication, object-lock and public-access-block change (26 actions, listed one by one: Hetzner
ignores `NotAction`, and refuses a policy naming `PutEncryptionConfiguration` or `PutBucketOwnershipControls` with
ServiceUnavailable); on `de0ch-claude-6fdff6` a Deny of `s3:*`. `PutObject` is allowed (`backup-read-key.py
allow-put`): the router adds each written key's backup (`keys/<store>/<key>.json`); the bucket is versioned, so a put
only adds a version (no prefix limit: Hetzner has no `NotResource` either; a version the router puts elsewhere is no
more than withholding, since every backup is checked against its writer's signature). Tested (throwaway names only):
list, get, list versions, get policy and put work; delete (plain, by version, multi), policy, versioning, lifecycle and
ACL changes are refused, and everything on the other bucket. A Ceph quirk seen with an earlier credential: a plain
delete (no version id) of an existing object may add a delete marker; that hides a backup but loses nothing (the
bucket is versioned), and the admin key removes the marker.

Making a new one (a box rebuild doesn't need one; a leak does): `infra/backup-read-key.py`, one step at a time,
with a headed Chrome on CDP port 9333 (`Xvfb :99` + `google-chrome --remote-debugging-port=9333 --disable-quic`;
the Console logs in with password only) and `HETZNER_USER`/`HETZNER_PASSWORD` (`pull-secrets --exec python3
infra/backup-read-key.py login` when they aren't in the env):

1. `login`, then `generate` — Console only (no API): Security → S3 credentials → a new `jarvis2-backup-read`
   (the Console accepts the same description twice), written straight to `~/.jarvis2/backup-read.env`
   (mode 600, never printed).
2. `policies` — the new access key replaces the old one as the principal in both bucket policies (admin key).
   Wait a minute, then `test` (the checks above, throwaway names only, cleaned up): seconds after a policy write a
   multi-delete once went through, a gateway not yet holding the new policy.
3. `delete-old` — the old credential's row ⋯ → Delete → OK (real mouse clicks; the menu ignores synthetic ones).
4. `install` — `infra/router-secrets.py --part backup` from the file, then the file is shredded; commit and push
   `k8s/secrets/router-backup.enc.yaml` and `k8s/apps/router.yaml` (the router restarts with it). Stop the Chrome
   and delete its profile.

## The Claude login

The router holds the one Claude OAuth pair every Claude session shares (`router/claudelogin.go`, API.md "The Claude
login", DECISIONS 115-121), on its volume, and is its ONLY refresher (Jarvis 2 never calls Jarvis 1; Jarvis 1, while it
still runs, follows the pair from here through `/peer/claude-login`). `infra/setup.py claude-login` shows it (no
secrets): account, expiry, last refresh, the participants of the refresh protocol (`m:<machine>` per session, `jarvis1`
while Jarvis 1 follows).

- **Re-login:** Settings → Claude account → Re-login (web page or app): the sign-in page opens; sign in, copy the code
  it shows (`code#state`), paste, Sign in. A new box starts with no login:
  Re-login once. A Re-login to another Claude account: also `infra/setup.py write claude CLAUDE_ACCOUNT_UUID` with the
  new account (DECISIONS 116).
- **A dead login** (the refresh was refused) DMs Deyao once; sessions stuck on "Please run /login" get "continue" after
  the Re-login.
- **Sessions:** a machine whose cert names the store `claude` takes the pair at boot and keeps a long poll open
  (`jarvis2-machine creds-sync`, its log in the machine's output), writing a new pair only when Anthropic says it is the
  store's account.

## Transcript search and the iCloud index

Two pods in jarvis2-edge (`services/search`, `services/icloud-index`; `k8s/apps/search.yaml`, `icloud-index.yaml`),
built by `.github/workflows/services.yml` (only the service that changed; its unit tests run inside the image build)
and pinned by digest like the router. Only the router reaches them (`router/searchsvc.go`); API.md "Transcript search"
and "iCloud index" for the calls. Check them from any Jarvis 2 session:
`curl -s "$JARVIS_URL/api/search/status"` and `curl -s "$JARVIS_URL/api/icloud/status"`.

- **The iCloud index is identity-level**: sessions reach it only while they hold the `identity` store (router 403
  otherwise; Deyao's app always). Its Storage Box copy is age-encrypted; the private key is `BACKUP_AGE_KEY` in the
  `icloud-index` part and `ICLOUD_BACKUP_AGE_KEY` in the sensitive store `icloud-backup` (re-run the part from that
  store after a box rebuild, or the copy can't be opened).
- **Their databases live on the pods' volumes, with a copy on the Storage Box** (`claude-records/.jarvis2-services/`:
  `search.db.gz` daily, `icloud-index.db.gz.age` weekly). A missing database (a new box, a lost volume) is seeded from
  that copy at start. The iCloud index refuses to start without one (`SEED_REQUIRED=1`): its database holds the AI
  budget's lifetime ledger (`ai_spent`, USD 25 cap, Deyao 2026-10-01), and starting empty would spend it again. To
  really start from nothing, set `SEED_REQUIRED` to "0" for one rollout.
- **The AI budget**: `AI_BUDGET_USD` in `k8s/apps/icloud-index.yaml`. At the move (2026-10-13) it was used up
  (USD 25.00 spent), so images, scans, video and speech wait (`wait-ai`); names and text documents are still read.
  Raising it is Deyao's call.
- **The iCloud login expired**: the pod DMs Deyao once and pauses. A session re-logs in (claude-env `icloud-drive`
  skill), then the `icloud-session` part is written again (above).
- **A file that kills the pod** (out of memory, a native crash) is retried at most 3 times, then marked
  `error: not read: stopped the indexer N times`; images over 40 megapixels are decoded small (JPEG) or skipped.
- **Moving from Jarvis 1** (done 2026-10-13): Jarvis 1's session token can't exec into its pods, so a temporary
  read-only Job in claude-env (`selfhost/k8s/jarvis2-export`) copied both databases (SQLite online backup) and the
  iCloud pod's own rclone session (SOPS-encrypted to `keys/box-age.pub`) to the Storage Box; the Jarvis 2 pods
  seeded from it. Jarvis 1's two pods keep running until its freeze: scale them to 0 then, so only one index reads
  iCloud and spends on embeddings.

## Importing a paused Jarvis 1 session

Jarvis 1's paused sessions stay where they are (`claude-records/.paused/<id>/`, read only). From the setup session
(`JARVIS2_URL=https://jarvis2.deyaochen.com`):

1. `infra/setup.py jarvis1` lists them with their import state; `infra/setup.py jarvis1 prepare ID… --wait` hashes
   each one's files (minutes for a few GB; the router streams them, nothing is staged).
2. Pick each one's Jarvis 2 stores: `default` for Jarvis 1's `default`, plus whatever split-off store the session's
   transcript shows it used (the store layout is private: claude-env `.claude/skills/jarvis2/`), plus the repo stores
   (`github-<repo>`) for its repos. Say the mapping in the reason.
3. Only when all are prepared (an approval lapses after 10 minutes): `infra/setup.py jarvis1 import ID --stores a,b
   --why "…"` for each, then ping Deyao on Discord ("waiting on you: …"). Each is one Inbox approval (Restore,
   "Restores machine <Jarvis 1 id>"), one Face ID each. A lapsed one: run the same import again.
4. After his approval: `infra/setup.py jarvis1` shows the new session ids (`imported` once one came up); check each
   machine's `~/artifacts/jarvis1-import/rearmed.txt` and the transcript tail (the move notice is the first prompt, so
   the reply shows the conversation resumed).

The machine has Fly's default 8 GB disk: an import that unpacks near 5 GB plus its pause snapshot is near the limit
(DECISIONS 130).

## Device leases and watches

Nothing to set up: both live in the router (`router/leases.go`, `router/watches.go`; API.md). Leases: `GET /api/leases`
shows every device's holder, queue and log; a stuck holder is cleared with `POST /api/leases/<name>/force-return`
(the app's Devices tab when it has one), and a lease that nobody renews lapses after its ttl (1 h) by itself.
Watches: each session's `watches` in `/api/state` show `runs`, `lastExit`, `lastError` and `lastOutput`; a watch whose
check always exits 2 with "not found" is usually missing a secret, which a check never gets (DECISIONS 114). The
watch runner is the Deployment `watch` in `jarvis2-edge` (`services/watch`, pinned by the `services` workflow); it
holds no state, so a restart only delays the due checks. When it is down every check counts as "not yet" (the
router logs `the watch runner is unreachable`) and nothing is delivered until it is back.

## Content stores

Jarvis 1's folders `claude-records/.content/<name>/` on the Storage Box, used in place (`router/content.go`, API "Content
stores"). Deyao manages them in the web page's Content tab; a session picks them in New session (web or the iPhone app)
and gets each in `~/content/<name>/` at every start (`content-sync pull` in the base image's entrypoint);
`content-sync status` / `content-sync push <name>` from inside the session. Nothing on the machine holds Storage Box
credentials. A task picks them with a field `optionsFrom: "content"` (`tasks/encrypt-to-content`, `paraphrase-to-content`,
`proton-send`; their key store is a field `optionsFrom: "stores"` whose store holds `AES_KEY`).

## Paired apps (OpenClaw, Paseo)

Deyao's OpenClaw and Paseo apps pair with `GET /api/devices/pair` (his Access login) and get their own Access service token;
Settings → Paired apps (web) lists and removes them. The Access app "Jarvis 2 devices" (`infra/cloudflare.py --devices`;
paths `/api/remotes`, `/api/sessions/*/start`; audience `ACCESS_DEVICES_AUD` in `k8s/apps/router.yaml`) lets any service
token through to those two paths and the router admits only paired ones. Check from outside: a service token that isn't
a paired app gets the router's 403 `{"error":"Access login required"}` on `/api/remotes` (not Cloudflare's login page).
The apps call `JarvisConfig.baseURL` (DE0CH/openclaw `apps/ios/Sources/Jarvis/JarvisModels.swift`) and `jarvis.url`
(DE0CH/paseo `packages/app/app.config.js`): both name jarvis2.deyaochen.com (TestFlight builds through claude-env skills
`openclaw-ios`, `paseo-ios`). Deyao pairs each app once: OpenClaw: Settings → Gateway → Jarvis → Sign In with Jarvis;
Paseo: Settings → Jarvis → Pair; each opens the Access sign-in sheet for this host. Paseo's CI simulator test runs its
Jarvis checks only with a paired device token (`JARVIS_E2E_CLIENT_ID/SECRET` in the fork's secrets); while the old
Jarvis 1 token is there, it only installs and launches the app.

## The box's network: IPv6-only, IPv4 out through WARP

Every box has no public IPv4 (Deyao, 2026-10-13: the Hetzner account is at its limit of 10 primary IPs; DECISIONS 156).
`infra/warp-host.sh` (run by cloud-init, and by the unit `jarvis2-warp-host.service` on a converted box) installs
Cloudflare's WARP client in mode `tunnel_only` with IPv6 excluded (`tunnel ip add-range ::/0`): IPv4 (GitHub, GHCR,
Fly's WireGuard gateways, 1.1.1.1 for CoreDNS) goes through WARP, IPv6 stays native. k3s's node IP is `10.254.254.1`
on the dummy interface `k3s0` (`/etc/rancher/k3s/config.yaml`), so the cluster stays IPv4. Everything the pods reach goes through WARP (they have no IPv6), the cloudflared tunnel included. Signs that WARP
is down: jarvis2.deyaochen.com unreachable (tunnel down), Flux "failed to checkout" from github.com, ImagePullBackOff on ghcr.io, machines unable to reach the router over the
peer. There is no way in to look; WARP reconnects by itself (warp-svc, always on), and a box git can't fix is
rebuilt. The same WARP steps for every other Hetzner server Claude makes: claude-env `scripts/hetzner-warp.sh`.

### Converting a box that still has its IPv4 (not planned: production keeps its IPv4, Deyao 2026-10-13)

`CONFIRM=yes infra/convert-ipv6.sh` (env `HETZNER_JARVIS2_MOCK_API`, plus `JARVIS2_SETUP_ACCESS_ID/SECRET` for the
wait): graceful shutdown, the primary IPv4 unassigned and deleted, a single-use rescue boot (throwaway SSH key, over
IPv6) that writes `warp-host.sh` and its boot unit onto the disk, then a boot into the box's own system; it waits until
the core answers through the tunnel. About 10 minutes of downtime. The box keeps its keys, Secrets and Flux state, but
it reboots, so the core starts empty: Deyao Recovers in the app (as after a power failure). DECISIONS 157.

## Rebuilding the box

1. Delete the server in the jarvis2 Hetzner project (API or console).
2. `infra/cloudflare.py ~/.jarvis2/cloudflare.env` (with `ROTATE=1` if that file is gone: a new setup service
   token; put it in the `default` store as JARVIS2_SETUP_ACCESS_ID/SECRET).
3. `infra/create.sh` — a new box key and age key (commit `keys/box.pub`, `keys/box-age.pub`), a new WireGuard
   peer, no SSH, no open port, no IPv4 (above). Then both `infra/router-secrets.py …` runs (above; the backup read credential
   needs a new one, since its old value exists nowhere but the old box's Secret). It waits until
   `setup.py identity` answers.
4. Deyao sets the core up in the app: Recover (above). Paused sessions are lost (their certs were signed by the
   old core).

## Testing

- Unit: `go test ./...` in core/, router/, machine/ (the core's guarantees are tested in core/).
- The app's crypto against the real core and router: the `ios` workflow's interop job (`ios/interop`, runs on
  Linux too with swift-crypto: `ios/ci/standins.sh W`, then `swift run Interop` with the `INTEROP_*` env).
- App code that needs no simulator (ResumeOnce: a continuation answered at most once): `swift run Units` in
  `ios/interop` (the interop job runs it first).
- The iOS app on a simulator: the `ios` workflow (compile both flavours, the walkthrough in light and dark against a
  real core and router on the runner, recorded); `transitions.yml` taps every navigation and fails on a blank screen.
- The web page: the `web` workflow (typecheck + export of `app/`).
- End to end on real Fly with a software phone and the public TEST master key: `infra/e2e.sh` (a local core
  and router, a throwaway WireGuard peer, the session image; set `E2E_SESSION_IMAGE` to a pinned tag). It sets its
  own core up and never touches the production core. It always runs with Jarvis 1 unreachable (DECISIONS 152; needs
  passwordless sudo, which sessions have): the router in its own mount namespace whose /etc/hosts sends
  jarvis.deyaochen.com to a listener that fails the test on any connection, each machine with it blackholed; search, the
  watch runner and the Storage Box are local stand-ins, so it also covers a search, a device lease, a watch, a content
  store pulled at boot and pushed back, and a newer Claude pair reaching a running machine.
  `E2E_ONLY=drain` (with its own `E2E_PEER`/`E2E_PORT` when another run is going) checks a rollout's drain instead of
  the rest: SIGTERM to the router while the first session's pause waits for its snapshot → reads served, new actions
  503, the pause ends `paused`, the router exits.

### Rehearsing Recover on a real box

`infra/rehearse-recover.sh` proves Reset → backups → failure → Recover → a session, on a REAL throwaway box built
the way production is (`infra/cloudflare.py`, `infra/create.sh`, `infra/cloud-init.sh`, Flux applying `./k8s/apps`
with the production images at a pinned commit), in the Hetzner project **runners** (`HCLOUD_TOKEN`). It never
touches the production box, core, router, tunnel, Access apps, WireGuard peer or bucket. About 45 minutes; one
cx23 for about an hour plus a second one for the rebuild (EUR 0.01056/h each; IPv6-only, no IPv4), a few minutes of small Fly
machines. Run it from a setup session (needs `JARVIS2_FLY_TOKEN`, `JARVIS2_SETUP_KEY`, `CF_JARVIS2_INFRA_TOKEN`,
`CLOUDFLARE_API`, `HETZNER_S3_*`) with a swift.org toolchain (`SWIFT_BIN`; the app's side is the `Rehearse` target
in `ios/interop`, the app's own CoreSetup/CoreCrypto):

1. its own tunnel + `jarvis2-rehearsal-<run>.deyaochen.com` + Access app + service token, its own versioned bucket
   `jarvis2-rehearsal-<run>` (the run id: the unix time at start), a core Fly token narrowed as production's that also expires after 6 h, then the box;
2. Reset with the TEST kit (`e2e/testdata`), stores written with `infra/setup.py` (dummy values: not sensitive,
   sensitive, created-then-marked, the harness's `claude` and `tunnel`, the core's Fly token), backups checked;
3. power failure (Hetzner hard reset) → Recover → every store and its sensitivity back (backups and the core's
   signed list) → a session on Fly with them, values checked on the machine → destroyed;
4. the app's restart (the kit wipes the core, Kubernetes starts an empty one) → Recover;
5. the server deleted and made again (new box key, new peer) → Recover → a session again (`SKIP_REBUILD=1` skips);
6. teardown, also on failure: servers, firewall, peer, the rehearsal cores' machines (`JARVIS2_CORE_KEY`),
   Cloudflare tunnel/DNS/app/token, every object version and the bucket: this run's only. After a crash:
   `infra/rehearse-recover.sh teardown <run>`.

Test-only differences (all in the box's user-data, none in git; `infra/rehearsal-box.sh`, shared with the phone
replica): the router runs `NO_ACCESS=1` behind an Access app whose only policy is the rehearsal service token (the
router's own check wants Deyao's email login); a Flux patch sets `MACHINE_URL` (the peer `jarvis2-rehearsal-<run>`),
`BACKUP_BUCKET`, `RECORDS_OFF=1` and Discord off, and there is no `k8s/secrets` Kustomization (encrypted to
production's age key); the router's backup read key is the admin S3 key (a narrowed one is Console-only); the kit is
the public test key, so the bucket holds only dummy values and the expiring Fly token. A hard reset waits 90 s after
the stores are written: a power cut seconds after the images were pulled leaves them truncated on disk ("exec
/router: exec format error" for ever after; only a rebuild cures it). Also checked: a session stuck at boot on a
locked store is destroyed within 90 s.

### The phone replica (the gate before a TestFlight build)

`infra/phone-replica.sh` (one command, about 70 minutes): a throwaway box as above but with Access as in production
(`MODE=replica`: the hostname admits one email, `bot@deyaochen.com`, by a real one-time-PIN login, and `/setup` the
service token; the router checks both JWTs with `ALLOWED_EMAIL` = that email), then `.github/workflows/replica.yml` on
a free GitHub macOS runner: the app's Release build (the TestFlight configuration of the native app in `ios/`; only
`JARVIS_BASE` and `JARVIS_KEYS_REF` point at the box) on an iPhone 17 simulator (Deyao's iPhone18,3) on iOS 27.0,
Face ID enrolled. `ios/UITests/ReplicaUITests.swift` taps every flow: the Access
sign-in sheet (the PIN read from the bot's mailbox by this script and relayed to the runner through ppng.io), Reset
(the kit read off the page, backgrounded mid-flow), stores (a Face ID failure, then unlock and lock), New session (one
page, its stores and the harness's unlocked) running on Fly within 10 minutes, a kill and relaunch, the terminal
(the router's page in a WebView: turned away → the grant review → Deny, then Allow with Face ID → a command's output), Grants (a standing rule,
forgotten), the Inbox from a session (`jarvis2-request` run in its machine by this script with `flyctl machine exec`:
a grant request denied, another allowed with Face ID; the badge, the three fields, the caller; then a batch of two
grants filed with `jarvis2-request batch`, allowed with ONE Face ID), Settings → Repos (a
throwaway repo's deploy key added and removed by the core; the script checks GitHub), the Inbox from the setup session
(`setup.py request remove-repo` denied with the repo kept, then `request add-repo` allowed: the key made on GitHub),
a session stuck at boot (its store locked right after Create) destroyed within 90 s, Destroy, then Recover with the
kit (restart and recover) and every store back with its sensitivity, and a relaunch. A step fails on a missing
element within its time, a near-blank screenshot, or a session not running in time. The run's video, screenshots and
logs land in `~/artifacts/replica/<run>/`. Teardown also removes the keys branch `rehearsal-keys-<run>`, the repo
`DE0CH/jarvis2-replica-<run>` and its 7-day PAT `jarvis2-replica-deploy-keys-<run>`. `infra/phone-replica.sh teardown
<run>` after a crash.

**One run at a time, and each run's resources are its own** (`infra/rehearsal-box.sh`): every name carries the run id
(`<base>-<run>`: box, firewall, WireGuard peer, tunnel, hostname, Access apps, service token, bucket; the box is also
labelled `rehearsal-base=<base>`), the script finds its workflow run by name (`replica rehearsal-keys-<run>`), and
teardown removes only its own run's. A run refuses to start while another run of the same base has a server, bucket
or tunnel, anywhere (it lists them: a run in flight, or a crashed run's leftovers, removed with `teardown <run>`); two
runs started at the same moment both see each other's bucket and both stop. The rehearsal (`jarvis2-rehearsal`) and
the replica (`jarvis2-rehearsal-replica`) are different bases and can run together. Before this, two sessions' replicas
under one shared name deleted each other's service token, PAT and bucket (2026-10-13).

- **The gate:** the `ios` workflow's TestFlight job (environment `release`, main only) ships only when a `replica` run
  passed on a commit with the same `ios/` and `policy/` (it checks the last 30 successful replica runs). After an app
  change: `infra/phone-replica.sh`, then run the `ios` workflow with `only=testflight`. `replica_gate=skip` ships without it (say why in the commit or the run).
- **The core it runs:** while `k8s/apps/core.yaml` carries `jarvis2/core-pin: hold` (a core change waiting for
  Deyao's go), the replica runs the core main builds — the one the shipped app expects — not the pinned one;
  `REPLICA_PINNED_CORE=1` runs the pinned core (what production has today: e.g. Settings → Repos says "the running
  core predates deploy keys").
- **The simulator:** the composite action `.github/actions/ios-simulator`, shared by `replica.yml`, `ios.yml`'s
  walkthrough and `transitions.yml`: Xcode 27.0 (build 27A266a), the iOS 27.0 runtime (Deyao's phone runs 27.0) and
  the device type whose profile says iPhone18,3 (iPhone 17), all pinned; a missing pin fails the run rather than
  falling back. It runs on GitHub's free `xcode-27` runner image, which ships that Xcode and runtime, so nothing is
  downloaded (only if the runtime were missing does it fetch it with `xcodebuild -downloadPlatform`). The jobs address
  the simulator by `$SIM_UDID` (the image has stock devices with the same name); `device.txt` and the run summary say
  what was used. A new iOS on his phone = bump the action's `ios`/`xcode`/`xcode-build` defaults (and `runs-on` when
  the Xcode moves to another image).
- **What only the replica differs in:** `JARVIS_BASE` and `JARVIS_KEYS_REF` in the Release build; Face ID on the
  simulator is LAContext in front of the software key (no Secure Enclave there); the Access login admits the bot's
  mailbox, not Deyao's.

## Looking at things

- What the core did: it keeps no log of its own (R2: as small and stateless as it can be); every change it makes is a
  signed answer the router keeps (certs, the input log in the router's `input-log.jsonl`).
- A session machine's log: `FLY_API_TOKEN=$JARVIS2_FLY_TOKEN flyctl logs -a jarvis2-sessions --machine <id> --no-tail`
- The box itself: no way in by design; GitHub (Flux status is visible only through what the services answer).
