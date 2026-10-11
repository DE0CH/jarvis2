# Jarvis 2 — runbook

Everything here runs from a Claude session whose env has Jarvis 1's `default` store (JARVIS2_* keys,
HETZNER_JARVIS2_MOCK_API, HETZNER_S3_*, CF tokens). The box has no SSH and no reachable k8s API: it changes only
through git, and a box git can't fix is replaced.

## Deploying

`git push` to main. The `images` workflow builds the core, router and session images, then pins their tags in
`k8s/apps/`; Flux applies within a minute. The core's tag moves only when `core/` changed (a core restart is a
new, empty core: see "Setting the core up"), and never while the core Deployment in `k8s/apps/core.yaml` carries the
annotation `jarvis2/core-pin: hold`: a core change that waits for Deyao's go (he then Recovers). To roll it out once
he says so, delete the annotation, push, then `gh workflow run images -R DE0CH/jarvis2` (a k8s/ push alone doesn't
run it): it pins the newest core and Flux restarts it.

## The keys (`keys/`)

- `box.pub` — written by `infra/create.sh` with each new box; commit it. The app and `setup.py` check a core's
  keys against it.
- `box-age.pub` — the box's age key (SOPS recipient of the router's secrets), also from `infra/create.sh`.
- `setup.pub` — the setup key (private half JARVIS2_SETUP_KEY); also `SETUP_KEY` in `k8s/apps/router.yaml`. It
  signs every `/setup` call and every store backup; the app checks the backups against it.

There is no master key in git: Deyao makes it in the app (Reset), and the core learns it from his claim.

## Setting the core up (Deyao, in the app — nothing for Claude to do)

A new core (after any restart, deploy of `core/`, or box rebuild) is empty. Deyao opens the app (it shows
Reset or recover by itself, or Settings → Reset or recover…):

- **Reset** — the app shows a new recovery kit (`jarvis2-kit:2:…`, Copy), he saves it in his password manager,
  taps "I've saved it", and the core is set up with no stores. Then "After a Reset" below.
- **Recover** — he pastes his kit; the app reads the backups through the router and the core is set up with every
  store. Nothing else to do.

`infra/setup.py identity` says whether the core is empty or set up (and with which master public key).

### After a Reset (the setup session)

`infra/fill-stores.sh` — once the core is set up: creates the non-sensitive stores, writes every store to the core
and its backup (sealed to the new master key, read from the core's signed state), minting or rotating every token
whose value lived only in the old stores and backups, sends the core its Fly token (`backup-core` with a fresh
`infra/fly-token.sh`), and deletes the local copies. The stores and their keys: Deyao's own stores by kind, `default` (not sensitive), `identity`, `infra`,
`money`, `devices`, `work` and `jarvis1` (sensitive), whose key names are listed in the private claude-env repo
(`.claude/skills/jarvis2/stores.txt`, read by the script; run it under `pull-secrets --exec` so it sees the setup
session's live store values); `github-deploy-keys` (sensitive; GITHUB_DEPLOY_KEYS_TOKEN: a new fine-grained PAT
`jarvis2-deploy-keys`, all repositories, Repository "Administration: read and write" only, minted by `github-web
pat-create-all`, which deletes the same-name token first; its line is in the layout file too); the harness stores
`openrouter` (OPENROUTER_API), `claude` (JARVIS1_CREDENTIALS_ID/SECRET: Access service token `jarvis2-store-claude`,
rotated), `tunnel` (CF_ACCESS_CLIENT_ID/SECRET: `jarvis2-tunnel`, rotated) and `core` (the Fly token). The narrowed
Fly token in an old `core` backup can't be revoked on its own (an attenuation of JARVIS2_FLY_TOKEN); it stays sealed
to the old master key. Old backup versions stay in the versioned bucket, sealed to their old key. Deyao then unlocks
stores in the app as usual, and adds his repos again in Settings → Repos (the repos' stores aren't backed up, below).

## Repos and their deploy keys

Each repo is added in the app (Settings → Repos → Add repo, or "Make key" on a listed repo whose store is missing):
the shell's secure page shows the core's signed request, and one Face ID lets the core use `github-deploy-keys` for
that call to make an ed25519 key, add it to the repo as a read/write deploy key titled `jarvis2 <store>`, and keep
the private half in the store `github-<repo>` (`github-jarvis2` always sensitive). Nothing for Claude to do. Remove
deletes both. A Recover brings no repo stores back (no backup): "Make key" again, which also deletes the old key on
GitHub. Sessions that include a repo's store clone, pull and push it over SSH (`machine/deploykeys.go`).

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
- `infra/setup.py mark-sensitive NAME` — the one-way upgrade, in the core and in the backup.
- The Fly token: `infra/fly-token.sh ~/.jarvis2/fly.tok` (narrowed to the app and to `jarvis2-init`), then
  `infra/setup.py backup-core ~/.jarvis2/fly.tok` — sent to the core sealed to its key, and backed up as the
  `core` store (a Recover brings it back).

All of them need a set-up core: they learn the master public key and the phone's keys from the core's signed
state, after checking its keys against `keys/box.pub`.

## The router's secrets

Non-sensitive only (nothing that can reach a code push), SOPS-encrypted to `keys/box-age.pub`; Flux decrypts them
on the box with the age key the box got in user-data. Three Secrets, each rewritten whole by
`infra/router-secrets.py` (nobody can read the old values back), so name every key of the one you write:

- `infra/router-secrets.py KEY[=SRC]…` → `k8s/secrets/router.enc.yaml`:
  `LOBSTER_TOKEN STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD FLY_READ_TOKEN=file:~/.jarvis2/fly-read.tok
  JARVIS1_CREDENTIALS_ID=file:… JARVIS1_CREDENTIALS_SECRET=file:… JARVIS1_SERVICES_ID=file:… JARVIS1_SERVICES_SECRET=file:…
  JARVIS2_TUNNEL_KEY=file:… JARVIS2_REMOTES_CLIENT_ID=…` (`JARVIS2_TUNNEL_KEY`: the tunnel proof key, the same value as the cf-tunnel Worker's
  secret `JARVIS2_TUNNEL_KEY` — without it no OpenCode/OpenClaw web UI; `JARVIS2_REMOTES_CLIENT_ID`: optional, the
  client id of the service token that may read `/api/remotes`)
  (`jarvis2-claude-credentials` and `jarvis2-services` are Jarvis 1 Access service tokens that claude-env's cf-tunnel
  Worker confines to their own paths, `CONFINED_TOKENS`) (the read-only Fly token: `infra/fly-read-token.sh`).
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

After a box rebuild, re-run all three (the age key is new).

### The backup bucket's read credential

The router's only way into the bucket; Deyao never sees it. It is the Hetzner S3 credential `jarvis2-backup-read`
in project "Cloud Code" (2827255), which also holds `de0ch-claude-6fdff6`. S3 credentials are project-wide, so
bucket policies narrow this one (principal `arn:aws:iam:::user/p2827255:<access key>`): on `jarvis2-backup-de0ch` a
Deny of every write, delete, delete-version, ACL, tagging, policy, versioning, lifecycle, CORS, website, logging,
notification, replication, object-lock and public-access-block change (27 actions, listed one by one: Hetzner
ignores `NotAction`, and refuses a policy naming `PutEncryptionConfiguration` or `PutBucketOwnershipControls` with
ServiceUnavailable); on `de0ch-claude-6fdff6` a Deny of `s3:*`. Tested (throwaway names only): list, get, list
versions and get policy work; put, copy, delete (plain, by version, multi), policy, versioning, lifecycle and ACL
changes are refused, and everything on the other bucket. A Ceph quirk seen with an earlier credential: a plain
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

## Rebuilding the box

1. Delete the server in the jarvis2 Hetzner project (API or console).
2. `infra/cloudflare.py ~/.jarvis2/cloudflare.env` (with `ROTATE=1` if that file is gone: a new setup service
   token; put it in the `default` store as JARVIS2_SETUP_ACCESS_ID/SECRET).
3. `infra/create.sh` — a new box key and age key (commit `keys/box.pub`, `keys/box-age.pub`), a new WireGuard
   peer, no SSH, no open port. Then both `infra/router-secrets.py …` runs (above; the backup read credential
   needs a new one, since its old value exists nowhere but the old box's Secret). It waits until
   `setup.py identity` answers.
4. Deyao sets the core up in the app: Recover (above). Paused sessions are lost (their certs were signed by the
   old core).

## Testing

- Unit: `go test ./...` in core/, router/, machine/ (the core's guarantees are tested in core/).
- The app's crypto against the real core and router: the `app` workflow's interop job (`app/ios/interop`, runs on
  Linux too with swift-crypto: `app/ios/ci/standins.sh W`, then `swift run Interop` with the `INTEROP_*` env).
- End to end on real Fly with a software phone and the public TEST master key: `infra/e2e.sh` (a local core
  and router, a throwaway WireGuard peer, the session image; set `E2E_SESSION_IMAGE` to a pinned tag). It sets its
  own core up and never touches the production core.

### Rehearsing Recover on a real box

`infra/rehearse-recover.sh` proves Reset → backups → failure → Recover → a session, on a REAL throwaway box built
the way production is (`infra/cloudflare.py`, `infra/create.sh`, `infra/cloud-init.sh`, Flux applying `./k8s/apps`
with the production images at a pinned commit), in the Hetzner project **runners** (`HCLOUD_TOKEN`). It never
touches the production box, core, router, tunnel, Access apps, WireGuard peer or bucket. About 45 minutes; one
cx23 for about an hour plus a second one for the rebuild (EUR 0.01056/h each + IPv4), a few minutes of small Fly
machines. Run it from a setup session (needs `JARVIS2_FLY_TOKEN`, `JARVIS2_SETUP_KEY`, `CF_JARVIS2_INFRA_TOKEN`,
`CLOUDFLARE_API`, `HETZNER_S3_*`) with a swift.org toolchain (`SWIFT_BIN`; the app's side is the `Rehearse` target
in `app/ios/interop`, the shell's own CoreSetup/CoreCrypto):

1. its own tunnel + `jarvis2-rehearsal.deyaochen.com` + Access app + service token, its own versioned bucket
   `jarvis2-rehearsal-<unix time>`, a core Fly token narrowed as production's that also expires after 6 h, then the box;
2. Reset with the TEST kit (`e2e/testdata`), stores written with `infra/setup.py` (dummy values: not sensitive,
   sensitive, created-then-marked, the harness's `claude` and `tunnel`, the core's Fly token), backups checked;
3. power failure (Hetzner hard reset) → Recover → every store and its sensitivity back (backups and the core's
   signed list) → a session on Fly with them, values checked on the machine → destroyed;
4. the app's restart (the kit wipes the core, Kubernetes starts an empty one) → Recover;
5. the server deleted and made again (new box key, new peer) → Recover → a session again (`SKIP_REBUILD=1` skips);
6. teardown, also on failure: servers, firewall, peer, the rehearsal cores' machines (`JARVIS2_CORE_KEY`),
   Cloudflare tunnel/DNS/app/token, every object version and the bucket. After a crash: `infra/rehearse-recover.sh
   teardown`.

Test-only differences (all in the box's user-data, none in git; `infra/rehearsal-box.sh`, shared with the phone
replica): the router runs `NO_ACCESS=1` behind an Access app whose only policy is the rehearsal service token (the
router's own check wants Deyao's email login); a Flux patch sets `MACHINE_URL` (the peer `jarvis2-rehearsal`),
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
a free GitHub macOS runner: the app's Release build (the TestFlight configuration, shell and extension; only
`JARVIS_BASE` and `JARVIS_KEYS_REF` point at the box) on an iPhone 17 simulator (Deyao's iPhone18,3) with the newest
iOS runtime the runner has, Face ID enrolled. `app/ios/UITests/ReplicaUITests.swift` taps every flow: the Access
sign-in sheet (the PIN read from the bot's mailbox by this script and relayed to the runner through ppng.io), Reset
(the kit read off the page, backgrounded mid-flow), stores (a Face ID failure, then unlock and lock), New session (one
page, its stores and the harness's unlocked) running on Fly within 10 minutes, a kill and relaunch, the terminal
(turned away → the grant page → Deny, then Allow with Face ID → a command's output), Grants (a standing rule,
forgotten), Settings → Repos (a throwaway repo's deploy key added and removed by the core; the script checks GitHub),
a session stuck at boot (its store locked right after Create) destroyed within 90 s, Destroy, then Recover with the
kit (restart and recover) and every store back with its sensitivity, and a relaunch. A step fails on a missing
element within its time, a near-blank screenshot, or a session not running in time. The run's video, screenshots and
logs land in `~/artifacts/replica/<time>/`. Teardown also removes the keys branch `rehearsal-keys-<time>`, the repo
`DE0CH/jarvis2-replica-<time>` and its 7-day PAT. `infra/phone-replica.sh teardown` after a crash. One run per
box name at a time (a lock); the rehearsal and the replica use different names and can run together.

- **The gate:** the `app` workflow's TestFlight job ships only when a `replica` run passed on a commit with the same
  `app/` (it checks the last 30 successful replica runs). After an app change: `infra/phone-replica.sh`, then run
  the `app` workflow with `only=testflight`. `replica_gate=skip` ships without it (say why in the commit or the run).
- **The core it runs:** while `k8s/apps/core.yaml` carries `jarvis2/core-pin: hold` (a core change waiting for
  Deyao's go), the replica runs the core main builds — the one the shipped app expects — not the pinned one;
  `REPLICA_PINNED_CORE=1` runs the pinned core (what production has today: e.g. Settings → Repos says "the running
  core predates deploy keys").
- **The simulator:** iPhone 17 (Deyao's iPhone18,3) with the newest runtime the runner image has; on macos-26 that
  is iOS 26.5 with Xcode 26.6 (his phone runs iOS 27.0, which needs Xcode 27; the workflow tries to download it and
  records what it used in `device.txt`).
- **What only the replica differs in:** `JARVIS_BASE` and `JARVIS_KEYS_REF` in the Release build; Face ID on the
  simulator is LAContext in front of the software key (no Secure Enclave there); the Access login admits the bot's
  mailbox, not Deyao's.

## Looking at things

- The core's signed log, through the app or `POST /api/core/log` (behind Deyao's login).
- A session machine's log: `FLY_API_TOKEN=$JARVIS2_FLY_TOKEN flyctl logs -a jarvis2-sessions --machine <id> --no-tail`
- The box itself: no way in by design; GitHub (Flux status is visible only through what the services answer).
