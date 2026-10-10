# Jarvis 2 — runbook

Everything here runs from a Claude session whose env has Jarvis 1's `default` store (JARVIS2_* keys,
HETZNER_JARVIS2_MOCK_API, HETZNER_S3_*, CF tokens). The box has no SSH and no reachable k8s API: it changes only
through git, and a box git can't fix is replaced.

## Deploying

`git push` to main. The `images` workflow builds the core, router and session images, then pins their tags in
`k8s/apps/`; Flux applies within a minute. The core's tag moves only when `core/` changed (a core restart is a
new, empty core: see "Setting the core up").

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
session's live store values); the harness stores `openrouter` (OPENROUTER_API), `github-claude-env` (GITHUB_TOKEN_CLAUDE_ENV: a new PAT
`jarvis2-sessions-claude-env-push`), `github-jarvis2` (sensitive; GITHUB_TOKEN_JARVIS2: a new PAT
`jarvis2-sessions-jarvis2-push`; `github-web pat-create` deletes the same-name token first), `claude`
(JARVIS1_CREDENTIALS_ID/SECRET: Access service token `jarvis2-store-claude`, rotated), `tunnel`
(CF_ACCESS_CLIENT_ID/SECRET: `jarvis2-tunnel`, rotated) and `core` (the Fly token). The narrowed Fly token in an
old `core` backup can't be revoked on its own (an attenuation of JARVIS2_FLY_TOKEN); it stays sealed to the old
master key. Old backup versions stay in the versioned bucket, sealed to their old key. Deyao then unlocks stores
in the app as usual.

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
on the box with the age key the box got in user-data. Two Secrets, each rewritten whole by
`infra/router-secrets.py` (nobody can read the old values back), so name every key of the one you write:

- `infra/router-secrets.py KEY[=SRC]…` → `k8s/secrets/router.enc.yaml`:
  `LOBSTER_TOKEN STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD FLY_READ_TOKEN=file:~/.jarvis2/fly-read.tok
  JARVIS1_CREDENTIALS_ID=file:… JARVIS1_CREDENTIALS_SECRET=file:… JARVIS1_SERVICES_ID=file:… JARVIS1_SERVICES_SECRET=file:… GITHUB_READ_TOKEN=file:…
  JARVIS2_TUNNEL_KEY=file:… JARVIS2_REMOTES_CLIENT_ID=…` (`GITHUB_READ_TOKEN`: a fine-grained token listing repos only,
  `github-web pat-create-read`; `JARVIS2_TUNNEL_KEY`: the tunnel proof key, the same value as the cf-tunnel Worker's
  secret `JARVIS2_TUNNEL_KEY` — without it no OpenCode/OpenClaw web UI; `JARVIS2_REMOTES_CLIENT_ID`: optional, the
  client id of the service token that may read `/api/remotes`)
  (`jarvis2-claude-credentials` and `jarvis2-services` are Jarvis 1 Access service tokens that claude-env's cf-tunnel
  Worker confines to their own paths, `CONFINED_TOKENS`) (the read-only Fly token: `infra/fly-read-token.sh`).
- `infra/router-secrets.py --part backup BACKUP_READ_ACCESS_KEY BACKUP_READ_SECRET_KEY` →
  `k8s/secrets/router-backup.enc.yaml`: the backup bucket's read credential, with which the router serves the
  locked backups to the app's Recover (`infra/backup-read-key.py install` writes it; below).

After a box rebuild, re-run both (the age key is new).

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

## Looking at things

- The core's signed log, through the app or `POST /api/core/log` (behind Deyao's login).
- A session machine's log: `FLY_API_TOKEN=$JARVIS2_FLY_TOKEN flyctl logs -a jarvis2-sessions --machine <id> --no-tail`
- The box itself: no way in by design; GitHub (Flux status is visible only through what the services answer).
