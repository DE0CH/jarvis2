# Jarvis 2 — runbook

Everything here runs from a Claude session whose env has Jarvis 1's `default` store (JARVIS2_* keys,
HETZNER_JARVIS2_MOCK_API, HETZNER_S3_*, CF tokens). The box has no SSH and no reachable k8s API: it changes only
through git, and a box git can't fix is replaced.

## Deploying

`git push` to main. The `images` workflow builds the core, router, session and session-test images, then pins
their tags in `k8s/apps/`; Flux applies within a minute. The core's tag moves only when `core/` changed (a core
restart is a new core: see "Recovery"). The production session image is built only once `keys/master.pub`
exists.

## The keys (`keys/`)

- `master.pub` — made on Deyao's iPhone (the app's master key page); he keeps the private half in his password
  manager. Commit it, and put the same value in `k8s/apps/core.yaml` (MASTER_KEY).
- `box.pub` — written by `infra/create.sh` with each new box; commit it.
- `setup.pub` — the setup key (private half JARVIS2_SETUP_KEY); also `SETUP_KEY` in `k8s/apps/router.yaml`.

## Stores

- `infra/setup.py stores` — the core's signed list.
- `infra/setup.py create NAME` — once per name, an empty store that is NOT sensitive. Without it, a store is
  sensitive.
- `infra/setup.py write NAME KEY[=SRC]…` — new contents (values from this session's env, never printed),
  written to the core wrapped to the phone + core key, and backed up to S3 (bucket `jarvis2-backup-de0ch`,
  versioned, encrypted to the master key, signed by the setup key).
- `infra/setup.py mark-sensitive NAME` — the one-way upgrade, in the core and in the backup.
- The Fly token: `infra/fly-token.sh ~/.jarvis2/fly.tok` (narrowed to the app and to `jarvis2-init`), then
  `infra/setup.py backup-core ~/.jarvis2/fly.tok` — the `core` store reaches a core only through recovery.

## The router's secrets

Non-sensitive only (nothing that can reach a code push): `infra/router-secrets.py KEY[=SRC]…` writes
`k8s/secrets/router.enc.yaml`, SOPS-encrypted to `keys/box-age.pub`; Flux decrypts it on the box with the age key
the box got in user-data. Every run rewrites the whole Secret, so name every key:
`LOBSTER_TOKEN STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD FLY_READ_TOKEN=file:~/.jarvis2/fly-read.tok
JARVIS1_CREDENTIALS_ID=file:… JARVIS1_CREDENTIALS_SECRET=file:… JARVIS1_SERVICES_ID=file:… JARVIS1_SERVICES_SECRET=file:… GITHUB_READ_TOKEN=file:…
JARVIS2_TUNNEL_KEY=file:… JARVIS2_REMOTES_CLIENT_ID=…` (`GITHUB_READ_TOKEN`: a fine-grained token listing repos only,
`github-web pat-create-read`; `JARVIS2_TUNNEL_KEY`: the tunnel proof key, the same value as the cf-tunnel Worker's
secret `JARVIS2_TUNNEL_KEY` — without it no OpenCode/OpenClaw web UI; `JARVIS2_REMOTES_CLIENT_ID`: optional, the
client id of the service token that may read `/api/remotes`)
(`jarvis2-claude-credentials` and `jarvis2-services` are Jarvis 1 Access service tokens that claude-env's cf-tunnel
Worker confines to their own paths, `CONFINED_TOKENS`) (the read-only Fly token: `infra/fly-read-token.sh`).
After a box rebuild, re-run it (the age key is new).

## Recovery (after a box rebuild or any core restart)

1. `infra/setup.py identity` prints the new core's 8 words (checked against `keys/box.pub`).
2. Deyao opens the app's recovery page: it shows the same 8 words, he pastes the master key and the backup
   bucket's read keys from his password manager, and the app restores every store from the backups.
3. Stores are locked; he unlocks them in the app as needed.

### The backup bucket's read keys

Deyao keeps them as `jarvis2-s3:<access key>:<secret key>` in his password manager, next to the master key. They are
the Hetzner S3 credential `jarvis2-backup-read` in project "Cloud Code" (2827255), which also holds
`de0ch-claude-6fdff6`. S3 credentials are project-wide, so bucket policies narrow this one (principal
`arn:aws:iam:::user/p2827255:<access key>`): on `jarvis2-backup-de0ch` a Deny of every write, delete-version and
policy/versioning change; on `de0ch-claude-6fdff6` a Deny of everything. Tested: list, get and list versions work;
put, delete a version, delete the policy and suspend versioning are refused. One gap, a Ceph quirk: a plain delete
(no version id) is still allowed and adds a delete marker; that hides a backup but loses nothing (the bucket is
versioned) — remove the marker with the admin key. `NotAction` in these policies is ignored by Hetzner (it let
everything through), so list the denied actions explicitly. Making a new credential is Console-only
(`hetzner-s3` skill in claude-env); after making it, update both policies with the new access key.

## Rebuilding the box

1. Delete the server in the jarvis2 Hetzner project (API or console).
2. `infra/cloudflare.py ~/.jarvis2/cloudflare.env` (with `ROTATE=1` if that file is gone: a new setup service
   token; put it in the `default` store as JARVIS2_SETUP_ACCESS_ID/SECRET).
3. `infra/create.sh` — a new box key and age key (commit `keys/box.pub`, `keys/box-age.pub`), a new WireGuard
   peer, no SSH, no open port. Then `infra/router-secrets.py …` (above). It waits until `setup.py identity` answers.
4. Recovery (above). Paused sessions are lost (their certs were signed by the old core).

## Testing

- Unit: `go test ./...` in core/ (the core's guarantees are tested there).
- End to end on real Fly with a software phone and the public TEST master key: `infra/e2e.sh` (a local core
  and router, a throwaway WireGuard peer, the jarvis2-session-test image; set `E2E_SESSION_IMAGE` to a pinned
  tag). It never touches the production core.

## Looking at things

- The core's signed log, through the app or `POST /api/core/log` (behind Deyao's login).
- A session machine's log: `FLY_API_TOKEN=$JARVIS2_FLY_TOKEN flyctl logs -a jarvis2-sessions --machine <id> --no-tail`
- The box itself: no way in by design; GitHub (Flux status is visible only through what the services answer).
