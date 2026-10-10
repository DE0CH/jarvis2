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

- `master.pub` — made on Deyao's iPhone (the app's master key page shows only the public half; the private half
  stays on the phone until it goes into his recovery kit). Commit it, and put the same value in
  `k8s/apps/core.yaml` (MASTER_KEY) — a clean cut, the old value gone everywhere. That restarts the core (a new
  core, new 8 words) and rebuilds the session image; then re-make every store backup sealed to the new key (below)
  and seal the read keys to it ("The backup bucket's read keys").
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
2. Deyao opens the app's recovery page: it shows the same 8 words, he pastes his recovery kit (`jarvis2-kit:1:…`,
   one string: the master key and the backup bucket's read keys) from his password manager, and the app restores
   every store from the backups.
3. Stores are locked; he unlocks them in the app as needed.

### The backup bucket's read keys and the recovery kit

The read keys reach Deyao only inside his recovery kit, never as text over Discord or a page (Deyao,
2026-10-10). They are the Hetzner S3 credential `jarvis2-backup-read` in project "Cloud Code" (2827255), which
also holds `de0ch-claude-6fdff6`. S3 credentials are project-wide, so bucket policies narrow this one (principal
`arn:aws:iam:::user/p2827255:<access key>`): on `jarvis2-backup-de0ch` a Deny of every write, delete,
delete-version, ACL, tagging, policy, versioning, lifecycle, CORS, website, logging, notification, replication,
object-lock and public-access-block change (27 actions, listed one by one: Hetzner ignores `NotAction`, and
refuses a policy naming `PutEncryptionConfiguration` or `PutBucketOwnershipControls` with ServiceUnavailable); on
`de0ch-claude-6fdff6` a Deny of `s3:*`. Tested (throwaway names only): list, get, list versions and get policy
work; put, copy, delete (plain, by version, multi), policy, versioning, lifecycle and ACL changes are refused,
and everything on the other bucket. A Ceph quirk seen with an earlier credential: a plain delete (no version id)
of an existing object may add a delete marker; that hides a backup but loses nothing (the bucket is versioned),
and the admin key removes the marker.

Making a new one (e.g. after a leak):

1. Console only (`hetzner-s3` skill in claude-env): Security → S3 credentials → generate, written straight to a
   mode-600 file `ACCESS_KEY=…` / `SECRET_KEY=…` (never printed); delete the old credential.
2. Put the new access key as the principal in both bucket policies (admin key); test as above.
3. `infra/setup.py recovery-keys FILE --credential=NAME` — sealed to `keys/master.pub`, signed by the setup key,
   kept by the router for the app; it reads the blob back to check. Then delete FILE.
4. Deyao, in the app: Settings → Recovery kit (or Recovery → Make the recovery kit…) on the iPhone that holds the
   private half of `keys/master.pub` → Make kit (Face ID) → saves the kit string → "I've saved the kit — delete
   the key here". The phone deletes the held key once the kit is saved, so a later new read credential needs a
   new master key pair as well (the page says so: "make a new master key pair and send Claude the public key").

### A new master key

Deyao makes the pair in the app (Settings → Master key, or Recovery → Make a master key pair…) and sends Claude
the public key; the private half stays on that iPhone. Claude then:

1. puts it in `keys/master.pub` and `k8s/apps/core.yaml` MASTER_KEY (nothing of the old key left) and pushes:
   CI rebuilds the session image, Flux restarts the core (a new core; `infra/setup.py identity` gives its words);
2. re-makes every store backup sealed to it (`setup.py backup …`, `backup-core` with a fresh
   `infra/fly-token.sh`), minting or rotating every token whose value lived only in the old backups (the GitHub
   push tokens with `github-web pat-create`, the Access service tokens `jarvis2-store-claude` and `jarvis2-tunnel`
   with Cloudflare's `rotate`), and deletes the local copies;
3. makes a new read credential and seals it to the new key (above).

Deyao then makes the kit on that iPhone, saves it, checks the new 8 words and recovers.

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
