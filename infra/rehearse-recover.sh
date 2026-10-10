#!/bin/bash
# rehearse-recover.sh — the Recover path end to end on a REAL throwaway box, built the way production is built
# (infra/cloudflare.py, infra/create.sh, infra/cloud-init.sh, Flux applying ./k8s/apps with the production images),
# in the Hetzner project "runners", never the jarvis2 project. It never touches the production box, core, router,
# tunnel, Access apps, WireGuard peer or bucket.
#
#   1. its own Cloudflare tunnel + hostname + Access app + service token, its own versioned bucket, a Fly token for
#      the core that expires by itself (6 h), then the box (create.sh) — waits for the core
#   2. Reset with the TEST kit (the public test master key, e2e/testdata), stores written by infra/setup.py
#      (dummy values; not sensitive, sensitive, created-then-marked, the harness's stores, the core's Fly token),
#      and the backups checked in the bucket
#   3. a power failure: the server is hard-reset (Hetzner "reset") → a new, empty core → Recover → every store and
#      its sensitivity back → a session starts on Fly with them (values checked on the machine) → destroyed
#   4. the app's own restart: the kit ends the core (wipe), Kubernetes starts a new, empty one → Recover
#   5. a full rebuild: the server is deleted and create.sh makes a new one (new box key, new peer) → Recover →
#      a session with the stores again
#   6. teardown (also on any failure): servers, firewall, WireGuard peer, the rehearsal cores' Fly machines,
#      Cloudflare tunnel/DNS/Access app/token, every object version and the bucket, the work dir. `teardown` as
#      the only argument runs just that (after a crash); KEEP=1 skips it (then run it yourself).
#
# The app's side (Reset, Recover, unlock, approving a session) is the shell's own CoreSetup/CoreCrypto in
# app/ios/interop's Rehearse target (needs a swift.org toolchain on Linux: SWIFT_BIN, default ~/swift/*/usr/bin).
#
# Test-only differences from production, all in the box's user-data (cloud-init's SYNC_YAML/EXTRA_MANIFEST), none in git:
#   - hostname NAME.deyaochen.com through tunnel NAME, behind ONE Access app whose only policy is the service token
#     NAME; the router runs with NO_ACCESS=1 (its own JWT checks want Deyao's email login, which a test client
#     can't have), so Cloudflare Access at the edge is the only gate
#   - router env (Flux patch on the same ./k8s/apps at the pinned commit): MACHINE_URL → the peer NAME,
#     BACKUP_BUCKET → the rehearsal bucket, RECORDS_OFF=1 and DISCORD_SESSION_CHANNELS=off (no Storage Box or
#     Discord keys on a test box); no k8s/secrets Kustomization (those are encrypted to production's age key)
#   - the router's backup read key is the admin S3 key (a narrowed one is Console-only, infra/backup-read-key.py),
#     in user-data only; the box has no inbound port and lives about an hour
#   - the kit is the public TEST master key, so the bucket holds nothing secret: dummy values, and a Fly token
#     narrowed as production's AND expiring after 6 h
#
# Env: HCLOUD_TOKEN (project runners), JARVIS2_FLY_TOKEN, JARVIS2_SETUP_KEY, CF_JARVIS2_INFRA_TOKEN, CLOUDFLARE_API,
#      HETZNER_S3_* (the admin key of project Cloud Code). Optional: REHEARSAL_NAME (default jarvis2-rehearsal),
#      REHEARSAL_REF (the commit Flux applies; default origin/main), SERVER_TYPE (cx23), SKIP_REBUILD=1.
# Prints no secret. Logs: $REHEARSAL_LOGS (default /tmp/jarvis2-rehearsal-logs).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${REHEARSAL_NAME:-jarvis2-rehearsal}"
case "$NAME" in jarvis2-rehearsal*) ;; *) echo "REHEARSAL_NAME must start with jarvis2-rehearsal"; exit 2 ;; esac
# a new bucket name per run (Hetzner's S3 refuses a name for a while after its bucket was deleted); teardown
# removes every bucket named $NAME-*
HOST="$NAME.deyaochen.com"; BUCKET="$NAME-$(date +%s)"
: "${HCLOUD_TOKEN:?}" "${JARVIS2_FLY_TOKEN:?}" "${JARVIS2_SETUP_KEY:?}" "${CF_JARVIS2_INFRA_TOKEN:?}" "${CLOUDFLARE_API:?}"
: "${HETZNER_S3_ENDPOINT:?}" "${HETZNER_S3_REGION:?}" "${HETZNER_S3_ACCESS_KEY:?}" "${HETZNER_S3_SECRET_KEY:?}"
LOGS="${REHEARSAL_LOGS:-/tmp/jarvis2-rehearsal-logs}"; mkdir -p "$LOGS"
W="${REHEARSAL_WORK:-$HOME/.jarvis2/$NAME}"; mkdir -p "$W"; chmod 700 "$W"
SWIFT_BIN="${SWIFT_BIN:-$(ls -d "$HOME"/swift/*/usr/bin 2>/dev/null | tail -1)}"
H="https://api.hetzner.cloud/v1"
step() { echo; echo "######## $* ($(date -u +%H:%M:%S))"; }

hz() { # hz METHOD PATH [JSON]
  curl -sS -X "$1" "$H$2" -H "Authorization: Bearer $HCLOUD_TOKEN" -H "Content-Type: application/json" ${3:+-d "$3"}
}

teardown() {
  set +e
  step "teardown"
  for id in $(hz GET "/servers?label_selector=rehearsal=$NAME" | python3 -c "import json,sys;print(' '.join(str(s['id']) for s in json.load(sys.stdin)['servers']))"); do
    hz DELETE "/servers/$id" >/dev/null && echo "server $id deleted"
  done
  for i in $(seq 1 20); do
    fw=$(hz GET "/firewalls?name=$NAME" | python3 -c "import json,sys;f=json.load(sys.stdin)['firewalls'];print(f[0]['id'] if f else '')")
    [ -z "$fw" ] && break
    hz DELETE "/firewalls/$fw" | grep -q '"error"' || { echo "firewall $NAME deleted"; break; }
    sleep 5
  done
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$NAME" >/dev/null 2>&1 && echo "WireGuard peer $NAME removed"
  # the session machines the rehearsal cores started (each machine names its core: JARVIS2_CORE_KEY)
  if [ -s "$W/cores" ]; then
    FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl machines list -a jarvis2-sessions --json 2>/dev/null | python3 -c "
import json,sys
cores=set(open(sys.argv[1]).read().split())
for m in json.load(sys.stdin):
    if (m.get('config',{}).get('env') or {}).get('JARVIS2_CORE_KEY') in cores: print(m['id'])" "$W/cores" | while read -r m; do
      FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl machines destroy -a jarvis2-sessions --force "$m" >/dev/null 2>&1 && echo "Fly machine $m destroyed"
    done
  fi
  REHEARSAL="$NAME" python3 "$ROOT/infra/cloudflare.py" --delete
  python3 - "$NAME-" <<'PY'
import os, sys, boto3
prefix = sys.argv[1]
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
for b in [x["Name"] for x in s3.list_buckets()["Buckets"] if x["Name"].startswith(prefix)]:
    n = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=b):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=b, Key=v["Key"], VersionId=v["VersionId"]); n += 1
    s3.delete_bucket(Bucket=b)
    print(f"bucket {b}: {n} object versions and the bucket deleted")
PY
  [ -d "$W" ] && find "$W" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$W"
  echo "teardown done"
}
if [ "${1:-}" = teardown ]; then teardown; exit 0; fi
[ "${KEEP:-}" = 1 ] || trap teardown EXIT

REF="${REHEARSAL_REF:-$(git -C "$ROOT" ls-remote https://github.com/DE0CH/jarvis2 refs/heads/main | cut -f1)}"
echo "rehearsal $NAME: https://$HOST/, bucket $BUCKET, Flux at commit $REF"

step "the app's side (swift build)"
(cd "$ROOT/app/ios/interop" && PATH="$SWIFT_BIN:$PATH" swift build --product Rehearse 2>&1 | tail -1)
RH="$ROOT/app/ios/interop/.build/debug/Rehearse"

step "Cloudflare: tunnel, hostname, Access app, service token ($NAME)"
REHEARSAL="$NAME" python3 "$ROOT/infra/cloudflare.py" "$W/cloudflare.env"
set -a; . "$W/cloudflare.env"; set +a   # SETUP_ACCESS_ID/SECRET, TUNNEL_TOKEN (not printed)

step "the bucket $BUCKET (versioned, as production's)"
python3 - "$BUCKET" <<'PY'
import os, sys, boto3
b = sys.argv[1]
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
import time
s3.create_bucket(Bucket=b)
for i in range(30):   # a new bucket can take a few seconds to be found
    try:
        s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"}); break
    except s3.exceptions.NoSuchBucket:
        time.sleep(2)
else:
    sys.exit(f"bucket {b} never appeared")
print(f"ok: {b}")
PY

step "the core's Fly token (narrowed as production's, expiring in 6 h)"
FLY_TOKEN_HOURS=6 bash "$ROOT/infra/fly-token.sh" "$W/fly.tok"

# the box's Flux sync: production's ./k8s/apps at commit REF, with the rehearsal's router env (no k8s/secrets)
cat > "$W/sync.yaml" <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: { name: jarvis2, namespace: flux-system }
spec:
  interval: 1m
  url: https://github.com/DE0CH/jarvis2
  ref: { commit: $REF }
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: { name: jarvis2, namespace: flux-system }
spec:
  interval: 1m
  retryInterval: 30s
  timeout: 5m
  sourceRef: { kind: GitRepository, name: jarvis2 }
  path: ./k8s/apps
  prune: true
  wait: false
  serviceAccountName: flux-applier
  patches:
    - target: { kind: Deployment, name: router, namespace: jarvis2-router }
      patch: |
        apiVersion: apps/v1
        kind: Deployment
        metadata: { name: router, namespace: jarvis2-router }
        spec:
          template:
            spec:
              containers:
                - name: router
                  env:
                    - { name: MACHINE_URL, value: "http://$NAME._peer.internal:8081" }
                    - { name: BACKUP_BUCKET, value: "$BUCKET" }
                    - { name: NO_ACCESS, value: "1" }
                    - { name: RECORDS_OFF, value: "1" }
                    - { name: DISCORD_SESSION_CHANNELS, value: "off" }
EOF
(umask 077; python3 - > "$W/extra.yaml" <<'PY'
import json, os
print(json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                  "metadata": {"name": "router-secrets-backup", "namespace": "jarvis2-router"},
                  "stringData": {"BACKUP_READ_ACCESS_KEY": os.environ["HETZNER_S3_ACCESS_KEY"],
                                 "BACKUP_READ_SECRET_KEY": os.environ["HETZNER_S3_SECRET_KEY"]}}))
PY
)
mkdir -p "$W/keys"; cp "$ROOT/keys/setup.pub" "$W/keys/setup.pub"

# everything setup.py, create.sh's wait and the Rehearse client need, pointed at the rehearsal
export JARVIS2_URL="https://$HOST" JARVIS2_BACKUP_BUCKET="$BUCKET" JARVIS2_KEYS_DIR="$W/keys"
export JARVIS2_SETUP_ACCESS_ID="$SETUP_ACCESS_ID" JARVIS2_SETUP_ACCESS_SECRET="$SETUP_ACCESS_SECRET"
export REHEARSE_BASE="https://$HOST/" REHEARSE_ACCESS_ID="$SETUP_ACCESS_ID" REHEARSE_ACCESS_SECRET="$SETUP_ACCESS_SECRET"
export REHEARSE_KEYS="$W/keys" REHEARSE_MASTER_PEM="$ROOT/e2e/testdata/master-test.pem" REHEARSE_PHONE="$W/phone.json"

make_box() {
  HCLOUD_PROJECT_TOKEN="$HCLOUD_TOKEN" WG_PEER="$NAME" CF_ENV="$W/cloudflare.env" KEYS_OUT="$W/keys" FIREWALL="$NAME" \
    LABELS="{\"role\":\"$NAME\",\"rehearsal\":\"$NAME\",\"session\":\"${SESSION_ID:-none}\"}" \
    SYNC_YAML_FILE="$W/sync.yaml" EXTRA_MANIFEST_FILE="$W/extra.yaml" SERVER_TYPE="${SERVER_TYPE:-cx23}" \
    bash "$ROOT/infra/create.sh" "$NAME" 2>&1 | tee -a "$LOGS/create.log"
  [ "${PIPESTATUS[0]}" = 0 ]
}
server_id() { hz GET "/servers?label_selector=rehearsal=$NAME" | python3 -c "import json,sys;print(json.load(sys.stdin)['servers'][0]['id'])"; }
wait_empty() { # → the new empty core's key, recorded for teardown
  "$RH" wait-empty "${1:-}" | tee "$W/wait.out"
  k=$(awk '/^CORE /{print $2}' "$W/wait.out"); echo "$k" >> "$W/cores"; CORE="$k"
}
on_machine() { # on_machine MACHINE CMD → stdout (Machines API exec, the org token)
  python3 - "$1" "$2" <<'PY'
import json, os, sys, urllib.request
req = urllib.request.Request(f"https://api.machines.dev/v1/apps/jarvis2-sessions/machines/{sys.argv[1]}/exec", method="POST",
    data=json.dumps({"command": ["sh", "-c", sys.argv[2]], "timeout": 60}).encode(),
    headers={"Authorization": "Bearer " + os.environ["JARVIS2_FLY_TOKEN"], "Content-Type": "application/json"})
print(json.load(urllib.request.urlopen(req, timeout=90)).get("stdout", "").strip())
PY
}
session_check() { # a session with rh-plain + rh-secret (+ the harness's claude, tunnel): the values on the machine
  "$RH" session rh-plain rh-secret | tee "$W/session.out"
  local sid m
  sid=$(awk '/^SESSION /{print $2}' "$W/session.out"); m=$(awk '/^MACHINE /{print $2}' "$W/session.out")
  for kv in "RH_PLAIN=$V_PLAIN" "RH_SECRET=$V_SECRET" "JARVIS1_CREDENTIALS_ID=$V_CLAUDE" "CF_ACCESS_CLIENT_ID=$V_TUNNEL"; do
    got=""
    for i in $(seq 1 12); do
      got=$(on_machine "$m" "grep -E '^(export )?${kv%%=*}=' /home/claude/.secrets | grep -c -F '${kv#*=}' || true" 2>/dev/null || true)  # that key's line holds that value
      [ "$got" = 1 ] && break; sleep 5
    done
    [ "$got" = 1 ] || { echo "FAIL ${kv%%=*} isn't on machine $m with the written value"; exit 1; }
    echo "ok   ${kv%%=*} is on machine $m with the value written before the failure"
  done
  got=$(on_machine "$m" "grep -c RH_MARKED /home/claude/.secrets || true")
  [ "$got" = 0 ] || { echo "FAIL a store that wasn't picked is on the machine"; exit 1; }
  echo "ok   rh-marked (not picked) is not on the machine"
  "$RH" destroy "$sid"
}

step "the box (infra/create.sh in project runners)"
make_box
echo "server $(server_id) up at $(date -u +%FT%TZ)" | tee -a "$LOGS/servers.log"
wait_empty

step "Reset with the test kit, then the stores (infra/setup.py, dummy values)"
"$RH" reset
rnd=$(python3 -c "import secrets;print(secrets.token_hex(6))")
export V_PLAIN="plain-$rnd" V_SECRET="secret-$rnd" V_MARKED="marked-$rnd" V_CLAUDE="claude-id-$rnd" V_TUNNEL="tunnel-id-$rnd"
export RH_PLAIN="$V_PLAIN" RH_SECRET="$V_SECRET" RH_MARKED="$V_MARKED" JARVIS1_CREDENTIALS_ID="$V_CLAUDE" \
  JARVIS1_CREDENTIALS_SECRET="claude-secret-$rnd" CF_ACCESS_CLIENT_ID="$V_TUNNEL" CF_ACCESS_CLIENT_SECRET="tunnel-secret-$rnd"
S="python3 $ROOT/infra/setup.py"
$S create rh-plain
$S create rh-marked
$S write rh-plain RH_PLAIN
$S write rh-secret RH_SECRET
$S write rh-marked RH_MARKED
$S mark-sensitive rh-marked
$S write claude JARVIS1_CREDENTIALS_ID JARVIS1_CREDENTIALS_SECRET
$S write tunnel CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET
$S backup-core "$W/fly.tok"
$S stores
python3 - "$W/expect.json" <<'PY'
import json, os, sys
e = lambda sens, **v: {"sensitive": sens, "values": v}
json.dump({"stores": {
    "rh-plain": e(False, RH_PLAIN=os.environ["RH_PLAIN"]),
    "rh-secret": e(True, RH_SECRET=os.environ["RH_SECRET"]),
    "rh-marked": e(True, RH_MARKED=os.environ["RH_MARKED"]),
    "claude": e(True, JARVIS1_CREDENTIALS_ID=os.environ["JARVIS1_CREDENTIALS_ID"], JARVIS1_CREDENTIALS_SECRET=os.environ["JARVIS1_CREDENTIALS_SECRET"]),
    "tunnel": e(True, CF_ACCESS_CLIENT_ID=os.environ["CF_ACCESS_CLIENT_ID"], CF_ACCESS_CLIENT_SECRET=os.environ["CF_ACCESS_CLIENT_SECRET"]),
}}, open(sys.argv[1], "w"))
PY
chmod 600 "$W/expect.json"

step "the backups are in the bucket"
python3 - "$BUCKET" <<'PY'
import os, sys, boto3
b = sys.argv[1]
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
keys = sorted(o["Key"] for o in s3.list_objects_v2(Bucket=b).get("Contents", []))
want = {f"stores/{n}.json" for n in ["rh-plain", "rh-secret", "rh-marked", "claude", "tunnel", "core"]} | {"sensitive/rh-marked.json"}
missing = want - set(keys)
print("objects:", keys)
if missing:
    sys.exit(f"FAIL missing backups: {sorted(missing)}")
print("ok   every store's backup and the sensitive marker are in", b)
PY

step "failure 1: the server loses power (Hetzner hard reset) → Recover → a session"
# Linux writes dirty pages back within ~30 s: a power cut seconds after the images were pulled leaves them
# truncated on disk ("exec /router: exec format error" for ever after; seen in the first run, 8 s after the pull),
# which only a rebuild cures. That is a box failing at its very start, not the failure rehearsed here, so wait.
sleep 90
hz POST "/servers/$(server_id)/actions/reset" >/dev/null
OLD="$CORE"; sleep 20
wait_empty "$OLD"
"$RH" recover "$W/expect.json"
session_check

step "a session stuck at boot on a locked store is destroyed at once (no 10-minute snapshot wait)"
"$RH" stuck rh-marked

step "failure 2: the app's restart (the kit ends the core; Kubernetes starts a new one) → Recover"
"$RH" wipe
wait_empty "$CORE"
"$RH" recover "$W/expect.json"

if [ "${SKIP_REBUILD:-}" != 1 ]; then
  step "failure 3: the box is gone (server deleted) → a new box (new box key, new peer) → Recover → a session"
  hz DELETE "/servers/$(server_id)" >/dev/null
  echo "server deleted at $(date -u +%FT%TZ)" | tee -a "$LOGS/servers.log"
  for i in $(seq 1 30); do [ "$(hz GET "/servers?label_selector=rehearsal=$NAME" | python3 -c "import json,sys;print(len(json.load(sys.stdin)['servers']))")" = 0 ] && break; sleep 5; done
  cp "$W/keys/box.pub" "$W/box-old.pub"
  make_box
  cmp -s "$W/box-old.pub" "$W/keys/box.pub" && { echo "FAIL the new box has the old box key"; exit 1; }
  echo "server $(server_id) up at $(date -u +%FT%TZ) (new box key)" | tee -a "$LOGS/servers.log"
  wait_empty
  "$RH" recover "$W/expect.json"
  session_check
fi

step "REHEARSAL PASSED"
