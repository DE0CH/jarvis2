# rehearsal-box.sh — sourced by infra/rehearse-recover.sh and infra/phone-replica.sh: a throwaway Jarvis 2 box built the
# way production is (infra/cloudflare.py, infra/create.sh, infra/cloud-init.sh, Flux applying ./k8s/apps at a pinned
# commit with the production images), in the Hetzner project "runners", never touching production. See those
# scripts' headers for what each one tests, and docs/RUNBOOK.md "Rehearsing Recover" / "The phone replica".
#
# The caller sets MODE before sourcing:
#   rehearse   one Access app on the hostname whose only policy is the service token NAME; the router runs
#              NO_ACCESS=1 (the test client can't hold Deyao's email login), so the edge is the only gate
#   replica    as production: the hostname for one email (REHEARSAL_EMAIL, a real Access one-time-PIN login, the
#              bot's mailbox) and NAME.deyaochen.com/setup for the service token; the router checks both JWTs, with
#              ALLOWED_EMAIL = that email
# Both: MACHINE_URL → the peer NAME, BACKUP_BUCKET → a bucket of its own, RECORDS_OFF=1 and Discord off (no Storage
# Box or Discord keys on a test box), no k8s/secrets Kustomization (encrypted to production's age key); the router's
# backup read key is the admin S3 key, in user-data only (a narrowed one is Console-only). All of it rides in the box's
# user-data (cloud-init's SYNC_YAML/EXTRA_MANIFEST), none in git.
# Env: HCLOUD_TOKEN (project runners), JARVIS2_FLY_TOKEN, JARVIS2_SETUP_KEY, CF_JARVIS2_INFRA_TOKEN, CLOUDFLARE_API,
#      HETZNER_S3_*. Optional: REHEARSAL_NAME (default jarvis2-rehearsal), REHEARSAL_REF (the commit Flux applies;
#      default origin/main), SERVER_TYPE (cx23), REHEARSAL_LOGS, KEEP=1 (no teardown on exit).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${REHEARSAL_NAME:-jarvis2-rehearsal}"
case "$NAME" in jarvis2-rehearsal*) ;; *) echo "REHEARSAL_NAME must start with jarvis2-rehearsal"; exit 2 ;; esac
# a new bucket name per run (Hetzner's S3 refuses a name for a while after its bucket was deleted); teardown
# removes every bucket named $NAME-<digits>
HOST="$NAME.deyaochen.com"; BUCKET="$NAME-$(date +%s)"
: "${HCLOUD_TOKEN:?}" "${JARVIS2_FLY_TOKEN:?}" "${JARVIS2_SETUP_KEY:?}" "${CF_JARVIS2_INFRA_TOKEN:?}" "${CLOUDFLARE_API:?}"
: "${HETZNER_S3_ENDPOINT:?}" "${HETZNER_S3_REGION:?}" "${HETZNER_S3_ACCESS_KEY:?}" "${HETZNER_S3_SECRET_KEY:?}"
LOGS="${REHEARSAL_LOGS:-/tmp/jarvis2-rehearsal-logs}"; mkdir -p "$LOGS"
mkdir -p "$HOME/.jarvis2"
# one run per NAME at a time (a second run's teardown would take the first one's work dir and box)
exec 9>"$HOME/.jarvis2/$NAME.lock"
flock -n 9 || { echo "another $NAME run (or its teardown) is still going"; exit 1; }
W="${REHEARSAL_WORK:-$HOME/.jarvis2/$NAME}"; mkdir -p "$W"; chmod 700 "$W"
H="https://api.hetzner.cloud/v1"
step() { echo; echo "######## $* ($(date -u +%H:%M:%S))"; }

hz() { # hz METHOD PATH [JSON]
  curl -sS -X "$1" "$H$2" -H "Authorization: Bearer $HCLOUD_TOKEN" -H "Content-Type: application/json" ${3:+-d "$3"}
}

teardown() {
  set +e
  step "teardown"
  if declare -F teardown_extra >/dev/null; then teardown_extra; fi
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
  # the session machines the rehearsal's cores started (each machine names its core: JARVIS2_CORE_KEY); the
  # replica's cores are learned from the box itself while it runs (cores file)
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
import re
# exactly NAME-<unix time>: jarvis2-rehearsal-* must not take jarvis2-rehearsal-replica-*'s bucket
for b in [x["Name"] for x in s3.list_buckets()["Buckets"] if re.fullmatch(re.escape(prefix) + r"[0-9]+", x["Name"])]:
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

# prepare: Cloudflare, the bucket, the core's Fly token, the box's Flux sync and Secrets, the env for setup.py
prepare() {
  REF="${REHEARSAL_REF:-$(git -C "$ROOT" ls-remote https://github.com/DE0CH/jarvis2 refs/heads/main | cut -f1)}"
  echo "$MODE $NAME: https://$HOST/, bucket $BUCKET, Flux at commit $REF"

  step "Cloudflare: tunnel, hostname, Access, service token ($NAME, $MODE)"
  if [ "$MODE" = replica ]; then
    REHEARSAL="$NAME" REHEARSAL_EMAIL="${REHEARSAL_EMAIL:?}" python3 "$ROOT/infra/cloudflare.py" "$W/cloudflare.env"
  else
    REHEARSAL="$NAME" python3 "$ROOT/infra/cloudflare.py" "$W/cloudflare.env"
  fi
  set -a; . "$W/cloudflare.env"; set +a   # SETUP_ACCESS_ID/SECRET, TUNNEL_TOKEN (+ APP_AUD, SETUP_AUD); not printed

  step "the bucket $BUCKET (versioned, as production's)"
  python3 - "$BUCKET" <<'PY'
import os, sys, time, boto3
b = sys.argv[1]
s3 = boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                  aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])
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

  local access_env
  if [ "$MODE" = replica ]; then
    access_env="                    - { name: ACCESS_APP_AUD, value: \"$APP_AUD\" }
                    - { name: ACCESS_SETUP_AUD, value: \"$SETUP_AUD\" }
                    - { name: ALLOWED_EMAIL, value: \"$REHEARSAL_EMAIL\" }"
  else
    access_env="                    - { name: NO_ACCESS, value: \"1\" }"
  fi
  # the box's Flux sync: production's ./k8s/apps at commit REF, with the test's router env (no k8s/secrets)
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
                    - { name: RECORDS_OFF, value: "1" }
                    - { name: DISCORD_SESSION_CHANNELS, value: "off" }
$access_env
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
  # what setup.py and create.sh's wait need, pointed at the test box
  export JARVIS2_URL="https://$HOST" JARVIS2_BACKUP_BUCKET="$BUCKET" JARVIS2_KEYS_DIR="$W/keys"
  export JARVIS2_SETUP_ACCESS_ID="$SETUP_ACCESS_ID" JARVIS2_SETUP_ACCESS_SECRET="$SETUP_ACCESS_SECRET"
}

make_box() {
  # a just-deleted server's primary IP counts against the project's limit for a while: wait and try again
  for i in $(seq 1 10); do
    make_box_once > "$W/make.out" 2>&1 && { cat "$W/make.out"; return 0; }
    cat "$W/make.out"
    grep -q "primary_ip_limit\|resource_limit_exceeded" "$W/make.out" || return 1
    echo "the project's IP/server limit: trying again in 30 s"; sleep 30
  done
  return 1
}
make_box_once() {
  HCLOUD_PROJECT_TOKEN="$HCLOUD_TOKEN" WG_PEER="$NAME" CF_ENV="$W/cloudflare.env" KEYS_OUT="$W/keys" FIREWALL="$NAME" \
    LABELS="{\"role\":\"$NAME\",\"rehearsal\":\"$NAME\",\"session\":\"${SESSION_ID:-none}\"}" \
    SYNC_YAML_FILE="$W/sync.yaml" EXTRA_MANIFEST_FILE="$W/extra.yaml" SERVER_TYPE="${SERVER_TYPE:-cx23}" \
    bash "$ROOT/infra/create.sh" "$NAME" 2>&1 | tee -a "$LOGS/create.log"
  [ "${PIPESTATUS[0]}" = 0 ]
}
server_id() { hz GET "/servers?label_selector=rehearsal=$NAME" | python3 -c "import json,sys;print(json.load(sys.stdin)['servers'][0]['id'])"; }
