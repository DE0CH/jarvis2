#!/bin/bash
# CI stand-ins for the app's tests (app.yml interop + simulator), all on 127.0.0.1 and all throwaway:
#   - a box key and a setup key (standin.py keys); their public halves served at :18099 in place of GitHub
#     (the CI build only — KeySource.swift);
#   - the backup bucket on rclone's S3 server at :18098 (it checks SigV4), seeded with infra/setup.py's own
#     code, encrypted to the public TEST master key; read keys in W/s3.env (ACCESS_KEY=/SECRET_KEY=), which the
#     router gets as BACKUP_READ_*; every bucket's objects also in W/backups.json;
#   - the kernel's secrets (core/cmd/secrets, -tags fakefly: an in-memory GitHub) and router binaries at W/secrets,
#     W/router, and W/core-loop.sh, which runs secrets again whenever it ends (as Kubernetes does: a wipe ends it and a
#     new, empty one takes its place); its key W/secrets-key.pem, its roster W/roster.json (the kernel's TEST roster,
#     core/kernel/testdata/keys.json: secrets checks grants by the mover and merger in it).
#     Unless NO_CORE=1 secrets (:8090, empty) and a router (:18080, or ROUTER_PORT; reading the stand-in bucket, its
#     SECRETS_URL the stand-in; the other kernel parts aren't run) are started.
# usage: standins.sh W
set -euo pipefail
W="$1"; ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$W"
python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install cryptography boto3
command -v rclone >/dev/null || brew install rclone
PY="$W/venv/bin/python -B"
$PY "$ROOT/ios/ci/standin.py" keys "$W"

secret=$(openssl rand -hex 16)
printf 'ACCESS_KEY=ciaccess\nSECRET_KEY=%s\n' "$secret" > "$W/s3.env"
mkdir -p "$W/s3"
nohup rclone serve s3 --addr 127.0.0.1:18098 --auth-key "ciaccess,$secret" "$W/s3" > "$W/s3.log" 2>&1 &
nohup "$W/venv/bin/python" -m http.server --bind 127.0.0.1 --directory "$W/keys" 18099 > "$W/keys-server.log" 2>&1 &
for i in $(seq 30); do curl -s -o /dev/null http://127.0.0.1:18098/ && curl -sf -o /dev/null http://127.0.0.1:18099/box.pub && break; sleep 1; done
HETZNER_S3_ENDPOINT=http://127.0.0.1:18098 HETZNER_S3_REGION=fsn1 HETZNER_S3_ACCESS_KEY=ciaccess HETZNER_S3_SECRET_KEY="$secret" \
  $PY "$ROOT/ios/ci/standin.py" seed "$W"

(cd "$ROOT/core" && go build -tags fakefly -o "$W/secrets" ./cmd/secrets)
(cd "$ROOT/router" && go build -o "$W/router" .)
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$W/secrets-key.pem"
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["roster"]))' "$ROOT/core/kernel/testdata/keys.json" > "$W/roster.json"
SECRETS_ENV="KEY_FILE=$W/secrets-key.pem ROSTER_FILE=$W/roster.json BOX_KEY_FILE=$W/box-key.pem ADDR=127.0.0.1:8090"
cat > "$W/core-loop.sh" <<EOF
#!/bin/bash
# secrets, started again whenever it ends (a wipe: a new key, as a new pod's); log to \$1
while true; do openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$W/secrets-key.pem"; env $SECRETS_ENV "$W/secrets" >> "\$1" 2>&1; sleep 1; done
EOF
chmod +x "$W/core-loop.sh"
# the router's env for the stand-in bucket (sourced by app.yml)
printf 'BACKUP_READ_ACCESS_KEY=ciaccess\nBACKUP_READ_SECRET_KEY=%s\nBACKUP_ENDPOINT=http://127.0.0.1:18098\nBACKUP_BUCKET=jarvis2-backup-ci\n' "$secret" > "$W/router-backup.env"
if [ "${NO_CORE:-}" != 1 ]; then
  nohup "$W/core-loop.sh" "$W/core.log" > /dev/null 2>&1 &
  for i in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:8090/identity && break; sleep 1; done
  mkdir -p "$W/router-data" "$W/web"
  echo '{"harnesses":{"claude":{"stores":["claude-login"]}}}' > "$W/policy.json"
  (set -a; . "$W/router-backup.env"; set +a
   NO_ACCESS=1 SECRETS_URL=http://127.0.0.1:8090 DATA_DIR="$W/router-data" WEB_DIR="$W/web" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" \
     ADDR=127.0.0.1:${ROUTER_PORT:-18080} MACHINE_ADDR=127.0.0.1:$((${ROUTER_PORT:-18080}+1)) nohup "$W/router" > "$W/router.log" 2>&1 &)
  for i in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:${ROUTER_PORT:-18080}/api/state && break; sleep 1; done
  echo "secrets and router up"
fi
