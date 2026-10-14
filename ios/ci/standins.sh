#!/bin/bash
# CI stand-ins for the app's tests (ios.yml interop + simulator, transitions.yml), all on 127.0.0.1 and all throwaway:
#   - a box key and a setup key (standin.py keys); their public halves served at :18099 in place of GitHub
#     (the CI build only — KeySource.swift);
#   - the backup bucket on rclone's S3 server at :18098 (it checks SigV4), seeded with infra/setup.py's own
#     code, encrypted to the public TEST master key; read keys in W/s3.env (ACCESS_KEY=/SECRET_KEY=), which the
#     router gets as BACKUP_READ_*; every bucket's objects also in W/backups.json;
#   - the kernel's eight parts (core/cmd/*; secrets and the spawner built with -tags fakefly: an in-memory GitHub and
#     Fly) and the router, binaries in W; a key per part (W/key-<role>.pem) and the roster W/roster.json naming them
#     (phone and root empty until the app claims secrets: roster-watch.py), the parts' URLs for the router in
#     W/kernel-urls.env, and W/core-loop.sh, which runs secrets again whenever it ends (as Kubernetes does: a wipe
#     ends it and a new, empty one takes its place).
#     Unless NO_CORE=1 the kernel and a router (:18080, reading the stand-in bucket) are started here (kernel-up.sh,
#     logs W/*-standins.log); with NO_CORE=1 the workflow starts them fresh for each attempt with kernel-up.sh.
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

for bin in secrets spawner notary notarizer mover merger identity-signer gullible-signer; do
  tags=""
  case "$bin" in secrets|spawner) tags="-tags fakefly" ;; esac
  # shellcheck disable=SC2086
  (cd "$ROOT/core" && go build $tags -o "$W/$bin" "./cmd/$bin")
done
(cd "$ROOT/router" && go build -o "$W/router" .)
# a key per part (secrets' own is made new at each start by core-loop.sh, as an emptied secrets'), the roster naming them
$PY "$ROOT/ios/ci/standin.py" kernel-keys "$W"
printf '%s\n' NOTARY_URL=http://127.0.0.1:8091 NOTARIZER_URL=http://127.0.0.1:8092 MOVER_URL=http://127.0.0.1:8093 \
  MERGER_URL=http://127.0.0.1:8094 IDENTITY_SIGNER_URL=http://127.0.0.1:8095 GULLIBLE_SIGNER_URL=http://127.0.0.1:8096 \
  SPAWNER_URL=http://127.0.0.1:8097 SECRETS_URL=http://127.0.0.1:8090 > "$W/kernel-urls.env"
SECRETS_ENV="KEY_FILE=$W/secrets-key.pem ROSTER_FILE=$W/roster.json BOX_KEY_FILE=$W/box-key.pem ADDR=127.0.0.1:8090"
cat > "$W/core-loop.sh" <<LOOP
#!/bin/bash
# secrets, started again whenever it ends (a wipe: a new key, as a new pod's); log to \$1
while true; do openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$W/secrets-key.pem"; env $SECRETS_ENV "$W/secrets" >> "\$1" 2>&1; sleep 1; done
LOOP
chmod +x "$W/core-loop.sh"
# the router's env for the stand-in bucket (kernel-up.sh sources it)
printf 'BACKUP_READ_ACCESS_KEY=ciaccess\nBACKUP_READ_SECRET_KEY=%s\nBACKUP_ENDPOINT=http://127.0.0.1:18098\nBACKUP_BUCKET=jarvis2-backup-ci\n' "$secret" > "$W/router-backup.env"
# the test policy: the claude harness brings claude-login
echo '{"harnesses":{"claude":{"stores":["claude-login"]},"opencode":{"stores":[]}}}' > "$W/policy.json"
if [ "${NO_CORE:-}" != 1 ]; then
  bash "$ROOT/ios/ci/kernel-up.sh" "$W" "$W" standins "$W/router-data"
fi
