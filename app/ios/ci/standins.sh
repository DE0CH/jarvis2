#!/bin/bash
# CI stand-ins for the app's tests (app.yml interop + simulator), all on 127.0.0.1 and all throwaway:
#   - a box key and a setup key (standin.py keys); their public halves served at :18099 in place of GitHub
#     (the CI build only — KeySource.swift);
#   - the backup bucket on rclone's S3 server at :18098 (it checks SigV4), seeded with infra/setup.py's own
#     code, encrypted to the public TEST master key; read keys in W/s3.env (ACCESS_KEY=/SECRET_KEY=), sealed as
#     infra/setup.py recovery-keys seals them in W/recovery-keys.json; the public TEST master key's private half
#     (base64 PKCS#8) in W/master-test.pkcs8, which the CI build holds as if the simulator had made the pair;
#   - the core binary (fakefly, MASTER_KEY = the test master key, BOX_KEY_FILE = the throwaway box key) at
#     W/core, and unless NO_CORE=1 started on :8090 (its identity words in W/words).
# usage: standins.sh W
set -euo pipefail
W="$1"; ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$W"
python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install cryptography boto3
command -v rclone >/dev/null || brew install rclone
PY="$W/venv/bin/python -B"
$PY "$ROOT/app/ios/ci/standin.py" keys "$W"

secret=$(openssl rand -hex 16)
printf 'ACCESS_KEY=ciaccess\nSECRET_KEY=%s\n' "$secret" > "$W/s3.env"
mkdir -p "$W/s3"
nohup rclone serve s3 --addr 127.0.0.1:18098 --auth-key "ciaccess,$secret" "$W/s3" > "$W/s3.log" 2>&1 &
nohup "$W/venv/bin/python" -m http.server --bind 127.0.0.1 --directory "$W/keys" 18099 > "$W/keys-server.log" 2>&1 &
for i in $(seq 30); do curl -s -o /dev/null http://127.0.0.1:18098/ && curl -sf -o /dev/null http://127.0.0.1:18099/box.pub && break; sleep 1; done
HETZNER_S3_ENDPOINT=http://127.0.0.1:18098 HETZNER_S3_REGION=fsn1 HETZNER_S3_ACCESS_KEY=ciaccess HETZNER_S3_SECRET_KEY="$secret" \
  $PY "$ROOT/app/ios/ci/standin.py" seed "$W"
$PY "$ROOT/app/ios/ci/standin.py" sealkeys "$W"
openssl pkcs8 -topk8 -nocrypt -in "$ROOT/e2e/testdata/master-test.pem" -outform DER | base64 | tr -d '\n' > "$W/master-test.pkcs8"

(cd "$ROOT/core" && go build -tags fakefly -o "$W/core" .)
if [ "${NO_CORE:-}" != 1 ]; then
  MASTER_KEY="$(cat "$ROOT/e2e/testdata/master-test.pub")" BOX_KEY_FILE="$W/box-key.pem" ADDR="${CORE_ADDR:-127.0.0.1:8090}" nohup "$W/core" > "$W/core.log" 2>&1 &
  for i in $(seq 30); do curl -sf -o /dev/null "http://${CORE_ADDR:-127.0.0.1:8090}/key" && break; sleep 1; done
  sed -n 's/.*core up; identity //p' "$W/core.log" > "$W/words"
  echo "core up: $(cat "$W/words")"
fi
