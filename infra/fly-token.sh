#!/bin/bash
# fly-token.sh OUT — the core's Fly token: JARVIS2_FLY_TOKEN narrowed (Fly macaroon caveats) to app
# jarvis2-sessions (read, write, create, delete, control — Fly needs write to create a machine) and to ONE
# command inside a machine: /usr/local/bin/jarvis2-init with no arguments (IfPresent: the command limit applies
# to exec only). Tested 2026-10-09: create/destroy allowed, `cat` refused (403), jarvis2-init allowed, with an
# argument refused. Written to OUT (mode 600), never printed; infra/setup.py backup-core puts it in the backup.
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
OUT="${1:?usage: fly-token.sh OUT}"
APPID="$(curl -s https://api.fly.io/graphql -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"{ app(name:\"jarvis2-sessions\"){ internalNumericId } }"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['app']['internalNumericId'])")"
CAV="$(mktemp)"; trap 'rm -f "$CAV"' EXIT
printf '[{"type":"Apps","body":{"apps":{"%s":"rwcdC"}}},{"type":"IfPresent","body":{"ifs":[{"type":"Commands","body":[{"args":["/usr/local/bin/jarvis2-init"],"exact":true}]}],"else":"rwcdC"}}]' "$APPID" > "$CAV"
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl tokens attenuate -f "$CAV" > "$OUT")
echo "ok: narrowed token in $OUT"
