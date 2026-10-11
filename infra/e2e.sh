#!/bin/bash
# e2e.sh — the end-to-end test against real Fly machines, from a session: builds the core and the router,
# runs them here (ports 28090/28080) with a throwaway box key, a throwaway WireGuard peer of the Fly org
# (jarvis2-e2e) and the session image, so the machines reach this router over Fly's private network as they reach
# the box's; the test sets its core up with the public TEST master key (e2e/testdata).
# Leaves nothing behind but the core's and router's logs (in $E2E_LOGS, default /tmp/jarvis2-e2e-logs): the
# peer is removed, the processes stopped. Never touches the production core.
#   JARVIS2_FLY_TOKEN   the jarvis2-370 org token
#   E2E_CORE_REF + E2E_HELD_CORE=1: run against the core of that ref (the held one) and check only that a session gets
#     its settings from the router as before
#   E2E_PEER (default jarvis2-e2e), E2E_PORT (default 28 → 28090/28080): another peer and ports let two runs go at once
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
PEER="${E2E_PEER:-jarvis2-e2e}"; PP="${E2E_PORT:-28}"
[ "$PEER" != jarvis2-box ] || { echo "E2E_PEER jarvis2-box is production's" >&2; exit 1; }
# sweep: destroy every machine in jarvis2-sessions whose JARVIS2_URL names THIS run's peer (earlier runs' leftovers at the
# start, this run's own at the end, on success, failure or interruption). Never one naming another peer: production's
# machines name jarvis2-box.
sweep() {
  curl -fsS -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" https://api.machines.dev/v1/apps/jarvis2-sessions/machines 2>/dev/null \
    | python3 -I -c '
import json, sys
want = "http://" + sys.argv[1] + "._peer.internal:8081"
for m in json.load(sys.stdin):
    if m.get("state") != "destroyed" and ((m.get("config") or {}).get("env") or {}).get("JARVIS2_URL") == want:
        print(m["id"])' "$PEER" \
    | while read -r m; do
        curl -fsS -o /dev/null -X DELETE -H "Authorization: Bearer $JARVIS2_FLY_TOKEN" \
          "https://api.machines.dev/v1/apps/jarvis2-sessions/machines/$m?force=true" && echo "e2e: destroyed leftover machine $m ($PEER)"
      done || true
}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d)"; chmod 700 "$W"
PIDS=()
cleanup() {
  mkdir -p "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}" && cp "$W"/*.log "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}/" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  sweep
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
sweep

# E2E_CORE_REF: build the core from that git ref instead (e.g. the held production core's commit, with E2E_HELD_CORE=1)
if [ -n "${E2E_CORE_REF:-}" ]; then
  git -C "$ROOT" worktree add -q --detach "$W/core-src" "$E2E_CORE_REF"
  (cd "$W/core-src/core" && go build -o "$W/core" .)
  git -C "$ROOT" worktree remove --force "$W/core-src"
else
  (cd "$ROOT/core" && go build -o "$W/core" .)
fi
(cd "$ROOT/router" && go build -o "$W/router" .)
python3 - "$W" <<'PY'
import base64, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as s
k = ec.generate_private_key(ec.SECP256R1())   # a throwaway box key
w = sys.argv[1]
open(f"{w}/box-key.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
open(f"{w}/box.pub", "w").write(base64.b64encode(k.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)).decode())
PY
# the test's policy: harnesses bring no stores (the production policy's would need a Claude login store)
echo '{"harnesses":{"claude":{"stores":[]},"opencode":{"stores":[]}}}' > "$W/policy.json"
FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$PEER" "$W/wg.conf" >/dev/null)

# the test router must never reach Deyao's Discord, the Storage Box or Jarvis 1: none of their keys go in
mkdir -p "$W/data" "$W/web"
# the core sets the router's address in every machine it makes (core/vouch.go), from its own deployment
BOX_KEY_FILE="$W/box-key.pem" ADDR=127.0.0.1:${PP}090 MACHINE_URL="http://$PEER._peer.internal:8081" "$W/core" > "$W/core.log" 2>&1 & PIDS+=($!)
# the core starts only the session image pinned by its linux/amd64 digest
E2E_SESSION_IMAGE="$("$ROOT/infra/image-digest.sh" "${E2E_SESSION_IMAGE:-ghcr.io/de0ch/jarvis2-session:latest}")"
env -u LOBSTER_TOKEN -u STORAGEBOX_HOST -u STORAGEBOX_USER -u STORAGEBOX_PASSWORD -u FLY_READ_TOKEN -u GITHUB_READ_TOKEN \
  -u JARVIS1_CREDENTIALS_ID -u JARVIS1_CREDENTIALS_SECRET -u JARVIS1_SERVICES_ID -u JARVIS1_SERVICES_SECRET \
  CORE_URL=http://127.0.0.1:${PP}090 NO_ACCESS=1 RECORDS_OFF=1 LIVE_SYNC_SECONDS=20 ADDR=127.0.0.1:${PP}080 DATA_DIR="$W/data" WEB_DIR="$W/web" \
  WG_CONFIG="$W/wg.conf" MACHINE_URL="http://$PEER._peer.internal:8081" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" \
  SESSION_IMAGE="$E2E_SESSION_IMAGE" \
  "$W/router" > "$W/router.log" 2>&1 & PIDS+=($!)
sleep 3
(cd "$ROOT/e2e" && E2E_ROUTER_LOG="$W/router.log" E2E_DATA_DIR="$W/data" E2E_ROUTER=http://127.0.0.1:${PP}080 E2E_CORE=http://127.0.0.1:${PP}090 E2E_MASTER_KEY_FILE="$ROOT/e2e/testdata/master-test.pem" E2E_BOX_PUB="$(cat "$W/box.pub")" \
  E2E_FLY_TOKEN="$JARVIS2_FLY_TOKEN" go run .) || { echo "--- router log"; tail -40 "$W/router.log"; exit 1; }
