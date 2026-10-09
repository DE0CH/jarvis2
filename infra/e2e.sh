#!/bin/bash
# e2e.sh — the end-to-end test against real Fly machines, from a session: builds the core and the router,
# runs them here (ports 28090/28080) with the public TEST master key, a throwaway box key and a throwaway
# WireGuard peer of the Fly
# org (jarvis2-e2e) and the jarvis2-session-test image, so the machines reach this router over Fly's private network as they reach the box's.
# Leaves nothing behind but the core's and router's logs (in $E2E_LOGS, default /tmp/jarvis2-e2e-logs): the
# peer is removed, the processes stopped. Never touches the production core.
#   JARVIS2_FLY_TOKEN   the jarvis2-370 org token
set -euo pipefail
: "${JARVIS2_FLY_TOKEN:?}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d)"; chmod 700 "$W"
PIDS=()
cleanup() {
  mkdir -p "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}" && cp "$W"/*.log "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}/" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 jarvis2-e2e >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT

(cd "$ROOT/core" && go build -o "$W/core" .)
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
FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 jarvis2-e2e >/dev/null 2>&1 || true
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr jarvis2-e2e "$W/wg.conf" >/dev/null)

mkdir -p "$W/data" "$W/web"
MASTER_KEY="$(cat "$ROOT/e2e/testdata/master-test.pub")" BOX_KEY_FILE="$W/box-key.pem" ADDR=127.0.0.1:28090 "$W/core" > "$W/core.log" 2>&1 & PIDS+=($!)
CORE_URL=http://127.0.0.1:28090 NO_ACCESS=1 RECORDS_OFF=1 ADDR=127.0.0.1:28080 DATA_DIR="$W/data" WEB_DIR="$W/web" \
  WG_CONFIG="$W/wg.conf" MACHINE_URL=http://jarvis2-e2e._peer.internal:8081 POLICY_FILE="$W/policy.json" \
  SESSION_IMAGE="${E2E_SESSION_IMAGE:-ghcr.io/de0ch/jarvis2-session-test:latest}" \
  "$W/router" > "$W/router.log" 2>&1 & PIDS+=($!)
sleep 3
(cd "$ROOT/e2e" && E2E_ROUTER=http://127.0.0.1:28080 E2E_CORE=http://127.0.0.1:28090 E2E_MASTER_KEY_FILE="$ROOT/e2e/testdata/master-test.pem" E2E_BOX_PUB="$(cat "$W/box.pub")" \
  E2E_FLY_TOKEN="$JARVIS2_FLY_TOKEN" E2E_FLY_APP=jarvis2-sessions go run .) || { echo "--- router log"; tail -40 "$W/router.log"; exit 1; }
