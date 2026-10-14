#!/bin/bash
# e2e.sh — the end-to-end test against real Fly machines, from a session: builds the eight kernel parts (core/cmd/*)
# and the router, runs them here (parts on ports ${PP}090–${PP}097, the router on ${PP}080), each part with its own
# throwaway key (KEY_FILE), one throwaway box key vouching for all of them (BOX_KEY_FILE) and a roster (ROSTER_FILE)
# naming them plus a throwaway test phone key and root key, a throwaway WireGuard peer of the Fly org (jarvis2-e2e) and
# the session image, so the machines reach this router over Fly's private network as they reach the box's; the test
# claims its secrets with the public TEST master key (e2e/testdata), signs as the phone and the root key, and sends the
# spawner the Fly token sealed to it. Secrets is built with -tags fakefly (an in-memory GitHub: no deploy-keys token
# here); the spawner without it (real Fly).
# Leaves nothing behind but the parts' and router's logs (in $E2E_LOGS, default /tmp/jarvis2-e2e-logs): the
# peer is removed, the processes stopped. Never touches production's kernel.
#   JARVIS2_FLY_TOKEN   the jarvis2-370 org token
#   E2E_ONLY=jarvis1-import: after secrets' setup, only the Jarvis 1 import step (a fake paused session on 127.0.0.1:${PP}070)
#   E2E_ONLY=drain: after the first session is up, only the drain: SIGTERM to the router with a pause in flight
#   E2E_ONLY=restore: after secrets' setup, only the restore of a store to an earlier version (no machines)
# Always with Jarvis 1 unreachable (e2e/nojarvis1.go): the router runs in its own mount namespace (sudo unshare) whose
#   /etc/hosts sends jarvis.deyaochen.com to a listener that fails the test on any connection; each machine gets it
#   blackholed too; search, the watch runner and the Storage Box are local stand-ins
#   E2E_PEER (default jarvis2-e2e), E2E_PORT (default 28 → 28090–28097/28080): another peer and ports let two runs go at once
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
PIDS=(); SUDO_PIDS=()
cleanup() {
  mkdir -p "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}" && cp "$W"/*.log "${E2E_LOGS:-/tmp/jarvis2-e2e-logs}/" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${SUDO_PIDS[@]}"; do sudo -n pkill -P "$p" 2>/dev/null || true; sudo -n kill "$p" 2>/dev/null || true; done
  sweep
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
sweep

# the kernel's parts, by roster role → binary (core/cmd/<binary>) and port
PARTS=(notary:notary:090 notarizer:notarizer:091 mover:mover:092 merger:merger:093 identity:identity-signer:094
       gullible:gullible-signer:095 spawner:spawner:096 secrets:secrets:097)
for p in "${PARTS[@]}"; do
  IFS=: read -r role bin port <<<"$p"
  tags=""; [ "$bin" = secrets ] && tags="-tags fakefly"   # an in-memory GitHub; the spawner stays on real Fly
  # shellcheck disable=SC2086
  (cd "$ROOT/core" && go build $tags -o "$W/$bin" "./cmd/$bin")
done
(cd "$ROOT/router" && go build -o "$W/router" .)
# throwaway keys: the box key, one per part, the test phone and root keys; the roster names every public key
python3 - "$W" <<'PY'
import base64, json, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as s
w = sys.argv[1]
def make(name):
    k = ec.generate_private_key(ec.SECP256R1())
    open(f"{w}/{name}.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
    return base64.b64encode(k.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)).decode()
open(f"{w}/box.pub", "w").write(make("box-key"))
roles = ["notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "secrets", "phone", "root"]
json.dump({r: make("key-" + r) for r in roles}, open(f"{w}/roster.json", "w"))
PY
chmod 600 "$W"/*.pem
# the test's policy: harnesses bring no stores (the production policy's would need a Claude login store)
echo '{"harnesses":{"claude":{"stores":[]},"opencode":{"stores":[]}}}' > "$W/policy.json"
FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$PEER" "$W/wg.conf" >/dev/null)

# the test router must never reach Deyao's Discord, the Storage Box or Jarvis 1: none of their keys go in (its env is
# only what router-env below names)
mkdir -p "$W/data" "$W/web"
# the parts, each with its own key; the spawner sets the router's address in every machine it makes (MACHINE_URL)
URLS=""
for p in "${PARTS[@]}"; do
  IFS=: read -r role bin port <<<"$p"
  extra=()
  case "$bin" in
    notary) extra=(LOG_FILE="$W/notary-log.jsonl") ;;
    notarizer) extra=(STATE_FILE="$W/notarizer-state.json") ;;
    spawner) extra=(MACHINE_URL="http://$PEER._peer.internal:8081") ;;
  esac
  env KEY_FILE="$W/key-$role.pem" BOX_KEY_FILE="$W/box-key.pem" ROSTER_FILE="$W/roster.json" ADDR=127.0.0.1:${PP}$port "${extra[@]}" \
    "$W/$bin" > "$W/$bin.log" 2>&1 & PIDS+=($!)
  var="$(echo "$bin" | tr 'a-z-' 'A-Z_')_URL"   # NOTARY_URL … IDENTITY_SIGNER_URL, GULLIBLE_SIGNER_URL …
  URLS="$URLS $var=http://127.0.0.1:${PP}$port"
done
# the spawner starts only the session image pinned by its linux/amd64 digest
E2E_SESSION_IMAGE="$("$ROOT/infra/image-digest.sh" "${E2E_SESSION_IMAGE:-ghcr.io/de0ch/jarvis2-session:latest}")"
# stand-ins for the box's other services (e2e/nojarvis1.go serves them): search, the watch runner, and the Storage Box
# (WebDAV over TLS with a throwaway certificate the router trusts through SSL_CERT_FILE, beside the system roots)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=127.0.0.1 \
  -addext subjectAltName=IP:127.0.0.1 -keyout "$W/dav.key" -out "$W/dav.crt" 2>/dev/null
cat /etc/ssl/certs/ca-certificates.crt "$W/dav.crt" > "$W/roots.pem"
# the backup bucket: rclone's S3 server (it checks SigV4) on a local directory; the router adds key backups there
# (router/storedocs.go) with the stand-in's key, as it does with its BACKUP_READ_* credential on Hetzner
mkdir -p "$W/s3/jarvis2-backup-de0ch"
S3_SECRET="$(openssl rand -hex 16)"
rclone serve s3 --addr 127.0.0.1:${PP}074 --auth-key "e2e,$S3_SECRET" "$W/s3" > "$W/s3.log" 2>&1 & PIDS+=($!)
cat > "$W/router-env" <<ENV
#!/bin/sh
exec env -i PATH="$PATH" HOME="$HOME" \\
  $URLS NO_ACCESS=1 RECORDS_OFF=1 LIVE_SYNC_SECONDS=20 ADDR=127.0.0.1:${PP}080 DATA_DIR="$W/data" WEB_DIR="$W/web" \\
  WG_CONFIG="$W/wg.conf" MACHINE_URL="http://$PEER._peer.internal:8081" POLICY_FILE="$W/policy.json" TASKS_DIR="$ROOT/tasks" \\
  SESSION_IMAGE="$E2E_SESSION_IMAGE" JARVIS1_PAUSED_URL="http://127.0.0.1:${PP}070/" \\
  STORAGEBOX_HOST=127.0.0.1:${PP}073 STORAGEBOX_USER=e2e STORAGEBOX_PASSWORD=e2e SSL_CERT_FILE="$W/roots.pem" \\
  SEARCH_URL=http://127.0.0.1:${PP}071 WATCH_URL=http://127.0.0.1:${PP}072 \\
  BACKUP_ENDPOINT=http://127.0.0.1:${PP}074 BACKUP_READ_ACCESS_KEY=e2e BACKUP_READ_SECRET_KEY="$S3_SECRET" \\
  "$W/router"
ENV
chmod 700 "$W/router-env"
# Jarvis 2 runs without Jarvis 1: the router runs in its own mount namespace whose /etc/hosts sends every Jarvis 1
# hostname to 127.0.0.2, where a listener (root: ports 80/443) logs any connection to $W/j1-hits.log; the test fails
# on any line there (e2e/nojarvis1.go). The test blackholes the same hostnames on every session machine.
J1_HOSTS="jarvis.deyaochen.com"
{ cat /etc/hosts; for h in $J1_HOSTS; do echo "127.0.0.2 $h"; done; } > "$W/hosts"
: > "$W/j1-hits.log"
cat > "$W/j1-listener.py" <<'PY'
import socket, sys, threading, time
log = sys.argv[1]
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.2", port)); s.listen(16)
    while True:
        c, a = s.accept()
        with open(log, "a") as f: f.write(f"{time.strftime('%H:%M:%S')} connection to Jarvis 1 port {port} from {a}\n")
        c.close()
for p in (80, 443): threading.Thread(target=serve, args=(p,), daemon=True).start()
while True: time.sleep(3600)
PY
sudo -n python3 -I "$W/j1-listener.py" "$W/j1-hits.log" & SUDO_PIDS+=($!)
# the router: unshare (root) bind-mounts the hosts file, then setpriv drops back to this user before the router runs
sudo -n unshare -m --propagation private sh -c 'mount --bind "$0" /etc/hosts && exec setpriv --reuid="$1" --regid="$2" --clear-groups "$3"' \
  "$W/hosts" "$(id -u)" "$(id -g)" "$W/router-env" > "$W/router.log" 2>&1 & SUDO_PIDS+=($!)
ROUTER_PID=""
for _ in $(seq 1 30); do
  for p in /proc/[0-9]*; do [ "$(readlink "$p/exe" 2>/dev/null)" = "$W/router" ] && ROUTER_PID="${p#/proc/}"; done
  [ -n "$ROUTER_PID" ] && break; sleep 0.5
done
[ -n "$ROUTER_PID" ] || { echo "the router didn't start"; cat "$W/router.log"; exit 1; }
PIDS+=("$ROUTER_PID")
for h in $J1_HOSTS; do
  grep -qx "127.0.0.2 $h" "/proc/$ROUTER_PID/root/etc/hosts" || { echo "the router's /etc/hosts doesn't blackhole $h"; exit 1; }
done
grep -q 'jarvis.deyaochen.com' /etc/hosts && { echo "the blackhole leaked into this session's own /etc/hosts"; exit 1; }
sleep 3
(cd "$ROOT/e2e" && E2E_ROUTER_PID="$ROUTER_PID" E2E_ROUTER_LOG="$W/router.log" E2E_DATA_DIR="$W/data" E2E_ROUTER=http://127.0.0.1:${PP}080 E2E_ROSTER_FILE="$W/roster.json" E2E_PHONE_KEY_FILE="$W/key-phone.pem" E2E_ROOT_KEY_FILE="$W/key-root.pem" E2E_MASTER_KEY_FILE="$ROOT/e2e/testdata/master-test.pem" E2E_BOX_PUB="$(cat "$W/box.pub")" \
  E2E_JARVIS1_ADDR=127.0.0.1:${PP}070 E2E_FLY_TOKEN="$JARVIS2_FLY_TOKEN" \
  E2E_PEER="$PEER" E2E_J1_HITS="$W/j1-hits.log" E2E_SEARCH_ADDR=127.0.0.1:${PP}071 E2E_WATCH_ADDR=127.0.0.1:${PP}072 \
  E2E_DAV_ADDR=127.0.0.1:${PP}073 E2E_DAV_CERT="$W/dav.crt" E2E_DAV_KEY="$W/dav.key" E2E_S3_DIR="$W/s3/jarvis2-backup-de0ch" go run .) || { echo "--- router log"; tail -40 "$W/router.log"; exit 1; }
