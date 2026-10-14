#!/bin/bash
# The kernel's eight parts and the router on the runner, fresh (ios.yml, transitions.yml; after standins.sh built the
# binaries and keys into W). Stops whatever an earlier attempt left running, then starts:
#   secrets            :8090 through W/core-loop.sh (a new, empty one whenever it ends: a Reset's wipe ends it)
#   notary … spawner   :8091-8097, each with its own key (W/key-<role>.pem) and the roster W/roster.json; the spawner
#                      is the fakefly build (machines made up in memory, their private keys in W/fakefly) and names
#                      the router's machine listener as MACHINE_URL
#   fake-machine.py    boots each of those machines as the guard would (boot chain, grant, pull, status, the command
#                      channel), so sessions get to "started", take add-ons, pause and resume
#   the router         :18080 (app) / :18081 (machines), reading the stand-in bucket, every part's *_URL set
#   roster-watch.py    puts the app's phone and root keys into the roster once it claims secrets (taken from the
#                      master-signed claim through infra/setup.py claim-keys, as the setup session does) and starts
#                      every part but secrets again on the new roster
# usage: [NO_SETUP_KEY=1] kernel-up.sh W LOGDIR TAG DATA_DIR   (logs: LOGDIR/{core,<part>,router,roster-watch}-TAG.log)
set -euo pipefail
W="$1"; LOGS="$2"; TAG="$3"; DATA="$4"; ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$LOGS" "$DATA" "$W/web"
for f in "$W"/*.pid; do [ -e "$f" ] && { kill $(cat "$f") 2>/dev/null || true; rm -f "$f"; }; done
pkill -x secrets 2>/dev/null || true
sleep 1
# the roster as the box has it before the app's first claim: every part's key, no phone or root yet
python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
r = json.load(open(f"{w}/roster.json"))
r["phone"] = r["root"] = ""
json.dump(r, open(f"{w}/roster.json", "w"), indent=2)
PY
rm -rf "$W/notarizer-state.json" "$W/notary-log.jsonl" "$W/fakefly"
mkdir -p "$W/fakefly"
(nohup "$W/core-loop.sh" "$LOGS/core-$TAG.log" > /dev/null 2>&1 & echo $! > "$W/core.pid")
bash "$ROOT/ios/ci/parts.sh" "$W" "$LOGS" "$TAG"
for port in 8090 8091 8092 8093 8094 8095 8096 8097; do
  for i in $(seq 30); do curl -sf -o /dev/null "http://127.0.0.1:$port/identity" && break; sleep 1; done
  curl -sf -o /dev/null "http://127.0.0.1:$port/identity" || { echo "::error::kernel part on :$port didn't come up"; exit 1; }
done
# the router checks the setup key's signature on /setup calls, unless NO_SETUP_KEY=1 (the interop test's own setup
# writes go unsigned, as a CI router without a setup key takes them)
SETUP_KEY="$(cat "$W/keys/setup.pub")"; [ "${NO_SETUP_KEY:-}" = 1 ] && SETUP_KEY=""
(set -a; . "$W/router-backup.env"; . "$W/kernel-urls.env"; set +a
 NO_ACCESS=1 SETUP_KEY="$SETUP_KEY" DATA_DIR="$DATA" WEB_DIR="$W/web" TASKS_DIR="$ROOT/tasks" SNAPSHOT_WAIT_SECONDS=2 \
   POLICY_FILE="$W/policy.json" MACHINE_URL=http://127.0.0.1:18081 DISCORD_SESSION_CHANNELS=off RECORDS_OFF=1 \
   SESSION_IMAGE=ghcr.io/de0ch/jarvis2-session:ci@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
   ADDR=127.0.0.1:18080 MACHINE_ADDR=127.0.0.1:18081 nohup "$W/router" > "$LOGS/router-$TAG.log" 2>&1 & echo $! > "$W/router.pid")
for i in $(seq 30); do curl -sf -o /dev/null http://127.0.0.1:18080/api/state && break; sleep 1; done
curl -sf -o /dev/null http://127.0.0.1:18080/api/state || { echo "::error::the router didn't come up"; tail -50 "$LOGS/router-$TAG.log"; exit 1; }
(nohup "$W/venv/bin/python" -B "$ROOT/ios/ci/roster-watch.py" "$W" "$LOGS" "$TAG" > "$LOGS/roster-watch-$TAG.log" 2>&1 & echo $! > "$W/roster-watch.pid")
(nohup "$W/venv/bin/python" -B "$ROOT/ios/ci/fake-machine.py" "$W/fakefly" http://127.0.0.1:18081 "$W/roster.json" > "$LOGS/fake-machine-$TAG.log" 2>&1 & echo $! > "$W/fake-machine.pid")
echo "kernel ($TAG): secrets, seven parts, the router, the roster watcher and the fake machines up"
