#!/bin/bash
# The kernel's parts but secrets (notary, notarizer, mover, merger, identity and gullible signers, the fakefly spawner)
# on :8091-8097, each with its key W/key-<role>.pem, the box key and the roster W/roster.json; whatever of them runs is
# stopped first (the parts read the roster once, at start: kernel-up.sh starts them, roster-watch.py again after the
# app's claim put its phone and root keys in). The notarizer's state and the notary's log stay across a restart.
# usage: parts.sh W LOGDIR TAG
set -euo pipefail
W="$1"; LOGS="$2"; TAG="$3"
PARTS=(notary:notary:8091 notarizer:notarizer:8092 mover:mover:8093 merger:merger:8094 identity:identity-signer:8095
       gullible:gullible-signer:8096 spawner:spawner:8097)
for p in "${PARTS[@]}"; do
  IFS=: read -r role bin port <<<"$p"
  [ -e "$W/part-$bin.pid" ] && { kill "$(cat "$W/part-$bin.pid")" 2>/dev/null || true; rm -f "$W/part-$bin.pid"; }
done
sleep 1
for p in "${PARTS[@]}"; do
  IFS=: read -r role bin port <<<"$p"
  extra=()
  case "$bin" in
    notary) extra=(LOG_FILE="$W/notary-log.jsonl") ;;
    notarizer) extra=(STATE_FILE="$W/notarizer-state.json") ;;
    spawner) extra=(MACHINE_URL=http://127.0.0.1:18081 FAKEFLY_KEYS_DIR="$W/fakefly") ;;
  esac
  (env KEY_FILE="$W/key-$role.pem" BOX_KEY_FILE="$W/box-key.pem" ROSTER_FILE="$W/roster.json" ADDR="127.0.0.1:$port" "${extra[@]}" \
     nohup "$W/$bin" >> "$LOGS/$bin-$TAG.log" 2>&1 & echo $! > "$W/part-$bin.pid")
done
for p in "${PARTS[@]}"; do
  IFS=: read -r role bin port <<<"$p"
  for i in $(seq 20); do curl -sf -o /dev/null "http://127.0.0.1:$port/identity" && break; sleep 0.5; done
done
