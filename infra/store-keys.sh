#!/bin/bash
# store-keys.sh — record every store's key NAMES at the router (router/storekeys.go), without writing a value:
# the same names infra/fill-stores.sh writes (the layout file + its fixed stores). `infra/setup.py write` records
# names itself; run this when the router's list is missing (a new box: the router's data volume starts empty) or
# out of step. Needs JARVIS2_SETUP_* only. Repo stores (github-<repo>) need nothing: their names follow from the repo.
set -euo pipefail
cd "$(dirname "$0")/.."
S="python3 infra/setup.py"
LAYOUT="${STORES_LAYOUT:-$HOME/workspace/claude-env/.claude/skills/jarvis2/stores.txt}"
grep -v '^#' "$LAYOUT" | while read -r store keys; do
  [ -n "$store" ] || continue
  # shellcheck disable=SC2086
  $S keys "$store" $keys
done
$S keys openrouter OPENROUTER_API
$S keys claude JARVIS1_CREDENTIALS_ID JARVIS1_CREDENTIALS_SECRET
$S keys tunnel CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET
