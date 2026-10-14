#!/bin/bash
# phone-replica.sh — the phone replica, one command: a throwaway box (infra/rehearsal-box.sh, MODE=replica: Access as
# in production, one email login + the /setup service token), the app's RELEASE build on the simulator closest to
# Deyao's iPhone on a free GitHub macOS runner (.github/workflows/replica.yml), every user flow tapped by
# ios/UITests/ReplicaUITests.swift against that box and real Fly sessions, then teardown. The gate before
# shipping a TestFlight build (docs/RUNBOOK.md "The phone replica").
#
# This script is the setup session and the person's mailbox around the phone, answering the UI test through a piping
# relay (ppng.io, a random path; only "otp", "reset-done", "repo-check", "done" and their answers cross it):
#   otp         the Access login's one-time PIN, read from the bot's mailbox (bot@deyaochen.com, BOT_EMAIL_PASSWORD)
#   reset-done  after the app's Reset: the stores written with infra/setup.py (dummy values; the harness's claude and
#               tunnel; github-deploy-keys = a 7-day PAT for the throwaway repo only; the core's Fly token, 6 h)
#   repo-added  the throwaway repo has its one deploy key now (the app shows the repo added)
#   repo-check  …and none left after the app removed it
#   inbox-setup-add / inbox-setup-remove   infra/setup.py request add-repo / remove-repo for the throwaway repo
#   inbox-session:<sid>:<holder>           jarvis2-request grant <holder> run inside that session's machine (flyctl exec)
#   inbox-batch:<sid>                      jarvis2-request batch (two grants, one summary) inside that session's machine
#   session-file:<sid>:<name>              the image attached on New session is on that session's machine (flyctl exec:
#                                          the machine's hash-checked copy, or the harness's ~/uploads copy)
#   done        the end
# What the test box needs that production keeps elsewhere: its keys/box.pub on a branch rehearsal-keys-<time> (the
# Release build reads keys from that git ref: JarvisKeysRef, KeySource.swift), a throwaway private repo
# DE0CH/jarvis2-replica-<run>. Teardown removes them with the box, its Cloudflare bits, bucket, Fly machines and PAT —
# its own run's only: every name carries the run id (infra/rehearsal-box.sh: one run at a time, refuses to start while
# another replica's server, bucket or tunnel exists). After a crash: `infra/phone-replica.sh teardown <run id>`.
#
# Env: as infra/rehearsal-box.sh, plus BOT_EMAIL_PASSWORD, GITHUB_TOKEN (gh), GITHUB_USER/PASSWORD/TOTP_SECRET (the
# github-web skill: the PAT and deleting the repo; GITHUB_WEB_DIR, default ~/workspace/claude-env/.claude/skills/
# github-web). Optional: REPLICA_REF (the branch the workflow runs from, default main), REHEARSAL_RUN (the run id),
# KEEP=1.
# Output: the run's video, screenshots and logs in ~/artifacts/replica/<time>/.
set -euo pipefail
MODE=replica
export REHEARSAL_NAME="${REHEARSAL_NAME:-jarvis2-rehearsal-replica}" REHEARSAL_EMAIL="${REHEARSAL_EMAIL:-bot@deyaochen.com}"
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rehearsal-box.sh"
: "${BOT_EMAIL_PASSWORD:?}" "${GITHUB_TOKEN:?}"
GW="${GITHUB_WEB_DIR:-$HOME/workspace/claude-env/.claude/skills/github-web}"
T="$RUN"   # rehearsal-box.sh's run id: in every name below, so teardown removes this run's and no other's
KEYS_BRANCH="rehearsal-keys-$T"; TREPO="jarvis2-replica-$T"; PAT="jarvis2-replica-deploy-keys-$T"
OUT="$HOME/artifacts/replica/$T"; mkdir -p "$OUT"

teardown_extra() {
  [ -s "$W/run" ] && gh run cancel "$(cat "$W/run")" -R DE0CH/jarvis2 >/dev/null 2>&1 || true
  record_core
  gh api -X DELETE "repos/DE0CH/jarvis2/git/refs/heads/$KEYS_BRANCH" >/dev/null 2>&1 && echo "branch $KEYS_BRANCH deleted"
  if gh repo view "DE0CH/$TREPO" >/dev/null 2>&1; then
    (cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js repo-delete "$TREPO" >/dev/null 2>&1) && echo "repo DE0CH/$TREPO deleted"
  fi
  (cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js pat-delete "$PAT" >/dev/null 2>&1) && echo "PAT $PAT deleted"
}
# the test box's core key, so teardown can find the session machines it started (JARVIS2_CORE_KEY)
record_core() {
  python3 - "$ROOT/infra/setup.py" >> "$W/cores" 2>/dev/null <<'PY' || true
import importlib.util, sys
spec = importlib.util.spec_from_file_location("jarvis2_setup", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(m.call("GET", "/setup/identity")["signingKey"])
PY
}
if [ "${1:-}" = teardown ]; then teardown; exit 0; fi   # `teardown <run id>` (rehearsal-box.sh)
[ "${KEEP:-}" = 1 ] || trap teardown EXIT

# while a core change waits for Deyao's go (k8s/apps/core.yaml jarvis2/core-pin: hold), production runs an older
# core than the app being shipped expects: the replica runs the core main builds (the tag the router is pinned at)
# and says so; REPLICA_PINNED_CORE=1 keeps the pinned one (what production runs today)
RAW=https://raw.githubusercontent.com/DE0CH/jarvis2/main/k8s/apps
if [ "${REPLICA_PINNED_CORE:-}" != 1 ] && curl -sf "$RAW/core.yaml" | grep -q 'jarvis2/core-pin: hold'; then
  export REHEARSAL_CORE_IMAGE="ghcr.io/de0ch/jarvis2-core:$(curl -sf "$RAW/router.yaml" | grep -o 'jarvis2-router:sha-[0-9a-f]*' | head -1 | cut -d: -f2)"
  echo "the production core is held (jarvis2/core-pin: hold): the replica runs $REHEARSAL_CORE_IMAGE"
fi
prepare

step "the throwaway repo DE0CH/$TREPO and its deploy-keys PAT (7 days, Administration on that repo only)"
gh repo create "DE0CH/$TREPO" --private --add-readme --description "phone replica test repo (deleted after the run)" >/dev/null
(cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js pat-create-repo "$PAT" "$TREPO" "$W/deploy-keys.tok" Administration=write | tail -1)

step "the box (infra/create.sh in project runners)"
make_box
echo "server $(server_id) up at $(date -u +%FT%TZ)" | tee -a "$LOGS/servers.log"

step "the box's keys on branch $KEYS_BRANCH (the Release build reads keys from that git ref)"
MAIN=$(gh api repos/DE0CH/jarvis2/git/ref/heads/main -q .object.sha)
gh api -X POST repos/DE0CH/jarvis2/git/refs -f ref="refs/heads/$KEYS_BRANCH" -f sha="$MAIN" >/dev/null
for k in box.pub box-age.pub; do
  sha=$(gh api "repos/DE0CH/jarvis2/contents/keys/$k?ref=$KEYS_BRANCH" -q .sha)
  gh api -X PUT "repos/DE0CH/jarvis2/contents/keys/$k" -f message="phone replica: the test box's $k [skip ci]" -f branch="$KEYS_BRANCH" \
    -f sha="$sha" -f content="$(base64 -w0 < "$W/keys/$k")" >/dev/null
done
echo "ok: https://github.com/DE0CH/jarvis2/tree/$KEYS_BRANCH/keys"

RELAY="https://ppng.io/$(python3 -c "import secrets;print(secrets.token_hex(16))")"
step "the replica run on a GitHub macOS runner"
gh workflow run replica.yml -R DE0CH/jarvis2 --ref "${REPLICA_REF:-main}" -f base="https://$HOST/" -f keys_ref="$KEYS_BRANCH" \
  -f relay="$RELAY" -f email="$REHEARSAL_EMAIL" -f repo="DE0CH/$TREPO"
# this run's workflow run: the one named after its keys branch (replica.yml run-name), not just the newest
for _ in $(seq 1 24); do
  sleep 5
  gh run list -R DE0CH/jarvis2 -w replica.yml -L 20 --json databaseId,displayTitle \
    -q ".[] | select(.displayTitle == \"replica $KEYS_BRANCH\") | .databaseId" | head -1 > "$W/run"
  [ -s "$W/run" ] && break
done
[ -s "$W/run" ] || { echo "the replica workflow run for $KEYS_BRANCH didn't show up"; exit 1; }
echo "run https://github.com/DE0CH/jarvis2/actions/runs/$(cat "$W/run")"

# ---- the setup session's answers ------------------------------------------------------------------------
otp() { # the newest Access code in the bot's mailbox that arrived after $1 (unix time); waits up to 3 minutes
  python3 - "$1" <<'PY'
import email, imaplib, os, re, sys, time
since = float(sys.argv[1])
for _ in range(36):
    m = imaplib.IMAP4_SSL("imap.fastmail.com", 993)
    m.login(os.environ.get("BOT_EMAIL_ADDRESS", "bot@deyaochen.com"), os.environ["BOT_EMAIL_PASSWORD"])
    m.select("INBOX", readonly=True)
    _, ids = m.search(None, "ALL")
    best = None
    for i in ids[0].split()[-10:]:
        _, d = m.fetch(i, "(RFC822)")
        msg = email.message_from_bytes(d[0][1])
        if "cloudflare" not in (msg.get("From", "") + msg.get("Subject", "")).lower():
            continue
        at = email.utils.parsedate_to_datetime(msg["Date"]).timestamp()
        if at < since - 60:
            continue
        body = ""
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                body += part.get_payload(decode=True).decode(errors="replace")
        c = re.search(r"\b(\d{6})\b", re.sub(r"<[^>]+>", " ", body))
        if c and (best is None or at > best[0]):
            best = (at, c.group(1))
    m.logout()
    if best:
        print(best[1]); sys.exit(0)
    time.sleep(5)
sys.exit("no Access code in the mailbox")
PY
}
fill_stores() {
  local rnd; rnd=$(python3 -c "import secrets;print(secrets.token_hex(6))")
  local S="python3 $ROOT/infra/setup.py"
  RH_PLAIN="plain-$rnd" RH_SECRET="secret-$rnd" RH_CLAUDE="claude-$rnd" \
  CF_ACCESS_CLIENT_ID="tunnel-id-$rnd" CF_ACCESS_CLIENT_SECRET="tunnel-secret-$rnd" bash -c "
    set -e
    export JARVIS2_NOT_SENSITIVE=rh-plain
    $S pin-master
    $S create rh-plain
    $S write rh-plain RH_PLAIN --explain 'RH_PLAIN=replica test value (not secret)'
    $S write rh-secret RH_SECRET --explain 'RH_SECRET=replica test value in a sensitive store'
    $S write claude RH_CLAUDE --explain 'RH_CLAUDE=replica dummy value'
    $S write tunnel CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET --explain 'CF_ACCESS_CLIENT_ID=replica dummy tunnel id' --explain 'CF_ACCESS_CLIENT_SECRET=replica dummy tunnel secret'
    $S write github-deploy-keys GITHUB_DEPLOY_KEYS_TOKEN=file:$W/deploy-keys.tok --explain 'GITHUB_DEPLOY_KEYS_TOKEN=7-day PAT for the replica throwaway repo only (deploy keys)'
    $S backup-core $W/fly.tok
    $S stores"
}
# a deploy key ever seen on the throwaway repo (watched in the background while the run goes)
( while :; do n=$(gh api "repos/DE0CH/$TREPO/keys" -q 'length' 2>/dev/null || echo 0); [ "$n" -gt 0 ] && touch "$W/key-seen"; sleep 5; done ) &
WATCH=$!
answer() { printf '%s' "$1" | curl -sS -m 900 -T - "$RELAY/resp" >/dev/null; }
while :; do
  msg=$(curl -sS -m 120 "$RELAY/req" 2>/dev/null || true)   # short polls: the loop also notices the run ending
  [ -z "$msg" ] && { gh run view "$(cat "$W/run")" -R DE0CH/jarvis2 --json status -q .status | grep -q completed && break; continue; }
  echo "relay: $msg ($(date -u +%H:%M:%S))"
  case "$msg" in
    otp) answer "$(otp "$(($(date +%s) - 30))" || echo none)" ;;
    reset-done) record_core; if fill_stores > "$LOGS/fill.log" 2>&1; then answer filled; else tail -5 "$LOGS/fill.log"; answer "fill failed"; fi ;;
    repo-added) n=$(gh api "repos/DE0CH/$TREPO/keys" -q 'length' 2>/dev/null || echo "?")
      if [ "$n" = 1 ]; then touch "$W/key-seen"; answer ok; else answer "keys=$n"; fi ;;
    repo-check) left=$(gh api "repos/DE0CH/$TREPO/keys" -q 'length' 2>/dev/null || echo "?")
      if [ -e "$W/key-seen" ] && [ "$left" = 0 ]; then answer ok; else answer "seen=$([ -e "$W/key-seen" ] && echo yes || echo no) left=$left"; fi ;;
    inbox-setup-add) : > "$LOGS/inbox.log"; python3 "$ROOT/infra/setup.py" request add-repo "DE0CH/$TREPO" --why "replica: Claude asks for the test repo" > "$LOGS/inbox.log" 2>&1 && answer ok || answer "request failed: $(tail -1 "$LOGS/inbox.log")" ;;
    inbox-setup-remove) : > "$LOGS/inbox.log"; python3 "$ROOT/infra/setup.py" request remove-repo "DE0CH/$TREPO" --why "replica: Claude asks to remove it (deny this)" > "$LOGS/inbox.log" 2>&1 && answer ok || answer "request failed: $(tail -1 "$LOGS/inbox.log")" ;;
    inbox-session:*) # jarvis2-request inside the session's own machine (flyctl exec as the org): the router names the session
      IFS=: read -r _ sid holder <<<"$msg"; : > "$LOGS/inbox.log"; m=""
      for _ in $(seq 1 18); do   # up to 90 s: the router's record of the session's current machine
        m=$(python3 "$ROOT/infra/setup.py" sessions 2>>"$LOGS/inbox.log" | awk -v s="$sid" '$1 == s && $2 != "-" {print $2}')
        [ -n "$m" ] && break; sleep 5
      done
      if [ -n "$m" ] && FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl machine exec "$m" -a jarvis2-sessions \
           "/usr/local/bin/jarvis2-request grant $holder --minutes 5 --why replica-the-session-asks-for-$holder" >> "$LOGS/inbox.log" 2>&1; then answer ok
      else answer "session request failed (machine ${m:-none}): $(tail -2 "$LOGS/inbox.log" 2>/dev/null)"; fi ;;
    inbox-batch:*) # a batch from the session (two grants, one summary): the app allows both under one Face ID. Not the
      # scheduler: the grants step later forgets ITS scheduler grant by the row's identifier, and a second scheduler row
      # from here kept that identifier on screen ("forgotten" failed, replica run 38350148683)
      sid=${msg#inbox-batch:}; : > "$LOGS/inbox.log"; m=""
      for _ in $(seq 1 18); do
        m=$(python3 "$ROOT/infra/setup.py" sessions 2>>"$LOGS/inbox.log" | awk -v s="$sid" '$1 == s && $2 != "-" {print $2}')
        [ -n "$m" ] && break; sleep 5
      done
      if [ -n "$m" ] && FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl machine exec "$m" -a jarvis2-sessions \
           "/usr/local/bin/jarvis2-request batch --summary replica-the-session-asks-for-two-grants --item grant,holder=status,minutes=5 --item grant,holder=remote,minutes=5" >> "$LOGS/inbox.log" 2>&1 \
           && grep -q '"id": "b' "$LOGS/inbox.log"; then answer ok   # flyctl exec exits 0 whatever the command did: the router's batch id is the proof
      else answer "session batch failed (machine ${m:-none}): $(tail -2 "$LOGS/inbox.log" 2>/dev/null)"; fi ;;
    session-file:*) # the machine keeps an attachment only when its bytes match the cert (and the core attested it)
      IFS=: read -r _ sid name <<<"$msg"; : > "$LOGS/inbox.log"; m=""; found=""
      if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then answer "bad name"; continue; fi
      for _ in $(seq 1 18); do
        m=$(python3 "$ROOT/infra/setup.py" sessions 2>>"$LOGS/inbox.log" | awk -v s="$sid" '$1 == s && $2 != "-" {print $2}')
        [ -n "$m" ] && found=$(FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl machine exec "$m" -a jarvis2-sessions \
          "find /root /home -maxdepth 3 -type f -name $name -size +0c" 2>>"$LOGS/inbox.log" | tr -d "\r" | grep -E "/(\.jarvis2-uploads|uploads)/$name\$" || true)
        [ -n "$found" ] && break; sleep 10
      done
      if [ -n "$found" ]; then answer "ok $(echo $found)"; else answer "not on the machine (${m:-none}): $(tail -2 "$LOGS/inbox.log" 2>/dev/null)"; fi ;;
    done) record_core; answer ok; break ;;
    *) answer "unknown: $msg" ;;
  esac
done
kill $WATCH 2>/dev/null || true

step "the run's result"
gh run watch "$(cat "$W/run")" -R DE0CH/jarvis2 > /dev/null 2>&1 || true
CONC=$(gh run view "$(cat "$W/run")" -R DE0CH/jarvis2 --json conclusion -q .conclusion)
gh run download "$(cat "$W/run")" -R DE0CH/jarvis2 -n replica -D "$OUT" 2>/dev/null || true
grep -E "Test Case|error:|XCTAssert|failed" "$OUT/test.log" 2>/dev/null | tail -40 || true
# the simulator's log runs to hundreds of MB: always kept gzipped (an 822 MB one nearly filled the session's disk)
[ -f "$OUT/sim.log" ] && gzip -f "$OUT/sim.log"
# the full run (video, logs, crash reports) goes to the Storage Box; locally only the logs and screenshots stay, so
# runs never fill the session's disk (STORAGEBOX_HOST/USER/PASSWORD; skipped without them)
if [ -n "${STORAGEBOX_HOST:-}" ] && [ -d "$OUT" ]; then
  K=$(mktemp); printf 'user = "%s:%s"\n' "$STORAGEBOX_USER" "$STORAGEBOX_PASSWORD" > "$K"
  SB="https://$STORAGEBOX_HOST/claude-records/.jarvis2-replica-runs"
  curl -s -o /dev/null -K "$K" -X MKCOL "https://$STORAGEBOX_HOST/claude-records/"; curl -s -o /dev/null -K "$K" -X MKCOL "$SB/"
  if tar -C "$(dirname "$OUT")" -czf - "$T" | curl -sf -o /dev/null -K "$K" -T - "$SB/$T.tar.gz"; then
    rm -rf "$OUT/replica.mp4" "$OUT/crash" "$OUT"/shots/*.mp4
    echo "full run on the Storage Box: claude-records/.jarvis2-replica-runs/$T.tar.gz" > "$OUT/MOVED.txt"
  fi
  rm -f "$K"
fi
echo "artifacts in $OUT (screenshots in shots/; video and crash reports: see MOVED.txt)"
rm -f "$W/run"
[ "$CONC" = success ] && step "REPLICA PASSED" || { step "REPLICA FAILED ($CONC)"; exit 1; }
