#!/bin/bash
# phone-replica.sh — the phone replica, one command: a throwaway box (infra/rehearsal-box.sh, MODE=replica: Access as
# in production, one email login + the /setup service token), the app's RELEASE build on the simulator closest to
# Deyao's iPhone on a free GitHub macOS runner (.github/workflows/replica.yml), every user flow tapped by
# app/ios/UITests/ReplicaUITests.swift against that box and real Fly sessions, then teardown. The gate before
# shipping a TestFlight build (docs/RUNBOOK.md "The phone replica").
#
# This script is the setup session and the person's mailbox around the phone, answering the UI test through a piping
# relay (ppng.io, a random path; only "otp", "reset-done", "repo-check", "done" and their answers cross it):
#   otp         the Access login's one-time PIN, read from the bot's mailbox (bot@deyaochen.com, BOT_EMAIL_PASSWORD)
#   reset-done  after the app's Reset: the stores written with infra/setup.py (dummy values; the harness's claude and
#               tunnel; github-deploy-keys = a 7-day PAT for the throwaway repo only; the core's Fly token, 6 h)
#   repo-check  the throwaway repo had a deploy key added and has none left
#   done        the end
# What the test box needs that production keeps elsewhere: its keys/box.pub on a branch rehearsal-keys-<time> (the
# Release build reads keys from that git ref: JarvisKeysRef, KeySource.swift), a throwaway private repo
# DE0CH/jarvis2-replica-<time>. Teardown removes them with the box, its Cloudflare bits, bucket, Fly machines and PAT.
#
# Env: as infra/rehearsal-box.sh, plus BOT_EMAIL_PASSWORD, GITHUB_TOKEN (gh), GITHUB_USER/PASSWORD/TOTP_SECRET (the
# github-web skill: the PAT and deleting the repo; GITHUB_WEB_DIR, default ~/workspace/claude-env/.claude/skills/
# github-web). Optional: REPLICA_REF (the branch the workflow runs from, default main), KEEP=1.
# Output: the run's video, screenshots and logs in ~/artifacts/replica/<time>/.
set -euo pipefail
MODE=replica
export REHEARSAL_NAME="${REHEARSAL_NAME:-jarvis2-rehearsal-replica}" REHEARSAL_EMAIL="${REHEARSAL_EMAIL:-bot@deyaochen.com}"
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rehearsal-box.sh"
: "${BOT_EMAIL_PASSWORD:?}" "${GITHUB_TOKEN:?}"
GW="${GITHUB_WEB_DIR:-$HOME/workspace/claude-env/.claude/skills/github-web}"
T="${REPLICA_TIME:-$(date +%s)}"
KEYS_BRANCH="rehearsal-keys-$T"; TREPO="jarvis2-replica-$T"; PAT="jarvis2-replica-deploy-keys"
OUT="$HOME/artifacts/replica/$T"; mkdir -p "$OUT"

teardown_extra() {
  [ -s "$W/run" ] && gh run cancel "$(cat "$W/run")" -R DE0CH/jarvis2 >/dev/null 2>&1 || true
  record_core
  for b in $(gh api "repos/DE0CH/jarvis2/branches?per_page=100" -q '.[].name' 2>/dev/null | grep '^rehearsal-keys-' || true); do
    gh api -X DELETE "repos/DE0CH/jarvis2/git/refs/heads/$b" >/dev/null 2>&1 && echo "branch $b deleted"
  done
  for r in $(gh repo list DE0CH --limit 200 --json name -q '.[].name' 2>/dev/null | grep '^jarvis2-replica-' || true); do
    (cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js repo-delete "$r" >/dev/null 2>&1) && echo "repo DE0CH/$r deleted"
  done
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
if [ "${1:-}" = teardown ]; then teardown; exit 0; fi
[ "${KEEP:-}" = 1 ] || trap teardown EXIT

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
sleep 15
gh run list -R DE0CH/jarvis2 -w replica.yml -L 1 --json databaseId -q '.[0].databaseId' > "$W/run"
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
  RH_PLAIN="plain-$rnd" RH_SECRET="secret-$rnd" JARVIS1_CREDENTIALS_ID="claude-id-$rnd" JARVIS1_CREDENTIALS_SECRET="claude-secret-$rnd" \
  CF_ACCESS_CLIENT_ID="tunnel-id-$rnd" CF_ACCESS_CLIENT_SECRET="tunnel-secret-$rnd" bash -c "
    set -e
    $S create rh-plain
    $S write rh-plain RH_PLAIN
    $S write rh-secret RH_SECRET
    $S write claude JARVIS1_CREDENTIALS_ID JARVIS1_CREDENTIALS_SECRET
    $S write tunnel CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET
    $S write github-deploy-keys GITHUB_DEPLOY_KEYS_TOKEN=file:$W/deploy-keys.tok
    $S backup-core $W/fly.tok
    $S stores"
}
# a deploy key ever seen on the throwaway repo (watched in the background while the run goes)
( while :; do n=$(gh api "repos/DE0CH/$TREPO/keys" -q 'length' 2>/dev/null || echo 0); [ "$n" -gt 0 ] && touch "$W/key-seen"; sleep 5; done ) &
WATCH=$!
answer() { printf '%s' "$1" | curl -sS -m 900 -T - "$RELAY/resp" >/dev/null; }
while :; do
  msg=$(curl -sS -m 3600 "$RELAY/req" || true)
  [ -z "$msg" ] && { gh run view "$(cat "$W/run")" -R DE0CH/jarvis2 --json status -q .status | grep -q completed && break; continue; }
  echo "relay: $msg ($(date -u +%H:%M:%S))"
  case "$msg" in
    otp) answer "$(otp "$(($(date +%s) - 30))" || echo none)" ;;
    reset-done) record_core; if fill_stores > "$LOGS/fill.log" 2>&1; then answer filled; else tail -5 "$LOGS/fill.log"; answer "fill failed"; fi ;;
    repo-check) left=$(gh api "repos/DE0CH/$TREPO/keys" -q 'length' 2>/dev/null || echo "?")
      if [ -e "$W/key-seen" ] && [ "$left" = 0 ]; then answer ok; else answer "seen=$([ -e "$W/key-seen" ] && echo yes || echo no) left=$left"; fi ;;
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
echo "artifacts in $OUT (video replica.mp4, screenshots in shots/)"
rm -f "$W/run"
[ "$CONC" = success ] && step "REPLICA PASSED" || { step "REPLICA FAILED ($CONC)"; exit 1; }
