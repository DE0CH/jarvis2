#!/bin/bash
# fill-stores.sh — after a Reset (docs/RUNBOOK.md "After a Reset"): fill every store in the core and its backup
# (sealed to the master key the core was set up with), minting or rotating every token whose value lived only in
# the old stores and backups, then delete the local copies. Values are never printed.
#
#   github-jarvis2     GITHUB_TOKEN_JARVIS2       a new fine-grained PAT jarvis2-sessions-jarvis2-push (sensitive)
#   github-claude-env  GITHUB_TOKEN_CLAUDE_ENV    a new PAT jarvis2-sessions-claude-env-push
#   claude             JARVIS1_CREDENTIALS_ID/SECRET  Access service token jarvis2-store-claude, rotated
#   tunnel             CF_ACCESS_CLIENT_ID/SECRET     Access service token jarvis2-tunnel, rotated
#   core               FLY_API_TOKEN              a fresh infra/fly-token.sh
#   default, identity, infra, money, devices, work, jarvis1   Deyao's own stores by kind: the keys are listed in
#                      claude-env .claude/skills/jarvis2/stores.txt (values from this session's env)
#   openrouter         OPENROUTER_API
#
# Needs: CLOUDFLARE_API, JARVIS2_FLY_TOKEN, JARVIS2_SETUP_*, HETZNER_S3_*, the env values above, and claude-env's
# github-web skill (GITHUB_WEB_DIR, default ~/workspace/claude-env/.claude/skills/github-web; its pat-create
# deletes the same-name token first, so the old PATs are revoked).
set -euo pipefail
cd "$(dirname "$0")/.."
D=~/.jarvis2; mkdir -p "$D"; chmod 700 "$D"
GW="${GITHUB_WEB_DIR:-$HOME/workspace/claude-env/.claude/skills/github-web}"
for v in CLOUDFLARE_API JARVIS2_FLY_TOKEN LOBSTER_TOKEN OPENROUTER_API EXA_API; do
  [ -n "${!v:-}" ] || { echo "missing env $v"; exit 1; }
done
trap 'shred -u "$D"/fly.tok "$D"/gh-*.token "$D"/j1creds.* "$D"/j2tunnel.* 2>/dev/null || true' EXIT

(cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js pat-create jarvis2-sessions-jarvis2-push jarvis2 "$D/gh-jarvis2.token")
(cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js pat-create jarvis2-sessions-claude-env-push claude-env "$D/gh-claude-env.token")

# the PATs: a bogus ref create is 422 on the token's own repo (it may write) and 403/404 on the other one
python3 - <<'EOF'
import json, os, urllib.request, urllib.error
for repo, other, f in [("jarvis2", "claude-env", "gh-jarvis2"), ("claude-env", "jarvis2", "gh-claude-env")]:
    t = open(os.path.expanduser(f"~/.jarvis2/{f}.token")).read().strip()
    codes = []
    for r in (repo, other):
        req = urllib.request.Request(f"https://api.github.com/repos/DE0CH/{r}/git/refs", method="POST",
                                     data=json.dumps({"ref": "refs/heads/zz-probe", "sha": "0" * 40}).encode(),
                                     headers={"Authorization": "Bearer " + t, "User-Agent": "probe"})
        try:
            codes.append(urllib.request.urlopen(req).status)
        except urllib.error.HTTPError as e:
            codes.append(e.code)
    assert codes[0] == 422 and codes[1] in (403, 404), (repo, codes)
    print(f"ok: the {repo} PAT writes {repo} only")
EOF

# the two Access service tokens: a new client secret, the same client id (policies keep working)
python3 - <<'EOF'
import json, os, urllib.request
API = "https://api.cloudflare.com/client/v4/accounts/ee3b4deef856baf11e1a67b242438325/access/service_tokens"
H = {"Authorization": "Bearer " + os.environ["CLOUDFLARE_API"], "User-Agent": "curl/8", "Content-Type": "application/json"}
call = lambda m, u: json.load(urllib.request.urlopen(urllib.request.Request(u, method=m, headers=H)))
toks = {t["name"]: t for t in call("GET", API + "?per_page=200")["result"]}
os.umask(0o077)
D = os.path.expanduser("~/.jarvis2")
for name, f in [("jarvis2-tunnel", "j2tunnel"), ("jarvis2-store-claude", "j1creds")]:
    t = toks[name]
    r = call("POST", f"{API}/{t['id']}/rotate")["result"]
    assert r["client_id"] == t["client_id"]
    open(f"{D}/{f}.id", "w").write(r["client_id"])
    open(f"{D}/{f}.secret", "w").write(r["client_secret"])
    print(f"ok: {name} rotated")
EOF
sleep 5
# jarvis2-store-claude reaches /api/credentials only; jarvis2-tunnel passes Access (the Worker then confines it)
c() { curl -s -o /dev/null -w "%{http_code}" -H "CF-Access-Client-Id: $(cat "$D/$1.id")" -H "CF-Access-Client-Secret: $(cat "$D/$1.secret")" "$2"; }
[ "$(c j1creds https://jarvis.deyaochen.com/api/credentials)" = 200 ] && [ "$(c j1creds https://jarvis.deyaochen.com/api/state)" = 403 ] \
  && [ "$(c j2tunnel https://tunnel.deyaochen.com/__status/x)" = 403 ] || { echo "a rotated Access token doesn't behave"; exit 1; }

bash infra/fly-token.sh "$D/fly.tok"

S="python3 infra/setup.py"
$S identity | grep -q '^set up' || { echo "the core is empty: Reset in the app first"; exit 1; }
# not sensitive: created first (a store the core never created is sensitive); a store that exists is kept
have="$($S stores | cut -d' ' -f1)"
for n in default openrouter github-claude-env claude tunnel; do
  grep -qx "$n" <<<"$have" || $S create "$n"
done
# Deyao's own stores, by kind, from the layout file (key names only; private, in claude-env): each line is
# "<store> KEY…", values from this session's env. Only `default` is created (not sensitive); the rest are sensitive.
LAYOUT="${STORES_LAYOUT:-$HOME/workspace/claude-env/.claude/skills/jarvis2/stores.txt}"
grep -v '^#' "$LAYOUT" | while read -r store keys; do
  [ -n "$store" ] || continue
  # shellcheck disable=SC2086
  $S write "$store" $keys
done
$S write openrouter OPENROUTER_API
$S write github-claude-env GITHUB_TOKEN_CLAUDE_ENV=file:$D/gh-claude-env.token
$S write github-jarvis2 GITHUB_TOKEN_JARVIS2=file:$D/gh-jarvis2.token
$S write claude JARVIS1_CREDENTIALS_ID=file:$D/j1creds.id JARVIS1_CREDENTIALS_SECRET=file:$D/j1creds.secret
$S write tunnel CF_ACCESS_CLIENT_ID=file:$D/j2tunnel.id CF_ACCESS_CLIENT_SECRET=file:$D/j2tunnel.secret
$S backup-core "$D/fly.tok"
$S stores
echo "ok: every store written to the core and backed up; local copies deleted"
