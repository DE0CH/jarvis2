#!/bin/bash
# fill-stores.sh — after a Reset (docs/RUNBOOK.md "After a Reset"): fill every store in secrets (the kernel part) and its
# key backups (sealed to the master key secrets was set up with), minting or rotating every token whose value lived only
# in the old stores and backups, send the spawner a fresh Fly token, then delete the local copies. Values are never printed.
#
#   github-deploy-keys GITHUB_DEPLOY_KEYS_TOKEN   a new fine-grained PAT jarvis2-deploy-keys: all repositories, Repository
#                      "Administration: read and write" only (sensitive). Secrets makes each repo's deploy key with it
#                      when Deyao adds the repo in the app; the repos' own stores (github-<repo>) are made there, one
#                      Face ID each, never here. Its line is in the layout file, valued from the file minted below.
#   claude             (no keys here)                 the router writes the Claude login into it (CLAUDE_CREDENTIALS,
#                      CLAUDE_ACCOUNT) right after the claim; made empty, not sensitive
#   tunnel             CF_ACCESS_CLIENT_ID/SECRET     Access service token jarvis2-tunnel, rotated
#   (the spawner)      FLY_API_TOKEN              a fresh infra/fly-token.sh, sealed to the spawner (not a store: the spawner
#                      keeps it in memory; `infra/setup.py fly-token` again after a spawner restart)
#   default, identity, infra, money, devices, work, jarvis1   Deyao's own stores by kind: the keys are listed in
#                      claude-env .claude/skills/jarvis2/stores.txt (values from this session's env)
#   openrouter         OPENROUTER_API
#
# Needs: CLOUDFLARE_API, JARVIS2_FLY_TOKEN, JARVIS2_SETUP_*, HETZNER_S3_*, the env values above, and claude-env's
# github-web skill (GITHUB_WEB_DIR, default ~/workspace/claude-env/.claude/skills/github-web; its pat-create-all
# deletes the same-name token first, so the old PAT is revoked).
set -euo pipefail
cd "$(dirname "$0")/.."
D=~/.jarvis2; mkdir -p "$D"; chmod 700 "$D"
GW="${GITHUB_WEB_DIR:-$HOME/workspace/claude-env/.claude/skills/github-web}"
for v in CLOUDFLARE_API JARVIS2_FLY_TOKEN LOBSTER_TOKEN OPENROUTER_API EXA_API; do
  [ -n "${!v:-}" ] || { echo "missing env $v"; exit 1; }
done
trap 'shred -u "$D"/fly.tok "$D"/gh-*.token "$D"/j2tunnel.* 2>/dev/null || true' EXIT

(cd "$GW" && NODE_PATH="$(npm root -g)" node github_web.js pat-create-all jarvis2-deploy-keys "$D/gh-deploy-keys.token" Administration=write)

# the deploy-keys PAT: it lists a repo's deploy keys (Administration) and can't write refs (no Contents)
python3 - <<'EOF'
import json, os, urllib.request, urllib.error
t = open(os.path.expanduser("~/.jarvis2/gh-deploy-keys.token")).read().strip()
def code(method, path, body=None):
    req = urllib.request.Request("https://api.github.com" + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": "Bearer " + t, "User-Agent": "probe", "Accept": "application/vnd.github+json"})
    try:
        return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        return e.code
assert code("GET", "/repos/DE0CH/jarvis2/keys") == 200, "the deploy-keys PAT can't list deploy keys"
assert code("POST", "/repos/DE0CH/jarvis2/git/refs", {"ref": "refs/heads/zz-probe", "sha": "0" * 40}) in (403, 404), "the deploy-keys PAT can write refs"
print("ok: the deploy-keys PAT manages deploy keys and can't push")
EOF

# the tunnel's Access service token: a new client secret, the same client id (policies keep working)
python3 - <<'EOF'
import json, os, urllib.request
API = "https://api.cloudflare.com/client/v4/accounts/ee3b4deef856baf11e1a67b242438325/access/service_tokens"
H = {"Authorization": "Bearer " + os.environ["CLOUDFLARE_API"], "User-Agent": "curl/8", "Content-Type": "application/json"}
call = lambda m, u: json.load(urllib.request.urlopen(urllib.request.Request(u, method=m, headers=H)))
toks = {t["name"]: t for t in call("GET", API + "?per_page=200")["result"]}
os.umask(0o077)
D = os.path.expanduser("~/.jarvis2")
for name, f in [("jarvis2-tunnel", "j2tunnel")]:
    t = toks[name]
    r = call("POST", f"{API}/{t['id']}/rotate")["result"]
    assert r["client_id"] == t["client_id"]
    open(f"{D}/{f}.id", "w").write(r["client_id"])
    open(f"{D}/{f}.secret", "w").write(r["client_secret"])
    print(f"ok: {name} rotated")
EOF
sleep 5
# jarvis2-tunnel passes Access (the Worker then confines it)
c() { curl -s -o /dev/null -w "%{http_code}" -H "CF-Access-Client-Id: $(cat "$D/$1.id")" -H "CF-Access-Client-Secret: $(cat "$D/$1.secret")" "$2"; }
[ "$(c j2tunnel https://tunnel.deyaochen.com/__status/x)" = 403 ] || { echo "a rotated Access token doesn't behave"; exit 1; }

bash infra/fly-token.sh "$D/fly.tok"

S="python3 infra/setup.py"
$S identity | grep -q '^set up' || { echo "secrets is empty: Reset in the app first"; exit 1; }
# not sensitive: created first (a store secrets never created is sensitive); a store that exists is kept
have="$($S stores | cut -d' ' -f1)"
for n in default openrouter claude tunnel shopping; do
  grep -qx "$n" <<<"$have" || $S create "$n"
done
# Deyao's own stores, by kind, from the layout file (key names only; private, in claude-env): each line is
# "<store> KEY…", values from this session's env. Only `default` and `shopping` are created (not sensitive); the rest are sensitive.
LAYOUT="${STORES_LAYOUT:-$HOME/workspace/claude-env/.claude/skills/jarvis2/stores.txt}"
grep -v '^#' "$LAYOUT" | while read -r store keys; do
  [ -n "$store" ] || continue
  # shellcheck disable=SC2086
  $S write "$store" $keys
done
$S write openrouter OPENROUTER_API
$S stores | grep -q '^claude \[' || $S create claude
$S write tunnel CF_ACCESS_CLIENT_ID=file:$D/j2tunnel.id CF_ACCESS_CLIENT_SECRET=file:$D/j2tunnel.secret
$S fly-token "$D/fly.tok"
$S stores
echo "ok: every store written to secrets and backed up, the spawner has its Fly token; local copies deleted"
