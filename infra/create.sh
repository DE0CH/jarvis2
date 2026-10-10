#!/bin/bash
# create.sh — make the Jarvis 2 box (once; rebuild = destroy the server + run this again).
#   HETZNER_JARVIS2_MOCK_API  the jarvis2 Hetzner project's token
#   JARVIS2_FLY_TOKEN         to (re)make the box's WireGuard peer in Fly org jarvis2-370
#   JARVIS2_SETUP_KEY, JARVIS2_SETUP_ACCESS_ID/SECRET  only to wait for the box to come up (setup.py identity)
#   ~/.jarvis2/cloudflare.env from infra/cloudflare.py (run it first; ROTATE=1 on a rebuild if the file is gone)
# The box has no SSH and no reachable k8s API: its firewall has no inbound rules, and everything after
# this script comes from git (Flux). Prints no secret.
# The defaults are production's. infra/rehearse-recover.sh makes a throwaway box with this same script and these
# overrides (each named, so nothing of production is touched):
#   HCLOUD_PROJECT_TOKEN  the Hetzner project's token (default HETZNER_JARVIS2_MOCK_API)
#   WG_PEER               the box's WireGuard peer name (default jarvis2-box)
#   CF_ENV                the cloudflare.env file (default ~/.jarvis2/cloudflare.env)
#   KEYS_OUT              where box.pub / box-age.pub go (default keys/ of this checkout)
#   FIREWALL, LABELS      the Hetzner firewall's name (default jarvis2) and the server's labels (JSON, default role=jarvis2)
#   SYNC_YAML_FILE, EXTRA_MANIFEST_FILE  a Flux sync in place of k8s/flux/sync.yaml, and Secrets applied before it
#                         (infra/cloud-init.sh)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D="$HOME/.jarvis2"; mkdir -p "$D"; chmod 700 "$D"
NAME="${1:-jarvis2}"; TYPE="${SERVER_TYPE:-cx23}"; LOC="${LOCATION:-fsn1}"
export HCLOUD_PROJECT_TOKEN="${HCLOUD_PROJECT_TOKEN:-${HETZNER_JARVIS2_MOCK_API:-}}"
: "${HCLOUD_PROJECT_TOKEN:?}" "${JARVIS2_FLY_TOKEN:?}"
PEER="${WG_PEER:-jarvis2-box}"; CFENV="${CF_ENV:-$D/cloudflare.env}"; KOUT="${KEYS_OUT:-$HERE/../keys}"
DEFAULT_LABELS='{"role":"jarvis2"}'
export FIREWALL="${FIREWALL:-jarvis2}" LABELS="${LABELS:-$DEFAULT_LABELS}"
[ -s "$CFENV" ] || { echo "run infra/cloudflare.py $CFENV first"; exit 1; }
set -a; . "$CFENV"; set +a

UD="$(mktemp)"; KEY="$(mktemp -d)"; trap 'rm -rf "$UD" "$KEY"' EXIT; chmod 600 "$UD"
# a fresh WireGuard peer for the box (router/wg.go); machines reach it as $PEER._peer.internal (production:
# jarvis2-box, MACHINE_URL in k8s/apps/router.yaml). Its config goes only into the box (user-data).
FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$PEER" "$KEY/wg.conf" >/dev/null)
# the box key: it vouches for every core this box starts. Its private half goes only into the box (user-data);
# its public half into git (keys/box.pub), where the app's recovery page checks the core's identity against it.
mkdir -p "$KOUT"
python3 - "$KEY" "$KOUT/box.pub" <<'PY'
import base64, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as s
k = ec.generate_private_key(ec.SECP256R1())
open(sys.argv[1] + "/box-key.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
open(sys.argv[2], "w").write(base64.b64encode(k.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)).decode() + "\n")
PY
# the box's age key: Flux decrypts the SOPS-encrypted secrets in k8s/secrets with it (infra/router-secrets.sh
# encrypts to keys/box-age.pub). Its private half goes only into the box (user-data).
age-keygen -o "$KEY/age.key" 2>/dev/null
age-keygen -y "$KEY/age.key" > "$KOUT/box-age.pub"
{ echo '#!/bin/bash'
  printf 'TUNNEL_TOKEN=%q\nWG_CONF=%q\nBOX_KEY=%q\nAGE_KEY=%q\n' "$TUNNEL_TOKEN" "$(cat "$KEY/wg.conf")" "$(cat "$KEY/box-key.pem")" "$(cat "$KEY/age.key")"
  printf 'SYNC_YAML=%q\nEXTRA_MANIFEST=%q\n' "$(cat "${SYNC_YAML_FILE:-/dev/null}")" "$(cat "${EXTRA_MANIFEST_FILE:-/dev/null}")"
  cat "$HERE/cloud-init.sh"; } > "$UD"
# Hetzner mails a root password when a server has no SSH key: give it a throwaway key whose private half
# is deleted with this script (sshd is off and port 22 closed anyway)
ssh-keygen -q -t ed25519 -N "" -C jarvis2-throwaway -f "$KEY/k"
python3 - "$NAME" "$TYPE" "$LOC" "$UD" "$KEY/k.pub" <<'PY'
import json,os,sys,time,urllib.request,urllib.error
name,stype,loc,ud,pub=sys.argv[1:6]
H={"Authorization":"Bearer "+os.environ["HCLOUD_PROJECT_TOKEN"],"Content-Type":"application/json"}
def call(m,p,b=None):
    r=urllib.request.Request("https://api.hetzner.cloud/v1"+p,method=m,headers=H,data=json.dumps(b).encode() if b is not None else None)
    try:
        resp=urllib.request.urlopen(r); return json.load(resp) if resp.status!=204 else {}
    except urllib.error.HTTPError as e: raise SystemExit(f"{m} {p}: {e.code} {e.read().decode()[:300]}")
kname=f"jarvis2-throwaway-{int(time.time())}"
key=call("POST","/ssh_keys",{"name":kname,"public_key":open(pub).read().strip()})["ssh_key"]["id"]
fwname=os.environ["FIREWALL"]
fws=[f for f in call("GET","/firewalls")["firewalls"] if f["name"]==fwname]
if fws:
    fw=fws[0]["id"]; call("POST",f"/firewalls/{fw}/actions/set_rules",{"rules":[]})
else:
    fw=call("POST","/firewalls",{"name":fwname,"rules":[]})["firewall"]["id"]   # no inbound at all
s=call("POST","/servers",{"name":name,"server_type":stype,"image":"ubuntu-24.04","location":loc,"ssh_keys":[key],
  "firewalls":[{"firewall":fw}],"labels":json.loads(os.environ["LABELS"]),"user_data":open(ud).read()})["server"]
call("DELETE",f"/ssh_keys/{key}")
print("server",s["id"],s["public_net"]["ipv4"]["ip"])
PY
echo "$KOUT/box.pub and box-age.pub are the new box's keys (production: re-run infra/router-secrets.py, which encrypts to the new age key, then commit and push)"
echo "waiting for the bootstrap (k3s + Flux + the core behind the tunnel)…"
for i in $(seq 1 90); do
  python3 "$HERE/setup.py" identity >/dev/null 2>&1 && { echo "up: the core answers through the tunnel and its identity checks"; exit 0; }
  sleep 10
done
echo "not up after 15 min; there is no way in to look — fix in git or destroy and run again"; exit 1
