#!/bin/bash
# create.sh — make the Jarvis 2 box (once; rebuild = destroy the server + run this again).
#   HETZNER_JARVIS2_MOCK_API  the jarvis2 Hetzner project's token
#   JARVIS2_FLY_TOKEN         to (re)make the box's WireGuard peer in Fly org jarvis2-370
#   JARVIS2_SETUP_KEY, JARVIS2_SETUP_ACCESS_ID/SECRET  only to wait for the box to come up (setup.py identity)
#   ~/.jarvis2/cloudflare.env from infra/cloudflare.py (run it first; ROTATE=1 on a rebuild if the file is gone)
# The box has no SSH and no reachable k8s API: its firewall has no inbound rules, and everything after
# this script comes from git (Flux). Prints no secret.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D="$HOME/.jarvis2"; mkdir -p "$D"; chmod 700 "$D"
NAME="${1:-jarvis2}"; TYPE="${SERVER_TYPE:-cx23}"; LOC="${LOCATION:-fsn1}"
: "${HETZNER_JARVIS2_MOCK_API:?}" "${JARVIS2_FLY_TOKEN:?}"
[ -s "$D/cloudflare.env" ] || { echo "run infra/cloudflare.py $D/cloudflare.env first"; exit 1; }
set -a; . "$D/cloudflare.env"; set +a

# a fresh WireGuard peer for the box (router/wg.go); machines reach it as jarvis2-box._peer.internal
FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 jarvis2-box >/dev/null 2>&1 || true
rm -f "$D/wg-box.conf"
(umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr jarvis2-box "$D/wg-box.conf" >/dev/null)

UD="$(mktemp)"; KEY="$(mktemp -d)"; trap 'rm -rf "$UD" "$KEY"' EXIT; chmod 600 "$UD"
# the box key: it vouches for every core this box starts. Its private half goes only into the box (user-data);
# its public half into git (keys/box.pub), where the app's recovery page checks the core's identity against it.
python3 - "$KEY" "$HERE/../keys/box.pub" <<'PY'
import base64, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as s
k = ec.generate_private_key(ec.SECP256R1())
open(sys.argv[1] + "/box-key.pem", "wb").write(k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
open(sys.argv[2], "w").write(base64.b64encode(k.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)).decode() + "\n")
PY
{ echo '#!/bin/bash'
  printf 'TUNNEL_TOKEN=%q\nWG_CONF=%q\nBOX_KEY=%q\n' "$TUNNEL_TOKEN" "$(cat "$D/wg-box.conf")" "$(cat "$KEY/box-key.pem")"
  cat "$HERE/cloud-init.sh"; } > "$UD"
# Hetzner mails a root password when a server has no SSH key: give it a throwaway key whose private half
# is deleted with this script (sshd is off and port 22 closed anyway)
ssh-keygen -q -t ed25519 -N "" -C jarvis2-throwaway -f "$KEY/k"
python3 - "$NAME" "$TYPE" "$LOC" "$UD" "$KEY/k.pub" <<'PY'
import json,os,sys,time,urllib.request,urllib.error
name,stype,loc,ud,pub=sys.argv[1:6]
H={"Authorization":"Bearer "+os.environ["HETZNER_JARVIS2_MOCK_API"],"Content-Type":"application/json"}
def call(m,p,b=None):
    r=urllib.request.Request("https://api.hetzner.cloud/v1"+p,method=m,headers=H,data=json.dumps(b).encode() if b is not None else None)
    try:
        resp=urllib.request.urlopen(r); return json.load(resp) if resp.status!=204 else {}
    except urllib.error.HTTPError as e: raise SystemExit(f"{m} {p}: {e.code} {e.read().decode()[:300]}")
kname=f"jarvis2-throwaway-{int(time.time())}"
key=call("POST","/ssh_keys",{"name":kname,"public_key":open(pub).read().strip()})["ssh_key"]["id"]
fws=[f for f in call("GET","/firewalls")["firewalls"] if f["name"]=="jarvis2"]
if fws:
    fw=fws[0]["id"]; call("POST",f"/firewalls/{fw}/actions/set_rules",{"rules":[]})
else:
    fw=call("POST","/firewalls",{"name":"jarvis2","rules":[]})["firewall"]["id"]   # no inbound at all
s=call("POST","/servers",{"name":name,"server_type":stype,"image":"ubuntu-24.04","location":loc,"ssh_keys":[key],
  "firewalls":[{"firewall":fw}],"labels":{"role":"jarvis2"},"user_data":open(ud).read()})["server"]
call("DELETE",f"/ssh_keys/{key}")
print("server",s["id"],s["public_net"]["ipv4"]["ip"])
PY
echo "keys/box.pub is the new box's key: commit and push it (the app checks the core against it)"
echo "waiting for the bootstrap (k3s + Flux + the core behind the tunnel)…"
for i in $(seq 1 90); do
  python3 "$HERE/setup.py" identity >/dev/null 2>&1 && { echo "up: the core answers through the tunnel and its identity checks"; exit 0; }
  sleep 10
done
echo "not up after 15 min; there is no way in to look — fix in git or destroy and run again"; exit 1
