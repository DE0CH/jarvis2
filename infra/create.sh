#!/bin/bash
# create.sh — make the Jarvis 2 box (once; rebuild = destroy the server + run this again).
#   HETZNER_JARVIS2_MOCK_API  the jarvis2 Hetzner project's token
#   JARVIS2_FLY_TOKEN         to (re)make the box's WireGuard peer in Fly org jarvis2-370
#   JARVIS2_SETUP_KEY, JARVIS2_SETUP_ACCESS_ID/SECRET  only to wait for the box to come up (setup.py identity)
#   ~/.jarvis2/cloudflare.env from infra/cloudflare.py (run it first; ROTATE=1 on a rebuild if the file is gone)
# The box is IPv6-only (no primary IPv4: the Hetzner account is at its limit of 10 primary IPs; Deyao, 2026-10-13);
# cloud-init.sh sends its outgoing IPv4 through Cloudflare WARP. The box has no SSH and no reachable k8s API: its firewall has no inbound rules, and everything after
# this script comes from git (Flux). Prints no secret.
# BOX_KIND=control|services makes one of the two boxes (docs/DESIGN.md "The boxes"; unset = the old single box until
# it is retired): cx33, attached to the Hetzner Network `jarvis2` (10.77.0.0/24, made here if missing) at PRIVATE_IP
# (control 10.77.0.2, services 10.77.0.3 by default), its own age key (keys/<kind>-age.pub) and Flux path
# (k8s/flux/<kind>.yaml). The services box gets no tunnel, no peer and no box key. The control box gets the box key
# (keys/box-next.pub, renamed keys/box.pub when its core takes over) and, with WG_PEER=none, NO WireGuard peer: the
# router move brings the live peer's config along (router/move.go) — never remove the peer a live router holds.
#   PRIVATE_ALLOW  control box: private addresses allowed in (default 10.77.0.9, the old box during the move)
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
BOX_KIND="${BOX_KIND:-}"
case "$BOX_KIND" in
  control)  NAME="${1:-jarvis2-control}"; TYPE="${SERVER_TYPE:-cx33}"; PRIVATE_IP="${PRIVATE_IP:-10.77.0.2}" ;;
  services) NAME="${1:-jarvis2-services}"; TYPE="${SERVER_TYPE:-cx33}"; PRIVATE_IP="${PRIVATE_IP:-10.77.0.3}" ;;
  "")       NAME="${1:-jarvis2}"; TYPE="${SERVER_TYPE:-cx23}"; PRIVATE_IP="" ;;
  *) echo "BOX_KIND is control or services"; exit 1 ;;
esac
LOC="${LOCATION:-fsn1}"; PRIVATE_ALLOW="${PRIVATE_ALLOW:-10.77.0.9}"
export BOX_KIND PRIVATE_IP NETWORK="${NETWORK:-jarvis2}"
export HCLOUD_PROJECT_TOKEN="${HCLOUD_PROJECT_TOKEN:-${HETZNER_JARVIS2_MOCK_API:-}}"
: "${HCLOUD_PROJECT_TOKEN:?}" "${JARVIS2_FLY_TOKEN:?}"
PEER="${WG_PEER:-jarvis2-box}"; CFENV="${CF_ENV:-$D/cloudflare.env}"; KOUT="${KEYS_OUT:-$HERE/../keys}"
DEFAULT_LABELS='{"role":"jarvis2"}'
[ -n "$BOX_KIND" ] && DEFAULT_LABELS="{\"role\":\"jarvis2-$BOX_KIND\"}"
export FIREWALL="${FIREWALL:-jarvis2}" LABELS="${LABELS:-$DEFAULT_LABELS}"
if [ "$BOX_KIND" != services ]; then
  [ -s "$CFENV" ] || { echo "run infra/cloudflare.py $CFENV first"; exit 1; }
  set -a; . "$CFENV"; set +a
fi
TUNNEL_TOKEN="${TUNNEL_TOKEN:-}"

UD="$(mktemp)"; KEY="$(mktemp -d)"; trap 'rm -rf "$UD" "$KEY"' EXIT; chmod 600 "$UD"
# a fresh WireGuard peer for the box (router/wg.go); machines reach it as $PEER._peer.internal (production:
# jarvis2-box, MACHINE_URL in k8s/apps/router.yaml). Its config goes only into the box (user-data).
: > "$KEY/wg.conf"
if [ "$BOX_KIND" != services ] && [ "$PEER" != none ]; then
  FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard remove jarvis2-370 "$PEER" >/dev/null 2>&1 || true
  (umask 077; FLY_API_TOKEN="$JARVIS2_FLY_TOKEN" flyctl wireguard create jarvis2-370 lhr "$PEER" "$KEY/wg.conf" >/dev/null)
fi
# the box key: it vouches for every core this box starts. Its private half goes only into the box (user-data);
# its public half into git (keys/box.pub), where the app's recovery page checks the core's identity against it.
mkdir -p "$KOUT"
BOXPUB="$KOUT/box.pub"; AGEPUB="$KOUT/box-age.pub"
case "$BOX_KIND" in control) BOXPUB="$KOUT/box-next.pub"; AGEPUB="$KOUT/control-age.pub" ;; services) BOXPUB=/dev/null; AGEPUB="$KOUT/services-age.pub" ;; esac
python3 - "$KEY" "$BOXPUB" <<'PY'
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
age-keygen -y "$KEY/age.key" > "$AGEPUB"
{ echo '#!/bin/bash'
  printf 'BOX_KIND=%q\nPRIVATE_ALLOW=%q\n' "$BOX_KIND" "$PRIVATE_ALLOW"
  printf 'TUNNEL_TOKEN=%q\nWG_CONF=%q\nBOX_KEY=%q\nAGE_KEY=%q\n' "$TUNNEL_TOKEN" "$(cat "$KEY/wg.conf")" "$([ "$BOX_KIND" = services ] || cat "$KEY/box-key.pem")" "$(cat "$KEY/age.key")"
  printf 'SYNC_YAML=%q\nEXTRA_MANIFEST=%q\n' "$(cat "${SYNC_YAML_FILE:-/dev/null}")" "$(cat "${EXTRA_MANIFEST_FILE:-/dev/null}")"
  cat "$HERE/warp-host.sh" "$HERE/cloud-init.sh"; } > "$UD"
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
try:   # the throwaway key goes whatever happens (a refused create used to leave it behind)
    fwname=os.environ["FIREWALL"]
    fws=[f for f in call("GET","/firewalls")["firewalls"] if f["name"]==fwname]
    if fws:
        fw=fws[0]["id"]; call("POST",f"/firewalls/{fw}/actions/set_rules",{"rules":[]})
    else:
        fw=call("POST","/firewalls",{"name":fwname,"rules":[]})["firewall"]["id"]   # no inbound at all
    pip=os.environ.get("PRIVATE_IP","")
    body={"name":name,"server_type":stype,"image":"ubuntu-24.04","location":loc,"ssh_keys":[key],
      "firewalls":[{"firewall":fw}],"public_net":{"enable_ipv4":False,"enable_ipv6":True},"labels":json.loads(os.environ["LABELS"]),"user_data":open(ud).read()}
    if pip:
        # the Hetzner Network: made once; the server is attached at its fixed address BEFORE its first boot, so
        # cloud-init configures the interface like any other
        nets=[n for n in call("GET","/networks?name="+os.environ["NETWORK"])["networks"]]
        net=nets[0]["id"] if nets else call("POST","/networks",{"name":os.environ["NETWORK"],"ip_range":"10.77.0.0/16",
            "subnets":[{"type":"cloud","network_zone":"eu-central","ip_range":"10.77.0.0/24"}],"labels":{"role":"jarvis2"}})["network"]["id"]
        body["start_after_create"]=False
    r=call("POST","/servers",body); s=r["server"]
    def wait(a):
        while call("GET",f"/actions/{a['id']}")["action"]["status"]=="running": time.sleep(2)
        st=call("GET",f"/actions/{a['id']}")["action"]
        if st["status"]!="success": raise SystemExit(f"{st['command']}: {st.get('error')}")
    if pip:
        wait(r["action"])
        wait(call("POST",f"/servers/{s['id']}/actions/attach_to_network",{"network":net,"ip":pip})["action"])
        wait(call("POST",f"/servers/{s['id']}/actions/poweron")["action"])
finally:
    call("DELETE",f"/ssh_keys/{key}")
print("server",s["id"],s["public_net"]["ipv6"]["ip"],os.environ.get("PRIVATE_IP",""))
PY
echo "$BOXPUB and $AGEPUB are the new box's keys (re-run infra/router-secrets.py${BOX_KIND:+ --box $BOX_KIND} for every part of this box, then commit and push)"
if [ "$BOX_KIND" = services ]; then echo "the services box has no tunnel: check it with its Alloy logs in Grafana and the router's /api/search/status"; exit 0; fi
if [ "$BOX_KIND" = control ]; then echo "the control box's core is the NEXT core until the move (docs/RUNBOOK.md \"Moving to the two boxes\")"; exit 0; fi
echo "waiting for the bootstrap (k3s + Flux + the core behind the tunnel)…"
for i in $(seq 1 90); do
  python3 "$HERE/setup.py" identity >/dev/null 2>&1 && { echo "up: the core answers through the tunnel and its identity checks"; exit 0; }
  sleep 10
done
echo "not up after 15 min; there is no way in to look — fix in git or destroy and run again"; exit 1
