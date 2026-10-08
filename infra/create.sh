#!/bin/bash
# create.sh — make the Jarvis 2 box (once; rebuild = destroy the server + run this again).
#   HETZNER_JARVIS2_MOCK_API  the jarvis2 Hetzner project's token
#   ~/.jarvis2/cloudflare.env from infra/cloudflare.py (run it first; ROTATE=1 on a rebuild if the file is gone)
# Writes ~/.jarvis2/k8s-admin-token, ~/.jarvis2/ssh (key) and ~/.jarvis2/kubeconfig; prints no secret.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D="$HOME/.jarvis2"; mkdir -p "$D"; chmod 700 "$D"
NAME="${1:-jarvis2}"; TYPE="${SERVER_TYPE:-cx23}"; LOC="${LOCATION:-fsn1}"
: "${HETZNER_JARVIS2_MOCK_API:?}"
[ -s "$D/cloudflare.env" ] || { echo "run infra/cloudflare.py $D/cloudflare.env first"; exit 1; }
[ -s "$D/k8s-admin-token" ] || (umask 077; openssl rand -hex 32 > "$D/k8s-admin-token")
[ -s "$D/ssh" ] || ssh-keygen -q -t ed25519 -N "" -C jarvis2-admin -f "$D/ssh"
set -a; . "$D/cloudflare.env"; set +a
UD="$(mktemp)"; trap 'rm -f "$UD"' EXIT; chmod 600 "$UD"
{ echo '#!/bin/bash'
  printf 'K8S_ADMIN_TOKEN=%q\nTUNNEL_TOKEN=%q\nROUTER_ENV=%q\n' "$(cat "$D/k8s-admin-token")" "$TUNNEL_TOKEN" \
    "$(grep -E '^(MACHINE_ACCESS_ID|MACHINE_ACCESS_SECRET|ACCESS_APP_AUD|ACCESS_MACHINE_AUD)=' "$D/cloudflare.env")"
  cat "$HERE/cloud-init.sh"; } > "$UD"
python3 - "$NAME" "$TYPE" "$LOC" "$UD" "$D/ssh.pub" <<'PY'
import json,os,sys,urllib.request,urllib.error
name,stype,loc,ud,pub=sys.argv[1:6]
H={"Authorization":"Bearer "+os.environ["HETZNER_JARVIS2_MOCK_API"],"Content-Type":"application/json"}
def call(m,p,b=None):
    r=urllib.request.Request("https://api.hetzner.cloud/v1"+p,method=m,headers=H,data=json.dumps(b).encode() if b else None)
    try: return json.load(urllib.request.urlopen(r))
    except urllib.error.HTTPError as e: raise SystemExit(f"{m} {p}: {e.code} {e.read().decode()[:300]}")
keys=[k for k in call("GET","/ssh_keys")["ssh_keys"] if k["name"]=="jarvis2-admin"]
key=keys[0]["id"] if keys else call("POST","/ssh_keys",{"name":"jarvis2-admin","public_key":open(pub).read().strip()})["ssh_key"]["id"]
fws=[f for f in call("GET","/firewalls")["firewalls"] if f["name"]=="jarvis2"]
fw=fws[0]["id"] if fws else call("POST","/firewalls",{"name":"jarvis2","rules":[
  {"direction":"in","protocol":"tcp","port":"22","source_ips":["0.0.0.0/0","::/0"]},
  {"direction":"in","protocol":"tcp","port":"6443","source_ips":["0.0.0.0/0","::/0"]},
  {"direction":"in","protocol":"icmp","source_ips":["0.0.0.0/0","::/0"]}]})["firewall"]["id"]
s=call("POST","/servers",{"name":name,"server_type":stype,"image":"ubuntu-24.04","location":loc,"ssh_keys":[key],
  "firewalls":[{"firewall":fw}],"labels":{"role":"jarvis2"},"user_data":open(ud).read()})["server"]
open(os.path.expanduser("~/.jarvis2/ip"),"w").write(s["public_net"]["ipv4"]["ip"])
print("server",s["id"],s["public_net"]["ipv4"]["ip"])
PY
IP="$(cat "$D/ip")"
cat > "$D/kubeconfig" <<KC
apiVersion: v1
kind: Config
clusters: [{name: jarvis2, cluster: {server: "https://$IP:6443", insecure-skip-tls-verify: true}}]
users: [{name: admin, user: {token: "$(cat "$D/k8s-admin-token")"}}]
contexts: [{name: jarvis2, context: {cluster: jarvis2, user: admin}}]
current-context: jarvis2
KC
chmod 600 "$D/kubeconfig"
echo "waiting for the bootstrap (k3s + Flux)…"
for i in $(seq 1 90); do
  KUBECONFIG="$D/kubeconfig" kubectl -n flux-system get kustomization jarvis2 >/dev/null 2>&1 && { echo "bootstrap done"; exit 0; }
  sleep 10
done
echo "bootstrap not finished after 15 min: ssh -i $D/ssh root@$IP tail /var/log/jarvis2-bootstrap.log"; exit 1
