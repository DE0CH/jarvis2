# Jarvis 2 box bootstrap (create.sh prepends a shebang and the variables). Blank Ubuntu → single-node k3s
# → Flux reconciling ./k8s/apps from the public repo. Secrets (the tunnel token, the router's settings)
# arrive in user-data and become k8s Secrets here; the user-data is shredded at the end.
# Injected: K8S_ADMIN_TOKEN TUNNEL_TOKEN ROUTER_ENV (KEY=VALUE lines)
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > >(tee -a /var/log/jarvis2-bootstrap.log) 2>&1
echo "=== jarvis2 bootstrap $(date -u +%FT%TZ) ==="
apt-get update -y && apt-get install -y --no-install-recommends ca-certificates curl git
PUBLIC_IP="$(curl -fsS --max-time 5 http://169.254.169.254/hetzner/v1/metadata/public-ipv4)"

mkdir -p /etc/rancher/k3s
printf '%s,jarvis2-admin,jarvis2-admin,"system:masters"\n' "$K8S_ADMIN_TOKEN" > /etc/rancher/k3s/tokens.csv
chmod 600 /etc/rancher/k3s/tokens.csv
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable traefik --tls-san $PUBLIC_IP --kube-apiserver-arg=token-auth-file=/etc/rancher/k3s/tokens.csv" sh - || exit 1
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for i in $(seq 1 60); do kubectl get nodes 2>/dev/null | grep -q ' Ready' && break; sleep 5; done

curl -s https://fluxcd.io/install.sh | bash || exit 1
flux install --timeout 5m || exit 1
# a Kustomization that names no service account applies as the powerless `default`, never as the controller
kubectl -n flux-system patch deployment kustomize-controller --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--default-service-account=default"}]'
kubectl -n flux-system rollout status deployment/kustomize-controller --timeout=120s

git clone --depth 1 https://github.com/DE0CH/jarvis2.git /root/jarvis2 || exit 1
kubectl apply -k /root/jarvis2/k8s/bootstrap || exit 1
kubectl -n jarvis2-edge create secret generic tunnel-token --from-literal=token="$TUNNEL_TOKEN"
printf '%s\n' "$ROUTER_ENV" > /root/router.env
kubectl -n jarvis2-router create secret generic router-env --from-env-file=/root/router.env
shred -u /root/router.env
kubectl apply -f /root/jarvis2/k8s/flux/sync.yaml || exit 1
rm -rf /root/jarvis2
echo "bootstrap COMPLETE $(date -u +%FT%TZ)" > /var/log/jarvis2-bootstrap.done
shred -u /var/lib/cloud/instance/user-data.txt* 2>/dev/null || true
