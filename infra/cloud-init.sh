# Jarvis 2 box bootstrap (create.sh prepends a shebang and the variables). Blank Ubuntu → single-node k3s
# → Flux reconciling ./k8s/apps from the public repo. After this the box takes changes only from git:
# no SSH, no k8s API from outside (the firewall has no inbound rules at all), no admin token. A box that
# git can't fix is replaced, not repaired. Secrets (the tunnel token, the router's WireGuard peer, the box key, the age key) arrive
# in user-data and become k8s Secrets here; the user-data is shredded at the end.
# Injected: TUNNEL_TOKEN WG_CONF (the wg-quick file of `fly wireguard create`) BOX_KEY (the box key, PEM)
#           AGE_KEY (Flux decrypts k8s/secrets with it)
#           SYNC_YAML, EXTRA_MANIFEST  empty in production; a rehearsal box (infra/rehearse-recover.sh) sets them:
#           its own Flux sync (the same ./k8s/apps with documented patches) in place of k8s/flux/sync.yaml, and
#           the Secrets that sync can't get from git
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > >(tee -a /var/log/jarvis2-bootstrap.log) 2>&1
echo "=== jarvis2 bootstrap $(date -u +%FT%TZ) ==="
apt-get update -y && apt-get install -y --no-install-recommends ca-certificates curl git
systemctl disable --now ssh.socket ssh.service 2>/dev/null || true

curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable traefik" sh - || exit 1
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
printf '%s\n' "$WG_CONF" > /root/wg.conf
kubectl -n jarvis2-router create secret generic router-wg --from-file=wg.conf=/root/wg.conf
shred -u /root/wg.conf
printf '%s\n' "$BOX_KEY" > /root/box-key.pem
kubectl -n jarvis2-core create secret generic core-box-key --from-file=box-key.pem=/root/box-key.pem
shred -u /root/box-key.pem
printf '%s\n' "$AGE_KEY" > /root/age.agekey
kubectl -n flux-system create secret generic sops-age --from-file=age.agekey=/root/age.agekey
shred -u /root/age.agekey
if [ -n "${EXTRA_MANIFEST:-}" ]; then
  printf '%s\n' "$EXTRA_MANIFEST" > /root/extra.yaml
  kubectl apply -f /root/extra.yaml; shred -u /root/extra.yaml
fi
if [ -n "${SYNC_YAML:-}" ]; then
  printf '%s\n' "$SYNC_YAML" | kubectl apply -f - || exit 1
else
  kubectl apply -f /root/jarvis2/k8s/flux/sync.yaml || exit 1
fi
rm -rf /root/jarvis2
echo "bootstrap COMPLETE $(date -u +%FT%TZ)" > /var/log/jarvis2-bootstrap.done
shred -u /var/lib/cloud/instance/user-data.txt* 2>/dev/null || true
