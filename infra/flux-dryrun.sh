#!/bin/bash
# infra/flux-dryrun.sh [BASE_REF] — does Flux accept this tree? (k8s.yml runs it on every push touching k8s/)
#
# Flux applies k8s/apps as the limited identity flux-applier (k8s/bootstrap: admin in the three namespaces only) and
# dry-runs EVERY object first: one object it can't apply fails the whole kustomization and nothing reaches the box —
# silently, since no Flux status leaves the box. 2026-10-15: a RoleBinding to a Role added in the same commit failed
# that dry-run (NotFound: the RBAC escalation check needs the Role to exist), and ~40 min of commits never landed.
#
# This starts a throwaway kube-apiserver + etcd (envtest binaries), applies the bootstrap, gives `admin` its aggregated
# rules (a bare apiserver has no controller-manager to aggregate them), applies BASE_REF's k8s/apps for real as
# flux-applier (the box as it is), then server-side dry-runs this tree's k8s/apps as flux-applier. Exit 1 on any
# refusal. BASE_REF defaults to HEAD~1.
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="${1:-HEAD~1}"
W="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; chmod -R u+w "$W" 2>/dev/null; rm -rf "$W"' EXIT
command -v setup-envtest >/dev/null || GOFLAGS= go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.22
E="$("$(go env GOPATH)/bin/setup-envtest" use 1.33.x --bin-dir "$W/bin" -p path 2>/dev/null || setup-envtest use 1.33.x --bin-dir "$W/bin" -p path)"
openssl genrsa -out "$W/sa.key" 2048 2>/dev/null; openssl rsa -in "$W/sa.key" -pubout -out "$W/sa.pub" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/tls.key" -out "$W/tls.crt" -days 1 -subj /CN=localhost 2>/dev/null
echo 'admintoken,admin,admin,system:masters' > "$W/tokens.csv"
cat > "$W/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: t, cluster: {server: "https://127.0.0.1:26443", insecure-skip-tls-verify: true}}]
users: [{name: admin, user: {token: admintoken}}]
contexts: [{name: t, context: {cluster: t, user: admin}}]
current-context: t
EOF
"$E/etcd" --data-dir "$W/etcd" --listen-client-urls http://127.0.0.1:22379 --advertise-client-urls http://127.0.0.1:22379 \
  --listen-peer-urls http://127.0.0.1:22380 > "$W/etcd.log" 2>&1 &
"$E/kube-apiserver" --etcd-servers http://127.0.0.1:22379 --secure-port 26443 --bind-address 127.0.0.1 \
  --tls-cert-file "$W/tls.crt" --tls-private-key-file "$W/tls.key" --token-auth-file "$W/tokens.csv" --authorization-mode RBAC \
  --service-account-issuer https://kubernetes.default.svc --service-account-key-file "$W/sa.pub" \
  --service-account-signing-key-file "$W/sa.key" --service-cluster-ip-range 10.43.0.0/16 > "$W/apiserver.log" 2>&1 &
K="kubectl --kubeconfig $W/kubeconfig"
# up, and its default RBAC roles bootstrapped (they appear a moment after the API answers)
for _ in $(seq 1 90); do $K get clusterrole system:aggregate-to-view >/dev/null 2>&1 && break; sleep 1; done
$K create ns flux-system >/dev/null
$K apply -k k8s/bootstrap >/dev/null
$K get clusterrole system:aggregate-to-admin system:aggregate-to-edit system:aggregate-to-view -o json \
  | jq '{apiVersion:"rbac.authorization.k8s.io/v1",kind:"ClusterRole",metadata:{name:"admin"},rules:[.items[].rules[]]}' > "$W/admin.json"
$K delete clusterrole admin >/dev/null; $K apply -f "$W/admin.json" >/dev/null
AS=(--server-side --field-manager=kustomize-controller --as=system:serviceaccount:flux-system:flux-applier)
mkdir -p "$W/base"; git archive "$BASE" k8s/apps | tar -x -C "$W/base"
kubectl kustomize "$W/base/k8s/apps" > "$W/base.yaml"
$K apply "${AS[@]}" -f "$W/base.yaml" > "$W/base.out" 2>&1 || { echo "note: $BASE itself doesn't apply cleanly:"; grep -v serverside-applied "$W/base.out" | head -5; }
kubectl kustomize k8s/apps > "$W/new.yaml"
if out="$($K apply "${AS[@]}" --dry-run=server -f "$W/new.yaml" 2>&1)"; then
  echo "flux-dryrun: Flux (as flux-applier) accepts k8s/apps on top of $BASE"
else
  echo "flux-dryrun: Flux would REFUSE this tree (and apply nothing):"; echo "$out" | grep -v serverside-applied; exit 1
fi
