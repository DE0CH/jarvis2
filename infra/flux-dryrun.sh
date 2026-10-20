#!/bin/bash
# infra/flux-dryrun.sh [BASE_REF] — does Flux accept this tree? (k8s.yml runs it on every push touching k8s/)
#
# Each box's Flux applies its apps as the limited identity flux-applier (k8s/bootstrap-<box>: admin in the box's
# namespaces only), one Kustomization per app, and dry-runs EVERY object of one first: one object it can't apply fails
# that whole Kustomization and nothing of it reaches the box — silently, since no Flux status leaves the box. 2026-10-15: a RoleBinding to a Role added in the same commit failed
# that dry-run (NotFound: the RBAC escalation check needs the Role to exist), and ~40 min of commits never landed.
#
# This starts a throwaway kube-apiserver + etcd (envtest binaries), applies the bootstrap, gives `admin` its aggregated
# rules (a bare apiserver has no controller-manager to aggregate them), applies BASE_REF's TREES for real as
# flux-applier (the box as it is), then server-side dry-runs this tree's TREES as flux-applier. Exit 1 on any
# refusal. BASE_REF defaults to HEAD~1. BOOTSTRAP and TREES (space-separated) pick a box, e.g.
# BOOTSTRAP=k8s/bootstrap-control TREES="k8s/control/apps/core k8s/control/apps/router k8s/control/apps/edge"
# (default: the control box). FRESH=1 skips BASE_REF: the tree on an empty cluster, as a NEW box's Flux meets it (2026-10-15: every rehearsal box failed on a
# RoleBinding whose Role was in the same apply, which the box built long ago never noticed).
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="${1:-HEAD~1}"
# the servers are waited for on exit, and every run takes free ports of its own: k8s.yml runs this several times in a
# row, and a second run on fixed ports met the first run's still-exiting apiserver ("connection refused", 2026-10-15)
W="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; chmod -R u+w "$W" 2>/dev/null; rm -rf "$W"' EXIT
read -r PE PP PA < <(python3 -c 'import socket
s=[socket.socket() for _ in range(3)]
[x.bind(("127.0.0.1",0)) for x in s]; print(*[x.getsockname()[1] for x in s])')
command -v setup-envtest >/dev/null || GOFLAGS= go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.22
E="$("$(go env GOPATH)/bin/setup-envtest" use 1.33.x --bin-dir "$W/bin" -p path 2>/dev/null || setup-envtest use 1.33.x --bin-dir "$W/bin" -p path)"
openssl genrsa -out "$W/sa.key" 2048 2>/dev/null; openssl rsa -in "$W/sa.key" -pubout -out "$W/sa.pub" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/tls.key" -out "$W/tls.crt" -days 1 -subj /CN=localhost 2>/dev/null
echo 'admintoken,admin,admin,system:masters' > "$W/tokens.csv"
cat > "$W/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: t, cluster: {server: "https://127.0.0.1:$PA", insecure-skip-tls-verify: true}}]
users: [{name: admin, user: {token: admintoken}}]
contexts: [{name: t, context: {cluster: t, user: admin}}]
current-context: t
EOF
"$E/etcd" --data-dir "$W/etcd" --listen-client-urls http://127.0.0.1:$PE --advertise-client-urls http://127.0.0.1:$PE \
  --listen-peer-urls http://127.0.0.1:$PP > "$W/etcd.log" 2>&1 &
"$E/kube-apiserver" --etcd-servers http://127.0.0.1:$PE --secure-port $PA --bind-address 127.0.0.1 \
  --tls-cert-file "$W/tls.crt" --tls-private-key-file "$W/tls.key" --token-auth-file "$W/tokens.csv" --authorization-mode RBAC \
  --service-account-issuer https://kubernetes.default.svc --service-account-key-file "$W/sa.pub" \
  --service-account-signing-key-file "$W/sa.key" --service-cluster-ip-range 10.43.0.0/16 > "$W/apiserver.log" 2>&1 &
K="kubectl --kubeconfig $W/kubeconfig"
# up, and its default RBAC roles bootstrapped (they appear a moment after the API answers)
for _ in $(seq 1 90); do $K get clusterrole system:aggregate-to-view >/dev/null 2>&1 && break; sleep 1; done
$K create ns flux-system >/dev/null
BOOTSTRAP="${BOOTSTRAP:-k8s/bootstrap-control}"; TREES="${TREES:-$(ls -d k8s/control/apps/*/ | sed 's#/$##' | tr '\n' ' ')}"
$K apply -k "$BOOTSTRAP" >/dev/null
$K get clusterrole system:aggregate-to-admin system:aggregate-to-edit system:aggregate-to-view -o json \
  | jq '{apiVersion:"rbac.authorization.k8s.io/v1",kind:"ClusterRole",metadata:{name:"admin"},rules:[.items[].rules[]]}' > "$W/admin.json"
$K delete clusterrole admin >/dev/null; $K apply -f "$W/admin.json" >/dev/null
AS=(--server-side --field-manager=kustomize-controller --as=system:serviceaccount:flux-system:flux-applier)
mkdir -p "$W/base"
for T in $TREES; do
  [ -n "${FRESH:-}" ] && break
  if git archive "$BASE" "$T" 2>/dev/null | tar -x -C "$W/base" 2>/dev/null && kubectl kustomize "$W/base/$T" > "$W/base.yaml" 2>/dev/null; then
    $K apply "${AS[@]}" -f "$W/base.yaml" > "$W/base.out" 2>&1 || { echo "note: $BASE's $T doesn't apply cleanly:"; grep -v serverside-applied "$W/base.out" | head -5; }
  fi
done
fail=0
for T in $TREES; do
  kubectl kustomize "$T" > "$W/new.yaml"
  [ -s "$W/new.yaml" ] || { echo "flux-dryrun: $T is empty"; continue; }
  if out="$($K apply "${AS[@]}" --dry-run=server -f "$W/new.yaml" 2>&1)"; then
    echo "flux-dryrun: Flux (as flux-applier) accepts $T on top of $BASE"
  else
    echo "flux-dryrun: Flux would REFUSE $T (and apply none of it):"; echo "$out" | grep -v serverside-applied; fail=1
  fi
done
exit $fail
