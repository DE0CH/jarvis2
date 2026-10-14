#!/bin/bash
# kernel-switchover.sh — fold k8s/apps-next into k8s/apps for the kernel switchover (docs/RUNBOOK.md "Switching to the
# kernel", step "the switchover commit"). Local git changes only: it neither commits nor pushes, so the diff is
# reviewed first. After it, Flux (once the commit is on main) applies the eight kernel parts in jarvis2-core with
# their roster, gives the router their URLs, and deletes the old core.
#
#   - refuses unless the roster is complete (infra/kernel-keys.py check) and every part has its SOPS key Secret
#     (k8s/secrets/kernel-key-<part>.enc.yaml, infra/kernel-keys.py new)
#   - git mv k8s/apps-next/kernel → k8s/apps/kernel, k8s/apps-next/router-kernel.yaml → k8s/apps/router-kernel.yaml;
#     git rm k8s/apps/core.yaml and k8s/apps-next
#   - k8s/apps/kustomization.yaml: the kernel files instead of core.yaml, the router patch, the roster ConfigMap
#   - .github/workflows/k8s.yml: the Deployments it expects
# The kernel Deployments keep their placeholder images (sha-000000000000): the images workflow's pin job pins each
# part the first time (holds included), then holds secrets, the spawner, the notary and the notarizer.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -d k8s/apps-next/kernel ] || { echo "no k8s/apps-next/kernel: already switched?"; exit 1; }
python3 infra/kernel-keys.py check
PARTS="notary notarizer mover merger identity-signer gullible-signer spawner secrets"
for p in $PARTS; do
  [ -f "k8s/secrets/kernel-key-$p.enc.yaml" ] || { echo "no k8s/secrets/kernel-key-$p.enc.yaml (infra/kernel-keys.py new)"; exit 1; }
  grep -q "  - kernel-key-$p.enc.yaml" k8s/secrets/kustomization.yaml || { echo "kernel-key-$p.enc.yaml isn't in k8s/secrets/kustomization.yaml"; exit 1; }
done
git mv k8s/apps-next/kernel k8s/apps/kernel
git mv k8s/apps-next/router-kernel.yaml k8s/apps/router-kernel.yaml
git rm -q k8s/apps-next/kustomization.yaml k8s/apps/core.yaml
python3 - "$PARTS" <<'PY'
import re, sys
parts = sys.argv[1].split()
p = "k8s/apps/kustomization.yaml"
s = open(p).read()
m = re.search(r"^resources: \[(.*)\]$", s, re.M)
if not m:
    sys.exit(f"{p}: no one-line `resources: [...]`")
res = [x.strip() for x in m.group(1).split(",") if x.strip() != "core.yaml"] + [f"kernel/{x}.yaml" for x in parts]
s = s[:m.start()] + "resources: [" + ", ".join(res) + "]" + s[m.end():]
s += """# the router on the kernel: one URL per part (router-kernel.yaml)
patches:
  - path: router-kernel.yaml
"""
s = s.replace("configMapGenerator:\n", """configMapGenerator:
  # every kernel part's public key, the phone's and the root key's (infra/kernel-keys.py): ROSTER_FILE of the parts and
  # the roster the spawner puts in every machine's Fly config. No name hash: a roster change must not restart secrets
  # (an empty secrets) by itself; the parts read it at start (docs/RUNBOOK.md "Kernel operations")
  - name: kernel-roster
    namespace: jarvis2-core
    files: [roster.json=kernel/roster.json]
    options: { disableNameSuffixHash: true }
""", 1)
open(p, "w").write(s)
w = ".github/workflows/k8s.yml"
y = open(w).read()
old = '[ "$deps" = "cloudflared core icloud-index news router search watch " ]'
new = '[ "$deps" = "cloudflared gullible-signer icloud-index identity-signer merger mover news notarizer notary router search secrets spawner watch " ]'
if old not in y:
    sys.exit(f"{w}: the Deployment list isn't the old one")
open(w, "w").write(y.replace(old, new).replace("checks the seven Deployments", "checks the fourteen Deployments"))
PY
rmdir k8s/apps-next 2>/dev/null || true
kubectl kustomize k8s/apps > /dev/null
git add k8s/apps/kustomization.yaml .github/workflows/k8s.yml
git status --short
echo "ok: k8s/apps now runs the kernel; review the diff, then commit (docs/RUNBOOK.md \"Switching to the kernel\")"
