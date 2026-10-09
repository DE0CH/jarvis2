#!/usr/bin/env python3
"""router-secrets.py — write the router's non-sensitive secrets into git, SOPS-encrypted to the box's age key
(keys/box-age.pub); Flux decrypts them on the box (k8s/flux/sync.yaml, Kustomization jarvis2-secrets).

    infra/router-secrets.py KEY[=SRC] …

SRC is `env:VAR` (default `env:KEY`) or `file:PATH`. The whole Secret is rewritten each run, so name every key.
Only for secrets that can't reach a code push (Deyao, 2026-10-09); the router's pod gets them as env
(k8s/apps/router.yaml envFrom router-secrets). Prints names only, never a value."""
import json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "k8s/secrets/router.enc.yaml")

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    data = {}
    for arg in sys.argv[1:]:
        key, _, src = arg.partition("=")
        src = src or "env:" + key
        kind, _, ref = src.partition(":")
        if kind == "env":
            v = os.environ.get(ref)
        elif kind == "file":
            v = open(os.path.expanduser(ref)).read().strip()
        else:
            sys.exit(f"{key}: SRC is env:VAR or file:PATH")
        if not v:
            sys.exit(f"{key}: {src} is empty")
        data[key] = v
    recipient = open(os.path.join(ROOT, "keys/box-age.pub")).read().strip()
    doc = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "router-secrets", "namespace": "jarvis2-router"},
           "type": "Opaque", "stringData": data}
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, dir=os.path.dirname(OUT)) as f:
        os.chmod(f.name, 0o600)
        json.dump(doc, f)  # JSON is YAML
        tmp = f.name
    try:
        enc = subprocess.run(["sops", "--encrypt", "--age", recipient, "--encrypted-regex", "^(data|stringData)$",
                              "--input-type", "yaml", "--output-type", "yaml", tmp], check=True, capture_output=True).stdout
    finally:
        os.remove(tmp)
    open(OUT, "wb").write(enc)
    kz = os.path.join(ROOT, "k8s/secrets/kustomization.yaml")
    s = open(kz).read()
    if "router.enc.yaml" not in s:
        open(kz, "w").write(s.replace("resources: []", "resources:\n  - router.enc.yaml"))
    print("wrote", os.path.relpath(OUT, ROOT), "with", ", ".join(sorted(data)))

main()
