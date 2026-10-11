#!/usr/bin/env python3
"""router-secrets.py — write the router's non-sensitive secrets into git, SOPS-encrypted to the box's age key
(keys/box-age.pub); Flux decrypts them on the box (k8s/flux/sync.yaml, Kustomization jarvis2-secrets).

    infra/router-secrets.py [--part backup|github] KEY[=SRC] …

SRC is `env:VAR` (default `env:KEY`) or `file:PATH`. A part is one Secret, rewritten whole each run, so name
every key of that part (nobody can read the old values back: only the box holds the age key):
  (default)      k8s/secrets/router.enc.yaml, Secret router-secrets — LOBSTER_TOKEN, Storage Box, tokens…
  --part backup  k8s/secrets/router-backup.enc.yaml, Secret router-secrets-backup — the backup bucket's read
                 credential (BACKUP_READ_ACCESS_KEY, BACKUP_READ_SECRET_KEY), set once per box / credential
  --part github  k8s/secrets/router-github.enc.yaml, Secret router-secrets-github — GITHUB_READ_TOKEN only (the
                 repo picker's list token), so it can be replaced without rewriting the default part. It is the
                 LAST envFrom in router.yaml, so it wins over the stale GITHUB_READ_TOKEN still in the default part
Only for secrets that can't reach a code push (Deyao, 2026-10-09); the router's pod gets them as env
(k8s/apps/router.yaml envFrom). Prints names only, never a value."""
import hashlib, json, os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = {  # part → (file, Secret name, router.yaml annotation)
    "": ("router.enc.yaml", "router-secrets", "jarvis2/secrets-rev"),
    "backup": ("router-backup.enc.yaml", "router-secrets-backup", "jarvis2/secrets-rev-backup"),
    "github": ("router-github.enc.yaml", "router-secrets-github", "jarvis2/secrets-rev-github"),
}


def main():
    args = sys.argv[1:]
    part = ""
    if args[:1] == ["--part"]:
        part, args = args[1], args[2:]
    if not args or part not in PARTS:
        sys.exit(__doc__)
    fname, secret, annotation = PARTS[part]
    out = os.path.join(ROOT, "k8s/secrets", fname)
    data = {}
    for arg in args:
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
    doc = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret, "namespace": "jarvis2-router"},
           "type": "Opaque", "stringData": data}
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, dir=os.path.dirname(out)) as f:
        os.chmod(f.name, 0o600)
        json.dump(doc, f)  # JSON is YAML
        tmp = f.name
    try:
        enc = subprocess.run(["sops", "--encrypt", "--age", recipient, "--encrypted-regex", "^(data|stringData)$",
                              "--input-type", "yaml", "--output-type", "yaml", tmp], check=True, capture_output=True).stdout
    finally:
        os.remove(tmp)
    open(out, "wb").write(enc)
    kz = os.path.join(ROOT, "k8s/secrets/kustomization.yaml")
    s = open(kz).read()
    if "  - " + fname not in s:
        s = s.replace("resources: []", "resources:")
        open(kz, "w").write(s.rstrip("\n") + "\n  - " + fname + "\n")
    rev = hashlib.sha256(enc).hexdigest()[:12]
    rp = os.path.join(ROOT, "k8s/apps/router.yaml")
    y = open(rp).read()  # read before opening for write: open(rp, "w") first would empty it
    if annotation + ': "' not in y:
        sys.exit(f"{rp}: no {annotation} annotation")
    open(rp, "w").write(re.sub(re.escape(annotation) + r': "[^"]*"', f'{annotation}: "{rev}"', y))
    print("wrote", os.path.relpath(out, ROOT), "with", ", ".join(sorted(data)), ";", annotation, rev)


main()
