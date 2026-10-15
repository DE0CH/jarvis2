#!/usr/bin/env python3
"""router-secrets.py — write the router's non-sensitive secrets into git, SOPS-encrypted to the box's age key
(keys/box-age.pub); Flux decrypts them on the box (k8s/flux/sync.yaml, Kustomization jarvis2-secrets).

    infra/router-secrets.py [--box control|services] [--part backup|github|flyorgs|flypersonal|browserbase|devices|search|icloud-index|icloud-session|alloy|move] KEY[=SRC] …

--box picks the box (docs/DESIGN.md "The boxes"): its age key (keys/<box>-age.pub), its secrets directory
(k8s/<box>/secrets/) and its manifests (k8s/<box>/apps/<app>/). Without --box: the old single box (keys/box-age.pub,
k8s/secrets/, k8s/apps/), until it is retired. Each box gets only its own parts:
  control   (default), backup, github, flyorgs, flypersonal, browserbase, devices, alloy, move
  services  search, icloud-index, icloud-session, alloy
  --part alloy   Secret alloy in jarvis2-obs — GRAFANA_LOGS_URL/USER, GRAFANA_METRICS_URL/USER, GRAFANA_WRITE_TOKEN: the
                 host's Grafana Alloy reads it (infra/alloy/; no pod uses it, so no manifest annotation)
  --part move    Secret router-move in jarvis2-router — MOVE_KEY: the shared key of the cross-box router move
                 (router/move.go); the old box's router gets the same value (without --box)

SRC is `env:VAR` (default `env:KEY`) or `file:PATH`. A part is one Secret, rewritten whole each run, so name
every key of that part (nobody can read the old values back: only the box holds the age key):
  (default)      k8s/secrets/router.enc.yaml, Secret router-secrets — LOBSTER_TOKEN, Storage Box, tokens…
  --part backup  k8s/secrets/router-backup.enc.yaml, Secret router-secrets-backup — the backup bucket's read
                 credential (BACKUP_READ_ACCESS_KEY, BACKUP_READ_SECRET_KEY), set once per box / credential
  --part github  k8s/secrets/router-github.enc.yaml, Secret router-secrets-github — GITHUB_READ_TOKEN only (the
                 repo picker's list token), so it can be replaced without rewriting the default part. It is the
                 LAST envFrom in router.yaml, so it wins over the stale GITHUB_READ_TOKEN still in the default part
  --part flyorgs k8s/secrets/router-flyorgs.enc.yaml, Secret router-secrets-flyorgs — FLY_ORG_READ_TOKENS only:
                 {"<org slug>": "<read-only org token>"} for the Machines view's other orgs (router/flyorgs.go)
  --part flypersonal  k8s/secrets/router-flypersonal.enc.yaml — FLY_PERSONAL_READ_TOKEN only: org personal's read-only
                 token for the Machines view (infra/fly-personal-read-token.sh; router/flyorgs.go)
  --part browserbase  k8s/secrets/router-browserbase.enc.yaml — BROWSERBASE_API_KEY only (router/bbbudget.go: the
                 spend DM reads the session list)
  --part devices k8s/secrets/router-devices.enc.yaml — CF_DEVICE_TOKENS_API only: the Cloudflare token "jarvis2-device-tokens"
                 (Access: Service Tokens read/write, nothing else) that mints and deletes the paired apps' tokens (router/devices.go)
  --part search  k8s/secrets/search.enc.yaml, Secret search-secrets in jarvis2-edge — STORAGEBOX_HOST/USER/PASSWORD
                 and OPENROUTER_API for transcript search (k8s/apps/search.yaml)
  --part icloud-index    k8s/secrets/icloud-index.enc.yaml, Secret icloud-index-secrets in jarvis2-edge — OPENROUTER_API,
                 LOBSTER_TOKEN, STORAGEBOX_HOST/USER/PASSWORD for the iCloud index (k8s/apps/icloud-index.yaml)
  --part icloud-session  k8s/secrets/icloud-session.enc.yaml, Secret icloud-index-session — ICLOUD_RCLONE_CONF only (the
                 saved iCloud login, mounted as a file; write it again after a re-login, e.g.
                 ICLOUD_RCLONE_CONF=file:~/.config/rclone/rclone.conf)
Only for secrets that can't reach a code push (Deyao, 2026-10-09); the router's pod gets them as env
(k8s/apps/router.yaml envFrom). Prints names only, never a value."""
import hashlib, json, os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOXES = {  # box → (age recipient file, secrets dir, {part: manifest path under k8s/<box>/apps/})
    "": ("keys/box-age.pub", "k8s/secrets", None),
    "control": ("keys/control-age.pub", "k8s/control/secrets", {
        "": "router/router.yaml", "backup": "router/router.yaml", "github": "router/router.yaml",
        "flyorgs": "router/router.yaml", "flypersonal": "router/router.yaml", "browserbase": "router/router.yaml",
        "devices": "router/router.yaml", "move": "router/router.yaml", "alloy": None}),
    "services": ("keys/services-age.pub", "k8s/services/secrets", {
        "search": "search/search.yaml", "icloud-index": "icloud-index/icloud-index.yaml",
        "icloud-session": "icloud-index/icloud-index.yaml", "alloy": None}),
}
PARTS = {  # part → (file, Secret name, annotation, namespace, manifest carrying the annotation)
    "": ("router.enc.yaml", "router-secrets", "jarvis2/secrets-rev", "jarvis2-router", "router.yaml"),
    "backup": ("router-backup.enc.yaml", "router-secrets-backup", "jarvis2/secrets-rev-backup", "jarvis2-router", "router.yaml"),
    "github": ("router-github.enc.yaml", "router-secrets-github", "jarvis2/secrets-rev-github", "jarvis2-router", "router.yaml"),
    "flyorgs": ("router-flyorgs.enc.yaml", "router-secrets-flyorgs", "jarvis2/secrets-rev-flyorgs", "jarvis2-router", "router.yaml"),
    "flypersonal": ("router-flypersonal.enc.yaml", "router-secrets-flypersonal", "jarvis2/secrets-rev-flypersonal", "jarvis2-router", "router.yaml"),
    "browserbase": ("router-browserbase.enc.yaml", "router-secrets-browserbase", "jarvis2/secrets-rev-browserbase", "jarvis2-router", "router.yaml"),
    "devices": ("router-devices.enc.yaml", "router-secrets-devices", "jarvis2/secrets-rev-devices", "jarvis2-router", "router.yaml"),
    "search": ("search.enc.yaml", "search-secrets", "jarvis2/secrets-rev-search", "jarvis2-edge", "search.yaml"),
    "icloud-index": ("icloud-index.enc.yaml", "icloud-index-secrets", "jarvis2/secrets-rev-icloud-index", "jarvis2-edge", "icloud-index.yaml"),
    "icloud-session": ("icloud-session.enc.yaml", "icloud-index-session", "jarvis2/secrets-rev-icloud-session", "jarvis2-edge", "icloud-index.yaml"),
    "alloy": ("alloy.enc.yaml", "alloy", None, "jarvis2-obs", None),
    "move": ("router-move.enc.yaml", "router-move", "jarvis2/secrets-rev-move", "jarvis2-router", "router.yaml"),
}


def main():
    args = sys.argv[1:]
    box, part = "", ""
    if args[:1] == ["--box"]:
        box, args = args[1], args[2:]
    if args[:1] == ["--part"]:
        part, args = args[1], args[2:]
    if not args or part not in PARTS or box not in BOXES:
        sys.exit(__doc__)
    keyfile, secdir, manifests = BOXES[box]
    fname, secret, annotation, namespace, manifest = PARTS[part]
    if manifests is not None:
        if part not in manifests:
            sys.exit(f"part {part or '(default)'} doesn't belong on the {box} box")
        manifest = manifests[part] and os.path.join("k8s", box, "apps", manifests[part])
        if box == "services":
            namespace = {"jarvis2-edge": "jarvis2-services"}.get(namespace, namespace)
    else:
        manifest = manifest and os.path.join("k8s/apps", manifest)
    out = os.path.join(ROOT, secdir, fname)
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
    recipient = open(os.path.join(ROOT, keyfile)).read().strip()
    doc = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret, "namespace": namespace},
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
    kz = os.path.join(ROOT, secdir, "kustomization.yaml")
    s = open(kz).read()
    if "  - " + fname not in s:
        s = s.replace("resources: []", "resources:")
        open(kz, "w").write(s.rstrip("\n") + "\n  - " + fname + "\n")
    rev = hashlib.sha256(enc).hexdigest()[:12]
    if not annotation or not manifest:
        print("wrote", os.path.relpath(out, ROOT), "with", ", ".join(sorted(data)))
        return
    rp = os.path.join(ROOT, manifest)
    y = open(rp).read()  # read before opening for write: open(rp, "w") first would empty it
    if annotation + ': "' not in y:
        sys.exit(f"{rp}: no {annotation} annotation")
    open(rp, "w").write(re.sub(re.escape(annotation) + r': "[^"]*"', f'{annotation}: "{rev}"', y))
    print("wrote", os.path.relpath(out, ROOT), "with", ", ".join(sorted(data)), ";", annotation, rev)


main()
