#!/usr/bin/env python3
"""kernel-keys.py — the kernel parts' private keys (one P-256 PKCS#8 key each, KEY_FILE of core/cmd/*) and their public
roster (ROSTER_FILE: k8s/apps-next/kernel/roster.json, after the switchover k8s/apps/kernel/roster.json).

    infra/kernel-keys.py new [--rotate] [PART…]
        a fresh key for each PART (default: all eight), each into its own Secret kernel-key-<part> in jarvis2-core,
        SOPS-encrypted to the box's age key (keys/box-age.pub) at k8s/secrets/kernel-key-<part>.enc.yaml (Flux decrypts
        it on the box; only that part's pod mounts it), and its public key into the roster. A part that already has a
        key is refused unless --rotate: a new key changes the roster, and every running session's guard checks the
        kernel's documents against the roster it booted with (so rotate only with no session running).
    infra/kernel-keys.py [--roster FILE] set-phone KEY | set-root KEY | from-claim
        the phone's signing key and the root key into the roster (base64 of the 65-byte uncompressed P-256 point): both
        are in the claim the app's master key signed, `infra/setup.py claim-keys`; from-claim reads that command's JSON
        ({"phone", "root"}) on stdin and sets both. --roster: another roster file (CI's stand-in)
    infra/kernel-keys.py check
        every roster entry is a P-256 point (what the guard requires of JARVIS2_ROSTER)
    infra/kernel-keys.py manifest OUT [--phone KEY] [--root KEY]
        a throwaway box's keys (rehearsals, the phone replica): the eight Secrets in PLAIN into OUT (a k8s List, mode
        0600, for the box's user-data, never git) and the roster beside it (OUT.roster.json); the repo is not touched.
        Without --phone/--root, a throwaway phone and root key are made too: their PEMs go to OUT.phone.pem and
        OUT.root.pem (0600) for the test's app side

Needs `sops` (new). Prints names and public keys only, never a private key; nothing private touches disk except the
encrypted files (new) or OUT (manifest).
"""
import base64, json, os, subprocess, sys, tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# core/cmd/<dir> → the roster's role name (core/kernel/README.md)
PARTS = {"notary": "notary", "notarizer": "notarizer", "mover": "mover", "merger": "merger",
         "identity-signer": "identity", "gullible-signer": "gullible", "spawner": "spawner", "secrets": "secrets"}
ORDER = ["notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "secrets", "phone", "root"]
NS = "jarvis2-core"


ROSTER_OVERRIDE = None


def roster_path():
    if ROSTER_OVERRIDE:
        return ROSTER_OVERRIDE
    for d in ("k8s/apps/kernel", "k8s/apps-next/kernel"):
        p = os.path.join(ROOT, d, "roster.json")
        if os.path.exists(p):
            return p
    sys.exit("no roster.json in k8s/apps/kernel or k8s/apps-next/kernel")


def load_roster(p=None):
    return json.load(open(p or roster_path()))


def save_roster(r, p=None):
    open(p or roster_path(), "w").write(json.dumps({k: r.get(k, "") for k in ORDER}, indent=2) + "\n")


def pub_b64(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()


def pem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def is_point(b64):
    try:
        raw = base64.b64decode(b64, validate=True)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        return len(raw) == 65 and raw[0] == 4
    except Exception:
        return False


def secret(d, key_pem):
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": f"kernel-key-{d}", "namespace": NS}, "stringData": {"key.pem": key_pem}}


def sops_write(doc, out):
    recipient = open(os.path.join(ROOT, "keys/box-age.pub")).read().strip()
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


def add_to_secrets_kustomization(fname):
    kz = os.path.join(ROOT, "k8s/secrets/kustomization.yaml")
    s = open(kz).read()
    if "  - " + fname not in s:
        open(kz, "w").write(s.rstrip("\n") + "\n  - " + fname + "\n")


def main():
    global ROSTER_OVERRIDE
    a = sys.argv[1:]
    if a[:1] == ["--roster"] and len(a) >= 2:
        ROSTER_OVERRIDE, a = a[1], a[2:]
    if not a:
        sys.exit(__doc__)
    cmd, a = a[0], a[1:]
    if cmd == "new":
        rotate = "--rotate" in a
        want = [x for x in a if x != "--rotate"] or list(PARTS)
        bad = [x for x in want if x not in PARTS]
        if bad:
            sys.exit(f"unknown part(s): {', '.join(bad)} (one of {', '.join(PARTS)})")
        r = load_roster()
        for d in want:
            out = os.path.join(ROOT, "k8s/secrets", f"kernel-key-{d}.enc.yaml")
            if (os.path.exists(out) or r.get(PARTS[d])) and not rotate:
                sys.exit(f"{d} has a key already (k8s/secrets/kernel-key-{d}.enc.yaml or the roster): --rotate replaces it")
        for d in want:
            k = ec.generate_private_key(ec.SECP256R1())
            fname = f"kernel-key-{d}.enc.yaml"
            sops_write(secret(d, pem(k)), os.path.join(ROOT, "k8s/secrets", fname))
            add_to_secrets_kustomization(fname)
            r[PARTS[d]] = pub_b64(k)
            del k
            print(f"{d}: k8s/secrets/{fname} written; roster {PARTS[d]} = {r[PARTS[d]][:24]}…")
        save_roster(r)
        print(f"ok: {os.path.relpath(roster_path(), ROOT)} updated; commit both (the restart of the parts that read the "
              "roster is in docs/RUNBOOK.md \"Kernel operations\")")
    elif cmd in ("set-phone", "set-root") and len(a) == 1:
        if not is_point(a[0]):
            sys.exit("not a base64 uncompressed P-256 point")
        r = load_roster()
        r[cmd[4:]] = a[0]
        save_roster(r)
        print(f"ok: roster {cmd[4:]} = {a[0][:24]}…")
    elif cmd == "from-claim" and not a:
        try:
            c = json.load(sys.stdin)
        except ValueError:
            sys.exit("from-claim: stdin isn't infra/setup.py claim-keys' JSON")
        bad = [k for k in ("phone", "root") if not is_point(c.get(k) or "")]
        if bad:
            sys.exit(f"from-claim: no {' or '.join(bad)} key in the claim (an app older than the root key names none)")
        r = load_roster()
        changed = [k for k in ("phone", "root") if r.get(k) != c[k]]
        r["phone"], r["root"] = c["phone"], c["root"]
        save_roster(r)
        print(f"ok: roster phone = {c['phone'][:24]}…, root = {c['root'][:24]}…" + ("" if changed else " (unchanged)"))
    elif cmd == "check":
        r = load_roster()
        bad = [k for k in ORDER if not is_point(r.get(k, ""))]
        extra = sorted(set(r) - set(ORDER))
        if bad or extra:
            sys.exit(f"roster incomplete: {', '.join(bad) or '-'} not keys; unknown fields: {', '.join(extra) or '-'}")
        print("ok: the roster names a key for every part, the phone and root")
    elif cmd == "manifest" and a:
        out, rest = a[0], a[1:]
        phone = root = None
        if "--phone" in rest:
            phone = rest[rest.index("--phone") + 1]
        if "--root" in rest:
            root = rest[rest.index("--root") + 1]
        old = os.umask(0o077)
        try:
            r, items = {}, []
            for d, role in PARTS.items():
                k = ec.generate_private_key(ec.SECP256R1())
                items.append(secret(d, pem(k)))
                r[role] = pub_b64(k)
            for name, given in (("phone", phone), ("root", root)):
                if given:
                    if not is_point(given):
                        sys.exit(f"--{name}: not a base64 uncompressed P-256 point")
                    r[name] = given
                else:
                    k = ec.generate_private_key(ec.SECP256R1())
                    open(f"{out}.{name}.pem", "w").write(pem(k))
                    r[name] = pub_b64(k)
            json.dump({"apiVersion": "v1", "kind": "List", "items": items}, open(out, "w"))
            save_roster(r, f"{out}.roster.json")
        finally:
            os.umask(old)
        print(f"ok: {len(items)} kernel keys in {out}, the roster in {out}.roster.json")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
