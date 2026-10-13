#!/usr/bin/env python3
"""decrypt-backup — open an offline copy of Jarvis 2's store backups with the master key from the recovery kit.

Runs fully offline (Python 3.9+ and the `cryptography` package; nothing else, no network):

  decrypt-backup.py FILE [--kit-file KIT | -] [--setup-pub keys/setup.pub] [--out PATH] [--stdout] [--force] [--skip-bad]

FILE is what the Jarvis 2 app's Settings → Encrypted backup → "Download encrypted backup" saves
(`jarvis2-backup-<date>.json`, format "jarvis2-backup-export" version 1: the objects exactly as `GET /api/backups`
served them, the bucket, the fetch time and the setup public key the app checked them with). Also taken: the router's
raw `GET /api/backups` answer ({bucket, objects}), and a single `stores/<name>.json` object ({doc, sig}) as stored in
the bucket (e.g. an older version fetched from the versioned bucket). Those carry no setup key: pass --setup-pub.

The kit (`jarvis2-kit:2:<master private key>`; a version-1 kit's master part works too) is read from --kit-file, from
stdin with `--kit-file -`, or asked for without echo when stdin is a terminal. Never pass it as an argument: it would
end up in the shell history.

Every object's signature is checked against the setup key in the file AND, when given, --setup-pub (the two must be the
same key); every store is decrypted (ECDH with the master key, HKDF-SHA256 info "jarvis2/backup", AES-256-GCM with the
store's name as associated data). Any problem stops it before anything is written, unless --skip-bad (the bad objects
are then left out and listed). The plaintext goes to --out (default ./jarvis2-stores-<date>.json), created with mode
0600 and never over an existing file unless --force; an --out ending in "/" (or an existing directory) gets one
<store>.json per store in a 0700 directory. Values are printed only with --stdout.

Output file: {"format": "jarvis2-stores", "version": 1, "source", "bucket", "fetchedAt", "setupKey",
              "stores": {name: {"sensitive", "at", "values": {KEY: value}}}}
Exit codes: 0 done, 1 a check or decryption failed, 2 bad usage or input.
"""
import argparse, base64, datetime, getpass, json, os, sys

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # pragma: no cover
    sys.exit("needs the `cryptography` package: python3 -m pip install cryptography (docs/RUNBOOK.md \"Offline copy of the stores\")")

EXPORT_FORMAT, EXPORT_VERSIONS = "jarvis2-backup-export", (1,)
BACKUP_INFO = b"jarvis2/backup"


class Bad(Exception):
    """a check that failed (exit 1)"""


class Usage(Exception):
    """bad input or arguments (exit 2)"""


# ---- keys --------------------------------------------------------------------------------------------------

def parse_kit(raw):
    """the master private key from the recovery kit text (whitespace ignored). Version 2 = jarvis2-kit:2:<base64 PKCS#8
    DER>; version 1 = jarvis2-kit:1:<base64 PKCS#8 DER>:<bucket keys> (only its master part is used); a PEM private
    key is also taken (the public TEST key in e2e/testdata)."""
    text = raw.strip()
    if "-----BEGIN" in text:
        try:
            k = serialization.load_pem_private_key(text.encode(), None)
        except Exception:
            raise Usage("that PEM isn't a private key")
        return check_p256(k), "PEM"
    s = "".join(text.split())
    if s.startswith("jarvis2-kit:2:"):
        body, version = s[len("jarvis2-kit:2:"):], 2
    elif s.startswith("jarvis2-kit:1:"):
        body, version = s[len("jarvis2-kit:1:"):].split(":")[0], 1
    elif s.startswith("jarvis2-kit:"):
        raise Usage("an unknown recovery kit version: " + s[:14])
    else:
        raise Usage("that isn't a recovery kit (it starts with jarvis2-kit:2:)")
    try:
        k = serialization.load_der_private_key(base64.b64decode(body, validate=True), None)
    except Exception:
        raise Usage("the recovery kit's master key doesn't parse")
    return check_p256(k), f"kit version {version}"


def check_p256(k):
    if not isinstance(k, ec.EllipticCurvePrivateKey) or k.curve.name != "secp256r1":
        raise Usage("the master key isn't a P-256 private key")
    return k


def public_b64(k):
    return base64.b64encode(k.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()


def load_pub(b64, what):
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode("".join(b64.split()), validate=True))
    except Exception:
        raise Usage(f"{what} isn't a P-256 public key (base64 X9.63)")


def valid(pub, payload, sig_b64):
    try:
        pub.verify(base64.b64decode(sig_b64, validate=True), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def open_sealed(sealed, master, aad):
    """{e, data}: ECDH(master, e) → HKDF-SHA256 (no salt, info "jarvis2/backup") → AES-256-GCM nonce‖ciphertext‖tag"""
    try:
        e = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(sealed["e"], validate=True))
        data = base64.b64decode(sealed["data"], validate=True)
    except Exception:
        raise Bad("the sealed value is malformed")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=BACKUP_INFO).derive(master.exchange(ec.ECDH(), e))
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], aad)
    except InvalidTag:
        raise Bad("doesn't open with this recovery kit")


# ---- the file ----------------------------------------------------------------------------------------------

def load_input(path):
    """→ (objects [{key, body}], meta {bucket, fetchedAt, setupKey})"""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError) as e:
        raise Usage(f"can't read {path}: {e}")
    if not isinstance(d, dict):
        raise Usage(f"{path} isn't a backup file")
    if d.get("format") == EXPORT_FORMAT:
        if d.get("version") not in EXPORT_VERSIONS:
            raise Usage(f"{path} is a newer export (version {d.get('version')}); this script reads {list(EXPORT_VERSIONS)}")
        meta = {k: d.get(k) for k in ("bucket", "fetchedAt", "setupKey")}
        objs = d.get("objects")
    elif "objects" in d:  # the router's raw GET /api/backups answer
        meta, objs = {"bucket": d.get("bucket"), "fetchedAt": None, "setupKey": None}, d["objects"]
    elif "doc" in d and "sig" in d:  # one object as stored in the bucket
        try:
            name = json.loads(d["doc"])["name"]
            kind = json.loads(d["doc"])["kind"]
        except Exception:
            raise Usage(f"{path} isn't a signed backup object")
        prefix = {"store-backup": "stores/", "store-sensitive": "sensitive/"}.get(kind)
        if not prefix:
            raise Usage(f"{path} is a {kind!r} document, not a store backup")
        with open(path, encoding="utf-8") as f:
            body = f.read()
        meta, objs = {"bucket": None, "fetchedAt": None, "setupKey": None}, [{"key": f"{prefix}{name}.json", "body": body}]
    else:
        raise Usage(f"{path} isn't a Jarvis 2 backup export")
    if not isinstance(objs, list) or not all(isinstance(o, dict) and isinstance(o.get("key"), str) and isinstance(o.get("body"), str) for o in objs):
        raise Usage(f"{path}: objects must be a list of {{key, body}}")
    return objs, meta


def name_of(key, prefix):
    if key.startswith(prefix) and key.endswith(".json") and len(key) > len(prefix) + 5:
        return key[len(prefix):-5]
    return None


def check_and_open(objs, setup_keys, master):
    """the same checks as the app's Recover (ios/Jarvis2/Security/CoreSetup.swift readBackups), per object.
    → (stores {name: {sensitive, at, values}}, problems [(key, why)])"""
    problems, docs = [], []
    for o in objs:
        key = o["key"]
        try:
            s = json.loads(o["body"])
            doc_text, sig = s["doc"], s["sig"]
            if not isinstance(doc_text, str) or not isinstance(sig, str):
                raise ValueError
        except Exception:
            problems.append((key, "isn't a signed document"))
            continue
        bad = [label for label, pub in setup_keys if not valid(pub, doc_text.encode(), sig)]
        if bad:
            problems.append((key, "isn't signed by " + " / ".join(bad)))
            continue
        try:
            docs.append((key, json.loads(doc_text)))
        except ValueError:
            problems.append((key, "isn't JSON inside"))
    marked = set()
    for key, d in docs:
        n = name_of(key, "sensitive/")
        if n is None:
            continue
        if d.get("kind") != "store-sensitive" or d.get("name") != n:
            problems.append((key, "names another store"))
        else:
            marked.add(n)
    stores = {}
    for key, d in docs:
        n = name_of(key, "stores/")
        if n is None:
            if name_of(key, "sensitive/") is None:
                problems.append((key, "isn't under stores/ or sensitive/"))
            continue
        if n in stores:
            problems.append((key, "comes twice"))
            continue
        if d.get("kind") != "store-backup" or d.get("name") != n or not isinstance(d.get("sealed"), dict):
            problems.append((key, "names another store"))
            continue
        try:
            plain = open_sealed(d["sealed"], master, n.encode())
        except Bad as e:
            problems.append((key, str(e)))
            continue
        try:
            values = json.loads(plain)
            if not isinstance(values, dict) or not all(isinstance(v, str) for v in values.values()):
                raise ValueError
        except ValueError:
            problems.append((key, "holds something that isn't a store"))
            continue
        stores[n] = {"sensitive": bool(d.get("sensitive")) or n in marked, "at": d.get("at"), "values": values}
    return stores, problems


# ---- output ------------------------------------------------------------------------------------------------

def write_private(path, data, force):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    if force and os.path.lexists(path):
        os.unlink(path)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise Usage(f"{path} exists: pass --force to replace it")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    os.chmod(path, 0o600)


def default_out(meta):
    at = meta.get("fetchedAt") or ""
    day = at[:10] if len(at) >= 10 else datetime.date.today().isoformat()
    return f"jarvis2-stores-{day}.json"


def main(argv=None):
    os.umask(0o077)
    p = argparse.ArgumentParser(prog="decrypt-backup", description="Open an offline copy of Jarvis 2's store backups "
                                "with the recovery kit (offline; docs/RUNBOOK.md \"Offline copy of the stores\").")
    p.add_argument("file", help="the app's jarvis2-backup-<date>.json (or a raw /api/backups answer, or one stores/<name>.json)")
    p.add_argument("--kit-file", metavar="KIT", help="a file holding the recovery kit; - = stdin (default: asked for, no echo)")
    p.add_argument("--setup-pub", metavar="PATH", help="keys/setup.pub from a clone of DE0CH/jarvis2: must be the file's setup key too")
    p.add_argument("--out", metavar="PATH", help="where the plaintext goes (default ./jarvis2-stores-<date>.json; a path ending in / = one file per store)")
    p.add_argument("--stdout", action="store_true", help="print the plaintext stores (JSON) to stdout instead of writing a file")
    p.add_argument("--force", action="store_true", help="replace an existing output file")
    p.add_argument("--skip-bad", action="store_true", help="leave out objects that fail a check instead of stopping")
    a = p.parse_args(argv)
    try:
        objs, meta = load_input(a.file)
        setup_keys = []
        if meta.get("setupKey"):
            setup_keys.append(("the file's setup key", load_pub(meta["setupKey"], "the file's setupKey")))
        if a.setup_pub:
            try:
                given = read_text(a.setup_pub)
            except OSError as e:
                raise Usage(f"can't read {a.setup_pub}: {e}")
            gk = load_pub(given, a.setup_pub)
            if setup_keys and public_bytes(gk) != public_bytes(setup_keys[0][1]):
                raise Bad(f"the file's setup key isn't {a.setup_pub}: the file was checked against another key")
            setup_keys.append((a.setup_pub, gk))
        if not setup_keys:
            raise Usage("this file names no setup key: pass --setup-pub keys/setup.pub")
        if a.kit_file and a.kit_file != "-":
            try:
                kit = read_text(a.kit_file)
            except OSError as e:
                raise Usage(f"can't read {a.kit_file}: {e}")
        elif a.kit_file == "-" or not sys.stdin.isatty():
            kit = sys.stdin.read()
        else:
            kit = getpass.getpass("Recovery kit (jarvis2-kit:2:…, not echoed): ")
        master, kit_kind = parse_kit(kit)
        del kit
        stores, problems = check_and_open(objs, setup_keys, master)
        log = lambda *x: print(*x, file=sys.stderr)
        log(f"{len(objs)} objects from {meta.get('bucket') or 'an unknown bucket'}"
            + (f", fetched {meta['fetchedAt']}" if meta.get("fetchedAt") else "") + f"; master key from the {kit_kind}")
        log("setup key checked: " + ", ".join(label for label, _ in setup_keys))
        for key, why in problems:
            log(f"BAD  {key}: {why}")
        if problems and not a.skip_bad:
            raise Bad(f"{len(problems)} object(s) failed; nothing written (--skip-bad leaves them out)")
        for n in sorted(stores):
            s = stores[n]
            log(f"ok   {n}: {len(s['values'])} keys{' (sensitive)' if s['sensitive'] else ''}")
        if not stores:
            raise Bad("no store in the file")
        out = {"format": "jarvis2-stores", "version": 1, "source": os.path.basename(a.file), "bucket": meta.get("bucket"),
               "fetchedAt": meta.get("fetchedAt"), "setupKey": public_b64(setup_keys[-1][1]),
               "stores": {n: stores[n] for n in sorted(stores)}}
        if a.stdout:
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0
        path = a.out or default_out(meta)
        if path.endswith("/") or os.path.isdir(path):
            os.makedirs(path, mode=0o700, exist_ok=True)
            os.chmod(path, 0o700)
            for n, s in out["stores"].items():
                write_private(os.path.join(path, n + ".json"), json.dumps(dict(s, name=n), indent=2, sort_keys=True) + "\n", a.force)
            log(f"wrote {len(stores)} files (mode 0600) in {path}")
        else:
            write_private(path, json.dumps(out, indent=2, sort_keys=True) + "\n", a.force)
            log(f"wrote {path} (mode 0600): {len(stores)} stores")
        return 0
    except Usage as e:
        print(f"decrypt-backup: {e}", file=sys.stderr)
        return 2
    except Bad as e:
        print(f"decrypt-backup: {e}", file=sys.stderr)
        return 1


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def public_bytes(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


if __name__ == "__main__":
    sys.exit(main())
