#!/usr/bin/env python3
"""The trusted setup session's side of Jarvis 2 (docs/DESIGN.md, docs/API.md "Setup"), through the router's
/setup/* (Access service token jarvis2-setup + a signature by the setup key on every call; the router checks
both). Values never print.

  JARVIS2_SETUP_KEY               the setup key (PEM, P-256); or ~/.jarvis2/setup-key.pem
  JARVIS2_SETUP_ACCESS_ID/SECRET  the Access service token for /setup; or ~/.jarvis2/cloudflare.env
  HETZNER_S3_*                    the backup bucket (jarvis2-backup-de0ch)

  infra/setup.py status                the router's health: secret names present, session image, core up
  infra/setup.py identity              whether the core is empty or set up (and with which master public key),
                                       checked against keys/box.pub and the core's own signature
  infra/setup.py stores                the core's signed store list
  infra/setup.py create NAME           a new, empty, NOT sensitive store (once per name)
  infra/setup.py write NAME KEY[=SRC]… new contents for a store; each value from this session's env var KEY,
                                       or SRC: another env var name, or file:PATH. Written to the core wrapped
                                       to the phone + core key, and backed up to S3 (encrypted to the master key
                                       the core was set up with)
  infra/setup.py mark-sensitive NAME   the one-way upgrade, in the core and in the backup
  infra/setup.py backup NAME KEY[=SRC]… [--not-sensitive]
                                       a store's backup only, for the next Recover; sensitive unless
                                       --not-sensitive
  infra/setup.py backup-core FILE      the core's Fly token, FLY_API_TOKEN from FILE (infra/fly-token.sh):
                                       sent to the core sealed to its key, and backed up as the `core` store

Everything is sealed to the master public key the core was set up with (Reset or Recover in the app), which
this script reads from the core's signed state, after checking the core's keys against keys/box.pub — so it
works only once the core is set up. A store the core never created (no `create` first) is sensitive.
"""
import base64, hashlib, json, os, sys, time, urllib.error, urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE = os.environ.get("JARVIS2_URL", "https://jarvis2.deyaochen.com")
D = os.path.expanduser("~/.jarvis2")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUCKET = os.environ.get("JARVIS2_BACKUP_BUCKET", "jarvis2-backup-de0ch")

# ---- P-256 point addition (the combined key P + K; the cryptography library has no point add) ----------
_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff


def _pt(b64):
    raw = base64.b64decode(b64)
    assert len(raw) == 65 and raw[0] == 4
    return int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")


def _add(P, Q):
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        raise SystemExit("P == ±K: refusing")
    l = (y2 - y1) * pow(x2 - x1, -1, _p) % _p
    x3 = (l * l - x1 - x2) % _p
    return x3, (l * (x1 - x3) - y1) % _p


def _pub(x, y):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"))


def _kdf(secret, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(secret)


def _gcm(key, plain, aad=None):
    n = os.urandom(12)
    return n + AESGCM(key).encrypt(n, plain, aad)


def _x963(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _verify(pub_b64, payload, sig_b64):
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---- the router -------------------------------------------------------------------------------------------

def setup_key():
    pem = os.environ.get("JARVIS2_SETUP_KEY") or open(os.path.join(D, "setup-key.pem")).read()
    return serialization.load_pem_private_key(pem.encode(), None)


def access():
    i, s = os.environ.get("JARVIS2_SETUP_ACCESS_ID"), os.environ.get("JARVIS2_SETUP_ACCESS_SECRET")
    if not (i and s):
        v = dict(l.rstrip("\n").split("=", 1) for l in open(os.path.join(D, "cloudflare.env")) if "=" in l)
        i, s = v["SETUP_ACCESS_ID"], v["SETUP_ACCESS_SECRET"]
    return {"CF-Access-Client-Id": i, "CF-Access-Client-Secret": s}


def call(method, path, body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    t = str(int(time.time()))
    msg = f"{method} {path} {t} {hashlib.sha256(raw).hexdigest()}".encode()
    h = dict(access(), **{"Content-Type": "application/json", "User-Agent": "jarvis2-setup/1", "X-Setup-Time": t,
                          "X-Setup-Sig": base64.b64encode(setup_key().sign(msg, ec.ECDSA(hashes.SHA256()))).decode()})
    req = urllib.request.Request(BASE + path, method=method, data=raw if body is not None else None, headers=h)
    try:
        return json.load(urllib.request.urlopen(req, timeout=60))
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            d = json.loads(b)
            msg = json.loads(d["payload"]).get("error") if "payload" in d else d
        except Exception:
            msg = b[:200]
        raise SystemExit(f"{path}: HTTP {e.code}: {msg}")


def keyfile(name):
    """keys/<name> from this checkout (JARVIS2_KEYS_DIR: another directory, for CI's stand-in keys)"""
    return open(os.path.join(os.environ.get("JARVIS2_KEYS_DIR") or os.path.join(ROOT, "keys"), name)).read().strip()


def identity():
    """the core's keys (checked against the box key, keys/box.pub) and its own signed state: {signingKey,
    agreementKey, master: the master public key it was set up with ("" while empty), phone: its keys or None}"""
    k = call("GET", "/setup/identity")
    text = f"jarvis2-core-identity {k['signingKey']} {k['agreementKey']}".encode()
    if not _verify(keyfile("box.pub"), text, k.get("boxSig", "")):
        raise SystemExit("the core's identity isn't signed by this box's key (keys/box.pub)")
    d = k.get("state") or {}
    if not _verify(k["signingKey"], (d.get("payload") or "").encode(), d.get("sig") or ""):
        raise SystemExit("the core's state isn't signed by the core")
    st = json.loads(d["payload"])
    if st.get("kind") != "core-state":
        raise SystemExit("not the core's state")
    return {"signingKey": k["signingKey"], "agreementKey": k["agreementKey"], "master": st.get("master") or "", "phone": st.get("phone")}


def set_up():
    """the core, only once it is set up (Reset or Recover in the app): the master key and the phone it names"""
    me = identity()
    if not me["master"] or not me["phone"]:
        raise SystemExit("the core is empty: Deyao sets it up in the app first (Reset or Recover)")
    return me


# ---- stores ---------------------------------------------------------------------------------------------

def blob(name, values, phone_agreement, core_agreement):
    """core.StoreBlob: the values under a data key (the name as associated data), the key wrapped to P + K"""
    dk = os.urandom(32)
    combined = _pub(*_add(_pt(phone_agreement), _pt(core_agreement)))
    e = ec.generate_private_key(ec.SECP256R1())
    shared_x = e.exchange(ec.ECDH(), combined)
    wrapped = _gcm(_kdf(shared_x, "jarvis2/store-data-key"), dk)
    return {"name": name, "wrapped": {"e": base64.b64encode(_x963(e.public_key())).decode(), "wrapped": base64.b64encode(wrapped).decode()},
            "data": base64.b64encode(_gcm(dk, json.dumps(values).encode(), name.encode())).decode()}


def s3():
    import boto3
    return boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                        aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])


def seal_to(pub_b64, plain, info, aad=None):
    """{e, data}: sealed to a P-256 public key — ECDH with a one-off key, HKDF-SHA256 (info), AES-256-GCM"""
    to = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(pub_b64))
    e = ec.generate_private_key(ec.SECP256R1())
    return {"e": base64.b64encode(_x963(e.public_key())).decode(),
            "data": base64.b64encode(_gcm(_kdf(e.exchange(ec.ECDH(), to), info), plain, aad)).decode()}


def signed(doc):
    """{doc, sig}: the document text and the setup key's signature over it"""
    return {"doc": doc, "sig": base64.b64encode(setup_key().sign(doc.encode(), ec.ECDSA(hashes.SHA256()))).decode()}


def backup(name, values, sensitive, master):
    """stores/<name>.json in the versioned bucket: the values sealed to the master key (info "jarvis2/backup",
    the store's name as associated data), signed by the setup key"""
    sealed = seal_to(master, json.dumps(values).encode(), "jarvis2/backup", name.encode())
    doc = json.dumps({"kind": "store-backup", "name": name, "sensitive": sensitive, "sealed": sealed, "at": int(time.time())})
    s3().put_object(Bucket=BUCKET, Key=f"stores/{name}.json", Body=json.dumps(signed(doc)).encode())


def mark_sensitive_backup(name):
    """sensitive/<name>.json: a signed marker; at a Recover a store with one is sensitive whatever its backup says"""
    doc = json.dumps({"kind": "store-sensitive", "name": name, "at": int(time.time())})
    s3().put_object(Bucket=BUCKET, Key=f"sensitive/{name}.json", Body=json.dumps(signed(doc)).encode())


def store_list():
    d = call("POST", "/setup/stores", {"nonce": "setup-" + str(int(time.time()))})
    return {s["name"]: s for s in json.loads(d["payload"])["stores"]}


def value(spec):
    key, _, src = spec.partition("=")
    src = src or key
    if src.startswith("file:"):
        return key, open(os.path.expanduser(src[5:])).read().strip()
    if src not in os.environ:
        raise SystemExit(f"not in this session's env: {src}")
    return key, os.environ[src]


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "status":
        print(json.dumps(call("GET", "/setup/status"), indent=1))
    elif cmd == "identity":
        me = identity()
        print(f"set up with master key {me['master'][:16]}…" if me["master"] else "empty: waiting for Reset or Recover in the app")
    elif cmd == "stores":
        for n, s in sorted(store_list().items()):
            print(n, "sensitive" if s["sensitive"] else "not-sensitive", "empty" if s["empty"] else "", "unlocked" if s["unlocked"] else "")
    elif cmd == "create":
        call("POST", "/setup/stores/create", {"name": args[0]})
        print(f"ok: store {args[0]} created (empty, not sensitive)")
    elif cmd == "write":
        name, vals = args[0], dict(value(a) for a in args[1:])
        me = set_up()
        b = blob(name, vals, me["phone"]["agreementKey"], me["agreementKey"])
        d = call("POST", "/setup/stores/write", {"store": b})
        sens = json.loads(d["payload"])["sensitive"]
        backup(name, vals, sens, me["master"])
        print(f"ok: store {name} written with {len(vals)} keys (sensitive={sens}), backed up")
    elif cmd == "mark-sensitive":
        set_up()
        call("POST", "/setup/stores/mark-sensitive", {"name": args[0]})
        mark_sensitive_backup(args[0])
        print(f"ok: {args[0]} is sensitive, in the core and in the backup")
    elif cmd == "backup":
        plain = "--not-sensitive" in args
        args = [a for a in args if a != "--not-sensitive"]
        backup(args[0], dict(value(a) for a in args[1:]), not plain, set_up()["master"])
        print(f"ok: backup of {args[0]} written (sensitive={not plain}); it comes in at the next Recover")
    elif cmd == "backup-core":
        me = set_up()
        tok = {"FLY_API_TOKEN": open(os.path.expanduser(args[0])).read().strip()}
        call("POST", "/setup/fly-token", {"sealed": seal_to(me["agreementKey"], json.dumps(tok).encode(), "jarvis2/fly-token")})
        backup("core", tok, True, me["master"])
        print("ok: the core has its Fly token, and the core store's backup is written")
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
