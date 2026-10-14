#!/usr/bin/env python3
"""infra/setup.py against the kernel's secrets (core/kernel/secrets): what it believes and what it sends.
- identity(): secrets' identity only when the box key signed it for the role `secrets`; its state and store key only
  when secrets signed them, and the store key only when it is P + K for that phone and secrets' agreement key.
- write: one /setup/stores/{store}/keys/{key} per key, each with `live` (sealed to secrets' agreement key under
  secrets.LiveInfo), the data key wrapped to P + K, the backup sealed to the master key (AAD store\\nkey) and the setup
  key's signature over secrets.WriterText; --replace is refused; a store meant sensitive is marked first.
- fly-token: sealed to the spawner's box-signed agreement key.
Runs offline (the router, S3 and the keys stubbed): python3 infra/setup_write_test.py"""
import base64, hashlib, importlib.util, json, os, sys, tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551  # the P-256 group order
keys = tempfile.mkdtemp()
gen = lambda: ec.generate_private_key(ec.SECP256R1())
setup_k, box_k, sec_sign, sec_agree, phone_sign, phone_agree, master, spawn_sign, spawn_agree = (gen() for _ in range(9))
pem = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
pub = lambda k: base64.b64encode(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()
sig = lambda k, t: base64.b64encode(k.sign(t.encode() if isinstance(t, str) else t, ec.ECDSA(hashes.SHA256()))).decode()
os.environ["JARVIS2_SETUP_KEY"] = pem(setup_k)
open(os.path.join(keys, "setup.pub"), "w").write(pub(setup_k))
open(os.path.join(keys, "box.pub"), "w").write(pub(box_k))
os.environ["JARVIS2_KEYS_DIR"] = keys
spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def doc(k, payload):
    t = json.dumps(payload)
    return {"payload": t, "sig": sig(k, t)}


def ident(role, s, a):
    return {"role": role, "signingKey": pub(s), "agreementKey": pub(a),
            "boxSig": sig(box_k, f"jarvis2-{role}-identity {pub(s)} {pub(a)}")}


def store_key_of(p, k):
    """P + K as the private scalar p + k: whoever holds both halves opens the store"""
    return ec.derive_private_key((p.private_numbers().private_value + k.private_numbers().private_value) % N, ec.SECP256R1())


PK = store_key_of(phone_agree, sec_agree)
world = {
    "identity": ident("secrets", sec_sign, sec_agree),
    "state": doc(sec_sign, {"kind": "secrets-state", "master": pub(master), "bundle": "keys",
                            "phone": {"signingKey": pub(phone_sign), "agreementKey": pub(phone_agree)}}),
    "storeKey": doc(sec_sign, {"kind": "store-key", "phone": pub(phone_agree), "storeKey": pub(PK)}),
    "stores": {"identity": {"name": "identity", "sensitive": True}, "default": {"name": "default", "sensitive": True}},
}
sent = []


def call(method, path, body=None):
    sent.append((method, path, body))
    if path == "/setup/identity":
        return world["identity"]
    if path == "/setup/store-keys":
        return {"state": world["state"], "storeKey": world["storeKey"], "agreementKey": world["identity"]["agreementKey"]}
    if path == "/setup/stores":
        return doc(sec_sign, {"kind": "stores", "nonce": body["nonce"], "stores": list(world["stores"].values())})
    if path == "/setup/kernel/identities":
        return {"spawner": ident("spawner", spawn_sign, spawn_agree), "secrets": world["identity"]}
    if path == "/setup/fly-token":
        return doc(spawn_sign, {"kind": "fly-token-set"})
    if path == "/setup/stores/mark-sensitive":
        world["stores"][body["name"]]["sensitive"] = True
        return {}
    return {"ok": True, "pulled": []}


S.call = call
S.trust = lambda me: None  # setup_trust_test.py covers the pins
S.mark_sensitive_backup = lambda name: None


def unseal(priv, sealed, info, aad=None):
    e = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(sealed["e"]))
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(priv.exchange(ec.ECDH(), e))
    raw = base64.b64decode(sealed["data"])
    return AESGCM(k).decrypt(raw[:12], raw[12:], aad)


def refused(fn, what):
    try:
        fn()
    except SystemExit as e:
        return str(e)
    raise AssertionError("not refused: " + what)


# ---- identity: everything checked -------------------------------------------------------------------------------
me = S.identity()
assert me["master"] == pub(master) and me["storeKey"] == pub(PK) and me["agreementKey"] == pub(sec_agree), me

good = dict(world)
world["identity"] = ident("secrets", sec_sign, sec_agree) | {"boxSig": sig(gen(), "x")}
refused(S.identity, "an identity the box key didn't sign")
world["identity"] = ident("spawner", sec_sign, sec_agree)
refused(S.identity, "another part's identity as secrets'")
world.update(good)
world["state"] = doc(gen(), json.loads(good["state"]["payload"]))
refused(S.identity, "a state secrets didn't sign")
world.update(good)
world["storeKey"] = doc(sec_sign, {"kind": "store-key", "phone": pub(phone_agree), "storeKey": pub(gen())})
assert "P + K" in refused(S.identity, "a store key that isn't P + K")
world.update(good)

# ---- write: three seals and the setup signature per key -----------------------------------------------------------
os.environ.update(A="alpha", B="beta")


def run(*args):
    sent.clear()
    sys.argv = ["setup.py", *args]
    try:
        S.main()
    except SystemExit as e:
        return str(e)
    return None


assert run("write", "identity", "A", "B=A", "--explain", "B=what B is") is None
writes = [(p, b) for m, p, b in sent if p.startswith("/setup/stores/identity/keys/")]
assert [p for p, _ in writes] == ["/setup/stores/identity/keys/A", "/setup/stores/identity/keys/B"], writes
for p, b in writes:
    key = p.rsplit("/", 1)[1]
    aad = f"identity\n{key}".encode()
    assert unseal(sec_agree, b["live"], f"jarvis2/live-key\nidentity\n{key}") == b"alpha", "live isn't sealed to secrets under LiveInfo"
    dk = unseal(PK, {"e": b["wrapped"]["e"], "data": b["wrapped"]["wrapped"]}, "jarvis2/store-data-key")
    raw = base64.b64decode(b["data"])
    assert AESGCM(dk).decrypt(raw[:12], raw[12:], aad) == b"alpha", "the data isn't under the data key wrapped to P + K"
    assert unseal(master, b["backup"], "jarvis2/backup", aad) == b"alpha", "the backup isn't sealed to the master key"
    assert b["backupSha256"] == hashlib.sha256((b["backup"]["e"] + "\n" + b["backup"]["data"]).encode()).hexdigest()
    text = f"jarvis2-store-key\nidentity\n{key}\n{b['wrapped']['e']}\n{hashlib.sha256(b['data'].encode()).hexdigest()}\n{b['backupSha256']}"
    assert b["writerText"] == text and S._verify(pub(setup_k), text.encode(), b["sig"]), "the setup signature isn't over WriterText"
assert writes[1][1]["explanation"] == "what B is" and writes[0][1]["explanation"] == ""

# a delete: no seals, still signed
assert run("delete", "identity", "A") is None
d = [b for m, p, b in sent if p == "/setup/stores/identity/keys/A"][0]
assert d["delete"] is True and "live" not in d and S._verify(pub(setup_k), "jarvis2-store-key\nidentity\nA\n\n\n".encode(), d["sig"]), d

err = run("write", "identity", "A", "--replace")
assert err and "--replace means nothing" in err, err
assert not any(p.startswith("/setup/stores/identity/keys/") for _, p, _ in sent), "a refused write reached the router"

# a store meant sensitive that someone created not sensitive: marked sensitive before any key goes in
world["stores"]["money"] = {"name": "money", "sensitive": False}
assert run("write", "money", "A") is None
paths = [p for _, p, _ in sent]
assert paths.index("/setup/stores/mark-sensitive") < paths.index("/setup/stores/money/keys/A"), paths

# ---- fly-token: sealed to the spawner's box-signed agreement key -------------------------------------------------
tok = os.path.join(keys, "fly.tok")
open(tok, "w").write("fly-secret\n")
assert run("fly-token", tok) is None
ft = [b for _, p, b in sent if p == "/setup/fly-token"][0]
assert json.loads(unseal(spawn_agree, ft["sealed"], "jarvis2/fly-token")) == {"FLY_API_TOKEN": "fly-secret"}
print("setup_write_test: ok")
