#!/usr/bin/env python3
"""The trusted setup session's side of Jarvis 2 (docs/DESIGN.md "Target design", docs/API.md "Setup"), through the
router's /setup/* (Access service token jarvis2-setup + a signature by the setup key on every call; the router checks
both, and relays to the kernel's parts: secrets and the spawner). Values never print.

  JARVIS2_SETUP_KEY               the setup key (PEM, P-256); or ~/.jarvis2/setup-key.pem
  JARVIS2_SETUP_ACCESS_ID/SECRET  the Access service token for /setup; or ~/.jarvis2/cloudflare.env
  HETZNER_S3_*                    the backup bucket (jarvis2-backup-de0ch)

  infra/setup.py status                the router's health: secret names present, session image, which kernel parts
                                       answer, whether it holds the root grant
  infra/setup.py identity              whether secrets is empty or set up (and with which master public key), its
                                       identity checked against keys/box.pub and its state against its own signature
  infra/setup.py kernel                every kernel part's identity (role, signing key), each checked against keys/box.pub,
                                       and the roster file they should match (k8s/apps-next/kernel/roster.json)
  infra/setup.py phone-key             the phone's signing key from secrets' signed state (for the roster's `phone`)
  infra/setup.py stores [--keys]       every store (secrets' signed list) with the key NAMES it holds (--keys: each
                                       key's explanation and writer)
  infra/setup.py create NAME           a new, empty, NOT sensitive store (once per name)
  infra/setup.py write NAME KEY[=SRC]… [--explain KEY=TEXT]…
                                       write these keys of a store, one by one (the store's other keys are never read
                                       or touched); each value from this session's env var KEY, or SRC: another env var
                                       name, or file:PATH. Each is sealed three ways: to the store key P + K (phone +
                                       secrets), to the master key for its backup, and to secrets' agreement key K
                                       (`live`: served on the next pull), and signed by the setup key (writer `setup`,
                                       over secrets.WriterText). The router backs it up first (keys/<store>/<key>.json),
                                       then writes it into secrets and sends `pull` to the running machines whose grant
                                       names the store. A key name that has no explanation yet needs --explain
  infra/setup.py delete NAME KEY…      delete these keys of a store (the backup keeps their earlier versions)
  infra/setup.py versions NAME         the store's earlier versions secrets keeps (number, time, what made it, key
                                       names), from secrets' signed list; put one back with `request restore`
  infra/setup.py docs NAME [--about TEXT] [KEY=TEXT…]
                                       what a store and its keys are for (shown in the app, the web page, `jarvis2 stores
                                       --keys`); KEY= with no text removes one
  infra/setup.py mark-sensitive NAME   the one-way upgrade, in secrets and in the backup
  infra/setup.py backup NAME KEY[=SRC]… [--not-sensitive]
                                       a store's backup only, for the next Recover; sensitive unless
                                       --not-sensitive
  infra/setup.py fly-token FILE        the spawner's Fly token, FLY_API_TOKEN from FILE (infra/fly-token.sh), sealed to the
                                       spawner's agreement key (from its box-signed identity). The spawner keeps it in
                                       memory only: send it again after every spawner restart
  infra/setup.py claude-login          the Claude login the router holds (no secrets): account, expiry, refresh
                                       state, participants of the refresh protocol
  infra/setup.py repos                 the router's repo list (repo, store, key fingerprint)
  infra/setup.py sessions              the router's sessions: id, current machine, state, title
  infra/setup.py lease take-over|hand-back DEVICE [--note TEXT]
                                       for Deyao: take a shared device over (agents refused) or hand it back
  infra/setup.py pause SESSION         cancel its wakeups and crons, then pause it (a kill into a fresh source)
  infra/setup.py resume SESSION        resume a paused session with no change (a spawn from its source, no phone)
  infra/setup.py restart SESSION       pause + resume as the app's Restart; wakeups and crons stay armed
  infra/setup.py requests              what waits in the phone's Inbox (requests and approvals)
  infra/setup.py jarvis1               Jarvis 1's paused sessions (its index) and each one's import state here
  infra/setup.py jarvis1 prepare ID… [--wait]
                                       the router hashes each paused Jarvis 1 session's files (in the background)
  infra/setup.py jarvis1 import ID [ID…] --stores a,b [--size S] [--prompt-file F] --why TEXT [--summary TEXT]
                                       a prepared one as a new Jarvis 2 session, waiting in the Inbox for Face ID
                                       (docs/API.md "Jarvis 1 import"); several IDs (or --summary) file them as ONE batch
  infra/setup.py request add-repo OWNER/NAME --why TEXT [--sensitive]
  infra/setup.py request remove-repo OWNER/NAME --why TEXT
  infra/setup.py request unlock SESSION --why TEXT
  infra/setup.py request restore STORE VERSION --why TEXT
  infra/setup.py request terminal SESSION [--minutes N] --why TEXT
  infra/setup.py request command SESSION --cmd-file FILE --why TEXT
  infra/setup.py request add-store SESSION STORE --why TEXT
                                       a request in the Inbox of the Jarvis 2 app (docs/API.md "Requests"): Deyao
                                       reviews what would be signed and allows it with Face ID, or denies it. The
                                       router records it as from "Claude (setup session)"; --why is required
  infra/setup.py request batch (--file FILE | --item INTENT,key=value,…) --summary TEXT
                                       several requests as ONE Inbox entry (allowed together under one Face ID, or
                                       denied together): FILE is a JSON list of items, each {"intent": …} plus that
                                       intent's fields (repo/add, repo/remove, unlock, terminal, command, add-store,
                                       new-session, jarvis1-import; docs/API.md "Batches"), each with an optional
                                       "explanation"
  infra/setup.py pin-master            pin the master key secrets was set up with (only after Deyao's own Recover)

Everything is sealed to the master public key secrets was set up with (Reset or Recover in the app), which this
script reads from secrets' signed state, after checking secrets' identity against keys/box.pub — so it works only once
secrets is set up. A store secrets never created (no `create` first) is sensitive.
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
ROSTER = os.path.join(ROOT, "k8s", "apps-next", "kernel", "roster.json")
# the kernel's parts by the roster's role names (core/kernel/README.md)
PARTS = ("notary", "notarizer", "mover", "merger", "identity", "gullible", "spawner", "secrets")

# ---- P-256 point addition (P + K; the cryptography library has no point add) ------------------------------------
_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff


def _pt(b64):
    raw = base64.b64decode(b64)
    if len(raw) != 65 or raw[0] != 4:
        raise SystemExit("not an uncompressed P-256 point")
    return int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")


def _add(P, Q):
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        raise SystemExit("P == ±K: refusing")
    l = (y2 - y1) * pow(x2 - x1, -1, _p) % _p
    x3 = (l * l - x1 - x2) % _p
    return x3, (l * (x1 - x3) - y1) % _p


def _b64pt(x, y):
    return base64.b64encode(b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")).decode()


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


def opened(pub_b64, doc, kind):
    """a kernel document {payload, sig}: its payload, only when pub_b64 signed it and it is of this kind"""
    if not isinstance(doc, dict) or not _verify(pub_b64, (doc.get("payload") or "").encode(), doc.get("sig") or ""):
        raise SystemExit(f"a {kind} document isn't signed by the part's key")
    p = json.loads(doc["payload"])
    if p.get("kind") != kind:
        raise SystemExit(f"expected a {kind} document, got {p.get('kind')!r}")
    return p


# ---- the router -------------------------------------------------------------------------------------------

class Refused(SystemExit):
    """an HTTP error from the router or a part (status in .code, the words in .msg)"""

    def __init__(self, path, code, msg):
        super().__init__(f"{path}: HTTP {code}: {msg}")
        self.status, self.msg = code, str(msg)


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
            msg = json.loads(d["payload"]).get("error") if "payload" in d else d.get("error", d)
        except Exception:
            msg = b[:200]
        raise Refused(path, e.code, msg)


def keyfile(name):
    """keys/<name> from this checkout (JARVIS2_KEYS_DIR: another directory, for CI's stand-in keys)"""
    return open(os.path.join(os.environ.get("JARVIS2_KEYS_DIR") or os.path.join(ROOT, "keys"), name)).read().strip()


def identity_text(role, signing, agreement):
    """kernel.IdentityText: what the box key signs for a part"""
    return f"jarvis2-{role}-identity {signing} {agreement}"


def checked_identity(role, k):
    """a part's /identity answer, only when it is that role's and the box key (keys/box.pub) signed it"""
    if not k or k.get("role") != role:
        raise SystemExit(f"no {role} identity (got {k and k.get('role')!r})")
    if not _verify(keyfile("box.pub"), identity_text(role, k["signingKey"], k.get("agreementKey") or "").encode(), k.get("boxSig") or ""):
        raise SystemExit(f"the {role}'s identity isn't signed by this box's key (keys/box.pub)")
    return k


def part_identities():
    """every kernel part's /identity, as the router relays them (GET /setup/kernel/identities: {role: identity|null}),
    each checked against the box key; a part that doesn't answer is None"""
    try:
        ids = call("GET", "/setup/kernel/identities")
    except Refused as e:
        if e.status == 404:
            raise SystemExit("the router has no GET /setup/kernel/identities (the setup mirror of GET /api/kernel/identities): "
                             "it is needed for the spawner's agreement key and the roster check")
        raise
    return {role: (checked_identity(role, ids.get(role)) if ids.get(role) else None) for role in PARTS}


def identity():
    """secrets' keys (checked against the box key) and its own signed state: {signingKey, agreementKey, master: the master
    public key it was claimed with ("" while empty), phone: its keys or None, storeKey: P + K (None while empty)}"""
    k = checked_identity("secrets", call("GET", "/setup/identity"))
    try:
        t = call("GET", "/setup/store-keys")  # {state, storeKey, agreementKey}: only once secrets is set up
    except Refused as e:
        if e.status == 400 and "isn't set up" in e.msg:
            return {"signingKey": k["signingKey"], "agreementKey": k["agreementKey"], "master": "", "phone": None, "storeKey": None}
        raise
    st = opened(k["signingKey"], t.get("state"), "secrets-state")
    if t.get("agreementKey") != k["agreementKey"]:
        raise SystemExit("the router named another agreement key than secrets' box-signed identity")
    phone = st.get("phone")
    sk = None
    if st.get("master") and phone:
        d = opened(k["signingKey"], t.get("storeKey"), "store-key")
        if d.get("phone") != phone["agreementKey"]:
            raise SystemExit("secrets' store key is for another phone")
        if _b64pt(*_add(_pt(phone["agreementKey"]), _pt(k["agreementKey"]))) != d.get("storeKey"):
            raise SystemExit("secrets' store key isn't P + K for its phone and its agreement key")
        sk = d["storeKey"]
    return {"signingKey": k["signingKey"], "agreementKey": k["agreementKey"], "master": st.get("master") or "",
            "phone": phone, "storeKey": sk}


def set_up():
    """secrets, only once it is set up (Reset or Recover in the app) by Deyao: the master key and the phone it names.
    Claim is first-come, so secrets' word isn't enough (R1 audit): its master key must be the one pinned in the
    bucket, or its claim must be countersigned by Deyao's pinned device key (a Reset in his app)."""
    me = identity()
    if not me["master"] or not me["phone"]:
        raise SystemExit("secrets is empty: Deyao sets it up in the app first (Reset or Recover)")
    trust(me)
    return me


# ---- whose secrets it is: the pins (pins.json in the bucket, signed by the setup key) ----------------------------
#
# master: the master public key the stores belong to; device: the app's long-lived device key (kept across Reset and
# Recover). A claim under the pinned master pins the device key it carries; a claim countersigned by the pinned device
# key moves the master pin (Deyao's Reset). Anything else — secrets someone else claimed first — gets nothing from here.

def load_pins():
    try:
        o = s3().get_object(Bucket=BUCKET, Key="pins.json")["Body"].read()
    except Exception as e:
        if "NoSuchKey" in str(e) or "404" in str(e):
            return {}
        raise
    d = json.loads(o)
    if not _verify(keyfile("setup.pub"), d["doc"].encode(), d["sig"]):
        raise SystemExit("pins.json in the bucket isn't signed by the setup key")
    p = json.loads(d["doc"])
    if p.get("kind") != "setup-pins":
        raise SystemExit("pins.json isn't the setup pins")
    return p


def save_pins(master, device):
    doc = json.dumps({"kind": "setup-pins", "master": master, "device": device, "at": int(time.time())})
    s3().put_object(Bucket=BUCKET, Key="pins.json", Body=json.dumps(signed(doc)).encode())


def claim_of(me):
    """the claim statement the router kept for the running secrets (checked: signed by its master key, naming this
    secrets — the statement's `core` field — and its phone), the device key it names (the app's long-lived key, inside
    the master-signed statement) and whether the router kept that device's countersignature over exactly this statement"""
    cc = call("GET", "/setup/secrets-cert")
    st_text = cc.get("statement") or ""
    if not _verify(me["master"], st_text.encode(), cc.get("masterSig") or ""):
        raise SystemExit("secrets' claim isn't signed by its master key")
    st = json.loads(st_text)
    if st.get("master") != me["master"] or st.get("core", {}).get("signingKey") != me["signingKey"] or \
            st.get("core", {}).get("agreementKey") != me["agreementKey"] or st.get("phone") != me["phone"]:
        raise SystemExit("secrets' claim names another master, secrets or phone")
    device = st.get("device") or ""
    countersigned = bool(device) and any(
        d.get("statement") == st_text and d.get("deviceKey") == device and _verify(device, st_text.encode(), d.get("deviceSig") or "")
        for d in call("GET", "/setup/claim-device"))
    return device, countersigned


def trust(me):
    pins = load_pins()
    if not pins.get("master"):
        raise SystemExit("no master key pinned yet: once secrets is known to be Deyao's (a Recover by him), "
                         "run `infra/setup.py pin-master` (docs/RUNBOOK.md)")
    device, countersigned = claim_of(me)
    if pins["master"] == me["master"]:
        if device and device != pins.get("device"):  # his app's device key, named in a claim his master key signed
            save_pins(me["master"], device)
        return
    if pins.get("device") and device == pins["device"] and countersigned:
        save_pins(me["master"], device)  # Deyao's Reset: a new master, countersigned by his device
        print(f"note: new master key {me['master'][:16]}… pinned (its claim is countersigned by the pinned device key)", file=sys.stderr)
        return
    raise SystemExit("REFUSED: secrets is set up with a master key that isn't the pinned one, and its claim isn't "
                     "countersigned by Deyao's device key. Someone other than Deyao's app may have claimed it: nothing "
                     "is written, backed up or sent. Empty secrets from git (RUNBOOK \"Emptying secrets\") and set it up in the app.")


# ---- stores ---------------------------------------------------------------------------------------------

def writer_text(store, key, e, data, backup_sha):
    """secrets.WriterText: what a setup writer signs"""
    sum_ = hashlib.sha256(data.encode()).hexdigest() if data else ""
    return f"jarvis2-store-key\n{store}\n{key}\n{e}\n{sum_}\n{backup_sha}"


def live_info(store, key):
    """secrets.LiveInfo: what a write's live copy is sealed under (to secrets' agreement key)"""
    return f"jarvis2/live-key\n{store}\n{key}"


def key_write(store, key, value, me, explanation=""):
    """the router's keyWriteIn for one key (value None = a delete): the value under a fresh data key (AAD store\\nkey),
    the data key wrapped to the store key P + K, the value sealed to the master key for its backup (AAD store\\nkey) and
    to secrets' agreement key (`live`), and the setup key's signature over WriterText"""
    req = {"delete": value is None, "explanation": explanation}
    e = data = bsha = ""
    if value is not None:
        aad = f"{store}\n{key}".encode()
        dk = os.urandom(32)
        w = seal_to(me["storeKey"], dk, "jarvis2/store-data-key")
        e = w["e"]
        data = base64.b64encode(_gcm(dk, value.encode(), aad)).decode()
        b = seal_to(me["master"], value.encode(), "jarvis2/backup", aad)
        bsha = hashlib.sha256((b["e"] + "\n" + b["data"]).encode()).hexdigest()
        req.update({"wrapped": {"e": e, "wrapped": w["data"]}, "data": data, "backup": b, "backupSha256": bsha,
                    "live": seal_to(me["agreementKey"], value.encode(), live_info(store, key))})
    text = writer_text(store, key, e, data, bsha)
    req["writerText"] = text
    req["sig"] = base64.b64encode(setup_key().sign(text.encode(), ec.ECDSA(hashes.SHA256()))).decode()
    return req


# the stores this writer means to be NOT sensitive (created first); every other store it writes is sensitive. The
# open create_store lets anyone (the router) create a name first, so the writer checks secrets' word against this
# list and marks a store sensitive before it writes into it (R1 audit). A change here is a visible commit.
NOT_SENSITIVE = ("default", "openrouter", "claude", "tunnel", "shopping") + tuple(
    n for n in os.environ.get("JARVIS2_NOT_SENSITIVE", "").split(",") if n)  # test boxes add their own (rehearsals)


def s3():
    import boto3
    return boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                        aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])


def seal_to(pub_b64, plain, info, aad=None):
    """{e, data}: sealed to a P-256 public key — ECDH with a one-off key, HKDF-SHA256 (info), AES-256-GCM
    (nonce‖ciphertext‖tag), as kernel.SealTo"""
    to = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(pub_b64))
    e = ec.generate_private_key(ec.SECP256R1())
    return {"e": base64.b64encode(_x963(e.public_key())).decode(),
            "data": base64.b64encode(_gcm(_kdf(e.exchange(ec.ECDH(), to), info), plain, aad)).decode()}


def signed(doc):
    """{doc, sig}: the document text and the setup key's signature over it"""
    return {"doc": doc, "sig": base64.b64encode(setup_key().sign(doc.encode(), ec.ECDSA(hashes.SHA256()))).decode()}


def backup(name, values, sensitive, master, at=None):
    """stores/<name>.json in the versioned bucket: the values sealed to the master key (info "jarvis2/backup",
    the store's name as associated data), signed by the setup key"""
    sealed = seal_to(master, json.dumps(values).encode(), "jarvis2/backup", name.encode())
    doc = json.dumps({"kind": "store-backup", "name": name, "sensitive": sensitive, "sealed": sealed,
                      "at": int(time.time()) if at is None else at})
    s3().put_object(Bucket=BUCKET, Key=f"stores/{name}.json", Body=json.dumps(signed(doc)).encode())


def mark_sensitive_backup(name):
    """sensitive/<name>.json: a signed marker; at a Recover a store with one is sensitive whatever its backup says"""
    doc = json.dumps({"kind": "store-sensitive", "name": name, "at": int(time.time())})
    s3().put_object(Bucket=BUCKET, Key=f"sensitive/{name}.json", Body=json.dumps(signed(doc)).encode())


def store_list(me):
    """secrets' signed store list (checked against its key), by name"""
    nonce = "setup-" + os.urandom(8).hex()
    d = opened(me["signingKey"], call("POST", "/setup/stores", {"nonce": nonce}), "stores")
    if d.get("nonce") != nonce:
        raise SystemExit("secrets' store list answers another nonce")
    return {s["name"]: s for s in d["stores"]}


def value(spec):
    key, _, src = spec.partition("=")
    src = src or key
    if src.startswith("file:"):
        return key, open(os.path.expanduser(src[5:])).read().strip()
    if src not in os.environ:
        raise SystemExit(f"not in this session's env: {src}")
    return key, os.environ[src]


def roster_check(ids):
    """the parts' answering keys against the committed roster (k8s/apps-next/kernel/roster.json); lines to print"""
    out = []
    try:
        roster = json.load(open(ROSTER))
    except FileNotFoundError:
        return [f"no roster file at {os.path.relpath(ROSTER, ROOT)}"]
    for role in PARTS:
        k = ids.get(role)
        have = k["signingKey"] if k else ""
        want = roster.get(role) or ""
        out.append(f"{role}: " + ("not answering" if not k else "matches the roster" if have == want else
                                  f"DIFFERS from the roster ({want[:16] or 'empty'}… vs {have[:16]}…)"))
    for role in ("phone", "root"):
        out.append(f"{role}: " + ("set in the roster" if roster.get(role) else "EMPTY in the roster"))
    return out


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "status":
        print(json.dumps(call("GET", "/setup/status"), indent=1))
    elif cmd == "identity":
        me = identity()
        print(f"set up with master key {me['master'][:16]}…" if me["master"] else "empty: waiting for Reset or Recover in the app")
    elif cmd == "kernel":
        ids = part_identities()
        for role in PARTS:
            k = ids[role]
            print(f"{role}: " + (f"{k['signingKey'][:24]}… (box-signed)" if k else "not answering"))
        print("\n".join(roster_check(ids)))
    elif cmd == "phone-key":
        me = identity()
        if not me["phone"]:
            raise SystemExit("secrets is empty: no phone yet")
        print(me["phone"]["signingKey"])
    elif cmd == "stores":
        for s in call("GET", "/setup/stores/keys")["stores"]:
            flags = ["sensitive" if s["sensitive"] else "not-sensitive"] + (["empty"] if s["empty"] else []) + (["unlocked"] if s["unlocked"] else [])
            print(f"{s['name']} [{', '.join(flags)}]: {' '.join(s.get('keys') or [])}")
            if "--keys" in args:
                if s.get("about"):
                    print("  " + s["about"])
                for k in s.get("keyInfo") or []:
                    w = k.get("writer") or {}
                    by = f" [written by session {w.get('sessionLabel')} {w.get('session')}]" if w.get("by") == "machine" else ""
                    print(f"  {k['name']}: {k.get('explanation') or '(no explanation yet)'}{by}")
    elif cmd == "docs":
        about, rest = None, args[1:]
        if "--about" in rest:
            i = rest.index("--about")
            about, rest = rest[i + 1], rest[:i] + rest[i + 2:]
        body = {"store": args[0], "keys": dict(a.split("=", 1) for a in rest)}
        if about is not None:
            body["about"] = about
        call("POST", "/setup/store-docs", body)
        print(f"ok: {args[0]}: {len(body['keys'])} explanation(s)" + (" and its about text" if about is not None else "") + " kept")
    elif cmd == "delete":
        me = set_up()
        for k in args[1:]:
            out = call("POST", f"/setup/stores/{args[0]}/keys/{k}", key_write(args[0], k, None, me))
            print(f"ok: {args[0]}: {k} deleted; pull sent to {len(out.get('pulled') or [])} running session(s)")
    elif cmd == "pin-master":
        me = identity()
        if not me["master"]:
            raise SystemExit("secrets is empty")
        device, _ = claim_of(me)
        save_pins(me["master"], device or load_pins().get("device"))
        print(f"ok: master key {me['master'][:16]}… pinned" + (" with the app's device key" if device else ""))
    elif cmd == "create":
        if args[0] not in NOT_SENSITIVE:
            raise SystemExit(f"{args[0]} isn't in NOT_SENSITIVE (infra/setup.py): a store not listed there stays sensitive")
        me = set_up()
        call("POST", "/setup/stores/create", {"name": args[0]})
        # the backup says so too: a store with only key backups reads as sensitive offline and at a Recover (secrets
        # makes a store sensitive on its first key unless it was created like this). Empty, and a second early, so a key
        # written in the same second still lays over it (tools/decrypt-backup.py skips key backups not after it)
        backup(args[0], {}, False, me["master"], at=int(time.time()) - 1)
        print(f"ok: store {args[0]} created (empty, not sensitive) and its not-sensitive backup written")
    elif cmd == "write":
        explain = {}
        while "--explain" in args:
            i = args.index("--explain")
            k, _, t = args[i + 1].partition("=")
            explain[k] = t
            del args[i:i + 2]
        if "--replace" in args:
            raise SystemExit("--replace means nothing: secrets writes keys one by one and never drops one; "
                             "remove a key with `infra/setup.py delete`")
        name, vals = args[0], dict(value(a) for a in args[1:])
        me = set_up()
        want_sensitive = name not in NOT_SENSITIVE
        have = store_list(me).get(name)
        if want_sensitive and have is not None and not have["sensitive"]:
            # created not sensitive by someone else (the open create_store): upgraded before anything is in it
            call("POST", "/setup/stores/mark-sensitive", {"name": name})
            mark_sensitive_backup(name)
            print(f"note: {name} existed as not sensitive; marked sensitive before writing", file=sys.stderr)
        for k in sorted(vals):
            out = call("POST", f"/setup/stores/{name}/keys/{k}", key_write(name, k, vals[k], me, explain.get(k, "")))
            print(f"ok: {name}: {k} written (backed up first); pull sent to {len(out.get('pulled') or [])} running session(s)")
        if want_sensitive and not store_list(me)[name]["sensitive"]:
            raise SystemExit(f"secrets calls {name} not sensitive after the write")
    elif cmd == "versions":
        me = identity()
        nonce = "setup-" + os.urandom(8).hex()
        v = opened(me["signingKey"], call("POST", "/setup/stores/versions", {"store": args[0], "nonce": nonce}), "store-versions")
        if v.get("nonce") != nonce or v.get("store") != args[0]:
            raise SystemExit("secrets' versions answer another store or nonce")
        for x in v["versions"]:
            c = x["cause"]
            what = c["kind"] + (f" {c['key']}" if c.get("key") else "") + (f" by {c['writer']['by']}" if c.get("writer") else "") + \
                (f" of version {c['from']}" if c.get("from") else "")
            cur = " (current)" if x["version"] == v["current"] else ""
            print(f"{x['seq']}{cur} {x['at']} {what}: {len(x['keys'])} keys: {' '.join(k['name'] for k in x['keys'])}")
    elif cmd == "mark-sensitive":
        set_up()
        call("POST", "/setup/stores/mark-sensitive", {"name": args[0]})
        mark_sensitive_backup(args[0])
        print(f"ok: {args[0]} is sensitive, in secrets and in the backup")
    elif cmd == "backup":
        plain = "--not-sensitive" in args
        args = [a for a in args if a != "--not-sensitive"]
        backup(args[0], dict(value(a) for a in args[1:]), not plain, set_up()["master"])
        print(f"ok: backup of {args[0]} written (sensitive={not plain}); it comes in at the next Recover")
    elif cmd == "fly-token":
        sp = part_identities()["spawner"]
        if not sp or not sp.get("agreementKey"):
            raise SystemExit("the spawner isn't answering (or has no agreement key)")
        tok = {"FLY_API_TOKEN": open(os.path.expanduser(args[0])).read().strip()}
        out = call("POST", "/setup/fly-token", {"sealed": seal_to(sp["agreementKey"], json.dumps(tok).encode(), "jarvis2/fly-token")})
        opened(sp["signingKey"], out, "fly-token-set")
        print("ok: the spawner has its Fly token (sealed to its agreement key, confirmed by its signature)")
    elif cmd == "claude-login":
        print(json.dumps(call("GET", "/setup/claude-login"), indent=1))
    elif cmd == "repos":
        for r in call("GET", "/setup/repos")["repos"]:
            print(r["repo"], r["store"], r.get("fingerprint") or "no key yet", "sensitive" if r.get("sensitive") else "")
    elif cmd == "sessions":
        for s in call("GET", "/setup/sessions")["sessions"]:
            print(s["id"], s["machineId"] or "-", s["state"], s["title"])
            if "-v" in args:  # the autopilot's view: status, background jobs, stall clock, last nudge
                print("   ", json.dumps({k: v for k, v in s.items() if k not in ("id", "machineId", "state", "title")}, sort_keys=True))
    elif cmd == "lease":
        if len(args) < 2 or args[0] not in ("take-over", "hand-back"):
            raise SystemExit(__doc__)
        act, dev = args[0], args[1]
        note = opt(args, "--note")
        print(json.dumps(call("POST", f"/setup/leases/{dev}/{act}", {"note": note} if note is not None else {}), indent=1))
    elif cmd in ("pause", "resume", "restart"):
        print(json.dumps(call("POST", "/setup/sessions/" + args[0] + "/" + cmd, {})))
    elif cmd == "requests":
        out = call("GET", "/setup/requests")
        for q in out["requests"]:
            c = q.get("call") or {}
            print(q["id"], q["kind"], json.dumps(q.get("params") or {}, sort_keys=True), "from", q["callerText"], "·", c.get("method", ""), c.get("path", ""),
                  ("· batch " + q["batch"]) if q.get("batch") else "")
        for b in out.get("batches") or []:
            print(b["id"], "batch of", len(b["items"]), f"(+{b['preparing']} preparing)" if b.get("preparing") else "", "from", b["callerText"], "|", b["summary"])
    elif cmd == "request":
        print(json.dumps(file_request(args), indent=1))
    elif cmd == "jarvis1":
        jarvis1(args)
    else:
        raise SystemExit(__doc__)


def parse_item(spec):
    """--item INTENT,key=value,…: one batch item (numbers become numbers, true/false booleans, a|b lists)"""
    parts = spec.split(",")
    item = {"intent": parts[0]}
    for kv in parts[1:]:
        if "=" not in kv:
            raise SystemExit(f"--item {spec}: {kv!r} is not key=value")
        k, v = kv.split("=", 1)
        item[k] = int(v) if v.isdigit() else {"true": True, "false": False}.get(v, v.split("|") if "|" in v else v)
    return item


def opt(args, name, default=None):
    """--name VALUE out of args (args is changed)"""
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args):
            raise SystemExit(f"{name} needs a value")
        v = args[i + 1]
        del args[i:i + 2]
        return v
    return default


def file_request(args):
    """infra/setup.py request KIND …: an Inbox request, signed with the setup key (the router names the caller)"""
    args = list(args)
    if args[:1] == ["batch"]:
        rest = args[1:]
        f, summary = opt(rest, "--file"), opt(rest, "--summary")
        inline = []
        while "--item" in rest:
            inline.append(parse_item(opt(rest, "--item")))
        if (not f and not inline) or not summary or rest:
            raise SystemExit("request batch (--file FILE | --item INTENT,key=value,…) --summary TEXT")
        items = json.load(open(os.path.expanduser(f))) if f else inline
        if not isinstance(items, list):
            raise SystemExit("FILE must hold a JSON list of items")
        return call("POST", "/setup/requests/batch", {"summary": summary, "items": items})
    why = opt(args, "--why")
    sensitive = "--sensitive" in args
    args = [a for a in args if a != "--sensitive"]
    minutes, cmd_file = opt(args, "--minutes"), opt(args, "--cmd-file")
    if not args or not why:
        raise SystemExit("request KIND … --why TEXT (see infra/setup.py without arguments)")
    kind, rest = args[0], args[1:]
    if kind in ("add-repo", "remove-repo") and len(rest) == 1:
        body = {"repo": rest[0], "explanation": why}
        if kind == "add-repo" and sensitive:
            body["sensitive"] = True
        return call("POST", "/setup/requests/repo/" + ("add" if kind == "add-repo" else "remove"), body)
    if kind == "restore" and len(rest) == 2 and rest[1].isdigit():
        return call("POST", "/setup/requests/restore", {"store": rest[0], "seq": int(rest[1]), "explanation": why})
    if kind == "unlock" and len(rest) == 1:
        return call("POST", "/setup/requests/unlock", {"session": rest[0], "explanation": why})
    if kind == "terminal" and len(rest) == 1:
        body = {"session": rest[0], "explanation": why}
        if minutes:
            body["minutes"] = int(minutes)
        return call("POST", "/setup/requests/terminal", body)
    if kind == "command" and len(rest) == 1 and cmd_file:
        return call("POST", "/setup/requests/command", {"session": rest[0], "cmd": open(os.path.expanduser(cmd_file)).read(), "explanation": why})
    if kind == "add-store" and len(rest) == 2:
        return call("POST", "/setup/requests/add-store", {"session": rest[0], "store": rest[1], "explanation": why})
    raise SystemExit(f"unknown request: {' '.join(args)} (see infra/setup.py without arguments)")


def jarvis1(args):
    """infra/setup.py jarvis1 [prepare ID… [--wait] | status ID | import ID --stores … --why …]"""
    args = list(args)
    if not args:
        for s in call("GET", "/setup/jarvis1/paused")["sessions"]:
            prep = (s.get("prepare") or {}).get("state") or ("ready" if s.get("sha256") else "-")
            made = ",".join(f"{x['id']}:{x['state']}" for x in s.get("sessions") or []) or "-"
            print(s["id"], prep, (s.get("sha256") or "")[:12] or "-", made, s.get("size"), "|", s.get("title"))
        return
    sub = args.pop(0)
    if sub == "prepare":
        wait = "--wait" in args
        ids = [a for a in args if a != "--wait"]
        for i in ids:
            call("POST", f"/setup/jarvis1/paused/{i}/prepare", {})
        while wait:
            states = {i: call("GET", f"/setup/jarvis1/paused/{i}") for i in ids}
            busy = [i for i, v in states.items() if (v.get("prepare") or {}).get("state") == "preparing"]
            for i, v in states.items():
                p = v.get("prepare") or {}
                print(i, p.get("state"), f"{p.get('bytesDone', 0) / 1e9:.2f}/{p.get('bytesTotal', 0) / 1e9:.2f} GB", p.get("file") or "",
                      (v.get("sha256") or "")[:12], p.get("error") or "")
            if not busy:
                break
            print("--")
            time.sleep(10)
    elif sub == "status" and len(args) == 1:
        print(json.dumps(call("GET", f"/setup/jarvis1/paused/{args[0]}"), indent=1))
    elif sub == "import" and args:
        why, stores, size, pf = opt(args, "--why"), opt(args, "--stores"), opt(args, "--size"), opt(args, "--prompt-file")
        summary = opt(args, "--summary")
        ids = args
        if not why or not stores or not ids:
            raise SystemExit("jarvis1 import ID [ID…] --stores a,b [--size S] [--prompt-file F] --why TEXT [--summary TEXT]")
        body = {"stores": [x for x in stores.split(",") if x], "explanation": why}
        if size:
            body["size"] = size
        if pf:
            body["prompt"] = open(os.path.expanduser(pf)).read()
        if len(ids) == 1 and not summary:
            print(json.dumps(call("POST", f"/setup/jarvis1/paused/{ids[0]}/import", body), indent=1))
            return
        # several: one batch (docs/API.md "Batches"), every import checked before any is filed
        if not summary:
            raise SystemExit("several imports are one batch: --summary TEXT says what the batch is for")
        items = [dict(body, intent="jarvis1-import", id=i) for i in ids]
        print(json.dumps(call("POST", "/setup/requests/batch", {"summary": summary, "items": items}), indent=1))
    else:
        raise SystemExit(jarvis1.__doc__)


if __name__ == "__main__":
    main()
