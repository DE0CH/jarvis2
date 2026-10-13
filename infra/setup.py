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
  infra/setup.py stores                every store (the core's signed list) with the key NAMES it holds
  infra/setup.py keys NAME KEY[=SRC]…  record a store's key names at the router only (no values needed or sent);
                                       `write` records them itself. `keys NAME --forget` drops them
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
  infra/setup.py repos                 the router's repo list (repo, store, key fingerprint)
  infra/setup.py sessions              the router's sessions: id, current machine, state, title
  infra/setup.py resume SESSION        resume a paused session unattended: same image, no prompt, no Face ID
  infra/setup.py requests              what waits in the phone's Inbox (requests and approvals)
  infra/setup.py request add-repo OWNER/NAME --why TEXT [--sensitive]
  infra/setup.py request remove-repo OWNER/NAME --why TEXT
  infra/setup.py request grant SESSION HOLDER [--minutes N | --days N] --why TEXT
  infra/setup.py request unlock SESSION --why TEXT
                                       a request in the Inbox of the Jarvis 2 app (docs/API.md "Requests"): Deyao
                                       reviews what would be signed and allows it with Face ID, or denies it. The
                                       router records it as from "Claude (setup session)"; --why is required

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
    """the core, only once it is set up (Reset or Recover in the app) by Deyao: the master key and the phone it names.
    Claim is first-come, so the core's word isn't enough (R1 audit): its master key must be the one pinned in the
    bucket, or its claim must be countersigned by Deyao's pinned device key (a Reset in his app)."""
    me = identity()
    if not me["master"] or not me["phone"]:
        raise SystemExit("the core is empty: Deyao sets it up in the app first (Reset or Recover)")
    trust(me)
    return me


# ---- whose core it is: the pins (pins.json in the bucket, signed by the setup key) ----------------------------
#
# master: the master public key the stores belong to; device: the app's long-lived device key (kept across Reset and
# Recover). A claim under the pinned master pins the device key it carries; a claim countersigned by the pinned device
# key moves the master pin (Deyao's Reset). Anything else — a core someone else claimed first — gets nothing from here.

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
    """the claim statement the core holds (checked: signed by its master key, naming this core and its phone), the
    device key it names (the app's long-lived key, inside the master-signed statement) and whether the router kept
    that device's countersignature over exactly this statement"""
    cc = call("GET", "/setup/core-cert")
    st_text = cc.get("statement") or ""
    if not _verify(me["master"], st_text.encode(), cc.get("masterSig") or ""):
        raise SystemExit("the core's claim isn't signed by its master key")
    st = json.loads(st_text)
    if st.get("master") != me["master"] or st.get("core", {}).get("signingKey") != me["signingKey"] or \
            st.get("core", {}).get("agreementKey") != me["agreementKey"] or st.get("phone") != me["phone"]:
        raise SystemExit("the core's claim names another master, core or phone")
    device = st.get("device") or ""
    countersigned = bool(device) and any(
        d.get("statement") == st_text and d.get("deviceKey") == device and _verify(device, st_text.encode(), d.get("deviceSig") or "")
        for d in call("GET", "/setup/claim-device"))
    return device, countersigned


def trust(me):
    pins = load_pins()
    if not pins.get("master"):
        raise SystemExit("no master key pinned yet: once the core is known to be Deyao's (a Recover by him), "
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
    raise SystemExit("REFUSED: the core is set up with a master key that isn't the pinned one, and its claim isn't "
                     "countersigned by Deyao's device key. Someone other than Deyao's app may have claimed it: nothing "
                     "is written, backed up or sent. Restart the core from git (RUNBOOK \"Emptying the core\") and set it up in the app.")


# the stores this writer means to be NOT sensitive (created first); every other store it writes is sensitive. The
# core's open create_store lets anyone (the router) create a name first, so the writer checks the core's word against
# this list and marks a store sensitive before it writes into it (R1 audit). A change here is a visible commit.
# ---- stores ---------------------------------------------------------------------------------------------

def blob(name, values, phone_agreement, core_agreement):
    """core.StoreBlob: the values under a data key (the name as associated data), the key wrapped to P + K, and the
    writer's signature, which the phone checks (keys/setup.pub) before it unlocks the blob (core.WriterText)"""
    dk = os.urandom(32)
    combined = _pub(*_add(_pt(phone_agreement), _pt(core_agreement)))
    e = ec.generate_private_key(ec.SECP256R1())
    shared_x = e.exchange(ec.ECDH(), combined)
    wrapped = _gcm(_kdf(shared_x, "jarvis2/store-data-key"), dk)
    E = base64.b64encode(_x963(e.public_key())).decode()
    data = base64.b64encode(_gcm(dk, json.dumps(values).encode(), name.encode())).decode()
    text = f"jarvis2-store-blob\n{name}\n{E}\n{hashlib.sha256(data.encode()).hexdigest()}".encode()
    sig = base64.b64encode(setup_key().sign(text, ec.ECDSA(hashes.SHA256()))).decode()
    return {"name": name, "wrapped": {"e": E, "wrapped": base64.b64encode(wrapped).decode()}, "data": data, "writerSig": sig}


# the stores this writer means to be NOT sensitive (created first); every other store it writes is sensitive. The
# core's open create_store lets anyone (the router) create a name first, so the writer checks the core's word against
# this list and marks a store sensitive before it writes into it (R1 audit). A change here is a visible commit.
NOT_SENSITIVE = ("default", "openrouter", "claude", "tunnel", "shopping") + tuple(
    n for n in os.environ.get("JARVIS2_NOT_SENSITIVE", "").split(",") if n)  # test boxes add their own (rehearsals)


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
        for s in call("GET", "/setup/stores/keys")["stores"]:
            flags = ["sensitive" if s["sensitive"] else "not-sensitive"] + (["empty"] if s["empty"] else []) + (["unlocked"] if s["unlocked"] else [])
            keys = " ".join(s["keys"]) if s["keys"] is not None else "(key names not recorded)"
            print(f"{s['name']} [{', '.join(flags)}]: {keys}")
    elif cmd == "keys":
        names = None if args[1:] == ["--forget"] else [a.partition("=")[0] for a in args[1:]]
        call("POST", "/setup/store-keys", {"name": args[0], "keys": names})
        print(f"ok: {args[0]}: key names forgotten" if names is None else f"ok: {args[0]}: {len(names)} key names recorded")
    elif cmd == "pin-master":
        me = identity()
        if not me["master"]:
            raise SystemExit("the core is empty")
        device, _ = claim_of(me)
        save_pins(me["master"], device or load_pins().get("device"))
        print(f"ok: master key {me['master'][:16]}… pinned" + (" with the app's device key" if device else ""))
    elif cmd == "create":
        if args[0] not in NOT_SENSITIVE:
            raise SystemExit(f"{args[0]} isn't in NOT_SENSITIVE (infra/setup.py): a store not listed there stays sensitive")
        set_up()
        call("POST", "/setup/stores/create", {"name": args[0]})
        print(f"ok: store {args[0]} created (empty, not sensitive)")
    elif cmd == "write":
        name, vals = args[0], dict(value(a) for a in args[1:])
        me = set_up()
        want_sensitive = name not in NOT_SENSITIVE
        have = store_list().get(name)
        if want_sensitive and have is not None and not have["sensitive"]:
            # created not sensitive by someone else (the open create_store): upgraded before anything is in it
            call("POST", "/setup/stores/mark-sensitive", {"name": name})
            mark_sensitive_backup(name)
            print(f"note: {name} existed as not sensitive; marked sensitive before writing", file=sys.stderr)
        b = blob(name, vals, me["phone"]["agreementKey"], me["agreementKey"])
        d = call("POST", "/setup/stores/write", {"store": b})
        sens = json.loads(d["payload"])["sensitive"]
        if want_sensitive and not sens:
            raise SystemExit(f"the core still calls {name} not sensitive after the write: no backup made")
        backup(name, vals, sens, me["master"])
        call("POST", "/setup/store-keys", {"name": name, "keys": sorted(vals)})
        print(f"ok: store {name} written with {len(vals)} keys (sensitive={sens}), backed up, key names recorded")
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
    elif cmd == "repos":
        for r in call("GET", "/setup/repos")["repos"]:
            print(r["repo"], r["store"], r.get("fingerprint") or "no key yet", "sensitive" if r.get("sensitive") else "")
    elif cmd == "sessions":
        for s in call("GET", "/setup/sessions")["sessions"]:
            print(s["id"], s["machineId"] or "-", s["state"], s["title"])
            if "-v" in args:  # the autopilot's view: status, background jobs, stall clock, last nudge
                print("   ", json.dumps({k: v for k, v in s.items() if k not in ("id", "machineId", "state", "title")}, sort_keys=True))
    elif cmd == "resume":
        # unattended: same image, no prompt (DESIGN "Resume, nothing changed"); a changed mode lands in the Inbox
        print(json.dumps(call("POST", "/setup/sessions/" + args[0] + "/resume", {})))
    elif cmd == "requests":
        for q in call("GET", "/setup/requests")["requests"]:
            c = q.get("call") or {}
            print(q["id"], q["kind"], json.dumps(q.get("params") or {}, sort_keys=True), "from", q["callerText"], "·", c.get("method", ""), c.get("path", ""))
    elif cmd == "request":
        print(json.dumps(file_request(args), indent=1))
    else:
        raise SystemExit(__doc__)


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
    why = opt(args, "--why")
    sensitive = "--sensitive" in args
    args = [a for a in args if a != "--sensitive"]
    minutes, days = opt(args, "--minutes"), opt(args, "--days")
    if not args or not why:
        raise SystemExit("request KIND … --why TEXT (see infra/setup.py without arguments)")
    kind, rest = args[0], args[1:]
    if kind in ("add-repo", "remove-repo") and len(rest) == 1:
        body = {"repo": rest[0], "explanation": why}
        if kind == "add-repo" and sensitive:
            body["sensitive"] = True
        return call("POST", "/setup/requests/repo/" + ("add" if kind == "add-repo" else "remove"), body)
    if kind == "grant" and len(rest) == 2:
        body = {"session": rest[0], "holder": rest[1], "explanation": why}
        if days:
            body["days"] = int(days)
        elif minutes:
            body["minutes"] = int(minutes)
        return call("POST", "/setup/requests/grant", body)
    if kind == "unlock" and len(rest) == 1:
        return call("POST", "/setup/requests/unlock", {"session": rest[0], "explanation": why})
    raise SystemExit(f"unknown request: {' '.join(args)} (see infra/setup.py without arguments)")


if __name__ == "__main__":
    main()
