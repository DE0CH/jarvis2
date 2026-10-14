#!/usr/bin/env python3
"""CI only: the session machines of the fakefly spawner, doing what the guard (machine/) does with the router so a
session gets past "initialising" without Fly. The spawner (FAKEFLY_KEYS_DIR) writes each machine's private keys to
DIR/<id>.json; for each new one this boots it as the guard would — GET /m/boot (the chain checked against the roster),
GET /m/grant, POST /m/secrets/pull, POST /m/status, which marks the session started — then answers the command channel
(GET /m/commands): a new grant or "pull" pulls again, "snapshot" says there is nothing to snapshot (X-Snapshot-None),
shell commands answer that a fake machine runs nothing. A machine the router no longer takes (destroyed, or its
session paused) is dropped. Every request is signed with the machine's key as the guard signs it
("METHOD PATH UNIX-TIME SHA256HEX(BODY)", headers X-Machine / X-Time / X-Sig).
usage: fake-machine.py DIR [ROUTER_MACHINE_URL] [ROSTER_FILE]"""
import base64, hashlib, json, os, sys, threading, time, urllib.error, urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

DIR = sys.argv[1]
URL = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:18081"
ROSTER = sys.argv[3] if len(sys.argv) > 3 else ""


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def key(b64):
    return ec.derive_private_key(int.from_bytes(base64.b64decode(b64), "big"), ec.SECP256R1())


def verify(pub_b64, payload, sig_b64):
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), payload.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


class Machine:
    def __init__(self, d):
        self.id, self.sig = d["id"], key(d["sig"])
        self.refused = 0

    def call(self, method, path, body=b"", headers=None, timeout=90):
        t = str(int(time.time()))
        msg = f"{method} {path} {t} {hashlib.sha256(body).hexdigest()}".encode()
        h = {"X-Machine": self.id, "X-Time": t, "X-Sig": base64.b64encode(self.sig.sign(msg, ec.ECDSA(hashes.SHA256()))).decode(),
             "Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request(URL + path, data=body if method != "GET" else None, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return 0, str(e).encode()

    def json(self, method, path, obj=None, timeout=90):
        code, out = self.call(method, path, json.dumps(obj).encode() if obj is not None else b"", timeout=timeout)
        try:
            return code, json.loads(out)
        except ValueError:
            return code, {"raw": out[:300].decode(errors="replace")}

    def gone(self, code):
        if code in (401, 403, 404, 410):
            self.refused += 1
        else:
            self.refused = 0
        return self.refused >= 5

    def pull(self, grant=None):
        if grant is None:
            code, g = self.json("GET", "/m/grant")
            grant = g.get("grant")
            if code != 200 or not grant:
                log(self.id, "no grant yet:", code, g)
                return code
        code, out = self.json("POST", "/m/secrets/pull", {"grant": grant})
        log(self.id, "pull:", code, "" if code == 200 else out)
        return code

    def run(self):
        while True:  # boot: the router answers once the spawn's chain is in place
            code, chain = self.json("GET", "/m/boot")
            if code == 200:
                break
            if self.gone(code):
                log(self.id, "never booted:", code, chain)
                return
            time.sleep(1)
        if ROSTER and os.path.exists(ROSTER):  # what the guard checks first: the spawn cert is signed by the roster's notarizer
            r = json.load(open(ROSTER))
            n = ((chain.get("spawn") or {}).get("notarization") or {})
            log(self.id, "spawn notarization", "signed by the roster's notarizer" if verify(r.get("notarizer", ""), n.get("payload", ""), n.get("sig", "")) else "NOT signed by the roster's notarizer")
        while self.pull() not in (200,):
            time.sleep(2)
            if self.refused >= 5:
                return
        self.json("POST", "/m/status", {"raw": "fake machine (CI)", "appTitle": ""})
        log(self.id, "booted")
        while True:
            code, a = self.json("GET", "/m/commands", timeout=120)
            if code != 200:
                if self.gone(code):
                    log(self.id, "dropped by the router:", code, a)
                    return
                time.sleep(1)
                continue
            self.refused = 0
            if a.get("grant"):
                self.pull(a["grant"])
            for w in a.get("commands") or []:
                log(self.id, "command:", w)
                if w == "pull":
                    self.pull()
                elif w == "snapshot":
                    c, out = self.call("POST", "/m/snapshot", b"", {"X-Snapshot-None": "a fake machine (CI) has nothing"})
                    log(self.id, "snapshot:", c, out[:200])
            for s in a.get("shell") or []:
                self.json("POST", "/m/shell-result", {"id": s.get("id"), "code": 127, "stdout": "", "stderr": "",
                                                      "error": "a fake machine (CI) runs nothing"})


seen = set()
os.makedirs(DIR, exist_ok=True)
log("watching", DIR, "for fakefly machines; router", URL)
while True:
    for f in sorted(os.listdir(DIR)):
        if f.endswith(".json") and f not in seen:
            seen.add(f)
            try:
                m = Machine(json.load(open(os.path.join(DIR, f))))
            except Exception as e:
                log("unreadable", f, e)
                continue
            log(m.id, "new machine")
            threading.Thread(target=m.run, daemon=True).start()
    time.sleep(0.5)
