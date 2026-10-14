#!/usr/bin/env python3
"""The CI kernel stand-in (standins.sh + kernel-up.sh) end to end, with this script as the iPhone: Recover (a claim
naming the phone and its root key; an empty bundle), the roster watcher putting both keys in, root's ⊤ on the sink, a
New session (its drafts signed by the phone key) up to "initialising" on the fakefly spawner, a terminal and an
add-store add-on, pause, resume (its drafts signed again), destroy. Checks the stand-in before the slow simulator
run uses it: run where standins.sh left the kernel up (python3 kernel-smoke.py W). Exit 0 = every step passed.
The app's own code does the same steps in the simulator walkthrough (ios/UITests)."""
import base64, hashlib, importlib.util, json, os, sys, time, urllib.error, urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

W = sys.argv[1]
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
R = "http://127.0.0.1:18080"
spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
S = importlib.util.module_from_spec(spec)
os.environ.setdefault("JARVIS2_SETUP_KEY", open(os.path.join(W, "setup-key.pem")).read())
spec.loader.exec_module(S)


def pub(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()


def sign(k, text):
    return base64.b64encode(k.sign(text.encode(), ec.ECDSA(hashes.SHA256()))).decode()


def call(method, path, body=None, ok=(200,)):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(R + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, out = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, out = e.code, e.read()
    if status not in ok:
        sys.exit(f"FAIL {method} {path}: HTTP {status} {out[:400]!r}")
    try:
        return json.loads(out)
    except ValueError:
        return out


def step(t):
    print(f"--- {t}", flush=True)


def until(what, fn, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(1)
    sys.exit(f"FAIL waiting for {what}")


phone, phone_agr, root = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
master = serialization.load_pem_private_key(open(os.path.join(ROOT, "e2e", "testdata", "master-test.pem"), "rb").read(), None)

step("Recover: the claim names the phone and its root key")
sid_ = call("GET", "/api/secrets/identity")
bundle = json.dumps({"format": "keys", "stores": ["default", "extra"], "keys": [], "notSensitive": ["default", "extra"], "owners": {}}).encode()
st = json.dumps({"kind": "claim", "master": pub(master), "core": {"signingKey": sid_["signingKey"], "agreementKey": sid_["agreementKey"]},
                 "phone": {"signingKey": pub(phone), "agreementKey": pub(phone_agr)}, "bundleSha256": hashlib.sha256(bundle).hexdigest(),
                 "root": pub(root), "device": None}, sort_keys=True, separators=(",", ":"))
call("POST", "/api/secrets/claim", {"statement": st, "masterSig": sign(master, st), "bundle": S.seal_to(sid_["agreementKey"], bundle, "jarvis2/claim")})

step("the roster watcher puts both keys in the roster")
until("the roster's phone and root", lambda: (lambda r: r.get("phone") == pub(phone) and r.get("root") == pub(root))(json.load(open(os.path.join(W, "roster.json")))), 60)
time.sleep(3)  # the parts start again on it

step("root's ⊤ on the sink, signed with the root key")
payload = '{"kind":"grant","by":"root","machine":{"id":"sink"},"allowed":{"except":[]},"conditions":[],"from":[]}'
call("PUT", "/api/kernel/root-grant", {"payload": payload, "sig": sign(root, payload)})


def approve(sid, kind):
    a = until(f"the {kind} approval", lambda: next((x for x in call("GET", "/api/approvals").get("approvals", []) if x.get("session") == sid or not sid), None), 60)
    out = call("POST", f"/api/approvals/{a['id']}/respond", {"signatures": [sign(phone, d["payload"]) for d in a["drafts"]]})
    return a, out


def state(sid):
    return next((s for s in call("GET", "/api/state")["sessions"] if s["id"] == sid), {})


def wait_state(sid, want, timeout=90):
    def f():
        s = state(sid)
        if s.get("state") == "failed":
            sys.exit(f"FAIL session {sid} failed: {s.get('error')}")
        return s.get("state") in want and s
    return until(f"{sid} {want}", f, timeout)


step("New session: the phone signs its drafts; the fakefly spawner makes its machine")
made = call("POST", "/api/sessions", {"label": "smoke", "stores": ["default"], "size": "small", "harness": "opencode"})
sid = made.get("id") or made.get("session")
a, _ = approve(sid, "new-session")
sid = sid or a.get("session")
s = wait_state(sid, ("started",))
print("   ", sid, s["state"], s.get("machineId") or s.get("machine"))

step("a terminal for 5 minutes (two drafts: the shell on the session, then the machine)")
call("POST", "/api/requests/terminal", {"session": sid, "minutes": 5})
a, out = approve(sid, "terminal")
print("    drafts:", len(a["drafts"]), "→", str(out)[:160])

step("add-store extra (merged into the main grant; the phone signs)")
out = call("POST", "/api/requests/add-store", {"session": sid, "store": "extra"})
print("   ", str(out)[:200])
if isinstance(out, dict) and out.get("id"):
    a, out = approve(sid, "add-store")
    print("    drafts:", len(a["drafts"]), "→", str(out)[:160])

step("command (sent once under its own grant; a fake machine answers that it runs nothing)")
call("POST", "/api/requests/command", {"session": sid, "cmd": "echo hi"})
a, out = approve(sid, "command")
print("    drafts:", len(a["drafts"]), "→", str(out)[:200])

step("pause → paused (the fake machine uploads a tiny signed snapshot)")
call("POST", f"/api/sessions/{sid}/pause", {})
wait_state(sid, ("paused",), 120)

step("resume with a prompt: the phone signs the new source's settings")
call("POST", f"/api/sessions/{sid}/resume", {"upgrade": False, "prompt": "carry on"})
a, _ = approve(sid, "resume")
p0 = json.loads(a["drafts"][0]["payload"])
if not (p0.get("successor") or {}).get("snapshot"):
    sys.exit(f"FAIL the resume's new source names no snapshot (the app refuses it): {a['drafts'][0]['payload'][:300]}")
wait_state(sid, ("started",))

step("destroy")
call("POST", f"/api/sessions/{sid}/destroy", {})
until("the session gone", lambda: not state(sid) or state(sid).get("state") in ("destroyed",), 120)
print("SMOKE PASSED")
