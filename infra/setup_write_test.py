#!/usr/bin/env python3
"""2026-10-13: `infra/setup.py write STORE K…` against a core that replaces whole stores wiped 24 keys. A write that
would leave out a key name recorded for the store is refused unless --replace; the router is told the names too.
Runs offline (the router and the core stubbed): python3 infra/setup_write_test.py"""
import importlib.util, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

sent = []
core = {"keys": False}
S.set_up = lambda: {"keys": core["keys"], "phone": {"agreementKey": "P"}, "agreementKey": "K", "master": "M"}
S.blob = lambda name, vals, p, k: {"name": name}
S.backup = lambda *a: None
S.store_list = lambda: {"identity": {"name": "identity", "sensitive": True}}

def call(method, path, body=None):
    if path == "/setup/stores/keys":
        return {"stores": [{"name": "identity", "keys": ["A", "B", "C"]}]}
    sent.append((path, body))
    if path == "/setup/stores/write":
        return {"payload": json.dumps({"sensitive": True})}
    return {}
S.call = call
os.environ.update(A="1", B="2", C="3", D="4")

def write(*args):
    sent.clear()
    sys.argv = ["setup.py", "write", *args]
    try:
        S.main()
    except SystemExit as e:
        return str(e)
    return None

err = write("identity", "A", "D")
assert err and "REFUSED" in err and "B, C" in err, err
assert not any(p == "/setup/stores/write" for p, _ in sent), "a refused write reached the router"

assert write("identity", "A", "B", "C", "D") is None
w = [b for p, b in sent if p == "/setup/stores/write"][0]
assert w["keys"] == ["A", "B", "C", "D"] and w["replace"] is False, w

assert write("identity", "A", "--replace") is None
w = [b for p, b in sent if p == "/setup/stores/write"][0]
assert w["keys"] == ["A"] and w["replace"] is True, w

core["keys"] = True  # a core whose stores are made of keys: a write never drops one, --replace means nothing
S.key_write = lambda *a, **k: {}
assert write("identity", "A", "--replace") is None  # --replace is ignored there (noted), the key still written
assert any(p == "/setup/stores/identity/keys/A" for p, _ in sent), sent
# a store the core calls not sensitive after the write is marked sensitive at once, not left so
S.store_list = lambda: {"identity": {"name": "identity", "sensitive": False}}
S.mark_sensitive_backup = lambda n: sent.append(("marker", n))
assert write("identity", "A") is None
assert ("marker", "identity") in sent and any(p == "/setup/stores/mark-sensitive" for p, _ in sent), sent
print("setup_write_test: ok")
