#!/usr/bin/env python3
"""`infra/setup.py write STORE K…` writes each key on its own (the store's other keys are never read or touched), and a
store the core calls not sensitive after the write is marked sensitive at once.
Runs offline (the router and the core stubbed): python3 infra/setup_write_test.py"""
import importlib.util, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

sent = []
S.set_up = lambda: {"phone": {"agreementKey": "P"}, "agreementKey": "K", "master": "M"}
S.key_write = lambda *a, **k: {}
S.store_list = lambda: {"identity": {"name": "identity", "sensitive": True}}
S.call = lambda method, path, body=None: sent.append((path, body)) or {}
os.environ.update(A="1", B="2")

def write(*args):
    sent.clear()
    sys.argv = ["setup.py", "write", *args]
    S.main()

write("identity", "B", "A", "--explain", "A=what A is for")
assert [p for p, _ in sent] == ["/setup/stores/identity/keys/A", "/setup/stores/identity/keys/B", "/setup/store-docs"], sent
assert sent[2][1] == {"store": "identity", "keys": {"A": "what A is for"}}, sent
# a store the core calls not sensitive after the write is marked sensitive at once, not left so
S.store_list = lambda: {"identity": {"name": "identity", "sensitive": False}}
S.mark_sensitive_backup = lambda n: sent.append(("marker", n))
write("identity", "A")
assert ("marker", "identity") in sent and any(p == "/setup/stores/mark-sensitive" for p, _ in sent), sent
print("setup_write_test: ok")
