#!/usr/bin/env python3
"""tools/decrypt-backup.py against backups sealed and signed by infra/setup.py's own code (backup, mark_sensitive_backup)
with the public TEST master key (e2e/testdata/master-test.pem) and a throwaway setup key, plus the committed vector
tools/testdata/backup-export-v1.json. Offline: python3 tools/decrypt_backup_test.py (needs `cryptography`).
The production master key is never used (no session has it)."""
import base64, importlib.util, io, json, os, stat, subprocess, sys, tempfile, unittest
from contextlib import redirect_stderr, redirect_stdout

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "decrypt-backup.py")
VECTOR = os.path.join(ROOT, "tools", "testdata", "backup-export-v1.json")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def put(path, text):
    with open(path, "w") as f:
        f.write(text)


def pem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def pub(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()


with open(os.path.join(ROOT, "e2e", "testdata", "master-test.pem")) as _f:
    MASTER_PEM = _f.read()
MASTER = serialization.load_pem_private_key(MASTER_PEM.encode(), None)
KIT = "jarvis2-kit:2:" + base64.b64encode(MASTER.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                               serialization.NoEncryption())).decode()
SETUP = ec.generate_private_key(ec.SECP256R1())
OTHER = ec.generate_private_key(ec.SECP256R1())
os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
S = load("jarvis2_setup", os.path.join(ROOT, "infra", "setup.py"))
D = load("decrypt_backup", TOOL)

STORES = {"default": ({"GITHUB_TOKEN": "t-1", "OTHER": "x y\nz"}, False), "core": ({"FLY_API_TOKEN": "fly-1"}, True),
          "marked": ({"M": "1"}, False), "empty": ({}, False)}


def seed(signer=None, only=None):
    """{key: body} as infra/setup.py writes them to the bucket"""
    bucket = {}

    class FakeS3:
        def put_object(self, Bucket, Key, Body):
            bucket[Key] = Body.decode() if isinstance(Body, bytes) else Body
    S.s3 = lambda: FakeS3()
    for n, (vals, sens) in STORES.items():
        if only and n not in only:
            continue
        os.environ["JARVIS2_SETUP_KEY"] = pem((signer or {}).get(n, SETUP))
        S.backup(n, vals, sens, pub(MASTER))
    os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
    S.mark_sensitive_backup("marked")
    return bucket


def export(bucket, setup_key=None):
    """the app's file (CoreSetup.exportFile): the objects as served plus bucket, fetch time and setup key"""
    return {"format": "jarvis2-backup-export", "version": 1, "bucket": "jarvis2-backup-test", "fetchedAt": "2026-10-13T10:00:00Z",
            "setupKey": setup_key or pub(SETUP), "setupKeySource": "test",
            "objects": [{"key": k, "body": v} for k, v in sorted(bucket.items())]}


class T(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def file(self, obj, name="in.json"):
        p = os.path.join(self.dir, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def kitfile(self, text=KIT):
        p = os.path.join(self.dir, "kit")
        with open(p, "w") as f:
            f.write(text)
        return p

    def run_tool(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = D.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_decrypts_every_store(self):
        f, out = self.file(export(seed())), os.path.join(self.dir, "plain.json")
        code, stdout, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out)
        self.assertEqual(code, 0, err)
        self.assertEqual(stdout, "", "nothing on stdout without --stdout")
        self.assertNotIn("t-1", err, "no value on the terminal")
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        d = json.load(open(out))
        self.assertEqual(d["format"], "jarvis2-stores")
        self.assertEqual({n: s["values"] for n, s in d["stores"].items()}, {n: v for n, (v, _) in STORES.items()})
        self.assertEqual({n: s["sensitive"] for n, s in d["stores"].items()}, {"default": False, "core": True, "marked": True, "empty": False},
                         "a sensitive/ marker wins over the backup's flag")
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out)
        self.assertEqual(code, 2, "never over an existing file")
        self.assertIn("--force", err)
        self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(), "--out", out, "--force")[0], 0)

    def test_dir_and_stdout(self):
        f = self.file(export(seed()))
        dout = os.path.join(self.dir, "stores") + "/"
        self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(), "--out", dout)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(dout).st_mode), 0o700)
        self.assertEqual(sorted(os.listdir(dout)), ["core.json", "default.json", "empty.json", "marked.json"])
        self.assertEqual(json.load(open(dout + "default.json"))["values"]["OTHER"], "x y\nz")
        self.assertEqual(stat.S_IMODE(os.stat(dout + "core.json").st_mode), 0o600)
        code, stdout, _ = self.run_tool(f, "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["stores"]["core"]["values"], {"FLY_API_TOKEN": "fly-1"})

    def test_kit_forms_and_stdin(self):
        f = self.file(export(seed()))
        body = KIT[len("jarvis2-kit:2:"):]
        wrapped = "  " + "\n".join(KIT[i:i + 64] for i in range(0, len(KIT), 64)) + "\n"
        for kit in (wrapped, f"jarvis2-kit:1:{body}:AK:SK", MASTER_PEM):
            self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(kit), "--stdout")[0], 0, kit[:20])
        for kit, want in (("jarvis2-kit:3:" + body, "unknown"), ("jarvis2-kit:2:AAAA", "doesn't parse"), (body, "isn't a recovery kit")):
            code, _, err = self.run_tool(f, "--kit-file", self.kitfile(kit), "--stdout")
            self.assertEqual(code, 2, kit[:20])
            self.assertIn(want, err)
        # the kit on stdin (a separate process, as Deyao runs it)
        p = subprocess.run([sys.executable, TOOL, f, "--kit-file", "-", "--out", os.path.join(self.dir, "s.json")],
                           input=KIT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run([sys.executable, TOOL, f, "--out", os.path.join(self.dir, "s2.json")], input=KIT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, "a piped kit without --kit-file: " + p.stderr)

    def test_wrong_kit(self):
        f = self.file(export(seed()))
        other = "jarvis2-kit:2:" + base64.b64encode(OTHER.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                                         serialization.NoEncryption())).decode()
        out = os.path.join(self.dir, "plain.json")
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(other), "--out", out)
        self.assertEqual(code, 1)
        self.assertIn("doesn't open with this recovery kit", err)
        self.assertFalse(os.path.exists(out), "nothing written")

    def test_bad_signature(self):
        f = self.file(export(seed(signer={"default": OTHER})))
        out = os.path.join(self.dir, "plain.json")
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out)
        self.assertEqual(code, 1)
        self.assertIn("stores/default.json: isn't signed by the file's setup key", err)
        self.assertFalse(os.path.exists(out))
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out, "--skip-bad")
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(json.load(open(out))["stores"]), ["core", "empty", "marked"])

    def test_setup_pub(self):
        b = seed()
        good, other = os.path.join(self.dir, "setup.pub"), os.path.join(self.dir, "other.pub")
        put(good, pub(SETUP) + "\n")
        put(other, pub(OTHER))
        f = self.file(export(b))
        self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")[0], 0)
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--setup-pub", other, "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("isn't " + other, err)
        # a file whose own key was swapped (with its signatures) fails against the real setup.pub
        b2 = seed(signer={n: OTHER for n in STORES})
        os.environ["JARVIS2_SETUP_KEY"] = pem(OTHER)
        S.mark_sensitive_backup("marked")
        os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
        swapped = self.file(export(b2, setup_key=pub(OTHER)), "swapped.json")
        self.assertEqual(self.run_tool(swapped, "--kit-file", self.kitfile(), "--stdout")[0], 0, "self-consistent on its own")
        self.assertEqual(self.run_tool(swapped, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")[0], 1,
                         "…but not against keys/setup.pub")
        # the raw router answer and a single bucket object carry no setup key: --setup-pub is required
        raw = self.file({"bucket": "b", "objects": export(b)["objects"]}, "raw.json")
        self.assertEqual(self.run_tool(raw, "--kit-file", self.kitfile(), "--stdout")[0], 2)
        self.assertEqual(self.run_tool(raw, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")[0], 0)
        one = os.path.join(self.dir, "default.json")
        put(one, b["stores/default.json"])
        code, stdout, _ = self.run_tool(one, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["stores"]["default"]["values"]["GITHUB_TOKEN"], "t-1")

    def test_store_name_binding(self):
        b = seed()
        # a store's backup served under another store's key
        moved = dict(b)
        moved["stores/marked.json"] = b["stores/core.json"]
        code, _, err = self.run_tool(self.file(export(moved)), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("stores/marked.json: names another store", err)
        # re-signed under another name (a setup key holder): the name is the associated data, so it doesn't open
        d = json.loads(json.loads(b["stores/core.json"])["doc"])
        d["name"] = "marked"
        os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
        moved["stores/marked.json"] = json.dumps(S.signed(json.dumps(d)))
        code, _, err = self.run_tool(self.file(export(moved)), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("stores/marked.json: doesn't open with this recovery kit", err)
        # served twice
        e = export(b)
        e["objects"].append(next(o for o in e["objects"] if o["key"].startswith("stores/")))
        self.assertEqual(self.run_tool(self.file(e), "--kit-file", self.kitfile(), "--stdout")[0], 1)

    def test_versions(self):
        e = export(seed())
        e["version"] = 2
        code, _, err = self.run_tool(self.file(e), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 2)
        self.assertIn("newer export", err)

    def test_committed_vector(self):
        """a file made once with the format as shipped: later changes must keep reading it"""
        code, stdout, err = self.run_tool(VECTOR, "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 0, err)
        d = json.loads(stdout)
        self.assertEqual(d["stores"]["default"]["values"], {"GITHUB_TOKEN": "vector-token", "NOTE": "ünïcode ✓"})
        self.assertEqual(d["stores"]["core"]["values"], {"FLY_API_TOKEN": "vector-fly"})
        self.assertEqual(d["stores"]["marked"]["sensitive"], True)
        self.assertEqual(d["bucket"], "jarvis2-backup-vector")


def make_vector():
    """python3 tools/decrypt_backup_test.py make-vector: (re)writes tools/testdata/backup-export-v1.json"""
    global STORES
    STORES = {"default": ({"GITHUB_TOKEN": "vector-token", "NOTE": "ünïcode ✓"}, False), "core": ({"FLY_API_TOKEN": "vector-fly"}, True),
              "marked": ({"M": "1"}, False)}
    e = export(seed())
    e.update(bucket="jarvis2-backup-vector", setupKeySource="a throwaway setup key (tools/decrypt_backup_test.py make-vector)")
    os.makedirs(os.path.dirname(VECTOR), exist_ok=True)
    with open(VECTOR, "w") as f:
        json.dump(e, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print("wrote", VECTOR)


if __name__ == "__main__":
    if sys.argv[1:] == ["make-vector"]:
        make_vector()
    else:
        unittest.main()
