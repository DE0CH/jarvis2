#!/usr/bin/env python3
"""CI stand-ins for the app's tests (app.yml): throwaway box + setup keys, and the backup bucket on a local
S3 stand-in (MinIO), seeded in exactly infra/setup.py's format by infra/setup.py's own code.

  standin.py keys DIR   DIR/keys/{box,setup,master}.pub (served to the CI build as its key source; master.pub
                        is the public TEST master key),
                        DIR/box-key.pem (the core's BOX_KEY_FILE), DIR/setup-key.pem (signs the backups)
  standin.py seed DIR   buckets on $HETZNER_S3_ENDPOINT, the backups encrypted to the public TEST master key
                        (e2e/testdata/master-test.pub):
                          jarvis2-backup-ci       core, default, gmail (sensitive), claude-login (the claude
                                                  harness's store), marked (backup says not sensitive, a
                                                  sensitive/ marker says it is)
                          jarvis2-backup-tampered default signed by another key → recovery must refuse
                          jarvis2-backup-nocore   no core store → recovery must refuse
  standin.py sealkeys DIR
                        DIR/recovery-keys.json: the bucket's read keys (DIR/s3.env) as infra/setup.py
                        recovery-keys seals them (to the TEST master key, signed by the setup key) — "good" —
                        plus "forged" (signed by another key) and "wrongAad" (sealed with a store's name as
                        associated data, as a store backup is) for the refusals
Nothing secret: every key here is made for one run, and the master key is the public test pair.
"""
import base64, importlib.util, os, sys

from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def pub(k):
    return base64.b64encode(k.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)).decode()


def pem(k):
    return k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())


def keys(d):
    os.makedirs(os.path.join(d, "keys"), exist_ok=True)
    for name in ("box", "setup"):
        k = ec.generate_private_key(ec.SECP256R1())
        with open(os.path.join(d, f"{name}-key.pem"), "wb") as f:
            f.write(pem(k))
        with open(os.path.join(d, "keys", f"{name}.pub"), "w") as f:
            f.write(pub(k) + "\n")
    # keys/master.pub: the public TEST master key (the app checks the kit's master key against it)
    with open(os.path.join(d, "keys", "master.pub"), "w") as f:
        f.write(open(os.path.join(ROOT, "e2e", "testdata", "master-test.pub")).read().strip() + "\n")


def load_setup(d):
    """infra/setup.py itself, its keys/ being the stand-ins (keys/master.pub = the TEST master key)"""
    os.environ["JARVIS2_KEYS_DIR"] = os.path.join(d, "keys")
    spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)
    return setup


def seed(d):
    setup = load_setup(d)
    good = open(os.path.join(d, "setup-key.pem")).read()
    other = pem(ec.generate_private_key(ec.SECP256R1())).decode()
    s3 = setup.s3()

    def bucket(name, stores, markers=(), bad=()):
        try:
            s3.create_bucket(Bucket=name)
        except Exception as e:
            if "BucketAlready" not in str(e):
                raise
        setup.BUCKET = name
        for n, vals, sens in stores:
            os.environ["JARVIS2_SETUP_KEY"] = other if n in bad else good
            setup.backup(n, vals, sens)
        os.environ["JARVIS2_SETUP_KEY"] = good
        for n in markers:
            setup.mark_sensitive_backup(n)
        print(f"seeded {name}: {[n for n, _, _ in stores]} markers {list(markers)}")

    core = ("core", {"FLY_API_TOKEN": "ci-dummy", "FLY_APP": "ci-dummy"}, True)
    default = ("default", {"GITHUB_TOKEN": "ci-dummy", "OTHER": "x"}, False)
    bucket("jarvis2-backup-ci", [core, default, ("gmail", {"GMAIL_TOKEN": "ci-dummy"}, True),
                                 ("claude-login", {"CLAUDE_CODE_OAUTH_TOKEN": "ci-dummy"}, False),
                                 ("marked", {"M": "1"}, False)], markers=["marked"])
    bucket("jarvis2-backup-tampered", [core, default], bad=["default"])
    bucket("jarvis2-backup-nocore", [default])


def sealkeys(d):
    import json
    setup = load_setup(d)
    ak, sk = setup.read_keys_file(os.path.join(d, "s3.env"))
    os.environ["JARVIS2_SETUP_KEY"] = open(os.path.join(d, "setup-key.pem")).read()
    good = setup.recovery_keys_doc(ak, sk, "ci-read")
    wrong = json.loads(good["doc"])
    wrong["sealed"] = setup.seal_to_master(json.dumps({"accessKey": ak, "secretKey": sk}).encode(), b"default")
    wrong_aad = setup.signed(json.dumps(wrong))
    os.environ["JARVIS2_SETUP_KEY"] = pem(ec.generate_private_key(ec.SECP256R1())).decode()
    forged = setup.recovery_keys_doc(ak, sk, "ci-read")
    with open(os.path.join(d, "recovery-keys.json"), "w") as f:
        json.dump({"good": good, "forged": forged, "wrongAad": wrong_aad}, f)
    print("sealed the read keys: good, forged, wrongAad")


if __name__ == "__main__":
    {"keys": keys, "seed": seed, "sealkeys": sealkeys}[sys.argv[1]](sys.argv[2])
