# Encrypt + upload helpers shared by the *-to-content tasks (identical copy in each template dir).
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aesfile, content


def aes_key(keystore):
    # AES_KEY comes from the key store picked in the task (a store of the task's line)
    raw = os.environ.get("AES_KEY", "")
    if not raw.strip():
        sys.exit(f"store {keystore!r} has no AES_KEY")
    return aesfile.key_from(raw)


def upload_encrypted(store, name, text, key):
    blob = aesfile.encrypt(text.encode("utf-8"), key)
    content.put(store, name, blob)
    print(f"saved {store}/{name} ({len(blob)} bytes, AES-256-GCM)")
