# AES-256-GCM for files in content stores: a file is nonce (12 bytes) || ciphertext || tag (16 bytes).
# AES_KEY = 32 random bytes as 64 hex chars or base64 (16/24-byte keys also work).
# Decrypt in a session: claude-env's scripts/aes-file.py decrypt <file> (reads AES_KEY from the env; it carries its
# own copy of this format). Identical copies in every tasks/ template that uses it (a template is one flat dir).
import base64, binascii, os


def key_from(raw):
    raw = (raw or "").strip()
    for decode in (bytes.fromhex, lambda s: base64.b64decode(s, validate=True)):
        try:
            k = decode(raw)
        except (ValueError, binascii.Error):
            continue
        if len(k) in (16, 24, 32):
            return k
    raise SystemExit("AES_KEY must be 16/24/32 bytes as hex or base64")


def encrypt(data, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt(blob, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)
