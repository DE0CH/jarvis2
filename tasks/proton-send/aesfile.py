# AES-256-GCM for files in content stores: a file is nonce (12 bytes) || ciphertext || tag (16 bytes).
# AES_KEY = 32 random bytes as 64 hex chars or base64 (16/24-byte keys also work).
# Decrypt in a session: scripts/aes-file.py decrypt <file> (reads AES_KEY from the env).
# Identical copies in selfhost/tasks/{encrypt,paraphrase}-to-content/ and proton-send/ (a template is one flat dir);
# scripts/aes-file.py imports the encrypt-to-content one.
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
