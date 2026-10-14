#!/usr/bin/env python3
"""Independent recomputation of the kernel's hash-to-curve keys (core/kernel/h2c.go), plain Python integers only.

try-and-increment onto P-256: for counter = 0, 1, ...: x = SHA-256(name || uint32_be(counter)) as a big-endian
integer; skip if x >= p or x^3 - 3x + b is not a square mod p; else y = the even square root; the point is (x, y),
written as base64 of the 65-byte uncompressed encoding.

  python3 h2c.py > h2c.json      (writes the golden file the Go tests compare against)
  python3 h2c.py NAME...         (prints the key for each name)
"""
import base64
import hashlib
import json
import sys

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

# The names the tests check: the sink, a few sources, and edge cases (empty, non-ASCII)
NAMES = [
    "jarvis2 sink signing",
    "jarvis2 sink encryption",
    "jarvis2 source-00000000000000000000000000000000 signing",
    "jarvis2 source-00000000000000000000000000000000 encryption",
    "jarvis2 source-0123456789abcdef0123456789abcdef signing",
    "jarvis2 source-0123456789abcdef0123456789abcdef encryption",
    "jarvis2 source-ffffffffffffffffffffffffffffffff encryption",
    "",
    "jarvis2 éè 中文",
]


def hash_to_point(name: str) -> str:
    counter = 0
    while True:
        x = int.from_bytes(hashlib.sha256(name.encode("utf-8") + counter.to_bytes(4, "big")).digest(), "big")
        counter += 1
        if x >= P:
            continue
        y2 = (pow(x, 3, P) - 3 * x + B) % P
        # p = 3 mod 4: sqrt is y2^((p+1)/4); check it squares back
        y = pow(y2, (P + 1) // 4, P)
        if y * y % P != y2:
            continue
        if y & 1:
            y = P - y
        assert (y * y - (x * x * x - 3 * x + B)) % P == 0
        return base64.b64encode(b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")).decode()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        for n in sys.argv[1:]:
            print(hash_to_point(n))
    else:
        print(json.dumps({n: hash_to_point(n) for n in NAMES}, indent=1, ensure_ascii=False))
