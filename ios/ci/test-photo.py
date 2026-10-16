#!/usr/bin/env python3
"""A test photo for the simulator's library (ios.yml walkthrough and replica: `simctl addmedia`): New session's UI tests attach it
from Photos. A 640x480 PNG, a checkerboard with a bar, made with the standard library only.

  test-photo.py OUT.png
"""
import struct, sys, zlib

W, H = 640, 480
rows = []
for y in range(H):
    row = bytearray(b"\x00")
    for x in range(W):
        if 200 <= y < 280:
            row += b"\xf0\xc0\x20"
        elif (x // 40 + y // 40) % 2:
            row += b"\xd0\x30\x30"
        else:
            row += b"\x30\x60\xd0"
    rows.append(bytes(row))


def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))


png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0)) + \
    chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
