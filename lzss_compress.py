#!/usr/bin/env python3
# LZSS compressor compatible with TP-Link's cen_uncompressBuff (NX511v/NX510v family).
# Strategy: ALL-LITERALS (no back-references) -> a valid stream their decompressor accepts.
# Output layout C: [4-byte LE uncompressed length] + stream.
#   stream = 1 initial literal byte, then blocks of [16-bit control word = 0x0000][up to 16 literal bytes].
#   (control bit 0 = literal; each 16-bit word carries 16 flags, each followed by its literal byte,
#    mirroring the bit/byte interleaving of the decompressor in lzss.py.)
# Trade-off: output is ~1.125x the input (vs real match-finding). Simple and correct; if the device
# rejects an oversized config, implement cen_compressBuff's match search to shrink it.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzss import lzss_decompress


def lzss_compress(data: bytes) -> bytes:
    assert len(data) >= 1
    s = bytearray()
    s.append(data[0])                       # first literal, emitted raw
    i = 1
    while i < len(data):
        s += b"\x00\x00"                    # 16 control bits, all 0 -> 16 literals
        s += data[i:i + 16]
        i += 16
    return len(data).to_bytes(4, "little") + bytes(s)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: lzss_compress.py <file>   (self-test: compress then round-trip)")
    data = open(sys.argv[1], "rb").read()
    c = lzss_compress(data)
    back, _ = lzss_decompress(c)
    print(f"in={len(data)}  compressed={len(c)} ({len(c)/len(data):.3f}x)  round-trip={'OK' if back == data else 'FAIL'}")
