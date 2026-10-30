#!/usr/bin/env python3
# Forge a conf.bin the NX511v/NX510v will accept, from an edited DslCpeConfig XML.
# Inverse of restore (see config-backup-format.md):
#   C = LZSS_compress(xml);  H = MD5(C);  plaintext = H(16) || C, zero-padded to a multiple of 8;
#   conf.bin = DES-ECB_encrypt(plaintext, key).
# The restore tolerates the padding (it appends up to 7 zero bytes when checking the MD5).
#   usage: forge_conf.py xml_in conf_out (--key <hex> | --devval <int>)
import os, sys, ctypes, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzss import lzss_decompress
# Real match-finding compressor (~0.16x) by default; --literals falls back to the
# all-literals one (~1.125x). Both produce a stream the device accepts.
from lzss_compress_real import lzss_compress as _lzss_real
from lzss_compress import lzss_compress as _lzss_lit
lzss_compress = _lzss_real

LIBCRYPTO = os.environ.get("LIBCRYPTO", "libcrypto.so.3")
LIB = ctypes.CDLL(LIBCRYPTO)
CONST8 = bytes.fromhex("748da50bf93e2dcf")


class _KS(ctypes.Structure):
    _fields_ = [("ks", ctypes.c_ubyte * 128)]


def key_from_devval(dv: int) -> bytes:
    hx = ("%08x" % (dv & 0xffffffff)).encode()
    return bytes(CONST8[i] ^ hx[i] for i in range(8))


def _des(data: bytes, key: bytes, enc: int) -> bytes:
    ks = _KS(); LIB.DES_set_key_unchecked(ctypes.c_char_p(key), ctypes.byref(ks))
    out = bytearray()
    for o in range(0, len(data) - 7, 8):
        i8 = (ctypes.c_ubyte * 8).from_buffer_copy(data[o:o + 8]); o8 = (ctypes.c_ubyte * 8)()
        LIB.DES_ecb_encrypt(ctypes.byref(i8), ctypes.byref(o8), ctypes.byref(ks), enc)
        out += bytes(o8)
    return bytes(out)


def forge(xml: bytes, key: bytes):
    C = lzss_compress(xml)
    H = hashlib.md5(C).digest()
    pt = H + C
    if len(pt) % 8:
        pt += b"\x00" * (8 - len(pt) % 8)
    return _des(pt, key, 1), H, C


def verify(conf: bytes, key: bytes):
    pt = _des(conf, key, 0)
    H, rest = pt[:16], pt[16:]
    ok = any(hashlib.md5(rest[:len(rest) - p] if p else rest).digest() == H for p in range(8))
    xml, _ = lzss_decompress(rest)
    return ok, xml


if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if a != "--literals"]
    if "--literals" in sys.argv:
        lzss_compress = _lzss_lit
    if len(argv) < 4:
        sys.exit("usage: forge_conf.py [--literals] xml_in conf_out (--key <hex> | --devval <int>)")
    xml = open(argv[0], "rb").read()
    key = bytes.fromhex(argv[3]) if argv[2] == "--key" else key_from_devval(int(argv[3], 0))
    conf, H, C = forge(xml, key)
    open(argv[1], "wb").write(conf)
    ok, xml2 = verify(conf, key)
    sys.stderr.write(f"wrote {argv[1]}  bytes={len(conf)}  C={len(C)}  digest_ok={ok}  roundtrip={xml2 == xml}\n")
