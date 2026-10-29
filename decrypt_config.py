#!/usr/bin/env python3
# Decrypt a TP-Link NX511v/NX510v conf.bin to its DslCpeConfig XML.
# Pipeline (see config-backup-format.md): DES-ECB decrypt -> [16B digest H][C] -> LZSS from +16 -> XML.
# You supply the per-device key, or the DEVVAL it is derived from.
#   usage: decrypt_config.py conf.bin --key  <16-hex>
#          decrypt_config.py conf.bin --devval <int>     (key = CONST8 XOR "%08x"%devval)
# Needs OpenSSL libcrypto (DES). On OpenSSL 3.x the legacy provider must be available.
import os, sys, ctypes, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzss import lzss_decompress

LIBCRYPTO = os.environ.get("LIBCRYPTO", "libcrypto.so.3")
LIB = ctypes.CDLL(LIBCRYPTO)
CONST8 = bytes.fromhex("748da50bf93e2dcf")   # fixed per model (embedded in libcmm.so)


class _KS(ctypes.Structure):
    _fields_ = [("ks", ctypes.c_ubyte * 128)]


def key_from_devval(dv: int) -> bytes:
    hx = ("%08x" % (dv & 0xffffffff)).encode()
    return bytes(CONST8[i] ^ hx[i] for i in range(8))


def des_decrypt(data: bytes, key: bytes) -> bytes:
    ks = _KS(); LIB.DES_set_key_unchecked(ctypes.c_char_p(key), ctypes.byref(ks))
    out = bytearray()
    for o in range(0, len(data) - 7, 8):
        i8 = (ctypes.c_ubyte * 8).from_buffer_copy(data[o:o + 8]); o8 = (ctypes.c_ubyte * 8)()
        LIB.DES_ecb_encrypt(ctypes.byref(i8), ctypes.byref(o8), ctypes.byref(ks), 0)
        out += bytes(o8)
    return bytes(out)


def decrypt_conf(conf: bytes, key: bytes):
    plano = des_decrypt(conf, key)
    H, C = plano[:16], plano[16:]
    # H = MD5(C) over C's real length; strip up to 7 bytes of DES padding to find it
    digest_ok = any(hashlib.md5(C[:len(C) - p] if p else C).digest() == H for p in range(8))
    xml, _ = lzss_decompress(C)              # LZSS starts at +16
    return xml, digest_ok


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit("usage: decrypt_config.py conf.bin (--key <hex> | --devval <int>)")
    conf = open(sys.argv[1], "rb").read()
    key = bytes.fromhex(sys.argv[3]) if sys.argv[2] == "--key" else key_from_devval(int(sys.argv[3], 0))
    xml, ok = decrypt_conf(conf, key)
    sys.stderr.write(f"key={key.hex()}  digest_ok={ok}  xml_len={len(xml)}\n")
    sys.stdout.buffer.write(xml)
