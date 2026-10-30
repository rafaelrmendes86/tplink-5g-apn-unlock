#!/usr/bin/env python3
# Real (match-finding) LZSS compressor for the TP-Link config format.
# Ported from sta-c0000/tpconf_bin_xml (the compress()/uncompress() there), with packint
# pinned to little-endian for the NX511v/NX510v. The on-wire format is byte-for-byte the
# same scheme as lzss.py (our device-derived decompressor): a 16-bit control word every
# 16 tokens (MSB first), a variable-length length/offset code, a raw low-offset byte, and
# the first byte stored literally. Output C = [4B uncompressed size, LE] + stream.
#
# vs the all-literals lzss_compress.py: this produces a real ~0.16x stream (a ~113 KB XML
# compresses to ~18.5 KB, matching/beating the device's own compressor) instead of ~1.125x.
# Validated: decode with lzss.lzss_decompress() round-trips, and it decodes a real device
# backup to the identical XML.
from struct import pack_into, unpack_from

packint = '<I'   # NX511v/NX510v store the size little-endian


def compress(src, skiphits=False):
    if src[-1]:
        src += b'\0'
    size = len(src)
    buffer_countdown = size
    hash_table = [0] * 0x2000
    dst = bytearray(0x40000)
    block16_countdown = 0x10
    block16_dict_bits = 0

    def put_bit(bit):
        nonlocal block16_countdown, block16_dict_bits, d_p, d_pb
        if block16_countdown:
            block16_countdown -= 1
        else:
            pack_into('H', dst, d_pb, block16_dict_bits)
            d_pb = d_p
            d_p += 2
            block16_countdown = 0xF
        block16_dict_bits = (bit + (block16_dict_bits << 1)) & 0xFFFF

    def put_dict_ld(bits):
        ldb = bits >> 1
        while True:
            lb = (ldb - 1) & ldb
            if not lb:
                break
            ldb = lb
        put_bit(int(ldb & bits > 0))
        ldb = ldb >> 1
        while ldb:
            put_bit(1)
            put_bit(int(ldb & bits > 0))
            ldb = ldb >> 1
        put_bit(0)

    def hash_key(offset):
        b4 = src[offset:offset + 4]
        hk = 0
        for b in b4[:3]:
            hk = (hk + b) * 0x13d
        return ((hk + b4[3]) & 0x1FFF)

    pack_into(packint, dst, 0, size)
    dst[4] = src[0]
    buffer_countdown -= 1
    s_p = 1
    s_ph = 0
    d_pb = 5
    d_p = 7

    while buffer_countdown > 4:
        while s_ph < s_p:
            hash_table[hash_key(s_ph)] = s_ph
            s_ph += 1
        hit = hash_table[hash_key(s_p)]
        count = 0
        if hit:
            while True:
                if src[hit + count] != src[s_p + count]:
                    break
                count += 1
                if count == buffer_countdown:
                    break
            if count >= 4 or count == buffer_countdown:
                hit = s_p - hit - 1
                put_bit(1)
                put_dict_ld(count - 2)
                put_dict_ld((hit >> 8) + 2)
                dst[d_p] = hit & 0xFF
                d_p += 1
                buffer_countdown -= count
                s_p += count
                if skiphits:
                    hash_table[hash_key(s_ph)] = s_ph
                    s_ph += count
                continue
        put_bit(0)
        dst[d_p] = src[s_p]
        s_p += 1
        d_p += 1
        buffer_countdown -= 1
    while buffer_countdown:
        put_bit(0)
        dst[d_p] = src[s_p]
        s_p += 1
        d_p += 1
        buffer_countdown -= 1
    pack_into('H', dst, d_pb, (block16_dict_bits << block16_countdown) & 0xFFFF)
    return bytes(dst[:d_p])


def uncompress(src):
    block16_countdown = 0
    block16_dict_bits = 0

    def get_bit():
        nonlocal block16_countdown, block16_dict_bits, s_p
        if block16_countdown:
            block16_countdown -= 1
        else:
            block16_dict_bits = unpack_from('H', src, s_p)[0]
            s_p += 2
            block16_countdown = 0xF
        block16_dict_bits = block16_dict_bits << 1
        return 1 if block16_dict_bits & 0x10000 else 0

    def get_dict_ld():
        bits = 1
        while True:
            bits = (bits << 1) + get_bit()
            if not get_bit():
                break
        return bits

    size = unpack_from(packint, src, 0)[0]
    dst = bytearray(size)
    s_p = 4
    d_p = 0
    dst[d_p] = src[s_p]; s_p += 1; d_p += 1
    while d_p < size:
        if get_bit():
            num_chars = get_dict_ld() + 2
            msB = (get_dict_ld() - 2) << 8
            lsB = src[s_p]; s_p += 1
            offset = d_p - (lsB + 1 + msB)
            for _ in range(num_chars):
                dst[d_p] = dst[offset]; d_p += 1; offset += 1
        else:
            dst[d_p] = src[s_p]; s_p += 1; d_p += 1
    return bytes(dst)


# Same signature as lzss_compress.lzss_compress: returns C = [4B size LE] + stream.
def lzss_compress(data):
    return compress(bytearray(data))


if __name__ == "__main__":
    import sys
    from lzss import lzss_decompress
    xml = open(sys.argv[1], "rb").read()
    C = lzss_compress(xml)
    back, _ = lzss_decompress(C)
    sys.stderr.write(f"xml={len(xml)}  C={len(C)} ({len(C)/len(xml):.3f}x)  roundtrip={back.rstrip(bytes(1)) == xml.rstrip(bytes(1))}\n")
