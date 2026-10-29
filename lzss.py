#!/usr/bin/env python3
# Descompressor LZSS do TP-Link (cen_uncompressBuff/0x1e1f0 do libcutil), portado do ARM.
# Formato: o buffer DES-decifrado = [4 bytes LE = tamanho descomprimido][stream LZSS].
# Leitor de bits: palavras de 16 bits LE, bits consumidos do MSB (bit15), refill a cada 16.
# get_value: val=1; repeat { val=val*2+bit } while(cont_bit==1).
# 1 bit de controlo: 0=literal (1 byte do stream), 1=match.
# match: length=get_value()+2 ; dist=((get_value()-2)<<8)+byte_raw+1 ; copia 'length' de (dp-dist).

def lzss_decompress(plain):
    expected = int.from_bytes(plain[:4], "little")
    src = plain[4:]
    sp = 0
    out = bytearray()
    bitbuf = 0
    bitcnt = 0

    def get_bit():
        nonlocal sp, bitbuf, bitcnt
        cnt = bitcnt
        bitcnt = cnt - 1
        if cnt == 0:
            bitbuf = src[sp] | (src[sp + 1] << 8)
            sp += 2
            bitcnt = 0xf
        bit = (bitbuf >> 15) & 1
        bitbuf = (bitbuf << 1) & 0xffffffff
        return bit

    def get_value():
        val = 1
        while True:
            val = val * 2 + get_bit()
            if get_bit() == 0:
                break
        return val

    # primeiro byte: literal direto
    out.append(src[sp]); sp += 1
    while len(out) < expected:
        if get_bit() == 0:
            out.append(src[sp]); sp += 1                 # literal
        else:
            length = get_value() + 2                      # match
            dist = ((get_value() - 2) << 8) + src[sp] + 1
            sp += 1
            start = len(out) - dist
            for k in range(length):
                out.append(out[start + k])
    return bytes(out), expected


if __name__ == "__main__":
    import sys
    plain = open(sys.argv[1], "rb").read()
    xml, exp = lzss_decompress(plain)
    sys.stderr.write(f"expected={exp} got={len(xml)}\n")
    sys.stdout.buffer.write(xml)
