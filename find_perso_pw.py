#!/usr/bin/env python3
"""
find_perso_pw.py -- locate the network-personalization ("PN") unlock password that
the TP-Link `mobile` daemon uses, in YOUR OWN extracted binary.

Some ISP builds (and newer modem firmwares shipped by OTA, e.g. the RG520N A06 in
the NX511v 1.26.0 build) arm a network-personalization lock on the modem. A foreign
SIM then can't even register: `AT+CPIN?` returns `PH-NET PIN` and
`AT+QSIMLOCK?` reports `"PN",<n>` (locked). The daemon knows how to clear it -- it
sends `AT+QSIMLOCK="PN","<password>"` -- but only for a home-operator SIM.

This tool disassembles your binary, finds the `AT+QSIMLOCK="PN","%s"` format string
and the string constant the surrounding code feeds as that `%s`. That constant is the
unlock password. It then prints the exact AT command to run on your own device.

    python3 find_perso_pw.py /path/to/your/mobile

Nothing here is operator- or firmware-specific: it reads the password out of the
binary you supply. Requires: capstone (`pip install --user capstone`).
Target: 32-bit ARM `mobile` (the NX5xx builds). Right-to-repair: your device, your SIM.
"""
import sys, struct
try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_OP_REG, CS_OP_MEM
    from capstone.arm_const import ARM_REG_PC
except ImportError:
    sys.exit("need capstone:  pip install --user capstone")

if len(sys.argv) != 2:
    sys.exit(__doc__)
data = open(sys.argv[1], "rb").read()
if data[:4] != b"\x7fELF" or data[4] != 1:
    sys.exit("not a 32-bit ELF")

# --- section headers (ELF32) ---
e_shoff   = struct.unpack_from("<I", data, 0x20)[0]
e_shentsz = struct.unpack_from("<H", data, 0x2e)[0]
e_shnum   = struct.unpack_from("<H", data, 0x30)[0]
e_shstrndx= struct.unpack_from("<H", data, 0x32)[0]
secs = []
for i in range(e_shnum):
    b = e_shoff + i * e_shentsz
    nm, typ, flags, addr, off, size = struct.unpack_from("<IIIIII", data, b)
    secs.append([nm, addr, off, size])
shstr = secs[e_shstrndx][2]
def sname(n):
    e = data.find(b"\x00", shstr + n); return data[shstr + n:e].decode("latin1", "replace")
text = rodata = None
for nm, addr, off, size in secs:
    if sname(nm) == ".text":   text   = (addr, off, size)
    if sname(nm) == ".rodata": rodata = (addr, off, size)
if not text:
    sys.exit("no .text section")
TVA, TOFF, TSZ = text

def va2off(va):
    for nm, addr, off, size in secs:
        if size and addr <= va < addr + size:
            return va - addr + off
    return None
def rd_str(va, maxlen=64):
    o = va2off(va)
    if o is None: return None
    e = data.find(b"\x00", o)
    return data[o:e].decode("latin1", "replace")[:maxlen]
def find_str(needle):
    if not rodata: return []
    rva, roff, rsz = rodata
    blob = data[roff:roff + rsz]; out = []; i = 0
    nb = needle.encode()
    while True:
        i = blob.find(nb, i)
        if i < 0: break
        # must be start of a C string (preceded by NUL) to get its address right
        if i == 0 or blob[i-1] == 0:
            out.append(rva + i)
        i += 1
    return out

UNLOCK_FMT = 'AT+QSIMLOCK="PN","%s"'
# the lock-format string (...,"%s",%d,"%s") has UNLOCK_FMT as a prefix, so keep
# only addresses whose full C string equals the unlock format exactly.
unlock_addrs = [a for a in find_str(UNLOCK_FMT) if rd_str(a) == UNLOCK_FMT]
if not unlock_addrs:
    sys.exit('this binary has no  AT+QSIMLOCK="PN","%s"  string -- no perso-unlock path here.')

# --- disassemble .text, resolve PIE string refs: ldr rX,[pc,#imm] + add rX,pc,rX ---
md = Cs(CS_ARCH_ARM, CS_MODE_ARM); md.detail = True
blob = data[TOFF:TOFF + TSZ]
ldrs = {}   # instr_addr -> (reg, loaded_word)
adds = []   # (instr_addr, reg)
for o in range(0, len(blob) - 3, 4):
    for ins in md.disasm(blob[o:o+4], TVA + o, count=1):
        ops = ins.operands
        if ins.mnemonic == "ldr" and len(ops) == 2 and ops[1].type == CS_OP_MEM \
           and ops[1].mem.base == ARM_REG_PC:
            lit = ((ins.address + 8) & ~3) + ops[1].mem.disp
            lo = lit - TVA + TOFF
            if 0 <= lo <= len(data) - 4:
                ldrs[ins.address] = (ops[0].reg, struct.unpack_from("<i", data, lo)[0])
        elif ins.mnemonic == "add" and len(ops) == 3 and ops[0].type == CS_OP_REG \
             and ops[1].type == CS_OP_REG and ops[1].reg == ARM_REG_PC \
             and ops[2].type == CS_OP_REG and ops[0].reg == ops[2].reg:
            adds.append((ins.address, ops[0].reg))
        break

# resolved ref site -> target va
refs = []   # (add_addr, target_va)
for aa, rd in adds:
    best = None
    for la, (lr, w) in ldrs.items():
        if lr == rd and 0 <= aa - la <= 40 and (best is None or la > best[0]):
            best = (la, w)
    if best:
        refs.append((aa, (best[1] + aa + 8) & 0xffffffff))
refs.sort()

def looks_like_pw(s):
    return s and 4 <= len(s) <= 24 and all(32 < ord(c) < 127 for c in s) \
           and not s.startswith("AT+") and "%" not in s and " " not in s

print(f"[.text @0x{TVA:x}  refs resolved: {len(refs)}]")
print(f"found {len(unlock_addrs)} unlock-format string(s): " +
      ", ".join(hex(a) for a in unlock_addrs))
found = []
for ua in unlock_addrs:
    # the password is the string referenced just before the unlock-format string
    idxs = [i for i, (_, t) in enumerate(refs) if t == ua]
    for i in idxs:
        for j in range(i - 1, max(-1, i - 6), -1):
            s = rd_str(refs[j][1])
            if looks_like_pw(s):
                found.append((s, refs[i][0]))
                print(f"\n  unlock site @0x{refs[i][0]:x}")
                print(f"  password constant @0x{refs[j][1]:x}  ->  \"{s}\"")
                break
if not found:
    sys.exit("\ncould not resolve the password constant automatically; "
             "inspect the bytes around the unlock-format string by hand.")
pw = found[0][0]
print("\n================  RESULT  ================")
print(f'perso unlock password : "{pw}"')
print(f'run on your device    : /usr/sbin/mobile_cli send_at_cmd \'AT+QSIMLOCK="PN","{pw}"\'')
print("then verify           : AT+QSIMLOCK?  (no \"PN\" line) and AT+CPIN?  (READY)")
