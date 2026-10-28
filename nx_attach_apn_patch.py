#!/usr/bin/env python3
"""
nx_attach_apn_patch.py  --  TP-Link NX5xxv "mobile" daemon: initial-attach APN patcher.

WHAT IT DOES
  ISP-branded (e.g. SFR) builds of the NX511v / NX510v firmware make the 5G/LTE
  *initial attach* (PDN context 1) use a BLANK APN on purpose. With a non-home SIM
  (e.g. MEO) the network then grants only a "signalling" bearer -> no Internet.
  This tool finds, in YOUR OWN extracted `/usr/sbin/mobile` binary, the three code
  paths of the attach-profile builder that set the attach APN to "" and rewrites
  them to use a real APN (default "internet"), so the attach gets a real data bearer.

WHAT IT DOES *NOT* DO
  - It does not touch firmware signing, nor let you reflash a modified image
    (the flash is gated by RSA + OEM-ID; this patch is applied/loaded at RUNTIME).
  - It ships NO vendor binaries. You run it on the binary you extracted yourself.

USAGE
  python3 nx_attach_apn_patch.py mobile                 # dry-run: show what it would do
  python3 nx_attach_apn_patch.py mobile -o mobile.patched --apply
  python3 nx_attach_apn_patch.py mobile --apn internet  --apply

REQUIREMENTS
  python3, capstone  (pip install --user capstone)

TESTED
  NX511v 1.10.0 Build 240419 (SFR).  Same functions present in 1.26.0 and NX510v 1.2.0.
  On other versions, always review the dry-run output before --apply.
"""
import sys, struct, argparse
try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_AC_WRITE
    from capstone.arm import (ARM_OP_REG, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC,
                              ARM_REG_R0, ARM_REG_R1)
except ImportError:
    sys.exit("capstone required:  pip install --user capstone")

# --- ARM register-id -> register number map (capstone ids are not 0..15) ---
from capstone.arm import (ARM_REG_R0 as _R0, ARM_REG_R1 as _R1, ARM_REG_R2,
    ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_R8,
    ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12, ARM_REG_SP, ARM_REG_LR,
    ARM_REG_PC as _PC)
REGNUM = {_R0:0,_R1:1,ARM_REG_R2:2,ARM_REG_R3:3,ARM_REG_R4:4,ARM_REG_R5:5,
    ARM_REG_R6:6,ARM_REG_R7:7,ARM_REG_R8:8,ARM_REG_R9:9,ARM_REG_R10:10,
    ARM_REG_R11:11,ARM_REG_R12:12,ARM_REG_SP:13,ARM_REG_LR:14,_PC:15}


class ELF:
    def __init__(self, data):
        self.data = data
        assert data[:4] == b'\x7fELF', "not an ELF"
        assert data[4] == 1, "only 32-bit ELF supported"
        e = '<' if data[5] == 1 else '>'
        (self.e_type, self.e_machine, _v, self.e_entry, _ph, self.e_shoff,
         _fl, _eh, _phe, _phn, she, shn, shstr) = struct.unpack_from(e+'HHIIIIIHHHHHH', data, 16)
        assert self.e_machine == 40, "not ARM (EM_ARM)"
        self.sections = []
        for i in range(shn):
            off = self.e_shoff + i*she
            name, stype, flags, addr, offset, size, *_ = struct.unpack_from(e+'IIIIIIIIII', data, off)
            self.sections.append(dict(nameoff=name, type=stype, addr=addr, offset=offset, size=size))
        s = self.sections[shstr]
        tab = data[s['offset']:s['offset']+s['size']]
        for sec in self.sections:
            end = tab.find(b'\0', sec['nameoff'])
            sec['name'] = tab[sec['nameoff']:end].decode('latin1')
        self.by_name = {s['name']: s for s in self.sections}

    def sec(self, n): return self.by_name[n]
    def vaddr_to_off(self, va):
        for s in self.sections:
            if s['addr'] and s['addr'] <= va < s['addr']+s['size'] and s['type'] != 8:
                return s['offset'] + (va - s['addr'])
        return None
    def byte_at(self, va):
        o = self.vaddr_to_off(va)
        return None if o is None else self.data[o]
    def read_cstr(self, va, maxlen=64):
        o = self.vaddr_to_off(va)
        if o is None: return b''
        end = self.data.find(b'\0', o, o+maxlen)
        return self.data[o:end if end >= 0 else o+maxlen]


class Analyzer:
    """Decode .text word-aligned (ARM is fixed 4-byte -> no literal-pool desync)
       and resolve PIC string-pointer loads: ldr[pc]+add-pc, movw/movt+add-pc."""
    def __init__(self, elf):
        self.e = elf
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM); self.md.detail = True
        t = elf.sec('.text'); self.base = t['addr']
        self.blob = elf.data[t['offset']:t['offset']+t['size']]
        self.ins = {}
        for off in range(0, len(self.blob) & ~3, 4):
            va = self.base + off
            i = next(self.md.disasm(self.blob[off:off+4], va), None)
            if i is not None: self.ins[va] = i
        self._resolve()

    def _rdword(self, va):
        o = self.e.vaddr_to_off(va)
        return None if o is None else struct.unpack_from('<I', self.e.data, o)[0]

    def _resolve(self):
        # refs: list of dicts {add_va,target,dst,literal_va}
        self.refs = []
        regs = {}  # reg -> (value, literal_va_or_None)
        for va in sorted(self.ins):
            ins = self.ins[va]; m = ins.mnemonic; ops = ins.operands
            if m in ('push', 'stmdb') and 'lr' in ins.op_str:
                regs = {}
            try:
                if m == 'ldr' and len(ops) == 2 and ops[1].type == ARM_OP_MEM and ops[1].mem.base == ARM_REG_PC:
                    lit = (va + 8 + ops[1].mem.disp) & 0xffffffff
                    w = self._rdword(lit)
                    if w is not None: regs[ops[0].reg] = (w, lit)
                    continue
                if m == 'movw' and ops[1].type == ARM_OP_IMM:
                    regs[ops[0].reg] = (ops[1].imm & 0xffff, None); continue
                if m == 'movt' and ops[1].type == ARM_OP_IMM:
                    lo = regs.get(ops[0].reg, (0, None))[0] & 0xffff
                    regs[ops[0].reg] = (((ops[1].imm & 0xffff) << 16) | lo, None); continue
                if m == 'add':
                    rs = [o.reg for o in ops if o.type == ARM_OP_REG]
                    if ARM_REG_PC in rs:
                        dst = ops[0].reg
                        others = [o.reg for o in ops[1:] if o.type == ARM_OP_REG and o.reg != ARM_REG_PC]
                        src = others[0] if others else dst
                        if src in regs:
                            val, litva = regs[src]
                            target = (val + va + 8) & 0xffffffff
                            regs[dst] = (target, None)
                            self.refs.append(dict(add_va=va, target=target, dst=dst, literal_va=litva))
                        continue
                    if len(ops) == 3 and ops[2].type == ARM_OP_IMM and ops[1].type == ARM_OP_REG and ops[1].reg in regs:
                        v, l = regs[ops[1].reg]; regs[ops[0].reg] = ((v + ops[2].imm) & 0xffffffff, None); continue
                if m == 'mov' and len(ops) == 2 and ops[1].type == ARM_OP_REG:
                    regs[ops[0].reg] = regs.get(ops[1].reg, (0, None)); continue
                if ops and ops[0].type == ARM_OP_REG and (ops[0].access & CS_AC_WRITE):
                    regs.pop(ops[0].reg, None)
            except Exception:
                pass

    def next_ins(self, va): return self.ins.get(va)


def find_free_space(elf, need):
    s = elf.sec('.rodata'); off = s['offset']; va0 = s['addr']; d = elf.data
    # collect ref targets to avoid (approx: any .rodata addr referenced)
    runs = []; i = off; end = off + s['size']
    while i < end:
        if d[i] == 0:
            j = i
            while j < end and d[j] == 0: j += 1
            if j - i >= need + 2: runs.append((va0 + (i - off), j - i))
            i = j
        else:
            i += 1
    return runs


BREAKERS = ('b', 'bx', 'pop', 'bl', 'blx')

def find_apn_sites(elf, an):
    """Return the APN-assignment sites in the attach-profile builder.
       Signature, tightly matched inside one basic block:
         load ptr to EMPTY string  ->  std::string construct (bl)
         ->  `add r0, rBase, #8`   (the APN field lives at struct+8; the FIRST
             field-store right after the construct must be #8, else it's
             user(+0x30)/password(+0x48) or unrelated -> rejected)."""
    sites = []
    for ref in an.refs:
        if elf.byte_at(ref['target']) != 0:           # empty-string targets only
            continue
        # 1) find the construct `bl` within a few instrs, tracking `mov r1,<dst>`
        bl_addr = None; mov_first_last = None
        cur = ref['add_va'] + 4
        for _ in range(6):
            ins = an.ins.get(cur)
            if ins is None: cur += 4; continue
            mn = ins.mnemonic; ops = ins.operands
            if mn == 'mov' and len(ops) == 2 and ops[0].type == ARM_OP_REG and \
               ops[0].reg == ARM_REG_R1 and ops[1].type == ARM_OP_REG and ops[1].reg == ref['dst']:
                mov_first_last = cur
            if mn == 'bl':
                bl_addr = cur; break
            if mn in BREAKERS:
                break
            cur += 4
        if bl_addr is None:
            continue
        # 2) the FIRST field-store after the bl decides: `add r0, rBase(!=sp), #imm`
        field_imm = None; cur = bl_addr + 4
        for _ in range(5):
            ins = an.ins.get(cur)
            if ins is None: cur += 4; continue
            mn = ins.mnemonic; ops = ins.operands
            if mn == 'add' and len(ops) == 3 and ops[0].type == ARM_OP_REG and \
               ops[0].reg == ARM_REG_R0 and ops[1].type == ARM_OP_REG and \
               ops[1].reg != ARM_REG_SP and ops[2].type == ARM_OP_IMM:
                field_imm = ops[2].imm; break
            if mn in BREAKERS:
                break
            cur += 4
        if field_imm != 8:                             # only the APN field (struct+8)
            continue
        form = 'cstr' if ref['dst'] == ARM_REG_R1 else ('firstlast' if mov_first_last else 'unknown')
        sites.append(dict(ref=ref, bl=bl_addr, form=form, mov_first_last=mov_first_last))
    return sites


def main():
    ap = argparse.ArgumentParser(description="Patch NX5xxv 'mobile' initial-attach APN.")
    ap.add_argument('input', help="path to the extracted /usr/sbin/mobile binary")
    ap.add_argument('-o', '--output', default=None, help="output path (default: <input>.patched)")
    ap.add_argument('--apn', default='internet', help="APN to inject (default: internet)")
    ap.add_argument('--apply', action='store_true', help="write the patched file (otherwise dry-run)")
    args = ap.parse_args()

    data = bytearray(open(args.input, 'rb').read())
    elf = ELF(bytes(data))
    an = Analyzer(elf)
    sites = find_apn_sites(elf, an)

    print("Found %d attach-APN assignment site(s):" % len(sites))
    for s in sites:
        r = s['ref']
        print("  @%08x  form=%-9s literal@%s  (sets APN field to \"\")"
              % (r['add_va'], s['form'],
                 ('%08x' % r['literal_va']) if r['literal_va'] else 'n/a'))
    if not sites:
        sys.exit("No sites found -- is this the 'mobile' daemon? Aborting.")
    if any(s['form'] == 'unknown' or s['ref']['literal_va'] is None for s in sites):
        sys.exit("Some sites use an unrecognised form (movw/movt or unknown). "
                 "Review manually; aborting to avoid a bad patch.")

    apn = args.apn.encode() + b'\x00'
    L = len(args.apn)
    # choose free space
    free = find_free_space(elf, len(apn))
    reftargets = {r['target'] for r in an.refs}
    S = None
    for va, n in free:
        cand = (va + 3) & ~3  # 4-align
        if cand + len(apn) <= va + n and not any(va - 4 <= t < cand + len(apn) for t in reftargets):
            S = cand; break
    if S is None:
        sys.exit("No free .rodata padding to inject the APN string; aborting.")
    print("Injecting %r at .rodata 0x%08x" % (args.apn, S))

    # apply to buffer
    o = elf.vaddr_to_off(S); data[o:o+len(apn)] = apn
    for s in sites:
        r = s['ref']; lit_off = elf.vaddr_to_off(r['literal_va'])
        if s['form'] == 'cstr':
            word = (S - (r['add_va'] + 8)) & 0xffffffff
            struct.pack_into('<I', data, lit_off, word)
        else:  # firstlast: last=S+L, and mov r1,dst -> sub r1,dst,#L
            word = ((S + L) - (r['add_va'] + 8)) & 0xffffffff
            struct.pack_into('<I', data, lit_off, word)
            srcnum = REGNUM[r['dst']]
            sub = 0xE2400000 | (srcnum << 16) | (1 << 12) | (L & 0xff)  # sub r1,<dst>,#L
            struct.pack_into('<I', data, elf.vaddr_to_off(s['mov_first_last']), sub)

    # verify
    elf2 = ELF(bytes(data)); an2 = Analyzer(elf2)
    ok = 0
    for s in sites:
        # re-find the ref at same add_va and check it now points to our APN
        for r in an2.refs:
            if r['add_va'] == s['ref']['add_va']:
                tgt = r['target'] - (L if s['form'] == 'firstlast' else 0)
                if elf2.read_cstr(tgt) == args.apn.encode():
                    ok += 1
                break
    print("Verification: %d/%d sites now resolve APN -> %r" % (ok, len(sites), args.apn))
    if ok != len(sites):
        sys.exit("Verification failed; NOT writing output.")

    if args.apply:
        out = args.output or (args.input + '.patched')
        open(out, 'wb').write(bytes(data))
        print("Wrote patched binary: %s" % out)
        print("Deploy at runtime (see README): push to /var/tmp, kill mobiledog+mobile, run it.")
    else:
        print("Dry-run OK. Re-run with --apply to write the patched file.")


if __name__ == '__main__':
    main()
