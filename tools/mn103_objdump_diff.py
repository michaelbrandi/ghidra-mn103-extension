#!/usr/bin/env python3
"""Differential disassembly: compare Ghidra's dump against objdump for the
identical raw byte stream, keyed by address. Reports honest agreement rates.

Ghidra dump lines:  D|<hexaddr>|<hexbytes>|<mnemonic operands>
objdump lines (from -b binary -m mn10300 -D): "  <addr>:\t<hex bytes>\t<insn>"
"""
import re, sys, collections

def norm_operand(s):
    s = s.strip().lower()
    s = s.split(';')[0].split('#')[0]
    s = s.replace(' ', '')
    # MN10300 A-register 3 is the stack pointer: objdump prints "a3", Ghidra "sp".
    # They denote the same register; treat as equal.
    s = re.sub(r'\ba3\b', 'sp', s)
    # Normalize every integer literal (hex OR signed decimal) to a canonical
    # signed value, so 0x99 == 153 and -0x71 == -113 compare equal.
    def numnorm(m):
        tok = m.group(0)
        neg = tok.startswith('-')
        body = tok[1:] if neg else tok
        try:
            v = int(body, 16) if body.startswith('0x') else int(body, 10)
        except ValueError:
            return tok
        if neg:
            v = -v
        # fold to signed 32-bit for consistent representation of e.g. 0xfffffff9 vs -7
        v &= 0xffffffff
        if v >= 0x80000000:
            v -= 0x100000000
        return str(v)
    s = re.sub(r'-?0x[0-9a-f]+|-?\b[0-9]+\b', numnorm, s)
    return s

def split_mn(insn):
    insn = insn.strip()
    if not insn:
        return ('', '')
    parts = insn.split(None, 1)
    mn = parts[0].lower()
    ops = parts[1] if len(parts) > 1 else ''
    return (mn, norm_operand(ops))

def load_ghidra(path):
    out = {}
    for line in open(path):
        if not line.startswith('D|'):
            continue
        _, addr, hexb, insn = line.rstrip('\n').split('|', 3)
        insn = re.sub(r'\s*\(GhidraScript\)\s*$', '', insn)
        out[int(addr, 16)] = (hexb.lower(), split_mn(insn))
    return out

def load_objdump(path):
    out = {}
    # lines like:  "   10:\t70       \tmov (a0),d0"
    pat = re.compile(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$')
    for line in open(path):
        m = pat.match(line.rstrip('\n'))
        if not m:
            continue
        addr = int(m.group(1), 16)
        hexb = m.group(2).replace(' ', '').lower()
        insn = m.group(3)
        # objdump appends things after tab-less; strip trailing whitespace
        out[addr] = (hexb, split_mn(insn))
    return out

def main():
    g = load_ghidra(sys.argv[1])
    o = load_objdump(sys.argv[2])
    common = sorted(set(g) & set(o))
    boundary_only_g = sorted(set(g) - set(o))
    boundary_only_o = sorted(set(o) - set(g))

    n = len(common)
    same_len = mn_match = full_match = 0
    mismatches = []
    for a in common:
        gh_b, (gh_mn, gh_ops) = g[a]
        ob_b, (ob_mn, ob_ops) = o[a]
        if len(gh_b) == len(ob_b):
            same_len += 1
        if gh_mn == ob_mn:
            mn_match += 1
            if gh_ops == ob_ops:
                full_match += 1
            else:
                mismatches.append(('OPERANDS', a, ob_mn, ob_ops, gh_ops, ob_b, gh_b))
        else:
            mismatches.append(('MNEMONIC', a, ob_mn, ob_ops, gh_mn+' '+gh_ops, ob_b, gh_b))

    print(f"=== differential summary ===")
    print(f"addresses where both decoded an instruction: {n}")
    print(f"ghidra-only boundary starts (objdump split differently): {len(boundary_only_g)}")
    print(f"objdump-only boundary starts: {len(boundary_only_o)}")
    if n:
        print(f"same instruction length:     {same_len}/{n} = {100.0*same_len/n:.2f}%")
        print(f"mnemonic agreement:          {mn_match}/{n} = {100.0*mn_match/n:.2f}%")
        print(f"full (mnemonic+operand):     {full_match}/{n} = {100.0*full_match/n:.2f}%")

    # top mnemonic-level disagreements by objdump mnemonic
    mnk = collections.Counter(m[2] for m in mismatches if m[0]=='MNEMONIC')
    print("\n=== top MNEMONIC disagreements (objdump mnemonic -> count) ===")
    for mn, c in mnk.most_common(25):
        print(f"  {mn:12s} {c}")
    print("\n=== sample mismatches (kind addr objdump | ghidra | bytes) ===")
    for kind, a, omn, oops, gh, ob_b, gh_b in mismatches[:40]:
        print(f"  {kind} {a:08x}  objdump='{omn} {oops}'  ghidra='{gh}'  ob_bytes={ob_b} gh_bytes={gh_b}")

    # write full mismatch list
    with open(sys.argv[3], 'w') as f:
        for kind, a, omn, oops, gh, ob_b, gh_b in mismatches:
            f.write(f"{kind}|{a:08x}|objdump={omn} {oops}|ghidra={gh}|ob={ob_b}|gh={gh_b}\n")
    print(f"\nfull mismatch list -> {sys.argv[3]} ({len(mismatches)} entries)")

if __name__ == '__main__':
    main()
