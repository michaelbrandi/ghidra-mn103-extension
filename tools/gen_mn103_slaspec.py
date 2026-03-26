#!/usr/bin/env python3
"""Generate an MN10300 SLEIGH spec from GNU binutils opcode tables.

The generated spec includes:
- Manual phase-2 control-flow constructors (branch/call/return) with p-code.
- Manual phase-3 core mov/add/sub/cmp constructors with operand rendering and
  baseline flag/ALU semantics for selected register/immediate forms.
- Manual phase-3.1 mov memory constructors for common base/stack/displacement
  forms with load/store p-code.
- Manual phase-3.2 advanced mov memory constructors for selected indexed/IMM32
  and AM33 R-register memory forms.
- Manual phase-3.3 advanced add/sub/cmp constructors (wide immediates, SP
  forms, and AM33 R-register forms).
- Manual phase-3.4 addc/subc/and/or/xor/not constructors for selected
  AM30/AM33 forms.
- Manual phase-3.5 AM33 mov memory edge constructors (MEMINC/RI/IMM32HI8 and
  SP variants) with post-increment behavior for MEMINC families.
- Manual phase-3.6 AM33 movbu/movhu memory constructors (including RI,
  IMM32HI8, and movhu MEMINC/MEMINC2 forms).
- Manual phase-3.7 non-AM33 movbu/movhu memory constructors (D0/D1/D2/S2/D4
  families).
- Manual phase-3.14 AM33_2 floating-point arithmetic/compare/convert
  constructors (selected semantics for the obvious float ops).
- Manual phase-3.15 AM33/AM33_2 mul/mac/dcpf constructors (operand rendering
  coverage).
- Manual phase-3.17 AM33 pair-op alias families (add/cmp/sub/mov with
  *_add/*_sub/*_cmp/*_mov/*_asr/*_lsr/*_asl).
- Manual phase-3.18 AM33 pair-op alias families (and/or/xor/swhw/sat16/dmach)
  plus D10 conditional `mov_l*` alias forms.
- Auto-generated fallback constructors for the remaining opcode patterns
  (mnemonic-first coverage while operand/p-code work is expanded).
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


OPCODE_ENTRY_RE = re.compile(
    r'\{\s*"([^"]+)",\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*'
    r'(FMT_[A-Z0-9]+),\s*([^,]+),\s*\{([^}]*)\}\s*\},'
)

MANUAL_MNEMONICS = {
    "beq",
    "bne",
    "bgt",
    "bge",
    "ble",
    "blt",
    "bhi",
    "bcc",
    "bls",
    "bcs",
    "bvc",
    "bvs",
    "bnc",
    "bns",
    "bra",
    "jmp",
    "call",
    "calls",
    "ret",
    "retf",
    "rets",
    "rti",
    "rtm",
}

MANUAL_KEYS = {
    # Phase 3: mov (core register/immediate/control-register forms).
    ("FMT_S1", 0x00008000, 0x0000F000),
    ("FMT_D0", 0x0000F1E0, 0x0000FFF0),
    ("FMT_D0", 0x0000F1D0, 0x0000FFF0),
    ("FMT_S1", 0x00009000, 0x0000F000),
    ("FMT_S0", 0x0000003C, 0x000000FC),
    ("FMT_D0", 0x0000F2F0, 0x0000FFF3),
    ("FMT_D0", 0x0000F2E4, 0x0000FFFC),
    ("FMT_D0", 0x0000F2F3, 0x0000FFF3),
    ("FMT_D0", 0x0000F2E0, 0x0000FFFC),
    ("FMT_D0", 0x0000F2F2, 0x0000FFF3),
    # add (core register/immediate forms).
    ("FMT_S0", 0x000000E0, 0x000000F0),
    ("FMT_D0", 0x0000F160, 0x0000FFF0),
    ("FMT_D0", 0x0000F150, 0x0000FFF0),
    ("FMT_D0", 0x0000F170, 0x0000FFF0),
    ("FMT_S1", 0x00002800, 0x0000FC00),
    ("FMT_S1", 0x00002000, 0x0000FC00),
    # sub (core register forms).
    ("FMT_D0", 0x0000F100, 0x0000FFF0),
    ("FMT_D0", 0x0000F120, 0x0000FFF0),
    ("FMT_D0", 0x0000F110, 0x0000FFF0),
    ("FMT_D0", 0x0000F130, 0x0000FFF0),
    # cmp (core register/immediate forms).
    ("FMT_S1", 0x0000A000, 0x0000F000),
    ("FMT_D0", 0x0000F1A0, 0x0000FFF0),
    ("FMT_D0", 0x0000F190, 0x0000FFF0),
    ("FMT_S1", 0x0000B000, 0x0000F000),
    # Phase 3.1: mov memory forms (base/sp/disp8/disp16/abs16).
    ("FMT_S0", 0x00000070, 0x000000F0),
    ("FMT_S1", 0x00005800, 0x0000FCFF),
    ("FMT_S2", 0x00300000, 0x00FC0000),
    ("FMT_D0", 0x0000F000, 0x0000FFF0),
    ("FMT_S1", 0x00005C00, 0x0000FCFF),
    ("FMT_D2", 0xFAA00000, 0xFFFC0000),
    ("FMT_S0", 0x00000060, 0x000000F0),
    ("FMT_S1", 0x00004200, 0x0000F3FF),
    ("FMT_S2", 0x00010000, 0x00F30000),
    ("FMT_D0", 0x0000F010, 0x0000FFF0),
    ("FMT_S1", 0x00004300, 0x0000F3FF),
    ("FMT_D2", 0xFA800000, 0xFFF30000),
    ("FMT_S1", 0x00005800, 0x0000FC00),
    ("FMT_S1", 0x00005C00, 0x0000FC00),
    ("FMT_S1", 0x00004200, 0x0000F300),
    ("FMT_S1", 0x00004300, 0x0000F300),
    ("FMT_D1", 0x00F80000, 0x00FFF000),
    ("FMT_D1", 0x00F82000, 0x00FFF000),
    ("FMT_D1", 0x00F81000, 0x00FFF000),
    ("FMT_D1", 0x00F83000, 0x00FFF000),
    ("FMT_D2", 0xFA000000, 0xFFF00000),
    ("FMT_D2", 0xFA200000, 0xFFF00000),
    ("FMT_D2", 0xFA100000, 0xFFF00000),
    ("FMT_D2", 0xFA300000, 0xFFF00000),
    # Phase 3.2: mov indexed/IMM32 and AM33 R-register memory forms.
    ("FMT_D0", 0x0000F300, 0x0000FFC0),
    ("FMT_D0", 0x0000F380, 0x0000FFC0),
    ("FMT_D0", 0x0000F340, 0x0000FFC0),
    ("FMT_D0", 0x0000F3C0, 0x0000FFC0),
    ("FMT_D4", 0xFCA40000, 0xFFFC0000),
    ("FMT_D4", 0xFCA00000, 0xFFFC0000),
    ("FMT_D4", 0xFC810000, 0xFFF30000),
    ("FMT_D4", 0xFC800000, 0xFFF30000),
    ("FMT_D6", 0x00F90A00, 0x00FFFF00),
    ("FMT_D6", 0x00F98A00, 0x00FFFF0F),
    ("FMT_D6", 0x00F91A00, 0x00FFFF00),
    ("FMT_D6", 0x00F99A00, 0x00FFFF0F),
    ("FMT_D7", 0xFB0E0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB1E0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB0A0000, 0xFFFF0000),
    ("FMT_D7", 0xFB1A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD0E0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD1E0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD0A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD1A0000, 0xFFFF0000),
    # Phase 3.3: add/sub/cmp advanced immediate + AM33 R-register forms.
    ("FMT_D1", 0x00F8FE00, 0x00FFFF00),
    ("FMT_D2", 0xFAC00000, 0xFFFC0000),
    ("FMT_D2", 0xFAD00000, 0xFFFC0000),
    ("FMT_D2", 0xFAFE0000, 0xFFFF0000),
    ("FMT_D6", 0x00F97800, 0x00FFFF00),
    ("FMT_D4", 0xFCC00000, 0xFFFC0000),
    ("FMT_D4", 0xFCD00000, 0xFFFC0000),
    ("FMT_D4", 0xFCFE0000, 0xFFFF0000),
    ("FMT_D7", 0xFB780000, 0xFFFF0000),
    ("FMT_D8", 0xFD780000, 0xFFFF0000),
    ("FMT_D9", 0xFE780000, 0xFFFF0000),
    ("FMT_D7", 0xFB7C0000, 0xFFFF000F),
    ("FMT_D6", 0x00F99800, 0x00FFFF00),
    ("FMT_D4", 0xFCC40000, 0xFFFC0000),
    ("FMT_D4", 0xFCD40000, 0xFFFC0000),
    ("FMT_D7", 0xFB980000, 0xFFFF0000),
    ("FMT_D8", 0xFD980000, 0xFFFF0000),
    ("FMT_D9", 0xFE980000, 0xFFFF0000),
    ("FMT_D7", 0xFB9C0000, 0xFFFF000F),
    ("FMT_D2", 0xFAC80000, 0xFFFC0000),
    ("FMT_D2", 0xFAD80000, 0xFFFC0000),
    ("FMT_D6", 0x00F9D800, 0x00FFFF00),
    ("FMT_D4", 0xFCC80000, 0xFFFC0000),
    ("FMT_D4", 0xFCD80000, 0xFFFC0000),
    ("FMT_D7", 0xFBD80000, 0xFFFF0000),
    ("FMT_D8", 0xFDD80000, 0xFFFF0000),
    ("FMT_D9", 0xFED80000, 0xFFFF0000),
    # Phase 3.4: addc/subc/and/or/xor/not advanced forms.
    ("FMT_D0", 0x0000F140, 0x0000FFF0),
    ("FMT_D6", 0x00F98800, 0x00FFFF00),
    ("FMT_D7", 0xFB880000, 0xFFFF0000),
    ("FMT_D8", 0xFD880000, 0xFFFF0000),
    ("FMT_D9", 0xFE880000, 0xFFFF0000),
    ("FMT_D7", 0xFB8C0000, 0xFFFF000F),
    ("FMT_D0", 0x0000F180, 0x0000FFF0),
    ("FMT_D6", 0x00F9A800, 0x00FFFF00),
    ("FMT_D7", 0xFBA80000, 0xFFFF0000),
    ("FMT_D8", 0xFDA80000, 0xFFFF0000),
    ("FMT_D9", 0xFEA80000, 0xFFFF0000),
    ("FMT_D7", 0xFBAC0000, 0xFFFF000F),
    ("FMT_D0", 0x0000F200, 0x0000FFF0),
    ("FMT_D1", 0x00F8E000, 0x00FFFC00),
    ("FMT_D2", 0xFAE00000, 0xFFFC0000),
    ("FMT_D6", 0x00F90900, 0x00FFFF00),
    ("FMT_D4", 0xFCE00000, 0xFFFC0000),
    ("FMT_D7", 0xFB090000, 0xFFFF0000),
    ("FMT_D8", 0xFD090000, 0xFFFF0000),
    ("FMT_D9", 0xFE090000, 0xFFFF0000),
    ("FMT_D7", 0xFB0D0000, 0xFFFF000F),
    ("FMT_D0", 0x0000F210, 0x0000FFF0),
    ("FMT_D1", 0x00F8E400, 0x00FFFC00),
    ("FMT_D2", 0xFAE40000, 0xFFFC0000),
    ("FMT_D6", 0x00F91900, 0x00FFFF00),
    ("FMT_D4", 0xFCE40000, 0xFFFC0000),
    ("FMT_D7", 0xFB190000, 0xFFFF0000),
    ("FMT_D8", 0xFD190000, 0xFFFF0000),
    ("FMT_D9", 0xFE190000, 0xFFFF0000),
    ("FMT_D7", 0xFB1D0000, 0xFFFF000F),
    ("FMT_D0", 0x0000F220, 0x0000FFF0),
    ("FMT_D2", 0xFAE80000, 0xFFFC0000),
    ("FMT_D6", 0x00F92900, 0x00FFFF00),
    ("FMT_D4", 0xFCE80000, 0xFFFC0000),
    ("FMT_D7", 0xFB290000, 0xFFFF0000),
    ("FMT_D8", 0xFD290000, 0xFFFF0000),
    ("FMT_D9", 0xFE290000, 0xFFFF0000),
    ("FMT_D7", 0xFB2D0000, 0xFFFF000F),
    ("FMT_D0", 0x0000F230, 0x0000FFFC),
    ("FMT_D6", 0x00F93900, 0x00FFFF00),
    # Phase 3.5: mov AM33 memory edge forms (MEMINC/RI/IMM32HI8 + SP forms).
    ("FMT_D6", 0x00F96A00, 0x00FFFF00),
    ("FMT_D6", 0x00F97A00, 0x00FFFF00),
    ("FMT_D7", 0xFB8E0000, 0xFFFF000F),
    ("FMT_D7", 0xFB9E0000, 0xFFFF000F),
    ("FMT_D7", 0xFB8A0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD8A0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB9A0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD9A0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB6A0000, 0xFFFF0000),
    ("FMT_D7", 0xFB7A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD6A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD7A0000, 0xFFFF0000),
    ("FMT_D9", 0xFE0E0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE1E0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE0A0000, 0xFFFF0000),
    ("FMT_D9", 0xFE1A0000, 0xFFFF0000),
    ("FMT_D9", 0xFE8A0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE9A0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE6A0000, 0xFFFF0000),
    ("FMT_D9", 0xFE7A0000, 0xFFFF0000),
    # Phase 3.6: movbu/movhu AM33 memory families.
    ("FMT_D6", 0x00F92A00, 0x00FFFF00),
    ("FMT_D6", 0x00F93A00, 0x00FFFF00),
    ("FMT_D6", 0x00F9AA00, 0x00FFFF0F),
    ("FMT_D6", 0x00F9BA00, 0x00FFFF0F),
    ("FMT_D7", 0xFB2A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD2A0000, 0xFFFF0000),
    ("FMT_D7", 0xFB3A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD3A0000, 0xFFFF0000),
    ("FMT_D7", 0xFBAA0000, 0xFFFF0F00),
    ("FMT_D8", 0xFDAA0000, 0xFFFF0F00),
    ("FMT_D7", 0xFBBA0000, 0xFFFF0F00),
    ("FMT_D8", 0xFDBA0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB2E0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD2E0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB3E0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD3E0000, 0xFFFF0F00),
    ("FMT_D7", 0xFBAE0000, 0xFFFF000F),
    ("FMT_D7", 0xFBBE0000, 0xFFFF000F),
    ("FMT_D9", 0xFE2A0000, 0xFFFF0000),
    ("FMT_D9", 0xFE3A0000, 0xFFFF0000),
    ("FMT_D9", 0xFEAA0000, 0xFFFF0F00),
    ("FMT_D9", 0xFEBA0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE2E0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE3E0000, 0xFFFF0F00),
    ("FMT_D6", 0x00F94A00, 0x00FFFF00),
    ("FMT_D6", 0x00F95A00, 0x00FFFF00),
    ("FMT_D6", 0x00F9CA00, 0x00FFFF0F),
    ("FMT_D6", 0x00F9DA00, 0x00FFFF0F),
    ("FMT_D6", 0x00F9EA00, 0x00FFFF00),
    ("FMT_D6", 0x00F9FA00, 0x00FFFF00),
    ("FMT_D7", 0xFB4A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD4A0000, 0xFFFF0000),
    ("FMT_D7", 0xFB5A0000, 0xFFFF0000),
    ("FMT_D8", 0xFD5A0000, 0xFFFF0000),
    ("FMT_D7", 0xFBCA0000, 0xFFFF0F00),
    ("FMT_D8", 0xFDCA0000, 0xFFFF0F00),
    ("FMT_D7", 0xFBDA0000, 0xFFFF0F00),
    ("FMT_D8", 0xFDDA0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB4E0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD4E0000, 0xFFFF0F00),
    ("FMT_D7", 0xFB5E0000, 0xFFFF0F00),
    ("FMT_D8", 0xFD5E0000, 0xFFFF0F00),
    ("FMT_D7", 0xFBCE0000, 0xFFFF000F),
    ("FMT_D7", 0xFBDE0000, 0xFFFF000F),
    ("FMT_D9", 0xFE4A0000, 0xFFFF0000),
    ("FMT_D9", 0xFE5A0000, 0xFFFF0000),
    ("FMT_D9", 0xFECA0000, 0xFFFF0F00),
    ("FMT_D9", 0xFEDA0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE4E0000, 0xFFFF0F00),
    ("FMT_D9", 0xFE5E0000, 0xFFFF0F00),
    ("FMT_D7", 0xFBEA0000, 0xFFFF0000),
    ("FMT_D7", 0xFBFA0000, 0xFFFF0000),
    ("FMT_D8", 0xFDEA0000, 0xFFFF0000),
    ("FMT_D8", 0xFDFA0000, 0xFFFF0000),
    ("FMT_D9", 0xFEEA0000, 0xFFFF0000),
    ("FMT_D9", 0xFEFA0000, 0xFFFF0000),
    # Phase 3.7: movbu/movhu non-AM33 memory families (D0/D1/D2/D4/S2).
    ("FMT_D0", 0x0000F040, 0x0000FFF0),
    ("FMT_D1", 0x00F84000, 0x00FFF000),
    ("FMT_D2", 0xFA400000, 0xFFF00000),
    ("FMT_D1", 0x00F8B800, 0x00FFFCFF),
    ("FMT_D1", 0x00F8B800, 0x00FFFC00),
    ("FMT_D2", 0xFAB80000, 0xFFFC0000),
    ("FMT_D0", 0x0000F400, 0x0000FFC0),
    ("FMT_S2", 0x00340000, 0x00FC0000),
    ("FMT_D0", 0x0000F050, 0x0000FFF0),
    ("FMT_D1", 0x00F85000, 0x00FFF000),
    ("FMT_D2", 0xFA500000, 0xFFF00000),
    ("FMT_D1", 0x00F89200, 0x00FFF3FF),
    ("FMT_D1", 0x00F89200, 0x00FFF300),
    ("FMT_D2", 0xFA920000, 0xFFF30000),
    ("FMT_D0", 0x0000F440, 0x0000FFC0),
    ("FMT_S2", 0x00020000, 0x00F30000),
    ("FMT_D4", 0xFC400000, 0xFFF00000),
    ("FMT_D4", 0xFCB80000, 0xFFFC0000),
    ("FMT_D4", 0xFCA80000, 0xFFFC0000),
    ("FMT_D4", 0xFC500000, 0xFFF00000),
    ("FMT_D4", 0xFC920000, 0xFFF30000),
    ("FMT_D4", 0xFC820000, 0xFFF30000),
    ("FMT_D0", 0x0000F060, 0x0000FFF0),
    ("FMT_D1", 0x00F86000, 0x00FFF000),
    ("FMT_D2", 0xFA600000, 0xFFF00000),
    ("FMT_D1", 0x00F8BC00, 0x00FFFCFF),
    ("FMT_D1", 0x00F8BC00, 0x00FFFC00),
    ("FMT_D2", 0xFABC0000, 0xFFFC0000),
    ("FMT_D0", 0x0000F480, 0x0000FFC0),
    ("FMT_S2", 0x00380000, 0x00FC0000),
    ("FMT_D0", 0x0000F070, 0x0000FFF0),
    ("FMT_D1", 0x00F87000, 0x00FFF000),
    ("FMT_D2", 0xFA700000, 0xFFF00000),
    ("FMT_D1", 0x00F89300, 0x00FFF3FF),
    ("FMT_D1", 0x00F89300, 0x00FFF300),
    ("FMT_D2", 0xFA930000, 0xFFF30000),
    ("FMT_D0", 0x0000F4C0, 0x0000FFC0),
    ("FMT_S2", 0x00030000, 0x00F30000),
    ("FMT_D4", 0xFC600000, 0xFFF00000),
    ("FMT_D4", 0xFCBC0000, 0xFFFC0000),
    ("FMT_D4", 0xFCAC0000, 0xFFFC0000),
    ("FMT_D4", 0xFC700000, 0xFFF00000),
    ("FMT_D4", 0xFC930000, 0xFFF30000),
    ("FMT_D4", 0xFC830000, 0xFFF30000),
    # Phase 3.8: movu/ext/clr/inc families.
    ("FMT_D7", 0xFB180000, 0xFFFF0000),
    ("FMT_D8", 0xFD180000, 0xFFFF0000),
    ("FMT_D9", 0xFE180000, 0xFFFF0000),
    ("FMT_D0", 0x0000F2D0, 0x0000FFFC),
    ("FMT_D6", 0x00F91800, 0x00FFFF00),
    ("FMT_D6", 0x00F92800, 0x00FFFF00),
    ("FMT_S0", 0x00000010, 0x000000FC),
    ("FMT_D6", 0x00F93800, 0x00FFFF00),
    ("FMT_S0", 0x00000014, 0x000000FC),
    ("FMT_D6", 0x00F94800, 0x00FFFF00),
    ("FMT_S0", 0x00000018, 0x000000FC),
    ("FMT_D6", 0x00F95800, 0x00FFFF00),
    ("FMT_S0", 0x0000001C, 0x000000FC),
    ("FMT_S0", 0x00000000, 0x000000F3),
    ("FMT_D6", 0x00F96800, 0x00FFFF00),
    ("FMT_S0", 0x00000040, 0x000000F3),
    ("FMT_S0", 0x00000041, 0x000000F3),
    ("FMT_D6", 0x00F9B800, 0x00FFFF00),
    ("FMT_S0", 0x00000050, 0x000000FC),
    ("FMT_D6", 0x00F9C800, 0x00FFFF00),
    # Phase 3.9: shift families (asr/lsr/asl).
    ("FMT_D0", 0x0000F2B0, 0x0000FFF0),
    ("FMT_D1", 0x00F8C800, 0x00FFFC00),
    ("FMT_D1", 0x00F8C801, 0x00FFFCFF),
    ("FMT_D6", 0x00F94900, 0x00FFFF00),
    ("FMT_D7", 0xFB490000, 0xFFFF0000),
    ("FMT_D7", 0xFB490001, 0xFFFF00FF),
    ("FMT_D8", 0xFD490000, 0xFFFF0000),
    ("FMT_D9", 0xFE490000, 0xFFFF0000),
    ("FMT_D7", 0xFB4D0000, 0xFFFF000F),
    ("FMT_D0", 0x0000F2A0, 0x0000FFF0),
    ("FMT_D1", 0x00F8C400, 0x00FFFC00),
    ("FMT_D1", 0x00F8C401, 0x00FFFCFF),
    ("FMT_D6", 0x00F95900, 0x00FFFF00),
    ("FMT_D7", 0xFB590000, 0xFFFF0000),
    ("FMT_D7", 0xFB590001, 0xFFFF00FF),
    ("FMT_D8", 0xFD590000, 0xFFFF0000),
    ("FMT_D9", 0xFE590000, 0xFFFF0000),
    ("FMT_D7", 0xFB5D0000, 0xFFFF000F),
    ("FMT_D0", 0x0000F290, 0x0000FFF0),
    ("FMT_D1", 0x00F8C000, 0x00FFFC00),
    ("FMT_D1", 0x00F8C001, 0x00FFFCFF),
    ("FMT_D6", 0x00F96900, 0x00FFFF00),
    ("FMT_D7", 0xFB690000, 0xFFFF0000),
    ("FMT_D7", 0xFB690001, 0xFFFF00FF),
    ("FMT_D8", 0xFD690000, 0xFFFF0000),
    ("FMT_D9", 0xFE690000, 0xFFFF0000),
    ("FMT_D7", 0xFB6D0000, 0xFFFF000F),
    # Phase 3.10: btst/bset/bclr families.
    ("FMT_D1", 0x00F8EC00, 0x00FFFC00),
    ("FMT_D2", 0xFAEC0000, 0xFFFC0000),
    ("FMT_D4", 0xFCEC0000, 0xFFFC0000),
    ("FMT_D7", 0xFBE90000, 0xFFFF0000),
    ("FMT_D8", 0xFDE90000, 0xFFFF0000),
    ("FMT_D9", 0xFEE90000, 0xFFFF0000),
    ("FMT_D3", 0xFE820000, 0xFFFF0000),
    ("FMT_D5", 0xFE020000, 0xFFFF0000),
    ("FMT_D2", 0xFAF80000, 0xFFFC0000),
    ("FMT_D0", 0x0000F080, 0x0000FFF0),
    ("FMT_D3", 0xFE800000, 0xFFFF0000),
    ("FMT_D5", 0xFE000000, 0xFFFF0000),
    ("FMT_D2", 0xFAF00000, 0xFFFC0000),
    ("FMT_D0", 0x0000F090, 0x0000FFF0),
    ("FMT_D3", 0xFE810000, 0xFFFF0000),
    ("FMT_D5", 0xFE010000, 0xFFFF0000),
    ("FMT_D2", 0xFAF40000, 0xFFFC0000),
    # Phase 3.11: cmp S0 non-equal register families.
    ("FMT_S0", 0x000000A0, 0x000000F0),
    ("FMT_S0", 0x000000B0, 0x000000F0),
    # Phase 3.12: remaining mov families (S0 no-match, system, wide immediate, and AM33 edge forms).
    ("FMT_S0", 0x00000080, 0x000000F0),
    ("FMT_S0", 0x00000090, 0x000000F0),
    ("FMT_D2", 0xFAB40000, 0xFFFC0000),
    ("FMT_D2", 0xFAB00000, 0xFFFC0000),
    ("FMT_D2", 0xFA910000, 0xFFF30000),
    ("FMT_D2", 0xFA900000, 0xFFF30000),
    ("FMT_D0", 0x0000F020, 0x0000FFFC),
    ("FMT_D0", 0x0000F024, 0x0000FFFC),
    ("FMT_D0", 0x0000F028, 0x0000FFFC),
    ("FMT_D0", 0x0000F02C, 0x0000FFFC),
    ("FMT_D0", 0x0000F030, 0x0000FFF3),
    ("FMT_D0", 0x0000F031, 0x0000FFF3),
    ("FMT_D0", 0x0000F032, 0x0000FFF3),
    ("FMT_D0", 0x0000F2EC, 0x0000FFFC),
    ("FMT_D0", 0x0000F2F1, 0x0000FFF3),
    ("FMT_D0", 0x0000F500, 0x0000FFC0),
    ("FMT_D0", 0x0000F540, 0x0000FFC0),
    ("FMT_D0", 0x0000F580, 0x0000FFC0),
    ("FMT_D0", 0x0000F5C0, 0x0000FFC0),
    ("FMT_D6", 0x00F90800, 0x00FFFF00),
    ("FMT_D6", 0x00F9E800, 0x00FFFF00),
    ("FMT_D6", 0x00F9F800, 0x00FFFF00),
    ("FMT_S2", 0x002C0000, 0x00FC0000),
    ("FMT_D4", 0xFCCC0000, 0xFFFC0000),
    ("FMT_S2", 0x00240000, 0x00FC0000),
    ("FMT_D4", 0xFCDC0000, 0xFFFC0000),
    ("FMT_D4", 0xFC000000, 0xFFF00000),
    ("FMT_D4", 0xFCB40000, 0xFFFC0000),
    ("FMT_D4", 0xFC200000, 0xFFF00000),
    ("FMT_D4", 0xFCB00000, 0xFFFC0000),
    ("FMT_D4", 0xFC100000, 0xFFF00000),
    ("FMT_D4", 0xFC910000, 0xFFF30000),
    ("FMT_D4", 0xFC300000, 0xFFF00000),
    ("FMT_D4", 0xFC900000, 0xFFF30000),
    ("FMT_D1", 0x00F8F000, 0x00FFFC00),
    ("FMT_D1", 0x00F8F400, 0x00FFFC00),
    ("FMT_D7", 0xFB080000, 0xFFFF0000),
    ("FMT_D8", 0xFD080000, 0xFFFF0000),
    ("FMT_D9", 0xFE080000, 0xFFFF0000),
    ("FMT_D7", 0xFBF80000, 0xFFFF0000),
    ("FMT_D8", 0xFDF80000, 0xFFFF0000),
    ("FMT_D9", 0xFEF80000, 0xFFFF0000),
    # Phase 3.13: fmov family (AM33_2).
    ("FMT_D6", 0x00F92000, 0x00FFFE00),
    ("FMT_D6", 0x00F92200, 0x00FFFE00),
    ("FMT_D6", 0x00F92400, 0x00FFFEF0),
    ("FMT_D6", 0x00F92600, 0x00FFFE00),
    ("FMT_D6", 0x00F93000, 0x00FFFD00),
    ("FMT_D6", 0x00F93100, 0x00FFFD00),
    ("FMT_D6", 0x00F93400, 0x00FFFD0F),
    ("FMT_D6", 0x00F93500, 0x00FFFD00),
    ("FMT_D6", 0x00F94000, 0x00FFFC00),
    ("FMT_D6", 0x00F9A000, 0x00FFFE01),
    ("FMT_D6", 0x00F9A200, 0x00FFFE01),
    ("FMT_D6", 0x00F9A400, 0x00FFFEF1),
    ("FMT_D6", 0x00F9B000, 0x00FFFD10),
    ("FMT_D6", 0x00F9B100, 0x00FFFD10),
    ("FMT_D6", 0x00F9B400, 0x00FFFD1F),
    ("FMT_D6", 0x00F9B500, 0x00FFFF0F),
    ("FMT_D6", 0x00F9B700, 0x00FFFFF0),
    ("FMT_D6", 0x00F9C000, 0x00FFFC11),
    ("FMT_D7", 0xFB200000, 0xFFFE0000),
    ("FMT_D7", 0xFB220000, 0xFFFE0000),
    ("FMT_D7", 0xFB240000, 0xFFFEF000),
    ("FMT_D7", 0xFB270000, 0xFFFF000D),
    ("FMT_D7", 0xFB300000, 0xFFFD0000),
    ("FMT_D7", 0xFB310000, 0xFFFD0000),
    ("FMT_D7", 0xFB340000, 0xFFFD0F00),
    ("FMT_D7", 0xFB370000, 0xFFFF000D),
    ("FMT_D7", 0xFB470000, 0xFFFF001D),
    ("FMT_D7", 0xFB570000, 0xFFFF001D),
    ("FMT_D7", 0xFBA00000, 0xFFFE0100),
    ("FMT_D7", 0xFBA20000, 0xFFFE0100),
    ("FMT_D7", 0xFBA40000, 0xFFFEF100),
    ("FMT_D7", 0xFBB00000, 0xFFFD1000),
    ("FMT_D7", 0xFBB10000, 0xFFFD1000),
    ("FMT_D7", 0xFBB40000, 0xFFFD1F00),
    ("FMT_D8", 0xFD200000, 0xFFFE0000),
    ("FMT_D8", 0xFD220000, 0xFFFE0000),
    ("FMT_D8", 0xFD240000, 0xFFFEF000),
    ("FMT_D8", 0xFD300000, 0xFFFD0000),
    ("FMT_D8", 0xFD310000, 0xFFFD0000),
    ("FMT_D8", 0xFD340000, 0xFFFD0F00),
    ("FMT_D8", 0xFDA00000, 0xFFFE0100),
    ("FMT_D8", 0xFDA20000, 0xFFFE0100),
    ("FMT_D8", 0xFDA40000, 0xFFFEF100),
    ("FMT_D8", 0xFDB00000, 0xFFFD1000),
    ("FMT_D8", 0xFDB10000, 0xFFFD1000),
    ("FMT_D8", 0xFDB40000, 0xFFFD1F00),
    ("FMT_D4", 0xFDB50000, 0xFFFF0000),
    ("FMT_D9", 0xFE200000, 0xFFFE0000),
    ("FMT_D9", 0xFE220000, 0xFFFE0000),
    ("FMT_D9", 0xFE240000, 0xFFFEF000),
    ("FMT_D9", 0xFE260000, 0xFFFEF000),
    ("FMT_D9", 0xFE300000, 0xFFFD0000),
    ("FMT_D9", 0xFE310000, 0xFFFD0000),
    ("FMT_D9", 0xFE340000, 0xFFFD0F00),
    ("FMT_D9", 0xFE400000, 0xFFFE0100),
    ("FMT_D9", 0xFE420000, 0xFFFE0100),
    ("FMT_D9", 0xFE440000, 0xFFFEF100),
    ("FMT_D9", 0xFE500000, 0xFFFD1000),
    ("FMT_D9", 0xFE510000, 0xFFFD1000),
    ("FMT_D9", 0xFE540000, 0xFFFD1F00),
}


@dataclass(frozen=True)
class OpcodeEntry:
    name: str
    opcode: int
    mask: int
    no_match_operands: str
    fmt: str
    machine: str
    operands: str


def parse_int(text: str) -> int:
    return int(text.strip(), 0)


def parse_opcode_entries(opc_path: Path) -> List[OpcodeEntry]:
    text = opc_path.read_text(encoding="utf-8")
    try:
        body = text.split("const struct mn10300_opcode mn10300_opcodes[] = {", 1)[1]
        body = body.split("{ 0, 0, 0, 0, 0, 0, {0}},", 1)[0]
    except IndexError as exc:
        raise RuntimeError("Could not locate mn10300_opcodes table in source file") from exc

    entries: List[OpcodeEntry] = []
    for m in OPCODE_ENTRY_RE.finditer(body):
        name, opcode, mask, no_match, fmt, machine, operands = m.groups()
        entries.append(
            OpcodeEntry(
                name=name,
                opcode=parse_int(opcode),
                mask=parse_int(mask),
                no_match_operands=no_match.strip(),
                fmt=fmt.strip(),
                machine=machine.strip(),
                operands=operands.strip(),
            )
        )
    if not entries:
        raise RuntimeError("No opcode entries parsed; regex may be stale")
    return entries


def format_layout(entry: OpcodeEntry) -> Tuple[int, int, List[int]]:
    """Return (instr_len_bytes, insn_bit_width, insn_byte_map_low_to_high).

    insn_byte_map_low_to_high maps insn byte index [0..3] (LSB to MSB) to raw byte
    index within instruction stream.
    """

    fmt = entry.fmt
    opc = entry.opcode

    # 1-byte formats.
    if fmt == "FMT_S0":
        return 1, 8, [0]

    # 2-byte formats (big-endian opcode word in stream).
    if fmt in {"FMT_S1", "FMT_D0"}:
        return 2, 16, [1, 0]

    # 3-byte formats.
    if fmt in {"FMT_D1", "FMT_D6"}:
        return 3, 24, [2, 1, 0]
    if fmt == "FMT_S2":
        # Special opcodes keep the original big-endian low 16 bits.
        if opc in {0xDE0000, 0xDF0000}:
            return 3, 24, [2, 1, 0]
        # Default S2 rewrite swaps low-16 bit order via little-endian read.
        return 3, 24, [1, 2, 0]

    # 4-byte formats.
    if fmt in {"FMT_D7", "FMT_D10"}:
        return 4, 32, [3, 2, 1, 0]
    if fmt == "FMT_D2":
        # Special AM33 opcodes skip low16 rewrite.
        if opc in {0xFAF80000, 0xFAF00000, 0xFAF40000}:
            return 4, 32, [3, 2, 1, 0]
        return 4, 32, [2, 3, 1, 0]

    # 5-byte formats.
    if fmt == "FMT_D3":
        return 5, 32, [2, 3, 1, 0]
    if fmt == "FMT_S4":
        # Special split-immediate case.
        if opc == 0xDC000000:
            return 5, 32, [2, 3, 4, 0]
        return 5, 32, [3, 1, 2, 0]

    # 6-byte formats.
    if fmt == "FMT_D4":
        return 6, 32, [4, 5, 1, 0]
    if fmt == "FMT_D8":
        return 6, 32, [5, 2, 1, 0]

    # 7-byte formats.
    if fmt == "FMT_D5":
        return 7, 32, [4, 5, 1, 0]
    if fmt == "FMT_D9":
        return 7, 32, [6, 2, 1, 0]
    if fmt == "FMT_S6":
        # S6 table entries use the 0xDD000000 style split encoding.
        return 7, 32, [2, 3, 4, 0]

    raise ValueError(f"Unsupported format: {fmt}")


def constructor_constraints(entry: OpcodeEntry) -> Tuple[int, Dict[int, List[Tuple[int, int]]]]:
    length, insn_bits, insn_map = format_layout(entry)
    constraints: Dict[int, List[Tuple[int, int]]] = {i: [] for i in range(length)}

    for insn_bit in range(insn_bits):
        if ((entry.mask >> insn_bit) & 1) == 0:
            continue
        insn_byte = insn_bit // 8
        raw_byte = insn_map[insn_byte]
        raw_bit = insn_bit & 7
        bit_val = (entry.opcode >> insn_bit) & 1
        constraints[raw_byte].append((raw_bit, bit_val))

    return length, constraints


def constraints_to_pattern(
    length: int,
    constraints: Dict[int, List[Tuple[int, int]]],
    extra: Dict[int, List[Tuple[int, int]]] | None = None,
) -> str:
    merged: Dict[int, Dict[int, int]] = {i: {} for i in range(length)}
    for raw_byte in range(length):
        for bit, val in constraints.get(raw_byte, []):
            merged[raw_byte][bit] = val
    if extra:
        for raw_byte, items in extra.items():
            for bit, val in items:
                merged[raw_byte][bit] = val

    parts: List[str] = []
    for raw_byte in range(length):
        c = merged[raw_byte]
        if not c:
            parts.append(f"b{raw_byte}_any")
            continue
        atoms = [f"b{raw_byte}_{bit}={val}" for bit, val in sorted(c.items(), reverse=True)]
        parts.append(" & ".join(atoms))
    return "; ".join(parts)


def sanitize_mnemonic(name: str) -> str:
    # Ghidra/SLEIGH constructor names are permissive for this set; keep as-is.
    return name


def needs_split_s0_non_equal(entry: OpcodeEntry) -> bool:
    return (
        entry.fmt == "FMT_S0"
        and entry.mask == 0xF0
        and (entry.opcode & 0xF0) in {0x80, 0x90, 0xA0, 0xB0}
    )


def needs_split_s1_equal(entry: OpcodeEntry) -> bool:
    return (
        entry.fmt == "FMT_S1"
        and entry.mask == 0xF000
        and (entry.opcode & 0xF000) in {0x8000, 0x9000, 0xA000, 0xB000}
    )


def render_slaspec(entries: List[OpcodeEntry]) -> str:
    # Keep first occurrence by (fmt, opcode, mask) to preserve table precedence.
    seen: set[Tuple[str, int, int]] = set()
    kept: List[OpcodeEntry] = []
    for e in entries:
        key = (e.fmt, e.opcode, e.mask)
        if key in seen:
            continue
        seen.add(key)
        kept.append(e)

    kept_by_key = {(e.fmt, e.opcode, e.mask): e for e in kept}

    lines: List[str] = []
    phase_manual_keys: set[Tuple[str, int, int]] = set()

    def append_keyed_constructor(
        head: str,
        key: Tuple[str, int, int],
        body: str = "{ }",
    ) -> None:
        entry = kept_by_key.get(key)
        if entry is None:
            raise RuntimeError(f"Manual constructor key not found in opcode table: {key}")
        length, base_constraints = constructor_constraints(entry)
        pattern = constraints_to_pattern(length, base_constraints)
        lines.append(f"{head} is {pattern} {body}")

    def assign_body(dest: str, expr: str) -> str:
        return f"{{ {dest} = {expr}; }}"

    def loop_back_body(cond: str | None) -> str:
        core = (
            "RREG_B3_HI = MEMINC2_SIMM4_RN4_D10; "
            "local inc:4 = sext(SIMM4_B2); "
            "RREG_B3_LO = RREG_B3_LO + inc; "
            "local loop_pc:4 = LAR - 4; "
        )
        if cond is None:
            return f"{{ {core} goto [loop_pc]; }}"
        return f"{{ {core} if ({cond}) goto [loop_pc]; }}"

    # Keep the post-increment bookkeeping centralized so the AM33 memory
    # families use the same displacement expressions everywhere.
    inc_simm8 = "sext(b3_simm)"
    inc_u24 = "zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16)"
    inc_u32 = "zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16) | (zext(b6_any) << 24)"
    postinc_rlo = "RREG_B2_LO = RREG_B2_LO + inc;"
    postinc_rhi = "RREG_B2_HI = RREG_B2_HI + inc;"

    lines.append("define endian=little;")
    lines.append("define alignment=1;")
    lines.append("")
    lines.append("define space ram      type=ram_space      size=4 default;")
    lines.append("define space register type=register_space size=4;")
    lines.append("")
    lines.append("define register offset=0  size=4 [ PC A0 A1 A2 SP D0 D1 D2 D3 ];")
    lines.append("define register offset=40 size=2 [ MDR PSW ];")
    lines.append("define register offset=48 size=4 [ R0 R1 R2 R3 R4 R5 R6 R7 ];")
    lines.append("define register offset=80 size=4 [ USP SSP MSP FPCR ];")
    lines.append("define register offset=96 size=2 [ EPSW ];")
    lines.append("define register offset=100 size=4 [ XR1 XR2 XR3 XR4 XR5 XR6 XR7 XR8 XR9 XR10 XR11 XR12 XR13 XR14 XR15 ];")
    lines.append("define register offset=160 size=4 [ FS0 FS1 FS2 FS3 FS4 FS5 FS6 FS7 FS8 FS9 FS10 FS11 FS12 FS13 FS14 FS15 FS16 FS17 FS18 FS19 FS20 FS21 FS22 FS23 FS24 FS25 FS26 FS27 FS28 FS29 FS30 FS31 ];")
    lines.append("define register offset=288 size=4 [ FD0 FD1 FD2 FD3 FD4 FD5 FD6 FD7 FD8 FD9 FD10 FD11 FD12 FD13 FD14 FD15 FD16 FD17 FD18 FD19 FD20 FD21 FD22 FD23 FD24 FD25 FD26 FD27 FD28 FD29 FD30 FD31 ];")
    lines.append("define register offset=416 size=4 [ LAR LIR ];")
    lines.append("")

    for i in range(7):
        lines.append(f"define token b{i} (8)")
        lines.append(f"    b{i}_any = (0,7)")
        lines.append(f"    b{i}_imm = (0,7) hex")
        lines.append(f"    b{i}_simm = (0,7) signed hex")
        lines.append(f"    b{i}_areg0 = (0,1)")
        lines.append(f"    b{i}_dlo = (0,1)")
        lines.append(f"    b{i}_dhi = (2,3)")
        lines.append(f"    b{i}_d2 = (4,5)")
        lines.append(f"    b{i}_alo = (0,1)")
        lines.append(f"    b{i}_ahi = (2,3)")
        lines.append(f"    b{i}_a2 = (4,5)")
        lines.append(f"    b{i}_rlo = (0,3)")
        lines.append(f"    b{i}_rhi = (4,7)")
        lines.append(f"    b{i}_rmid = (2,5)")
        lines.append(f"    b{i}_xrlo = (0,3)")
        lines.append(f"    b{i}_xrhi = (4,7)")
        lines.append(f"    b{i}_xrmid = (2,5)")
        lines.append(f"    b{i}_imm4lo = (0,3) hex")
        lines.append(f"    b{i}_imm4hi = (4,7) hex")
        lines.append(f"    b{i}_simm4lo = (0,3) signed hex")
        lines.append(f"    b{i}_simm4hi = (4,7) signed hex")
        lines.append(f"    b{i}_fsl0 = (0,3)")
        lines.append(f"    b{i}_fsh0 = (4,7)")
        lines.append(f"    b{i}_fsl1 = (0,3)")
        lines.append(f"    b{i}_fsh1 = (4,7)")
        lines.append(f"    b{i}_fdl0 = (0,3)")
        lines.append(f"    b{i}_fdh0 = (4,7)")
        lines.append(f"    b{i}_fdl1 = (0,3)")
        lines.append(f"    b{i}_fdh1 = (4,7)")
        for bit in range(8):
            lines.append(f"    b{i}_{bit} = ({bit},{bit})")
        lines.append(";")
        lines.append("")

    lines.append("attach variables [ b0_dlo b0_dhi b1_dlo b1_dhi ] [ D0 D1 D2 D3 ];")
    lines.append("attach variables [ b0_alo b0_ahi b1_alo b1_ahi b1_areg0 ] [ A0 A1 A2 SP ];")
    lines.append("attach variables [ b1_d2 ] [ D0 D1 D2 D3 ];")
    lines.append("attach variables [ b1_a2 ] [ A0 A1 A2 SP ];")
    lines.append(
        "attach variables [ b1_rlo b1_rhi b1_rmid b2_rlo b2_rhi b3_rlo b3_rhi ] "
        "[ R0 R1 R2 R3 R4 R5 R6 R7 A0 A1 A2 SP D0 D1 D2 D3 ];"
    )
    lines.append(
        "attach variables [ b1_xrlo b1_xrhi b1_xrmid b2_xrlo b2_xrhi b3_xrlo b3_xrhi ] "
        "[ SP XR1 XR2 XR3 XR4 XR5 XR6 XR7 XR8 XR9 XR10 XR11 XR12 XR13 XR14 XR15 ];"
    )
    lines.append(
        "attach variables [ b2_fsl0 b2_fsh0 b3_fsl0 b3_fsh0 ] "
        "[ FS0 FS1 FS2 FS3 FS4 FS5 FS6 FS7 FS8 FS9 FS10 FS11 FS12 FS13 FS14 FS15 ];"
    )
    lines.append(
        "attach variables [ b2_fsl1 b2_fsh1 b3_fsl1 b3_fsh1 ] "
        "[ FS16 FS17 FS18 FS19 FS20 FS21 FS22 FS23 FS24 FS25 FS26 FS27 FS28 FS29 FS30 FS31 ];"
    )
    lines.append(
        "attach variables [ b2_fdl0 b2_fdh0 b3_fdl0 b3_fdh0 ] "
        "[ FD0 FD1 FD2 FD3 FD4 FD5 FD6 FD7 FD8 FD9 FD10 FD11 FD12 FD13 FD14 FD15 ];"
    )
    lines.append(
        "attach variables [ b2_fdl1 b2_fdh1 b3_fdl1 b3_fdh1 ] "
        "[ FD16 FD17 FD18 FD19 FD20 FD21 FD22 FD23 FD24 FD25 FD26 FD27 FD28 FD29 FD30 FD31 ];"
    )
    lines.append("")
    lines.append('@define ZF \"PSW[0,1]\"')
    lines.append('@define NF \"PSW[1,1]\"')
    lines.append('@define CF \"PSW[2,1]\"')
    lines.append('@define VF \"PSW[3,1]\"')
    lines.append("")
    lines.append("# Phase 2: key control-flow operands + p-code")
    lines.append("")
    lines.append('IND_AREG_D0: \"(\"^b1_areg0^\")\" is b1_areg0 { export b1_areg0; }')
    lines.append(
        "PCREL8_S1: addr is b1_simm "
        "[ addr = inst_start + b1_simm; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        "PCREL8_D1: addr is b2_simm "
        "[ addr = inst_start + b2_simm; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        "PCREL16_S2: addr is b1_any; b2_simm "
        "[ addr = inst_start + (b1_any | (b2_simm << 8)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        "PCREL16_D2: addr is b2_any; b3_simm "
        "[ addr = inst_start + (b2_any | (b3_simm << 8)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        "PCREL32_S4: addr is b1_any; b2_any; b3_any; b4_simm "
        "[ addr = inst_start + (b1_any | (b2_any << 8) | "
        "(b3_any << 16) | (b4_simm << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        "CALL16_S4: addr is b1_any; b2_simm; b3_any; b4_any "
        "[ addr = inst_start + (b1_any | (b2_simm << 8)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        "PCREL32_D4: addr is b2_any; b3_any; b4_any; b5_simm "
        "[ addr = inst_start + (b2_any | (b3_any << 8) | "
        "(b4_any << 16) | (b5_simm << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        "CALL32_S6: addr is b1_any; b2_any; b3_any; b4_simm; b5_any; b6_any "
        "[ addr = inst_start + (b1_any | (b2_any << 8) | "
        "(b3_any << 16) | (b4_simm << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append("")
    lines.append(":beq PCREL8_S1 is b0_any=0xC8; PCREL8_S1 { if ($(ZF) == 1) goto PCREL8_S1; }")
    lines.append(":bne PCREL8_S1 is b0_any=0xC9; PCREL8_S1 { if ($(ZF) == 0) goto PCREL8_S1; }")
    lines.append(
        ":bgt PCREL8_S1 is b0_any=0xC1; PCREL8_S1 { "
        "if (($(ZF) == 0) && ((($(NF) == 1) ^ ($(VF) == 1)) == 0)) goto PCREL8_S1; }"
    )
    lines.append(
        ":bge PCREL8_S1 is b0_any=0xC2; PCREL8_S1 { "
        "if ((($(NF) == 1) ^ ($(VF) == 1)) == 0) goto PCREL8_S1; }"
    )
    lines.append(
        ":ble PCREL8_S1 is b0_any=0xC3; PCREL8_S1 { "
        "if (($(ZF) == 1) || (($(NF) == 1) ^ ($(VF) == 1))) goto PCREL8_S1; }"
    )
    lines.append(
        ":blt PCREL8_S1 is b0_any=0xC0; PCREL8_S1 { "
        "if (($(VF) == 1) ^ ($(NF) == 1)) goto PCREL8_S1; }"
    )
    lines.append(
        ":bhi PCREL8_S1 is b0_any=0xC5; PCREL8_S1 { "
        "if (($(CF) == 0) && ($(ZF) == 0)) goto PCREL8_S1; }"
    )
    lines.append(":bcc PCREL8_S1 is b0_any=0xC6; PCREL8_S1 { if ($(CF) == 0) goto PCREL8_S1; }")
    lines.append(
        ":bls PCREL8_S1 is b0_any=0xC7; PCREL8_S1 { "
        "if (($(CF) == 1) || ($(ZF) == 1)) goto PCREL8_S1; }"
    )
    lines.append(":bcs PCREL8_S1 is b0_any=0xC4; PCREL8_S1 { if ($(CF) == 1) goto PCREL8_S1; }")
    lines.append(":bvc PCREL8_D1 is b0_any=0xF8; b1_any=0xE8; PCREL8_D1 { if ($(VF) == 0) goto PCREL8_D1; }")
    lines.append(":bvs PCREL8_D1 is b0_any=0xF8; b1_any=0xE9; PCREL8_D1 { if ($(VF) == 1) goto PCREL8_D1; }")
    lines.append(":bnc PCREL8_D1 is b0_any=0xF8; b1_any=0xEA; PCREL8_D1 { if ($(NF) == 0) goto PCREL8_D1; }")
    lines.append(":bns PCREL8_D1 is b0_any=0xF8; b1_any=0xEB; PCREL8_D1 { if ($(NF) == 1) goto PCREL8_D1; }")
    lines.append(":bra PCREL8_S1 is b0_any=0xCA; PCREL8_S1 { goto PCREL8_S1; }")
    lines.append("")
    lines.append(
        ":jmp IND_AREG_D0 is b0_any=0xF0; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & IND_AREG_D0 { "
        "goto [IND_AREG_D0]; }"
    )
    lines.append(":jmp PCREL16_S2 is b0_any=0xCC; PCREL16_S2 { goto PCREL16_S2; }")
    lines.append(":jmp PCREL32_S4 is b0_any=0xDC; PCREL32_S4 { goto PCREL32_S4; }")
    lines.append("")
    lines.append(":call CALL16_S4 is b0_any=0xCD; CALL16_S4 { call CALL16_S4; }")
    lines.append(":call CALL32_S6 is b0_any=0xDD; CALL32_S6 { call CALL32_S6; }")
    lines.append(
        ":calls IND_AREG_D0 is b0_any=0xF0; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & IND_AREG_D0 { "
        "call [IND_AREG_D0]; }"
    )
    lines.append(":calls PCREL16_D2 is b0_any=0xFA; b1_any=0xFF; PCREL16_D2 { call PCREL16_D2; }")
    lines.append(":calls PCREL32_D4 is b0_any=0xFC; b1_any=0xFF; PCREL32_D4 { call PCREL32_D4; }")
    lines.append("")
    lines.append(":ret is b0_any=0xDF; b1_any; b2_any { return [SP]; }")
    lines.append(":retf is b0_any=0xDE; b1_any; b2_any { return [SP]; }")
    lines.append(":rets is b0_any=0xF0; b1_any=0xFC { return [SP]; }")
    lines.append(":rti is b0_any=0xF0; b1_any=0xFD { return [SP]; }")
    lines.append(":rtm is b0_any=0xF0; b1_any=0xFF { return [SP]; }")
    lines.append("")
    lines.append("# Phase 3: core mov/add/sub/cmp operand rendering + baseline semantics")
    lines.append("")
    lines.append("macro update_zn32(val) {")
    lines.append("    $(ZF) = (val == 0);")
    lines.append("    $(NF) = (val s< 0);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_bitop_flags32(val) {")
    lines.append("    $(CF) = 0;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(val);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_add32(dst, src) {")
    lines.append("    $(VF) = scarry(dst, src);")
    lines.append("    $(CF) = carry(dst, src);")
    lines.append("    dst = dst + src;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_sub32(dst, src) {")
    lines.append("    $(VF) = sborrow(dst, src);")
    lines.append("    $(CF) = (src > dst);")
    lines.append("    dst = dst - src;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_cmp32(a, b) {")
    lines.append("    $(VF) = sborrow(a, b);")
    lines.append("    $(CF) = (b > a);")
    lines.append("    local r:4 = a - b;")
    lines.append("    update_zn32(r);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_and32(dst, src) {")
    lines.append("    dst = dst & src;")
    lines.append("    $(CF) = 0;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_or32(dst, src) {")
    lines.append("    dst = dst | src;")
    lines.append("    $(CF) = 0;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_xor32(dst, src) {")
    lines.append("    dst = dst ^ src;")
    lines.append("    $(CF) = 0;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_not32(dst) {")
    lines.append("    dst = ~dst;")
    lines.append("    $(CF) = 0;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_asl32(dst, count) {")
    lines.append("    local sh:4 = count & 0x1f;")
    lines.append("    local old:4 = dst;")
    lines.append("    local nz:1 = sh != 0;")
    lines.append("    local cshift:4 = (32 - sh) & 0x1f;")
    lines.append("    local c:1 = (old >> cshift) & 1;")
    lines.append("    dst = old << sh;")
    lines.append("    $(CF) = c & nz;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_lsr32(dst, count) {")
    lines.append("    local sh:4 = count & 0x1f;")
    lines.append("    local old:4 = dst;")
    lines.append("    local nz:1 = sh != 0;")
    lines.append("    local cshift:4 = (sh - 1) & 0x1f;")
    lines.append("    local c:1 = (old >> cshift) & 1;")
    lines.append("    dst = old >> sh;")
    lines.append("    $(CF) = c & nz;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_asr32(dst, count) {")
    lines.append("    local sh:4 = count & 0x1f;")
    lines.append("    local old:4 = dst;")
    lines.append("    local nz:1 = sh != 0;")
    lines.append("    local cshift:4 = (sh - 1) & 0x1f;")
    lines.append("    local c:1 = (old >> cshift) & 1;")
    lines.append("    dst = old s>> sh;")
    lines.append("    $(CF) = c & nz;")
    lines.append("    $(VF) = 0;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_btst_reg32(bitidx, src) {")
    lines.append("    local bit:4 = bitidx & 0x1f;")
    lines.append("    local mask:4 = 1 << bit;")
    lines.append("    local result:4 = src & mask;")
    lines.append("    update_bitop_flags32(result);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_btst_mem8(bitidx, m) {")
    lines.append("    local bit:4 = bitidx & 7;")
    lines.append("    local mask:1 = 1 << bit;")
    lines.append("    local result:4 = zext(m) & zext(mask);")
    lines.append("    update_bitop_flags32(result);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_bset_mem8(bitidx, m) {")
    lines.append("    local bit:4 = bitidx & 7;")
    lines.append("    local mask:1 = 1 << bit;")
    lines.append("    local result:4 = zext(m) & zext(mask);")
    lines.append("    update_bitop_flags32(result);")
    lines.append("    m = m | mask;")
    lines.append("}")
    lines.append("")
    lines.append("macro update_bclr_mem8(bitidx, m) {")
    lines.append("    local bit:4 = bitidx & 7;")
    lines.append("    local mask:1 = 1 << bit;")
    lines.append("    local result:4 = zext(m) & zext(~mask);")
    lines.append("    update_bitop_flags32(result);")
    lines.append("    m = m & ~mask;")
    lines.append("}")
    lines.append("")
    lines.append("macro update_addc32(dst, src) {")
    lines.append("    local c:4 = zext($(CF));")
    lines.append("    local t:4 = dst + src;")
    lines.append("    local cf1:1 = carry(dst, src);")
    lines.append("    local vf1:1 = scarry(dst, src);")
    lines.append("    local cf2:1 = carry(t, c);")
    lines.append("    local vf2:1 = scarry(t, c);")
    lines.append("    dst = t + c;")
    lines.append("    $(CF) = cf1 | cf2;")
    lines.append("    $(VF) = vf1 | vf2;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("macro update_subc32(dst, src) {")
    lines.append("    local c:4 = zext($(CF));")
    lines.append("    local t:4 = dst - src;")
    lines.append("    local cf1:1 = (src > dst);")
    lines.append("    local vf1:1 = sborrow(dst, src);")
    lines.append("    local cf2:1 = (c > t);")
    lines.append("    local vf2:1 = sborrow(t, c);")
    lines.append("    dst = t - c;")
    lines.append("    $(CF) = cf1 | cf2;")
    lines.append("    $(VF) = vf1 | vf2;")
    lines.append("    update_zn32(dst);")
    lines.append("}")
    lines.append("")
    lines.append("SIMM8_B1: b1_simm is b1_simm { local v:1 = b1_simm; export v; }")
    lines.append("IMM8_B1:  b1_imm  is b1_imm  { local v:1 = b1_imm;  export v; }")
    lines.append("IMM8_B2:  b2_imm  is b2_imm  { local v:1 = b2_imm;  export v; }")
    lines.append("SIMM8_B2: b2_simm is b2_simm { local v:1 = b2_simm; export v; }")
    lines.append("IMM8_B3:  b3_imm  is b3_imm  { local v:1 = b3_imm;  export v; }")
    lines.append("SIMM8_B3: b3_simm is b3_simm { local v:1 = b3_simm; export v; }")
    lines.append("IMM8E_B4: b4_imm  is b4_imm  { local v:1 = b4_imm;  export v; }")
    lines.append("IMM8E_B6: b6_imm  is b6_imm  { local v:1 = b6_imm;  export v; }")
    lines.append("IMM4_B2:  b2_imm4hi  is b2_imm4hi  { local v:4 = b2_imm4hi;  export v; }")
    lines.append("SIMM4_B2: b2_simm4hi is b2_simm4hi { local v:4 = b2_simm4hi; export v; }")
    lines.append("SIMM4_B3: b3_simm4hi is b3_simm4hi { local v:4 = b3_simm4hi; export v; }")
    lines.append("SIMM16_B23: v is b2_any; b3_any [ v = b2_any | (b3_any << 8); ] { export v; }")
    lines.append("IMM16_B23:  v is b2_any; b3_any [ v = b2_any | (b3_any << 8); ] { export v; }")
    lines.append("IMM32_B2345: v is b2_any; b3_any; b4_any; b5_any [ v = b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24); ] { export v; }")
    lines.append("IMM24_B345:  v is b3_any; b4_any; b5_any [ v = b3_any | (b4_any << 8) | (b5_any << 16); ] { export v; }")
    lines.append("SIMM24_B345: v is b3_any; b4_any; b5_any [ v = b3_any | (b4_any << 8) | (b5_any << 16); ] { export v; }")
    lines.append("IMM32HI8_B3456: v is b3_any; b4_any; b5_any; b6_any [ v = b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24); ] { export v; }")
    lines.append("")
    lines.append("DREG_S0_LO: b0_dlo is b0_dlo { export b0_dlo; }")
    lines.append("DREG_S0_HI: b0_dhi is b0_dhi { export b0_dhi; }")
    lines.append("AREG_S0_LO: b0_alo is b0_alo { export b0_alo; }")
    lines.append("AREG_S0_HI: b0_ahi is b0_ahi { export b0_ahi; }")
    lines.append("")
    lines.append("DREG_S1_LO: b0_dlo is b0_dlo { export b0_dlo; }")
    lines.append("DREG_S1_HI: b0_dhi is b0_dhi { export b0_dhi; }")
    lines.append("AREG_S1_LO: b0_alo is b0_alo { export b0_alo; }")
    lines.append("AREG_S1_HI: b0_ahi is b0_ahi { export b0_ahi; }")
    lines.append("DREG_S1_EQ: b0_dlo is b0_dlo & b0_dhi=b0_dlo { export b0_dlo; }")
    lines.append("AREG_S1_EQ: b0_alo is b0_alo & b0_ahi=b0_alo { export b0_alo; }")
    lines.append("")
    lines.append("DREG_D0_LO: b1_dlo is b1_dlo { export b1_dlo; }")
    lines.append("DREG_D0_HI: b1_dhi is b1_dhi { export b1_dhi; }")
    lines.append("DREG_D0_2:  b1_d2  is b1_d2  { export b1_d2; }")
    lines.append("AREG_D0_LO: b1_alo is b1_alo { export b1_alo; }")
    lines.append("AREG_D0_HI: b1_ahi is b1_ahi { export b1_ahi; }")
    lines.append("AREG_D0_2:  b1_a2  is b1_a2  { export b1_a2; }")
    lines.append("")
    lines.append("RREG_B2_LO: b2_rlo is b2_rlo { export b2_rlo; }")
    lines.append("RREG_B2_HI: b2_rhi is b2_rhi { export b2_rhi; }")
    lines.append("RREG_B3_HI: b3_rhi is b3_rhi { export b3_rhi; }")
    lines.append("RREG_B3_LO: b3_rlo is b3_rlo { export b3_rlo; }")
    lines.append("RREG_B1_LO: b1_rlo is b1_rlo { export b1_rlo; }")
    lines.append("RREG_B1_MID: b1_rmid is b1_rmid { export b1_rmid; }")
    lines.append("RREG_RN02_EQ: b2_rlo is b2_rlo & b2_rhi=b2_rlo { export b2_rlo; }")
    lines.append("")
    lines.append("XRREG_B2_LO: b2_xrlo is b2_xrlo { export b2_xrlo; }")
    lines.append("XRREG_B2_HI: b2_xrhi is b2_xrhi { export b2_xrhi; }")
    lines.append("XRREG_B1_MID: b1_xrmid is b1_xrmid { export b1_xrmid; }")
    lines.append("XRREG_RN02_EQ: b2_xrlo is b2_xrlo & b2_xrhi=b2_xrlo { export b2_xrlo; }")
    lines.append("")
    lines.append("FSM0_D6: b2_fsl0 is b1_0=0 & b2_fsl0 { export b2_fsl0; }")
    lines.append("FSM0_D6: b2_fsl1 is b1_0=1 & b2_fsl1 { export b2_fsl1; }")
    lines.append("FSM1_D6: b2_fsh0 is b1_1=0 & b2_fsh0 { export b2_fsh0; }")
    lines.append("FSM1_D6: b2_fsh1 is b1_1=1 & b2_fsh1 { export b2_fsh1; }")
    lines.append("FDM0_D6: b2_fdl0 is b1_0=0 & b2_fdl0 { export b2_fdl0; }")
    lines.append("FDM0_D6: b2_fdl1 is b1_0=1 & b2_fdl1 { export b2_fdl1; }")
    lines.append("FDM1_D6: b2_fdh0 is b1_1=0 & b2_fdh0 { export b2_fdh0; }")
    lines.append("FDM1_D6: b2_fdh1 is b1_1=1 & b2_fdh1 { export b2_fdh1; }")
    lines.append("")
    lines.append("FSM2_D789: b2_fsl0 is b2_fsl0 { export b2_fsl0; }")
    lines.append("FSM2_D789: b2_fsl1 is b2_fsl1 { export b2_fsl1; }")
    lines.append("FSM3_D789: b2_fsh0 is b2_fsh0 { export b2_fsh0; }")
    lines.append("FSM3_D789: b2_fsh1 is b2_fsh1 { export b2_fsh1; }")
    lines.append("FDM2_D789: b2_fdl0 is b2_fdl0 { export b2_fdl0; }")
    lines.append("FDM2_D789: b2_fdl1 is b2_fdl1 { export b2_fdl1; }")
    lines.append("FDM3_D789: b2_fdh0 is b2_fdh0 { export b2_fdh0; }")
    lines.append("FDM3_D789: b2_fdh1 is b2_fdh1 { export b2_fdh1; }")
    lines.append("FSN1_D7: b3_fsh0 is b3_1=0 & b3_fsh0 { export b3_fsh0; }")
    lines.append("FSN1_D7: b3_fsh1 is b3_1=1 & b3_fsh1 { export b3_fsh1; }")
    lines.append("FDN1_D7: b3_fdh0 is b3_1=0 & b3_fdh0 { export b3_fdh0; }")
    lines.append("FDN1_D7: b3_fdh1 is b3_1=1 & b3_fdh1 { export b3_fdh1; }")
    lines.append("FSN2_D10: b2_fsl0 is b3_2=0 & b2_fsl0 { export b2_fsl0; }")
    lines.append("FSN2_D10: b2_fsl1 is b3_2=1 & b2_fsl1 { export b2_fsl1; }")
    lines.append("FSN3_D10: b2_fsh0 is b3_3=0 & b2_fsh0 { export b2_fsh0; }")
    lines.append("FSN3_D10: b2_fsh1 is b3_3=1 & b2_fsh1 { export b2_fsh1; }")
    lines.append("FDN2_D10: b2_fdl0 is b3_2=0 & b2_fdl0 { export b2_fdl0; }")
    lines.append("FDN2_D10: b2_fdl1 is b3_2=1 & b2_fdl1 { export b2_fdl1; }")
    lines.append("FDN3_D10: b2_fdh0 is b3_3=0 & b2_fdh0 { export b2_fdh0; }")
    lines.append("FDN3_D10: b2_fdh1 is b3_3=1 & b2_fdh1 { export b2_fdh1; }")
    lines.append("")
    lines.append(
        'MEM_AREG_S0_LO:addr is b0_alo '
        "[ addr = b0_alo; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_AREG_D0_LO:addr is b1_alo '
        "[ addr = b1_alo; ] { export *[ram]:4 addr; }"
    )
    lines.append('MEM_SP_S1:addr is b1_any=0x00 [ addr = SP; ] { export *[ram]:4 addr; }')
    lines.append(
        'MEM_IMM8_SP_S1:addr is b1_imm '
        "[ addr = SP + b1_imm; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_ABS16_S2:addr is b1_any; b2_any '
        "[ addr = b1_any | (b2_any << 8); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_ABS16_D2:addr is b2_any; b3_any '
        "[ addr = b2_any | (b3_any << 8); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM16_SP_D2:addr is b2_any; b3_any '
        "[ addr = SP + (b2_any | (b3_any << 8)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_SD8_AREG_D1:addr is b1_alo; b2_simm '
        "[ addr = b1_alo + b2_simm; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_SD16_AREG_D2:addr is b1_alo; b2_any; b3_simm '
        "[ addr = b1_alo + (b2_any | (b3_simm << 8)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_DI_AREG_D0:addr is b1_dhi & b1_alo '
        "[ addr = b1_alo + b1_dhi; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_ABS32_D4:addr is b2_any; b3_any; b4_any; b5_any '
        "[ addr = b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_RREG_D6:addr is b2_rlo [ addr = b2_rlo; ] { export *[ram]:4 addr; }'
    )
    lines.append(
        'MEM_RREG_HI_D6:addr is b2_rhi [ addr = b2_rhi; ] { export *[ram]:4 addr; }'
    )
    lines.append('MEM_SP_D6:addr is b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 [ addr = SP; ] { export *[ram]:4 addr; }')
    lines.append('MEM_SP_HI_D6:addr is b2_7=0 & b2_6=0 & b2_5=0 & b2_4=0 [ addr = SP; ] { export *[ram]:4 addr; }')
    lines.append(
        'MEM_IMM8_D7:addr is b3_any [ addr = b3_any; ] { export *[ram]:4 addr; }'
    )
    lines.append(
        'MEM_SD8_RREG_D7:addr is b2_rlo; b3_simm '
        "[ addr = b2_rlo + b3_simm; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_SD8_RREG_HI_D7:addr is b2_rhi; b3_simm '
        "[ addr = b2_rhi + b3_simm; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM24_D8:addr is b3_any; b4_any; b5_any '
        "[ addr = b3_any | (b4_any << 8) | (b5_any << 16); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_SD24_RREG_D8:addr is b2_rlo; b3_any; b4_any; b5_simm '
        "[ addr = b2_rlo + (b3_any | (b4_any << 8) | (b5_simm << 16)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_SD24_RREG_HI_D8:addr is b2_rhi; b3_any; b4_any; b5_simm '
        "[ addr = b2_rhi + (b3_any | (b4_any << 8) | (b5_simm << 16)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC_RREG_D6:addr is b2_rlo '
        "[ addr = b2_rlo; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC_RREG_HI_D6:addr is b2_rhi '
        "[ addr = b2_rhi; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM8_SP_D7:addr is b3_any '
        "[ addr = SP + b3_any; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM8_SP_HI_D7:addr is b2_7=0 & b2_6=0 & b2_5=0 & b2_4=0; b3_any '
        "[ addr = SP + b3_any; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM24_SP_D8:addr is b3_any; b4_any; b5_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM24_SP_HI_D8:addr is b2_7=0 & b2_6=0 & b2_5=0 & b2_4=0; b3_any; b4_any; b5_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_RI_RREG_D7:addr is b2_rhi & b2_rlo '
        "[ addr = b2_rlo + b2_rhi; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC2_SIMM8_RREG_D7:addr is b2_rlo; b3_simm '
        "[ addr = b2_rlo; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC2_SIMM8_RREG_HI_D7:addr is b2_rhi; b3_simm '
        "[ addr = b2_rhi; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC2_SIMM4_RN4_D10:addr is b3_rlo & SIMM4_B2 '
        "[ addr = b3_rlo; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC2_IMM24_RREG_D8:addr is b2_rlo; b3_any; b4_any; b5_any '
        "[ addr = b2_rlo + (b3_any | (b4_any << 8) | (b5_any << 16)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC2_IMM24_RREG_HI_D8:addr is b2_rhi; b3_any; b4_any; b5_any '
        "[ addr = b2_rhi + (b3_any | (b4_any << 8) | (b5_any << 16)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM32HI8_D9:addr is b3_any; b4_any; b5_any; b6_any '
        "[ addr = b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM32HI8_RREG_D9:addr is b2_rlo; b3_any; b4_any; b5_any; b6_any '
        "[ addr = b2_rlo + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM32HI8_RREG_HI_D9:addr is b2_rhi; b3_any; b4_any; b5_any; b6_any '
        "[ addr = b2_rhi + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM32HI8_SP_D9:addr is b3_any; b4_any; b5_any; b6_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM32HI8_SP_HI_D9:addr is b2_7=0 & b2_6=0 & b2_5=0 & b2_4=0; b3_any; b4_any; b5_any; b6_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC2_IMM32HI8_RREG_D9:addr is b2_rlo; b3_any; b4_any; b5_any; b6_any '
        "[ addr = b2_rlo; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEMINC2_IMM32HI8_RREG_HI_D9:addr is b2_rhi; b3_any; b4_any; b5_any; b6_any '
        "[ addr = b2_rhi; ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM8_RREG_D6:addr is b2_rlo [ addr = b2_rlo; ] { export *[ram]:1 addr; }'
    )
    lines.append('MEM8_SP_D6:addr is b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 [ addr = SP; ] { export *[ram]:1 addr; }')
    lines.append(
        'MEM8_IMM8_D7:addr is b3_any [ addr = b3_any; ] { export *[ram]:1 addr; }'
    )
    lines.append(
        'MEM8_SD8_RREG_D7:addr is b2_rlo; b3_simm '
        "[ addr = b2_rlo + b3_simm; ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_IMM24_D8:addr is b3_any; b4_any; b5_any '
        "[ addr = b3_any | (b4_any << 8) | (b5_any << 16); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_SD24_RREG_D8:addr is b2_rlo; b3_any; b4_any; b5_simm '
        "[ addr = b2_rlo + (b3_any | (b4_any << 8) | (b5_simm << 16)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_IMM8_SP_D7:addr is b3_any '
        "[ addr = SP + b3_any; ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_IMM24_SP_D8:addr is b3_any; b4_any; b5_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_RI_RREG_D7:addr is b2_rhi & b2_rlo '
        "[ addr = b2_rlo + b2_rhi; ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_IMM32HI8_D9:addr is b3_any; b4_any; b5_any; b6_any '
        "[ addr = b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_IMM32HI8_RREG_D9:addr is b2_rlo; b3_any; b4_any; b5_any; b6_any '
        "[ addr = b2_rlo + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_IMM32HI8_SP_D9:addr is b3_any; b4_any; b5_any; b6_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_RREG_D6:addr is b2_rlo [ addr = b2_rlo; ] { export *[ram]:2 addr; }'
    )
    lines.append('MEM16_SP_D6:addr is b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 [ addr = SP; ] { export *[ram]:2 addr; }')
    lines.append(
        'MEM16_IMM8_D7:addr is b3_any [ addr = b3_any; ] { export *[ram]:2 addr; }'
    )
    lines.append(
        'MEM16_SD8_RREG_D7:addr is b2_rlo; b3_simm '
        "[ addr = b2_rlo + b3_simm; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_IMM24_D8:addr is b3_any; b4_any; b5_any '
        "[ addr = b3_any | (b4_any << 8) | (b5_any << 16); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_SD24_RREG_D8:addr is b2_rlo; b3_any; b4_any; b5_simm '
        "[ addr = b2_rlo + (b3_any | (b4_any << 8) | (b5_simm << 16)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_IMM8_SP_D7:addr is b3_any '
        "[ addr = SP + b3_any; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_IMM24_SP_D8:addr is b3_any; b4_any; b5_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_RI_RREG_D7:addr is b2_rhi & b2_rlo '
        "[ addr = b2_rlo + b2_rhi; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_IMM32HI8_D9:addr is b3_any; b4_any; b5_any; b6_any '
        "[ addr = b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_IMM32HI8_RREG_D9:addr is b2_rlo; b3_any; b4_any; b5_any; b6_any '
        "[ addr = b2_rlo + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16_IMM32HI8_SP_D9:addr is b3_any; b4_any; b5_any; b6_any '
        "[ addr = SP + (b3_any | (b4_any << 8) | (b5_any << 16) | (b6_any << 24)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16INC_RREG_D6:addr is b2_rlo '
        "[ addr = b2_rlo; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16INC2_SIMM8_RREG_D7:addr is b2_rlo; b3_simm '
        "[ addr = b2_rlo; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16INC2_IMM24_RREG_D8:addr is b2_rlo; b3_any; b4_any; b5_any '
        "[ addr = b2_rlo; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM16INC2_IMM32HI8_RREG_D9:addr is b2_rlo; b3_any; b4_any; b5_any; b6_any '
        "[ addr = b2_rlo; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_AREG_D0_LO:addr is b1_alo [ addr = b1_alo; ] { export *[ram]:1 addr; }'
    )
    lines.append(
        'MEM16_AREG_D0_LO:addr is b1_alo [ addr = b1_alo; ] { export *[ram]:2 addr; }'
    )
    lines.append(
        'MEM8_SD8_AREG_D1:addr is b1_alo; b2_simm '
        "[ addr = b1_alo + b2_simm; ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_SD8_AREG_D1:addr is b1_alo; b2_simm '
        "[ addr = b1_alo + b2_simm; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_SD16_AREG_D2:addr is b1_alo; b2_any; b3_simm '
        "[ addr = b1_alo + (b2_any | (b3_simm << 8)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_SD16_AREG_D2:addr is b1_alo; b2_any; b3_simm '
        "[ addr = b1_alo + (b2_any | (b3_simm << 8)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_SD8N_SHIFT8_AREG_D2:addr is AREG_D0_LO; b2_simm '
        "[ addr = AREG_D0_LO + (b2_simm << 8); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM_SD8N_SHIFT8_AREG_D1:addr is AREG_D0_LO; b2_simm '
        "[ addr = AREG_D0_LO + (b2_simm << 8); ] { export *[ram]:4 addr; }"
    )
    lines.append('MEM8_SP_D1:addr is b2_any=0x00 [ addr = SP; ] { export *[ram]:1 addr; }')
    lines.append('MEM16_SP_D1:addr is b2_any=0x00 [ addr = SP; ] { export *[ram]:2 addr; }')
    lines.append(
        'MEM8_IMM8_SP_D1:addr is b2_any '
        "[ addr = SP + zext(b2_any); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_IMM8_SP_D1:addr is b2_any '
        "[ addr = SP + zext(b2_any); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_IMM16_SP_D2:addr is b2_any; b3_any '
        "[ addr = SP + (zext(b2_any) | (zext(b3_any) << 8)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_IMM16_SP_D2:addr is b2_any; b3_any '
        "[ addr = SP + (zext(b2_any) | (zext(b3_any) << 8)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_DI_AREG_D0:addr is DREG_D0_HI; AREG_D0_LO '
        "[ addr = AREG_D0_LO + DREG_D0_HI; ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_DI_AREG_D0:addr is DREG_D0_HI; AREG_D0_LO '
        "[ addr = AREG_D0_LO + DREG_D0_HI; ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_ABS16_S2:addr is b1_any; b2_any '
        "[ addr = zext(b1_any) | (zext(b2_any) << 8); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_ABS16_S2:addr is b1_any; b2_any '
        "[ addr = zext(b1_any) | (zext(b2_any) << 8); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_ABS16_D3:addr is b2_any; b3_any '
        "[ addr = zext(b2_any) | (zext(b3_any) << 8); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_ABS32_D4:addr is b2_any; b3_any; b4_any; b5_any '
        "[ addr = zext(b2_any) | (zext(b3_any) << 8) | "
        "(zext(b4_any) << 16) | (zext(b5_any) << 24); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM8_ABS32_D5:addr is b2_any; b3_any; b4_any; b5_any '
        "[ addr = zext(b2_any) | (zext(b3_any) << 8) | "
        "(zext(b4_any) << 16) | (zext(b5_any) << 24); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_ABS32_D4:addr is b2_any; b3_any; b4_any; b5_any '
        "[ addr = b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_IMM32_AREG_D4:addr is b1_alo; b2_any; b3_any; b4_any; b5_any '
        "[ addr = b1_alo + (b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_IMM32_AREG_D4:addr is b1_alo; b2_any; b3_any; b4_any; b5_any '
        "[ addr = b1_alo + (b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM8_IMM32_SP_D4:addr is b2_any; b3_any; b4_any; b5_any '
        "[ addr = SP + (b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24)); ] { export *[ram]:1 addr; }"
    )
    lines.append(
        'MEM16_IMM32_SP_D4:addr is b2_any; b3_any; b4_any; b5_any '
        "[ addr = SP + (b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24)); ] { export *[ram]:2 addr; }"
    )
    lines.append(
        'MEM_IMM32_AREG_D4:addr is b1_alo; b2_any; b3_any; b4_any; b5_any '
        "[ addr = b1_alo + (b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append(
        'MEM_IMM32_SP_D4:addr is b2_any; b3_any; b4_any; b5_any '
        "[ addr = SP + (b2_any | (b3_any << 8) | (b4_any << 16) | (b5_any << 24)); ] { export *[ram]:4 addr; }"
    )
    lines.append("")
    lines.append(
        ":mov SIMM8_B1, DREG_S1_EQ is b0_7=1 & b0_6=0 & b0_5=0 & b0_4=0 & DREG_S1_EQ; SIMM8_B1 "
        "{ DREG_S1_EQ = sext(SIMM8_B1); }"
    )
    lines.append(
        ":mov DREG_D0_HI, AREG_D0_LO is b0_any=0xF1; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & DREG_D0_HI & AREG_D0_LO "
        "{ AREG_D0_LO = DREG_D0_HI; }"
    )
    lines.append(
        ":mov AREG_D0_HI, DREG_D0_LO is b0_any=0xF1; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & AREG_D0_HI & DREG_D0_LO "
        "{ DREG_D0_LO = AREG_D0_HI; }"
    )
    lines.append(
        ":mov IMM8_B1, AREG_S1_EQ is b0_7=1 & b0_6=0 & b0_5=0 & b0_4=1 & AREG_S1_EQ; IMM8_B1 "
        "{ AREG_S1_EQ = zext(IMM8_B1); }"
    )
    lines.append(
        ":mov SP, AREG_S0_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=1 & b0_3=1 & b0_2=1 & AREG_S0_LO "
        "{ AREG_S0_LO = SP; }"
    )
    lines.append(
        ":mov AREG_D0_HI, SP is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & AREG_D0_HI & b1_1=0 & b1_0=0 "
        "{ SP = AREG_D0_HI; }"
    )
    lines.append(
        ":mov PSW, DREG_D0_LO is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & DREG_D0_LO "
        "{ DREG_D0_LO = zext(PSW); }"
    )
    lines.append(
        ":mov DREG_D0_HI, PSW is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=1 "
        "{ PSW = DREG_D0_HI:2; }"
    )
    lines.append(
        ":mov MDR, DREG_D0_LO is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & DREG_D0_LO "
        "{ DREG_D0_LO = zext(MDR); }"
    )
    lines.append(
        ":mov DREG_D0_HI, MDR is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=0 "
        "{ MDR = DREG_D0_HI:2; }"
    )
    lines.append("")
    lines.append("# Phase 3.1: mov memory forms (baseline)")
    lines.append("")
    lines.append(
        ":mov MEM_AREG_S0_LO, DREG_S0_HI is b0_7=0 & b0_6=1 & b0_5=1 & b0_4=1 & MEM_AREG_S0_LO & DREG_S0_HI "
        "{ DREG_S0_HI = MEM_AREG_S0_LO; }"
    )
    lines.append(
        ":mov MEM_AREG_D0_LO, AREG_D0_HI is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=0 & MEM_AREG_D0_LO & AREG_D0_HI "
        "{ AREG_D0_HI = MEM_AREG_D0_LO; }"
    )
    lines.append(
        ":mov DREG_S0_HI, MEM_AREG_S0_LO is b0_7=0 & b0_6=1 & b0_5=1 & b0_4=0 & DREG_S0_HI & MEM_AREG_S0_LO "
        "{ MEM_AREG_S0_LO = DREG_S0_HI; }"
    )
    lines.append(
        ":mov AREG_D0_HI, MEM_AREG_D0_LO is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=1 & AREG_D0_HI & MEM_AREG_D0_LO "
        "{ MEM_AREG_D0_LO = AREG_D0_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_SP_S1, DREG_S1_LO is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=1 & b0_3=1 & b0_2=0 & DREG_S1_LO; MEM_SP_S1 "
        "{ DREG_S1_LO = MEM_SP_S1; }"
    )
    lines.append(
        ":mov MEM_SP_S1, AREG_S1_LO is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=1 & b0_3=1 & b0_2=1 & AREG_S1_LO; MEM_SP_S1 "
        "{ AREG_S1_LO = MEM_SP_S1; }"
    )
    lines.append(
        ":mov DREG_S1_HI, MEM_SP_S1 is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=0 & DREG_S1_HI & b0_1=1 & b0_0=0; MEM_SP_S1 "
        "{ MEM_SP_S1 = DREG_S1_HI; }"
    )
    lines.append(
        ":mov AREG_S1_HI, MEM_SP_S1 is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=0 & AREG_S1_HI & b0_1=1 & b0_0=1; MEM_SP_S1 "
        "{ MEM_SP_S1 = AREG_S1_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_IMM8_SP_S1, DREG_S1_LO is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=1 & b0_3=1 & b0_2=0 & DREG_S1_LO; MEM_IMM8_SP_S1 "
        "{ DREG_S1_LO = MEM_IMM8_SP_S1; }"
    )
    lines.append(
        ":mov MEM_IMM8_SP_S1, AREG_S1_LO is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=1 & b0_3=1 & b0_2=1 & AREG_S1_LO; MEM_IMM8_SP_S1 "
        "{ AREG_S1_LO = MEM_IMM8_SP_S1; }"
    )
    lines.append(
        ":mov DREG_S1_HI, MEM_IMM8_SP_S1 is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=0 & DREG_S1_HI & b0_1=1 & b0_0=0; MEM_IMM8_SP_S1 "
        "{ MEM_IMM8_SP_S1 = DREG_S1_HI; }"
    )
    lines.append(
        ":mov AREG_S1_HI, MEM_IMM8_SP_S1 is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=0 & AREG_S1_HI & b0_1=1 & b0_0=1; MEM_IMM8_SP_S1 "
        "{ MEM_IMM8_SP_S1 = AREG_S1_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_ABS16_S2, DREG_S1_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=1 & b0_3=0 & b0_2=0 & DREG_S1_LO; MEM_ABS16_S2 "
        "{ DREG_S1_LO = MEM_ABS16_S2; }"
    )
    lines.append(
        ":mov DREG_S1_HI, MEM_ABS16_S2 is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=0 & DREG_S1_HI & b0_1=0 & b0_0=1; MEM_ABS16_S2 "
        "{ MEM_ABS16_S2 = DREG_S1_HI; }"
    )
    lines.append(
        ":mov MEM_ABS16_D2, AREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & AREG_D0_LO; MEM_ABS16_D2 "
        "{ AREG_D0_LO = MEM_ABS16_D2; }"
    )
    lines.append(
        ":mov AREG_D0_HI, MEM_ABS16_D2 is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=0 & AREG_D0_HI & b1_1=0 & b1_0=0; MEM_ABS16_D2 "
        "{ MEM_ABS16_D2 = AREG_D0_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_SD8_AREG_D1, DREG_D0_HI is b0_any=0xF8; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=0 & MEM_SD8_AREG_D1 & DREG_D0_HI "
        "{ DREG_D0_HI = MEM_SD8_AREG_D1; }"
    )
    lines.append(
        ":mov MEM_SD8_AREG_D1, AREG_D0_HI is b0_any=0xF8; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & MEM_SD8_AREG_D1 & AREG_D0_HI "
        "{ AREG_D0_HI = MEM_SD8_AREG_D1; }"
    )
    lines.append(
        ":mov DREG_D0_HI, MEM_SD8_AREG_D1 is b0_any=0xF8; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM_SD8_AREG_D1 "
        "{ MEM_SD8_AREG_D1 = DREG_D0_HI; }"
    )
    lines.append(
        ":mov AREG_D0_HI, MEM_SD8_AREG_D1 is b0_any=0xF8; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & AREG_D0_HI & MEM_SD8_AREG_D1 "
        "{ MEM_SD8_AREG_D1 = AREG_D0_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_SD16_AREG_D2, DREG_D0_HI is b0_any=0xFA; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=0 & MEM_SD16_AREG_D2 & DREG_D0_HI "
        "{ DREG_D0_HI = MEM_SD16_AREG_D2; }"
    )
    lines.append(
        ":mov MEM_SD16_AREG_D2, AREG_D0_HI is b0_any=0xFA; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & MEM_SD16_AREG_D2 & AREG_D0_HI "
        "{ AREG_D0_HI = MEM_SD16_AREG_D2; }"
    )
    lines.append(
        ":mov DREG_D0_HI, MEM_SD16_AREG_D2 is b0_any=0xFA; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM_SD16_AREG_D2 "
        "{ MEM_SD16_AREG_D2 = DREG_D0_HI; }"
    )
    lines.append(
        ":mov AREG_D0_HI, MEM_SD16_AREG_D2 is b0_any=0xFA; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & AREG_D0_HI & MEM_SD16_AREG_D2 "
        "{ MEM_SD16_AREG_D2 = AREG_D0_HI; }"
    )
    lines.append("")
    lines.append("# Phase 3.2: mov indexed/IMM32 and AM33 R-register memory forms")
    lines.append("")
    lines.append(
        ":mov MEM_DI_AREG_D0, DREG_D0_2 is b0_any=0xF3; b1_7=0 & b1_6=0 & DREG_D0_2 & MEM_DI_AREG_D0 "
        "{ DREG_D0_2 = MEM_DI_AREG_D0; }"
    )
    lines.append(
        ":mov MEM_DI_AREG_D0, AREG_D0_2 is b0_any=0xF3; b1_7=1 & b1_6=0 & AREG_D0_2 & MEM_DI_AREG_D0 "
        "{ AREG_D0_2 = MEM_DI_AREG_D0; }"
    )
    lines.append(
        ":mov DREG_D0_2, MEM_DI_AREG_D0 is b0_any=0xF3; b1_7=0 & b1_6=1 & DREG_D0_2 & MEM_DI_AREG_D0 "
        "{ MEM_DI_AREG_D0 = DREG_D0_2; }"
    )
    lines.append(
        ":mov AREG_D0_2, MEM_DI_AREG_D0 is b0_any=0xF3; b1_7=1 & b1_6=1 & AREG_D0_2 & MEM_DI_AREG_D0 "
        "{ MEM_DI_AREG_D0 = AREG_D0_2; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_ABS32_D4, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & DREG_D0_LO; MEM_ABS32_D4 "
        "{ DREG_D0_LO = MEM_ABS32_D4; }"
    )
    lines.append(
        ":mov MEM_ABS32_D4, AREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & AREG_D0_LO; MEM_ABS32_D4 "
        "{ AREG_D0_LO = MEM_ABS32_D4; }"
    )
    lines.append(
        ":mov DREG_D0_HI, MEM_ABS32_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=0 & DREG_D0_HI & b1_1=0 & b1_0=1; MEM_ABS32_D4 "
        "{ MEM_ABS32_D4 = DREG_D0_HI; }"
    )
    lines.append(
        ":mov AREG_D0_HI, MEM_ABS32_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=0 & AREG_D0_HI & b1_1=0 & b1_0=0; MEM_ABS32_D4 "
        "{ MEM_ABS32_D4 = AREG_D0_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_RREG_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0x0A; MEM_RREG_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = MEM_RREG_D6; }"
    )
    lines.append(
        ":mov MEM_SP_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0x8A; MEM_SP_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = MEM_SP_D6; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_RREG_D6 is b0_any=0xF9; b1_any=0x1A; RREG_B2_HI & MEM_RREG_D6 "
        "{ MEM_RREG_D6 = RREG_B2_HI; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_SP_D6 is b0_any=0xF9; b1_any=0x9A; RREG_B2_HI & MEM_SP_D6 "
        "{ MEM_SP_D6 = RREG_B2_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_IMM8_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x0E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM8_D7 "
        "{ RREG_B2_HI = MEM_IMM8_D7; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_IMM8_D7 is b0_any=0xFB; b1_any=0x1E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM8_D7 "
        "{ MEM_IMM8_D7 = RREG_B2_HI; }"
    )
    lines.append(
        ":mov MEM_SD8_RREG_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x0A; MEM_SD8_RREG_D7 & RREG_B2_HI "
        "{ RREG_B2_HI = MEM_SD8_RREG_D7; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_SD8_RREG_D7 is b0_any=0xFB; b1_any=0x1A; RREG_B2_HI & MEM_SD8_RREG_D7 "
        "{ MEM_SD8_RREG_D7 = RREG_B2_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_IMM24_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x0E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM24_D8 "
        "{ RREG_B2_HI = MEM_IMM24_D8; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_IMM24_D8 is b0_any=0xFD; b1_any=0x1E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM24_D8 "
        "{ MEM_IMM24_D8 = RREG_B2_HI; }"
    )
    lines.append(
        ":mov MEM_SD24_RREG_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x0A; MEM_SD24_RREG_D8 & RREG_B2_HI "
        "{ RREG_B2_HI = MEM_SD24_RREG_D8; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_SD24_RREG_D8 is b0_any=0xFD; b1_any=0x1A; RREG_B2_HI & MEM_SD24_RREG_D8 "
        "{ MEM_SD24_RREG_D8 = RREG_B2_HI; }"
    )
    lines.append("")
    lines.append(
        ":add DREG_S0_HI, DREG_S0_LO is b0_7=1 & b0_6=1 & b0_5=1 & b0_4=0 & DREG_S0_HI & DREG_S0_LO "
        "{ update_add32(DREG_S0_LO, DREG_S0_HI); }"
    )
    lines.append(
        ":add DREG_D0_HI, AREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=0 & DREG_D0_HI & AREG_D0_LO "
        "{ update_add32(AREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":add AREG_D0_HI, DREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=1 & AREG_D0_HI & DREG_D0_LO "
        "{ update_add32(DREG_D0_LO, AREG_D0_HI); }"
    )
    lines.append(
        ":add AREG_D0_HI, AREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=1 & AREG_D0_HI & AREG_D0_LO "
        "{ update_add32(AREG_D0_LO, AREG_D0_HI); }"
    )
    lines.append(
        ":add SIMM8_B1, DREG_S1_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=0 & b0_3=1 & b0_2=0 & DREG_S1_LO; SIMM8_B1 "
        "{ local s:4 = sext(SIMM8_B1); update_add32(DREG_S1_LO, s); }"
    )
    lines.append(
        ":add SIMM8_B1, AREG_S1_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=0 & b0_3=0 & b0_2=0 & AREG_S1_LO; SIMM8_B1 "
        "{ local s:4 = sext(SIMM8_B1); update_add32(AREG_S1_LO, s); }"
    )
    lines.append("")
    lines.append(
        ":sub DREG_D0_HI, DREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=0 & DREG_D0_HI & DREG_D0_LO "
        "{ update_sub32(DREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":sub DREG_D0_HI, AREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & DREG_D0_HI & AREG_D0_LO "
        "{ update_sub32(AREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":sub AREG_D0_HI, DREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=1 & AREG_D0_HI & DREG_D0_LO "
        "{ update_sub32(DREG_D0_LO, AREG_D0_HI); }"
    )
    lines.append(
        ":sub AREG_D0_HI, AREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & AREG_D0_HI & AREG_D0_LO "
        "{ update_sub32(AREG_D0_LO, AREG_D0_HI); }"
    )
    lines.append("")
    lines.append(
        ":cmp SIMM8_B1, DREG_S1_EQ is b0_7=1 & b0_6=0 & b0_5=1 & b0_4=0 & DREG_S1_EQ; SIMM8_B1 "
        "{ local s:4 = sext(SIMM8_B1); update_cmp32(DREG_S1_EQ, s); }"
    )
    lines.append(
        ":cmp DREG_D0_HI, AREG_D0_LO is b0_any=0xF1; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & DREG_D0_HI & AREG_D0_LO "
        "{ update_cmp32(AREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":cmp AREG_D0_HI, DREG_D0_LO is b0_any=0xF1; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & AREG_D0_HI & DREG_D0_LO "
        "{ update_cmp32(DREG_D0_LO, AREG_D0_HI); }"
    )
    lines.append(
        ":cmp IMM8_B1, AREG_S1_EQ is b0_7=1 & b0_6=0 & b0_5=1 & b0_4=1 & AREG_S1_EQ; IMM8_B1 "
        "{ local u:4 = zext(IMM8_B1); update_cmp32(AREG_S1_EQ, u); }"
    )
    lines.append("")
    lines.append("# Phase 3.3: add/sub/cmp advanced immediate + AM33 R-register forms")
    lines.append("")
    lines.append(
        ":add SIMM8_B2, SP is b0_any=0xF8; b1_any=0xFE; SIMM8_B2 "
        "{ local s:4 = sext(SIMM8_B2); update_add32(SP, s); }"
    )
    lines.append(
        ":add SIMM16_B23, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=0 & b1_2=0 & DREG_D0_LO; SIMM16_B23 "
        "{ local s:4 = sext(SIMM16_B23); update_add32(DREG_D0_LO, s); }"
    )
    lines.append(
        ":add SIMM16_B23, AREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & b1_3=0 & b1_2=0 & AREG_D0_LO; SIMM16_B23 "
        "{ local s:4 = sext(SIMM16_B23); update_add32(AREG_D0_LO, s); }"
    )
    lines.append(
        ":add SIMM16_B23, SP is b0_any=0xFA; b1_any=0xFE; SIMM16_B23 "
        "{ local s:4 = sext(SIMM16_B23); update_add32(SP, s); }"
    )
    lines.append(
        ":add RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x78; RREG_B2_HI & RREG_B2_LO "
        "{ update_add32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":add IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=0 & b1_2=0 & DREG_D0_LO; IMM32_B2345 "
        "{ update_add32(DREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":add IMM32_B2345, AREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & b1_3=0 & b1_2=0 & AREG_D0_LO; IMM32_B2345 "
        "{ update_add32(AREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":add IMM32_B2345, SP is b0_any=0xFC; b1_any=0xFE; IMM32_B2345 "
        "{ update_add32(SP, IMM32_B2345); }"
    )
    lines.append(
        ":add SIMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x78; RREG_RN02_EQ; SIMM8_B3 "
        "{ local s:4 = sext(SIMM8_B3); update_add32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":add SIMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x78; RREG_RN02_EQ; SIMM24_B345 "
        "{ local s:4 = sext(SIMM24_B345); update_add32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":add IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x78; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_add32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append(
        ":add RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x7C; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; update_add32(t, RREG_B2_HI); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":sub RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x98; RREG_B2_HI & RREG_B2_LO "
        "{ update_sub32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":sub IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=0 & b1_2=1 & DREG_D0_LO; IMM32_B2345 "
        "{ update_sub32(DREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":sub IMM32_B2345, AREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & b1_3=0 & b1_2=1 & AREG_D0_LO; IMM32_B2345 "
        "{ update_sub32(AREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":sub SIMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x98; RREG_RN02_EQ; SIMM8_B3 "
        "{ local s:4 = sext(SIMM8_B3); update_sub32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":sub SIMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x98; RREG_RN02_EQ; SIMM24_B345 "
        "{ local s:4 = sext(SIMM24_B345); update_sub32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":sub IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x98; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_sub32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append(
        ":sub RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x9C; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; update_sub32(t, RREG_B2_HI); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":cmp SIMM16_B23, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=1 & b1_2=0 & DREG_D0_LO; SIMM16_B23 "
        "{ local s:4 = sext(SIMM16_B23); update_cmp32(DREG_D0_LO, s); }"
    )
    lines.append(
        ":cmp IMM16_B23, AREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & b1_3=1 & b1_2=0 & AREG_D0_LO; IMM16_B23 "
        "{ local u:4 = zext(IMM16_B23); update_cmp32(AREG_D0_LO, u); }"
    )
    lines.append(
        ":cmp RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0xD8; RREG_B2_HI & RREG_B2_LO "
        "{ update_cmp32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":cmp IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=1 & b1_2=0 & DREG_D0_LO; IMM32_B2345 "
        "{ update_cmp32(DREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":cmp IMM32_B2345, AREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & b1_3=1 & b1_2=0 & AREG_D0_LO; IMM32_B2345 "
        "{ update_cmp32(AREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":cmp SIMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0xD8; RREG_RN02_EQ; SIMM8_B3 "
        "{ local s:4 = sext(SIMM8_B3); update_cmp32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":cmp SIMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0xD8; RREG_RN02_EQ; SIMM24_B345 "
        "{ local s:4 = sext(SIMM24_B345); update_cmp32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":cmp IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0xD8; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_cmp32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append("")
    lines.append("# Phase 3.4: addc/subc/and/or/xor/not advanced forms")
    lines.append("")
    lines.append(
        ":addc DREG_D0_HI, DREG_D0_LO is b0_any=0xF1; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=0 & DREG_D0_HI & DREG_D0_LO "
        "{ update_addc32(DREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":addc RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x88; RREG_B2_HI & RREG_B2_LO "
        "{ update_addc32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":addc SIMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x88; RREG_RN02_EQ; SIMM8_B3 "
        "{ local s:4 = sext(SIMM8_B3); update_addc32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":addc SIMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x88; RREG_RN02_EQ; SIMM24_B345 "
        "{ local s:4 = sext(SIMM24_B345); update_addc32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":addc IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x88; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_addc32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append(
        ":addc RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x8C; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; update_addc32(t, RREG_B2_HI); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":subc DREG_D0_HI, DREG_D0_LO is b0_any=0xF1; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=0 & DREG_D0_HI & DREG_D0_LO "
        "{ update_subc32(DREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":subc RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0xA8; RREG_B2_HI & RREG_B2_LO "
        "{ update_subc32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":subc SIMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0xA8; RREG_RN02_EQ; SIMM8_B3 "
        "{ local s:4 = sext(SIMM8_B3); update_subc32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":subc SIMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0xA8; RREG_RN02_EQ; SIMM24_B345 "
        "{ local s:4 = sext(SIMM24_B345); update_subc32(RREG_RN02_EQ, s); }"
    )
    lines.append(
        ":subc IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0xA8; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_subc32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append(
        ":subc RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0xAC; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; update_subc32(t, RREG_B2_HI); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":and DREG_D0_HI, DREG_D0_LO is b0_any=0xF2; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=0 & DREG_D0_HI & DREG_D0_LO "
        "{ update_and32(DREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":and IMM8_B2, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & DREG_D0_LO; IMM8_B2 "
        "{ local u:4 = zext(IMM8_B2); update_and32(DREG_D0_LO, u); }"
    )
    lines.append(
        ":and IMM16_B23, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & DREG_D0_LO; IMM16_B23 "
        "{ local u:4 = zext(IMM16_B23); update_and32(DREG_D0_LO, u); }"
    )
    lines.append(
        ":and RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x09; RREG_B2_HI & RREG_B2_LO "
        "{ update_and32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":and IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & DREG_D0_LO; IMM32_B2345 "
        "{ update_and32(DREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":and IMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x09; RREG_RN02_EQ; IMM8_B3 "
        "{ local u:4 = zext(IMM8_B3); update_and32(RREG_RN02_EQ, u); }"
    )
    lines.append(
        ":and IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x09; RREG_RN02_EQ; IMM24_B345 "
        "{ local u:4 = zext(IMM24_B345); update_and32(RREG_RN02_EQ, u); }"
    )
    lines.append(
        ":and IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x09; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_and32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append(
        ":and RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x0D; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; update_and32(t, RREG_B2_HI); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":or DREG_D0_HI, DREG_D0_LO is b0_any=0xF2; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & DREG_D0_LO "
        "{ update_or32(DREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":or IMM8_B2, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & DREG_D0_LO; IMM8_B2 "
        "{ local u:4 = zext(IMM8_B2); update_or32(DREG_D0_LO, u); }"
    )
    lines.append(
        ":or IMM16_B23, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & DREG_D0_LO; IMM16_B23 "
        "{ local u:4 = zext(IMM16_B23); update_or32(DREG_D0_LO, u); }"
    )
    lines.append(
        ":or RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x19; RREG_B2_HI & RREG_B2_LO "
        "{ update_or32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":or IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & DREG_D0_LO; IMM32_B2345 "
        "{ update_or32(DREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":or IMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x19; RREG_RN02_EQ; IMM8_B3 "
        "{ local u:4 = zext(IMM8_B3); update_or32(RREG_RN02_EQ, u); }"
    )
    lines.append(
        ":or IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x19; RREG_RN02_EQ; IMM24_B345 "
        "{ local u:4 = zext(IMM24_B345); update_or32(RREG_RN02_EQ, u); }"
    )
    lines.append(
        ":or IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x19; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_or32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append(
        ":or RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x1D; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; update_or32(t, RREG_B2_HI); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":xor DREG_D0_HI, DREG_D0_LO is b0_any=0xF2; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & DREG_D0_HI & DREG_D0_LO "
        "{ update_xor32(DREG_D0_LO, DREG_D0_HI); }"
    )
    lines.append(
        ":xor IMM16_B23, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=0 & DREG_D0_LO; IMM16_B23 "
        "{ local u:4 = zext(IMM16_B23); update_xor32(DREG_D0_LO, u); }"
    )
    lines.append(
        ":xor RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x29; RREG_B2_HI & RREG_B2_LO "
        "{ update_xor32(RREG_B2_LO, RREG_B2_HI); }"
    )
    lines.append(
        ":xor IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=0 & DREG_D0_LO; IMM32_B2345 "
        "{ update_xor32(DREG_D0_LO, IMM32_B2345); }"
    )
    lines.append(
        ":xor IMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x29; RREG_RN02_EQ; IMM8_B3 "
        "{ local u:4 = zext(IMM8_B3); update_xor32(RREG_RN02_EQ, u); }"
    )
    lines.append(
        ":xor IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x29; RREG_RN02_EQ; IMM24_B345 "
        "{ local u:4 = zext(IMM24_B345); update_xor32(RREG_RN02_EQ, u); }"
    )
    lines.append(
        ":xor IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x29; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ update_xor32(RREG_RN02_EQ, IMM32HI8_B3456); }"
    )
    lines.append(
        ":xor RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x2D; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; update_xor32(t, RREG_B2_HI); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":not DREG_D0_LO is b0_any=0xF2; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & DREG_D0_LO "
        "{ update_not32(DREG_D0_LO); }"
    )
    lines.append(
        ":not RREG_RN02_EQ is b0_any=0xF9; b1_any=0x39; RREG_RN02_EQ "
        "{ update_not32(RREG_RN02_EQ); }"
    )
    lines.append("")
    lines.append("# Phase 3.5: mov AM33 memory edge forms (MEMINC/RI/IMM32HI8 + SP forms)")
    lines.append("")
    lines.append(
        ":mov MEMINC_RREG_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0x6A; MEMINC_RREG_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = MEMINC_RREG_D6; RREG_B2_LO = RREG_B2_LO + 4; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEMINC_RREG_D6 is b0_any=0xF9; b1_any=0x7A; RREG_B2_HI & MEMINC_RREG_D6 "
        "{ MEMINC_RREG_D6 = RREG_B2_HI; RREG_B2_LO = RREG_B2_LO + 4; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_RI_RREG_D7, RREG_B3_HI is b0_any=0xFB; b1_any=0x8E; MEM_RI_RREG_D7 & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ RREG_B3_HI = MEM_RI_RREG_D7; }"
    )
    lines.append(
        ":mov RREG_B3_HI, MEM_RI_RREG_D7 is b0_any=0xFB; b1_any=0x9E; RREG_B3_HI & MEM_RI_RREG_D7 & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ MEM_RI_RREG_D7 = RREG_B3_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_IMM8_SP_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x8A; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM8_SP_D7 "
        "{ RREG_B2_HI = MEM_IMM8_SP_D7; }"
    )
    lines.append(
        ":mov MEM_IMM24_SP_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x8A; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM24_SP_D8 "
        "{ RREG_B2_HI = MEM_IMM24_SP_D8; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_IMM8_SP_D7 is b0_any=0xFB; b1_any=0x9A; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM8_SP_D7 "
        "{ MEM_IMM8_SP_D7 = RREG_B2_HI; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_IMM24_SP_D8 is b0_any=0xFD; b1_any=0x9A; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM24_SP_D8 "
        "{ MEM_IMM24_SP_D8 = RREG_B2_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEMINC2_SIMM8_RREG_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x6A; MEMINC2_SIMM8_RREG_D7 & RREG_B2_HI "
        "{ RREG_B2_HI = MEMINC2_SIMM8_RREG_D7; local inc:4 = sext(b3_simm); RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEMINC2_SIMM8_RREG_D7 is b0_any=0xFB; b1_any=0x7A; RREG_B2_HI & MEMINC2_SIMM8_RREG_D7 "
        "{ MEMINC2_SIMM8_RREG_D7 = RREG_B2_HI; local inc:4 = sext(b3_simm); RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":mov MEMINC2_IMM24_RREG_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x6A; MEMINC2_IMM24_RREG_D8 & RREG_B2_HI "
        "{ RREG_B2_HI = MEMINC2_IMM24_RREG_D8; "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEMINC2_IMM24_RREG_D8 is b0_any=0xFD; b1_any=0x7A; RREG_B2_HI & MEMINC2_IMM24_RREG_D8 "
        "{ MEMINC2_IMM24_RREG_D8 = RREG_B2_HI; "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append("")
    lines.append(
        ":mov MEM_IMM32HI8_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x0E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM32HI8_D9 "
        "{ RREG_B2_HI = MEM_IMM32HI8_D9; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_IMM32HI8_D9 is b0_any=0xFE; b1_any=0x1E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM32HI8_D9 "
        "{ MEM_IMM32HI8_D9 = RREG_B2_HI; }"
    )
    lines.append(
        ":mov MEM_IMM32HI8_RREG_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x0A; MEM_IMM32HI8_RREG_D9 & RREG_B2_HI "
        "{ RREG_B2_HI = MEM_IMM32HI8_RREG_D9; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x1A; RREG_B2_HI & MEM_IMM32HI8_RREG_D9 "
        "{ MEM_IMM32HI8_RREG_D9 = RREG_B2_HI; }"
    )
    lines.append(
        ":mov MEM_IMM32HI8_SP_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x8A; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM32HI8_SP_D9 "
        "{ RREG_B2_HI = MEM_IMM32HI8_SP_D9; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEM_IMM32HI8_SP_D9 is b0_any=0xFE; b1_any=0x9A; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM_IMM32HI8_SP_D9 "
        "{ MEM_IMM32HI8_SP_D9 = RREG_B2_HI; }"
    )
    lines.append("")
    lines.append(
        ":mov MEMINC2_IMM32HI8_RREG_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x6A; MEMINC2_IMM32HI8_RREG_D9 & RREG_B2_HI "
        "{ RREG_B2_HI = MEMINC2_IMM32HI8_RREG_D9; "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16) | (zext(b6_any) << 24); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":mov RREG_B2_HI, MEMINC2_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x7A; RREG_B2_HI & MEMINC2_IMM32HI8_RREG_D9 "
        "{ MEMINC2_IMM32HI8_RREG_D9 = RREG_B2_HI; "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16) | (zext(b6_any) << 24); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append("")
    lines.append("# Phase 3.6: movbu/movhu AM33 memory families")
    lines.append("")
    lines.append(
        ":movbu MEM8_RREG_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0x2A; MEM8_RREG_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM8_RREG_D6); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_RREG_D6 is b0_any=0xF9; b1_any=0x3A; RREG_B2_HI & MEM8_RREG_D6 "
        "{ MEM8_RREG_D6 = RREG_B2_HI:1; }"
    )
    lines.append(
        ":movbu MEM8_SP_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0xAA; MEM8_SP_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM8_SP_D6); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_SP_D6 is b0_any=0xF9; b1_any=0xBA; RREG_B2_HI & MEM8_SP_D6 "
        "{ MEM8_SP_D6 = RREG_B2_HI:1; }"
    )
    lines.append("")
    lines.append(
        ":movbu MEM8_SD8_RREG_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x2A; MEM8_SD8_RREG_D7 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM8_SD8_RREG_D7); }"
    )
    lines.append(
        ":movbu MEM8_SD24_RREG_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x2A; MEM8_SD24_RREG_D8 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM8_SD24_RREG_D8); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_SD8_RREG_D7 is b0_any=0xFB; b1_any=0x3A; RREG_B2_HI & MEM8_SD8_RREG_D7 "
        "{ MEM8_SD8_RREG_D7 = RREG_B2_HI:1; }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_SD24_RREG_D8 is b0_any=0xFD; b1_any=0x3A; RREG_B2_HI & MEM8_SD24_RREG_D8 "
        "{ MEM8_SD24_RREG_D8 = RREG_B2_HI:1; }"
    )
    lines.append(
        ":movbu MEM8_IMM8_SP_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0xAA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM8_SP_D7 "
        "{ RREG_B2_HI = zext(MEM8_IMM8_SP_D7); }"
    )
    lines.append(
        ":movbu MEM8_IMM24_SP_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0xAA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM24_SP_D8 "
        "{ RREG_B2_HI = zext(MEM8_IMM24_SP_D8); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_IMM8_SP_D7 is b0_any=0xFB; b1_any=0xBA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM8_SP_D7 "
        "{ MEM8_IMM8_SP_D7 = RREG_B2_HI:1; }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_IMM24_SP_D8 is b0_any=0xFD; b1_any=0xBA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM24_SP_D8 "
        "{ MEM8_IMM24_SP_D8 = RREG_B2_HI:1; }"
    )
    lines.append("")
    lines.append(
        ":movbu MEM8_IMM8_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x2E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM8_D7 "
        "{ RREG_B2_HI = zext(MEM8_IMM8_D7); }"
    )
    lines.append(
        ":movbu MEM8_IMM24_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x2E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM24_D8 "
        "{ RREG_B2_HI = zext(MEM8_IMM24_D8); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_IMM8_D7 is b0_any=0xFB; b1_any=0x3E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM8_D7 "
        "{ MEM8_IMM8_D7 = RREG_B2_HI:1; }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_IMM24_D8 is b0_any=0xFD; b1_any=0x3E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM24_D8 "
        "{ MEM8_IMM24_D8 = RREG_B2_HI:1; }"
    )
    lines.append("")
    lines.append(
        ":movbu MEM8_RI_RREG_D7, RREG_B3_HI is b0_any=0xFB; b1_any=0xAE; MEM8_RI_RREG_D7 & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ RREG_B3_HI = zext(MEM8_RI_RREG_D7); }"
    )
    lines.append(
        ":movbu RREG_B3_HI, MEM8_RI_RREG_D7 is b0_any=0xFB; b1_any=0xBE; RREG_B3_HI & MEM8_RI_RREG_D7 & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ MEM8_RI_RREG_D7 = RREG_B3_HI:1; }"
    )
    lines.append("")
    lines.append(
        ":movbu MEM8_IMM32HI8_RREG_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x2A; MEM8_IMM32HI8_RREG_D9 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM8_IMM32HI8_RREG_D9); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x3A; RREG_B2_HI & MEM8_IMM32HI8_RREG_D9 "
        "{ MEM8_IMM32HI8_RREG_D9 = RREG_B2_HI:1; }"
    )
    lines.append(
        ":movbu MEM8_IMM32HI8_SP_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0xAA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM32HI8_SP_D9 "
        "{ RREG_B2_HI = zext(MEM8_IMM32HI8_SP_D9); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_IMM32HI8_SP_D9 is b0_any=0xFE; b1_any=0xBA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM32HI8_SP_D9 "
        "{ MEM8_IMM32HI8_SP_D9 = RREG_B2_HI:1; }"
    )
    lines.append(
        ":movbu MEM8_IMM32HI8_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x2E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM32HI8_D9 "
        "{ RREG_B2_HI = zext(MEM8_IMM32HI8_D9); }"
    )
    lines.append(
        ":movbu RREG_B2_HI, MEM8_IMM32HI8_D9 is b0_any=0xFE; b1_any=0x3E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM8_IMM32HI8_D9 "
        "{ MEM8_IMM32HI8_D9 = RREG_B2_HI:1; }"
    )
    lines.append("")
    lines.append(
        ":movhu MEM16_RREG_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0x4A; MEM16_RREG_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16_RREG_D6); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_RREG_D6 is b0_any=0xF9; b1_any=0x5A; RREG_B2_HI & MEM16_RREG_D6 "
        "{ MEM16_RREG_D6 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu MEM16_SP_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0xCA; MEM16_SP_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16_SP_D6); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_SP_D6 is b0_any=0xF9; b1_any=0xDA; RREG_B2_HI & MEM16_SP_D6 "
        "{ MEM16_SP_D6 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu MEM16INC_RREG_D6, RREG_B2_HI is b0_any=0xF9; b1_any=0xEA; MEM16INC_RREG_D6 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16INC_RREG_D6); RREG_B2_LO = RREG_B2_LO + 2; }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16INC_RREG_D6 is b0_any=0xF9; b1_any=0xFA; RREG_B2_HI & MEM16INC_RREG_D6 "
        "{ MEM16INC_RREG_D6 = RREG_B2_HI:2; RREG_B2_LO = RREG_B2_LO + 2; }"
    )
    lines.append("")
    lines.append(
        ":movhu MEM16_SD8_RREG_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x4A; MEM16_SD8_RREG_D7 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16_SD8_RREG_D7); }"
    )
    lines.append(
        ":movhu MEM16_SD24_RREG_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x4A; MEM16_SD24_RREG_D8 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16_SD24_RREG_D8); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_SD8_RREG_D7 is b0_any=0xFB; b1_any=0x5A; RREG_B2_HI & MEM16_SD8_RREG_D7 "
        "{ MEM16_SD8_RREG_D7 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_SD24_RREG_D8 is b0_any=0xFD; b1_any=0x5A; RREG_B2_HI & MEM16_SD24_RREG_D8 "
        "{ MEM16_SD24_RREG_D8 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu MEM16_IMM8_SP_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0xCA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM8_SP_D7 "
        "{ RREG_B2_HI = zext(MEM16_IMM8_SP_D7); }"
    )
    lines.append(
        ":movhu MEM16_IMM24_SP_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0xCA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM24_SP_D8 "
        "{ RREG_B2_HI = zext(MEM16_IMM24_SP_D8); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_IMM8_SP_D7 is b0_any=0xFB; b1_any=0xDA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM8_SP_D7 "
        "{ MEM16_IMM8_SP_D7 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_IMM24_SP_D8 is b0_any=0xFD; b1_any=0xDA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM24_SP_D8 "
        "{ MEM16_IMM24_SP_D8 = RREG_B2_HI:2; }"
    )
    lines.append("")
    lines.append(
        ":movhu MEM16_IMM8_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0x4E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM8_D7 "
        "{ RREG_B2_HI = zext(MEM16_IMM8_D7); }"
    )
    lines.append(
        ":movhu MEM16_IMM24_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0x4E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM24_D8 "
        "{ RREG_B2_HI = zext(MEM16_IMM24_D8); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_IMM8_D7 is b0_any=0xFB; b1_any=0x5E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM8_D7 "
        "{ MEM16_IMM8_D7 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_IMM24_D8 is b0_any=0xFD; b1_any=0x5E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM24_D8 "
        "{ MEM16_IMM24_D8 = RREG_B2_HI:2; }"
    )
    lines.append("")
    lines.append(
        ":movhu MEM16_RI_RREG_D7, RREG_B3_HI is b0_any=0xFB; b1_any=0xCE; MEM16_RI_RREG_D7 & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ RREG_B3_HI = zext(MEM16_RI_RREG_D7); }"
    )
    lines.append(
        ":movhu RREG_B3_HI, MEM16_RI_RREG_D7 is b0_any=0xFB; b1_any=0xDE; RREG_B3_HI & MEM16_RI_RREG_D7 & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ MEM16_RI_RREG_D7 = RREG_B3_HI:2; }"
    )
    lines.append("")
    lines.append(
        ":movhu MEM16_IMM32HI8_RREG_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x4A; MEM16_IMM32HI8_RREG_D9 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16_IMM32HI8_RREG_D9); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x5A; RREG_B2_HI & MEM16_IMM32HI8_RREG_D9 "
        "{ MEM16_IMM32HI8_RREG_D9 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu MEM16_IMM32HI8_SP_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0xCA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM32HI8_SP_D9 "
        "{ RREG_B2_HI = zext(MEM16_IMM32HI8_SP_D9); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_IMM32HI8_SP_D9 is b0_any=0xFE; b1_any=0xDA; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM32HI8_SP_D9 "
        "{ MEM16_IMM32HI8_SP_D9 = RREG_B2_HI:2; }"
    )
    lines.append(
        ":movhu MEM16_IMM32HI8_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0x4E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM32HI8_D9 "
        "{ RREG_B2_HI = zext(MEM16_IMM32HI8_D9); }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16_IMM32HI8_D9 is b0_any=0xFE; b1_any=0x5E; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI; MEM16_IMM32HI8_D9 "
        "{ MEM16_IMM32HI8_D9 = RREG_B2_HI:2; }"
    )
    lines.append("")
    lines.append(
        ":movhu MEM16INC2_SIMM8_RREG_D7, RREG_B2_HI is b0_any=0xFB; b1_any=0xEA; MEM16INC2_SIMM8_RREG_D7 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16INC2_SIMM8_RREG_D7); local inc:4 = sext(b3_simm); RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16INC2_SIMM8_RREG_D7 is b0_any=0xFB; b1_any=0xFA; RREG_B2_HI & MEM16INC2_SIMM8_RREG_D7 "
        "{ MEM16INC2_SIMM8_RREG_D7 = RREG_B2_HI:2; local inc:4 = sext(b3_simm); RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":movhu MEM16INC2_IMM24_RREG_D8, RREG_B2_HI is b0_any=0xFD; b1_any=0xEA; MEM16INC2_IMM24_RREG_D8 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16INC2_IMM24_RREG_D8); "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16INC2_IMM24_RREG_D8 is b0_any=0xFD; b1_any=0xFA; RREG_B2_HI & MEM16INC2_IMM24_RREG_D8 "
        "{ MEM16INC2_IMM24_RREG_D8 = RREG_B2_HI:2; "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":movhu MEM16INC2_IMM32HI8_RREG_D9, RREG_B2_HI is b0_any=0xFE; b1_any=0xEA; MEM16INC2_IMM32HI8_RREG_D9 & RREG_B2_HI "
        "{ RREG_B2_HI = zext(MEM16INC2_IMM32HI8_RREG_D9); "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16) | (zext(b6_any) << 24); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append(
        ":movhu RREG_B2_HI, MEM16INC2_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0xFA; RREG_B2_HI & MEM16INC2_IMM32HI8_RREG_D9 "
        "{ MEM16INC2_IMM32HI8_RREG_D9 = RREG_B2_HI:2; "
        "local inc:4 = zext(b3_any) | (zext(b4_any) << 8) | (zext(b5_any) << 16) | (zext(b6_any) << 24); "
        "RREG_B2_LO = RREG_B2_LO + inc; }"
    )
    lines.append("")
    lines.append("# Phase 3.7: movbu/movhu non-AM33 memory families")
    lines.append("")
    lines.append(
        ":movbu MEM8_AREG_D0_LO, DREG_D0_HI is b0_any=0xF0; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=0 & MEM8_AREG_D0_LO & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM8_AREG_D0_LO); }"
    )
    lines.append(
        ":movbu MEM8_SD8_AREG_D1, DREG_D0_HI is b0_any=0xF8; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=0 & MEM8_SD8_AREG_D1 & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM8_SD8_AREG_D1); }"
    )
    lines.append(
        ":movbu MEM8_SD16_AREG_D2, DREG_D0_HI is b0_any=0xFA; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=0 & MEM8_SD16_AREG_D2 & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM8_SD16_AREG_D2); }"
    )
    lines.append(
        ":movbu MEM8_SP_D1, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=0 & DREG_D0_LO; MEM8_SP_D1 "
        "{ DREG_D0_LO = zext(MEM8_SP_D1); }"
    )
    lines.append(
        ":movbu MEM8_IMM8_SP_D1, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=0 & DREG_D0_LO; MEM8_IMM8_SP_D1 "
        "{ DREG_D0_LO = zext(MEM8_IMM8_SP_D1); }"
    )
    lines.append(
        ":movbu MEM8_IMM16_SP_D2, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=0 & DREG_D0_LO; MEM8_IMM16_SP_D2 "
        "{ DREG_D0_LO = zext(MEM8_IMM16_SP_D2); }"
    )
    lines.append(
        ":movbu MEM8_DI_AREG_D0, DREG_D0_2 is b0_any=0xF4; b1_7=0 & b1_6=0 & DREG_D0_2 & MEM8_DI_AREG_D0 "
        "{ DREG_D0_2 = zext(MEM8_DI_AREG_D0); }"
    )
    lines.append(
        ":movbu MEM8_ABS16_S2, DREG_S1_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=1 & b0_3=0 & b0_2=1 & DREG_S1_LO; MEM8_ABS16_S2 "
        "{ DREG_S1_LO = zext(MEM8_ABS16_S2); }"
    )
    lines.append(
        ":movbu MEM8_IMM32_AREG_D4, DREG_D0_HI is b0_any=0xFC; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=0 & MEM8_IMM32_AREG_D4 & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM8_IMM32_AREG_D4); }"
    )
    lines.append(
        ":movbu MEM8_IMM32_SP_D4, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=0 & DREG_D0_LO; MEM8_IMM32_SP_D4 "
        "{ DREG_D0_LO = zext(MEM8_IMM32_SP_D4); }"
    )
    lines.append(
        ":movbu MEM8_ABS32_D4, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=0 & DREG_D0_LO; MEM8_ABS32_D4 "
        "{ DREG_D0_LO = zext(MEM8_ABS32_D4); }"
    )
    lines.append("")
    lines.append(
        ":movbu DREG_D0_HI, MEM8_AREG_D0_LO is b0_any=0xF0; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM8_AREG_D0_LO "
        "{ MEM8_AREG_D0_LO = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_SD8_AREG_D1 is b0_any=0xF8; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM8_SD8_AREG_D1 "
        "{ MEM8_SD8_AREG_D1 = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_SD16_AREG_D2 is b0_any=0xFA; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM8_SD16_AREG_D2 "
        "{ MEM8_SD16_AREG_D2 = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_SP_D1 is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=0; MEM8_SP_D1 "
        "{ MEM8_SP_D1 = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_IMM8_SP_D1 is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=0; MEM8_IMM8_SP_D1 "
        "{ MEM8_IMM8_SP_D1 = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_IMM16_SP_D2 is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=0; MEM8_IMM16_SP_D2 "
        "{ MEM8_IMM16_SP_D2 = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_2, MEM8_DI_AREG_D0 is b0_any=0xF4; b1_7=0 & b1_6=1 & DREG_D0_2 & MEM8_DI_AREG_D0 "
        "{ MEM8_DI_AREG_D0 = DREG_D0_2:1; }"
    )
    lines.append(
        ":movbu DREG_S1_HI, MEM8_ABS16_S2 is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=0 & DREG_S1_HI & b0_1=1 & b0_0=0; MEM8_ABS16_S2 "
        "{ MEM8_ABS16_S2 = DREG_S1_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_IMM32_AREG_D4 is b0_any=0xFC; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM8_IMM32_AREG_D4 "
        "{ MEM8_IMM32_AREG_D4 = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_IMM32_SP_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=0; MEM8_IMM32_SP_D4 "
        "{ MEM8_IMM32_SP_D4 = DREG_D0_HI:1; }"
    )
    lines.append(
        ":movbu DREG_D0_HI, MEM8_ABS32_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=0 & DREG_D0_HI & b1_1=1 & b1_0=0; MEM8_ABS32_D4 "
        "{ MEM8_ABS32_D4 = DREG_D0_HI:1; }"
    )
    lines.append("")
    lines.append(
        ":movhu MEM16_AREG_D0_LO, DREG_D0_HI is b0_any=0xF0; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=0 & MEM16_AREG_D0_LO & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM16_AREG_D0_LO); }"
    )
    lines.append(
        ":movhu MEM16_SD8_AREG_D1, DREG_D0_HI is b0_any=0xF8; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=0 & MEM16_SD8_AREG_D1 & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM16_SD8_AREG_D1); }"
    )
    lines.append(
        ":movhu MEM16_SD16_AREG_D2, DREG_D0_HI is b0_any=0xFA; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=0 & MEM16_SD16_AREG_D2 & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM16_SD16_AREG_D2); }"
    )
    lines.append(
        ":movhu MEM16_SP_D1, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=1 & DREG_D0_LO; MEM16_SP_D1 "
        "{ DREG_D0_LO = zext(MEM16_SP_D1); }"
    )
    lines.append(
        ":movhu MEM16_IMM8_SP_D1, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=1 & DREG_D0_LO; MEM16_IMM8_SP_D1 "
        "{ DREG_D0_LO = zext(MEM16_IMM8_SP_D1); }"
    )
    lines.append(
        ":movhu MEM16_IMM16_SP_D2, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=1 & DREG_D0_LO; MEM16_IMM16_SP_D2 "
        "{ DREG_D0_LO = zext(MEM16_IMM16_SP_D2); }"
    )
    lines.append(
        ":movhu MEM16_DI_AREG_D0, DREG_D0_2 is b0_any=0xF4; b1_7=1 & b1_6=0 & DREG_D0_2 & MEM16_DI_AREG_D0 "
        "{ DREG_D0_2 = zext(MEM16_DI_AREG_D0); }"
    )
    lines.append(
        ":movhu MEM16_ABS16_S2, DREG_S1_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=1 & b0_3=1 & b0_2=0 & DREG_S1_LO; MEM16_ABS16_S2 "
        "{ DREG_S1_LO = zext(MEM16_ABS16_S2); }"
    )
    lines.append(
        ":movhu MEM16_IMM32_AREG_D4, DREG_D0_HI is b0_any=0xFC; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=0 & MEM16_IMM32_AREG_D4 & DREG_D0_HI "
        "{ DREG_D0_HI = zext(MEM16_IMM32_AREG_D4); }"
    )
    lines.append(
        ":movhu MEM16_IMM32_SP_D4, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=1 & DREG_D0_LO; MEM16_IMM32_SP_D4 "
        "{ DREG_D0_LO = zext(MEM16_IMM32_SP_D4); }"
    )
    lines.append(
        ":movhu MEM16_ABS32_D4, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=1 & DREG_D0_LO; MEM16_ABS32_D4 "
        "{ DREG_D0_LO = zext(MEM16_ABS32_D4); }"
    )
    lines.append("")
    lines.append(
        ":movhu DREG_D0_HI, MEM16_AREG_D0_LO is b0_any=0xF0; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=1 & DREG_D0_HI & MEM16_AREG_D0_LO "
        "{ MEM16_AREG_D0_LO = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_SD8_AREG_D1 is b0_any=0xF8; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=1 & DREG_D0_HI & MEM16_SD8_AREG_D1 "
        "{ MEM16_SD8_AREG_D1 = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_SD16_AREG_D2 is b0_any=0xFA; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=1 & DREG_D0_HI & MEM16_SD16_AREG_D2 "
        "{ MEM16_SD16_AREG_D2 = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_SP_D1 is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=1; MEM16_SP_D1 "
        "{ MEM16_SP_D1 = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_IMM8_SP_D1 is b0_any=0xF8; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=1; MEM16_IMM8_SP_D1 "
        "{ MEM16_IMM8_SP_D1 = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_IMM16_SP_D2 is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=1; MEM16_IMM16_SP_D2 "
        "{ MEM16_IMM16_SP_D2 = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_2, MEM16_DI_AREG_D0 is b0_any=0xF4; b1_7=1 & b1_6=1 & DREG_D0_2 & MEM16_DI_AREG_D0 "
        "{ MEM16_DI_AREG_D0 = DREG_D0_2:2; }"
    )
    lines.append(
        ":movhu DREG_S1_HI, MEM16_ABS16_S2 is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=0 & DREG_S1_HI & b0_1=1 & b0_0=1; MEM16_ABS16_S2 "
        "{ MEM16_ABS16_S2 = DREG_S1_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_IMM32_AREG_D4 is b0_any=0xFC; b1_7=0 & b1_6=1 & b1_5=1 & b1_4=1 & DREG_D0_HI & MEM16_IMM32_AREG_D4 "
        "{ MEM16_IMM32_AREG_D4 = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_IMM32_SP_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=1 & b1_0=1; MEM16_IMM32_SP_D4 "
        "{ MEM16_IMM32_SP_D4 = DREG_D0_HI:2; }"
    )
    lines.append(
        ":movhu DREG_D0_HI, MEM16_ABS32_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=0 & DREG_D0_HI & b1_1=1 & b1_0=1; MEM16_ABS32_D4 "
        "{ MEM16_ABS32_D4 = DREG_D0_HI:2; }"
    )
    lines.append("")
    lines.append("# Phase 3.8: movu/ext/clr/inc families")
    lines.append("")
    lines.append(
        ":movu IMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x18; RREG_RN02_EQ; IMM8_B3 "
        "{ RREG_RN02_EQ = zext(IMM8_B3); }"
    )
    lines.append(
        ":movu IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x18; RREG_RN02_EQ; IMM24_B345 "
        "{ RREG_RN02_EQ = zext(IMM24_B345); }"
    )
    lines.append(
        ":movu IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x18; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ RREG_RN02_EQ = IMM32HI8_B3456; }"
    )
    lines.append("")
    lines.append(
        ":ext DREG_D0_LO is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & DREG_D0_LO "
        "{ DREG_D0_LO = sext(DREG_D0_LO:2); }"
    )
    lines.append(
        ":ext RREG_RN02_EQ is b0_any=0xF9; b1_any=0x18; RREG_RN02_EQ "
        "{ RREG_RN02_EQ = sext(RREG_RN02_EQ:2); }"
    )
    lines.append(
        ":extb DREG_S0_LO is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=1 & b0_3=0 & b0_2=0 & DREG_S0_LO "
        "{ DREG_S0_LO = sext(DREG_S0_LO); }"
    )
    lines.append(
        ":extb RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x28; RREG_B2_HI & RREG_B2_LO "
        "{ RREG_B2_LO = sext(RREG_B2_HI); }"
    )
    lines.append(
        ":extbu DREG_S0_LO is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=1 & b0_3=0 & b0_2=1 & DREG_S0_LO "
        "{ DREG_S0_LO = zext(DREG_S0_LO); }"
    )
    lines.append(
        ":extbu RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x38; RREG_B2_HI & RREG_B2_LO "
        "{ RREG_B2_LO = zext(RREG_B2_HI); }"
    )
    lines.append(
        ":exth DREG_S0_LO is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=1 & b0_3=1 & b0_2=0 & DREG_S0_LO "
        "{ DREG_S0_LO = sext(DREG_S0_LO:2); }"
    )
    lines.append(
        ":exth RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x48; RREG_B2_HI & RREG_B2_LO "
        "{ RREG_B2_LO = sext(RREG_B2_HI:2); }"
    )
    lines.append(
        ":exthu DREG_S0_LO is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=1 & b0_3=1 & b0_2=1 & DREG_S0_LO "
        "{ DREG_S0_LO = zext(DREG_S0_LO:2); }"
    )
    lines.append(
        ":exthu RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x58; RREG_B2_HI & RREG_B2_LO "
        "{ RREG_B2_LO = zext(RREG_B2_HI:2); }"
    )
    lines.append("")
    lines.append(
        ":clr DREG_S0_HI is b0_7=0 & b0_6=0 & b0_5=0 & b0_4=0 & DREG_S0_HI & b0_1=0 & b0_0=0 "
        "{ DREG_S0_HI = 0; }"
    )
    lines.append(
        ":clr RREG_RN02_EQ is b0_any=0xF9; b1_any=0x68; RREG_RN02_EQ "
        "{ RREG_RN02_EQ = 0; }"
    )
    lines.append("")
    lines.append(
        ":inc DREG_S0_HI is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=0 & DREG_S0_HI & b0_1=0 & b0_0=0 "
        "{ DREG_S0_HI = DREG_S0_HI + 1; }"
    )
    lines.append(
        ":inc AREG_S0_HI is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=0 & AREG_S0_HI & b0_1=0 & b0_0=1 "
        "{ AREG_S0_HI = AREG_S0_HI + 1; }"
    )
    lines.append(
        ":inc RREG_RN02_EQ is b0_any=0xF9; b1_any=0xB8; RREG_RN02_EQ "
        "{ RREG_RN02_EQ = RREG_RN02_EQ + 1; }"
    )
    lines.append(
        ":inc4 AREG_S0_LO is b0_7=0 & b0_6=1 & b0_5=0 & b0_4=1 & b0_3=0 & b0_2=0 & AREG_S0_LO "
        "{ AREG_S0_LO = AREG_S0_LO + 4; }"
    )
    lines.append(
        ":inc4 RREG_RN02_EQ is b0_any=0xF9; b1_any=0xC8; RREG_RN02_EQ "
        "{ RREG_RN02_EQ = RREG_RN02_EQ + 4; }"
    )
    lines.append("")
    lines.append("# Phase 3.9: asr/lsr/asl shift families")
    lines.append("")
    lines.append(
        ":asr DREG_D0_HI, DREG_D0_LO is b0_any=0xF2; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & DREG_D0_HI & DREG_D0_LO "
        "{ local sh:4 = DREG_D0_HI; update_asr32(DREG_D0_LO, sh); }"
    )
    lines.append(
        ":asr IMM8_B2, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=1 & b1_2=0 & DREG_D0_LO; IMM8_B2 "
        "{ local sh:4 = zext(IMM8_B2); update_asr32(DREG_D0_LO, sh); }"
    )
    lines.append(
        ":asr RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x49; RREG_B2_HI & RREG_B2_LO "
        "{ local sh:4 = RREG_B2_HI; update_asr32(RREG_B2_LO, sh); }"
    )
    lines.append(
        ":asr IMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x49; RREG_RN02_EQ; IMM8_B3 "
        "{ local sh:4 = zext(IMM8_B3); update_asr32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":asr IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x49; RREG_RN02_EQ; IMM24_B345 "
        "{ local sh:4 = zext(IMM24_B345); update_asr32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":asr IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x49; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ local sh:4 = IMM32HI8_B3456; update_asr32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":asr RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x4D; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; local sh:4 = RREG_B2_HI; update_asr32(t, sh); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":lsr DREG_D0_HI, DREG_D0_LO is b0_any=0xF2; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & DREG_D0_HI & DREG_D0_LO "
        "{ local sh:4 = DREG_D0_HI; update_lsr32(DREG_D0_LO, sh); }"
    )
    lines.append(
        ":lsr IMM8_B2, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=0 & b1_2=1 & DREG_D0_LO; IMM8_B2 "
        "{ local sh:4 = zext(IMM8_B2); update_lsr32(DREG_D0_LO, sh); }"
    )
    lines.append(
        ":lsr RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x59; RREG_B2_HI & RREG_B2_LO "
        "{ local sh:4 = RREG_B2_HI; update_lsr32(RREG_B2_LO, sh); }"
    )
    lines.append(
        ":lsr IMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x59; RREG_RN02_EQ; IMM8_B3 "
        "{ local sh:4 = zext(IMM8_B3); update_lsr32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":lsr IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x59; RREG_RN02_EQ; IMM24_B345 "
        "{ local sh:4 = zext(IMM24_B345); update_lsr32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":lsr IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x59; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ local sh:4 = IMM32HI8_B3456; update_lsr32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":lsr RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x5D; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; local sh:4 = RREG_B2_HI; update_lsr32(t, sh); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append(
        ":asl DREG_D0_HI, DREG_D0_LO is b0_any=0xF2; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & DREG_D0_LO "
        "{ local sh:4 = DREG_D0_HI; update_asl32(DREG_D0_LO, sh); }"
    )
    lines.append(
        ":asl IMM8_B2, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=0 & b1_2=0 & DREG_D0_LO; IMM8_B2 "
        "{ local sh:4 = zext(IMM8_B2); update_asl32(DREG_D0_LO, sh); }"
    )
    lines.append(
        ":asl RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x69; RREG_B2_HI & RREG_B2_LO "
        "{ local sh:4 = RREG_B2_HI; update_asl32(RREG_B2_LO, sh); }"
    )
    lines.append(
        ":asl SIMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x69; RREG_RN02_EQ; SIMM8_B3 "
        "{ local sh:4 = sext(SIMM8_B3); update_asl32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":asl IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x69; RREG_RN02_EQ; IMM24_B345 "
        "{ local sh:4 = zext(IMM24_B345); update_asl32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":asl IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x69; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ local sh:4 = IMM32HI8_B3456; update_asl32(RREG_RN02_EQ, sh); }"
    )
    lines.append(
        ":asl RREG_B2_HI, RREG_B2_LO, RREG_B3_HI is b0_any=0xFB; b1_any=0x6D; RREG_B2_HI & RREG_B2_LO & RREG_B3_HI & b3_3=0 & b3_2=0 & b3_1=0 & b3_0=0 "
        "{ local t:4 = RREG_B2_LO; local sh:4 = RREG_B2_HI; update_asl32(t, sh); RREG_B3_HI = t; }"
    )
    lines.append("")
    lines.append("# Phase 3.10: btst/bset/bclr families")
    lines.append("")
    lines.append(
        ":btst IMM8_B2, DREG_D0_LO is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=1 & DREG_D0_LO; IMM8_B2 "
        "{ local bit:4 = zext(IMM8_B2); update_btst_reg32(bit, DREG_D0_LO); }"
    )
    lines.append(
        ":btst IMM16_B23, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=1 & DREG_D0_LO; IMM16_B23 "
        "{ local bit:4 = zext(IMM16_B23); update_btst_reg32(bit, DREG_D0_LO); }"
    )
    lines.append(
        ":btst IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=1 & DREG_D0_LO; IMM32_B2345 "
        "{ local bit:4 = IMM32_B2345; update_btst_reg32(bit, DREG_D0_LO); }"
    )
    lines.append(
        ":btst IMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0xE9; RREG_RN02_EQ; IMM8_B3 "
        "{ local bit:4 = zext(IMM8_B3); update_btst_reg32(bit, RREG_RN02_EQ); }"
    )
    lines.append(
        ":btst IMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0xE9; RREG_RN02_EQ; IMM24_B345 "
        "{ local bit:4 = zext(IMM24_B345); update_btst_reg32(bit, RREG_RN02_EQ); }"
    )
    lines.append(
        ":btst IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0xE9; RREG_RN02_EQ; IMM32HI8_B3456 "
        "{ local bit:4 = IMM32HI8_B3456; update_btst_reg32(bit, RREG_RN02_EQ); }"
    )
    lines.append(
        ":btst IMM8_B3, MEM8_SD8N_SHIFT8_AREG_D2 is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & b1_3=1 & b1_2=0 & MEM8_SD8N_SHIFT8_AREG_D2; IMM8_B3 "
        "{ local bit:4 = zext(IMM8_B3); update_btst_mem8(bit, MEM8_SD8N_SHIFT8_AREG_D2); }"
    )
    lines.append(
        ":btst IMM8E_B4, MEM8_ABS16_D3 is b0_any=0xFE; b1_any=0x82; IMM8E_B4; MEM8_ABS16_D3 "
        "{ local bit:4 = zext(IMM8E_B4); update_btst_mem8(bit, MEM8_ABS16_D3); }"
    )
    lines.append(
        ":btst IMM8E_B6, MEM8_ABS32_D5 is b0_any=0xFE; b1_any=0x02; b2_any; b3_any; b4_any; b5_any; IMM8E_B6 "
        "{ local bit:4 = zext(IMM8E_B6); update_btst_mem8(bit, MEM8_ABS32_D5); }"
    )
    lines.append("")
    lines.append(
        ":bset DREG_D0_HI, MEM8_AREG_D0_LO is b0_any=0xF0; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=0 & DREG_D0_HI & MEM8_AREG_D0_LO "
        "{ local bit:4 = DREG_D0_HI; update_bset_mem8(bit, MEM8_AREG_D0_LO); }"
    )
    lines.append(
        ":bset IMM8_B3, MEM8_SD8N_SHIFT8_AREG_D2 is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & MEM8_SD8N_SHIFT8_AREG_D2; IMM8_B3 "
        "{ local bit:4 = zext(IMM8_B3); update_bset_mem8(bit, MEM8_SD8N_SHIFT8_AREG_D2); }"
    )
    lines.append(
        ":bset IMM8E_B4, MEM8_ABS16_D3 is b0_any=0xFE; b1_any=0x80; IMM8E_B4; MEM8_ABS16_D3 "
        "{ local bit:4 = zext(IMM8E_B4); update_bset_mem8(bit, MEM8_ABS16_D3); }"
    )
    lines.append(
        ":bset IMM8E_B6, MEM8_ABS32_D5 is b0_any=0xFE; b1_any=0x00; b2_any; b3_any; b4_any; b5_any; IMM8E_B6 "
        "{ local bit:4 = zext(IMM8E_B6); update_bset_mem8(bit, MEM8_ABS32_D5); }"
    )
    lines.append("")
    lines.append(
        ":bclr DREG_D0_HI, MEM8_AREG_D0_LO is b0_any=0xF0; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM8_AREG_D0_LO "
        "{ local bit:4 = DREG_D0_HI; update_bclr_mem8(bit, MEM8_AREG_D0_LO); }"
    )
    lines.append(
        ":bclr IMM8_B3, MEM8_SD8N_SHIFT8_AREG_D2 is b0_any=0xFA; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & MEM8_SD8N_SHIFT8_AREG_D2; IMM8_B3 "
        "{ local bit:4 = zext(IMM8_B3); update_bclr_mem8(bit, MEM8_SD8N_SHIFT8_AREG_D2); }"
    )
    lines.append(
        ":bclr IMM8E_B4, MEM8_ABS16_D3 is b0_any=0xFE; b1_any=0x81; IMM8E_B4; MEM8_ABS16_D3 "
        "{ local bit:4 = zext(IMM8E_B4); update_bclr_mem8(bit, MEM8_ABS16_D3); }"
    )
    lines.append(
        ":bclr IMM8E_B6, MEM8_ABS32_D5 is b0_any=0xFE; b1_any=0x01; b2_any; b3_any; b4_any; b5_any; IMM8E_B6 "
        "{ local bit:4 = zext(IMM8E_B6); update_bclr_mem8(bit, MEM8_ABS32_D5); }"
    )
    lines.append("")
    lines.append("# Phase 3.11: cmp S0 non-equal register families")
    lines.append("")
    for low in range(4):
        for high in range(4):
            if low == high:
                continue
            lines.append(
                f":cmp DREG_S0_HI, DREG_S0_LO is b0_7=1 & b0_6=0 & b0_5=1 & b0_4=0 & "
                f"DREG_S0_HI & DREG_S0_LO & b0_3={(high >> 1) & 1} & b0_2={high & 1} & "
                f"b0_1={(low >> 1) & 1} & b0_0={low & 1} "
                "{ update_cmp32(DREG_S0_LO, DREG_S0_HI); }"
            )
    for low in range(4):
        for high in range(4):
            if low == high:
                continue
            lines.append(
                f":cmp AREG_S0_HI, AREG_S0_LO is b0_7=1 & b0_6=0 & b0_5=1 & b0_4=1 & "
                f"AREG_S0_HI & AREG_S0_LO & b0_3={(high >> 1) & 1} & b0_2={high & 1} & "
                f"b0_1={(low >> 1) & 1} & b0_0={low & 1} "
                "{ update_cmp32(AREG_S0_LO, AREG_S0_HI); }"
            )
    lines.append("")
    lines.append("# Phase 3.12: mov remaining families (S0 no-match, system/XR, and wide immediate/memory)")
    lines.append("")
    for low in range(4):
        for high in range(4):
            if low == high:
                continue
            lines.append(
                f":mov DREG_S0_HI, DREG_S0_LO is b0_7=1 & b0_6=0 & b0_5=0 & b0_4=0 & "
                f"DREG_S0_HI & DREG_S0_LO & b0_3={(high >> 1) & 1} & b0_2={high & 1} & "
                f"b0_1={(low >> 1) & 1} & b0_0={low & 1} "
                "{ DREG_S0_LO = DREG_S0_HI; }"
            )
    for low in range(4):
        for high in range(4):
            if low == high:
                continue
            lines.append(
                f":mov AREG_S0_HI, AREG_S0_LO is b0_7=1 & b0_6=0 & b0_5=0 & b0_4=1 & "
                f"AREG_S0_HI & AREG_S0_LO & b0_3={(high >> 1) & 1} & b0_2={high & 1} & "
                f"b0_1={(low >> 1) & 1} & b0_0={low & 1} "
                "{ AREG_S0_LO = AREG_S0_HI; }"
            )
    lines.append("")
    mov_phase312 = [
        ":mov MEM_IMM16_SP_D2, DREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & DREG_D0_LO; MEM_IMM16_SP_D2 { DREG_D0_LO = MEM_IMM16_SP_D2; }",
        ":mov MEM_IMM16_SP_D2, AREG_D0_LO is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & AREG_D0_LO; MEM_IMM16_SP_D2 { AREG_D0_LO = MEM_IMM16_SP_D2; }",
        ":mov DREG_D0_HI, MEM_IMM16_SP_D2 is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=0 & b1_0=1; MEM_IMM16_SP_D2 { MEM_IMM16_SP_D2 = DREG_D0_HI; }",
        ":mov AREG_D0_HI, MEM_IMM16_SP_D2 is b0_any=0xFA; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & AREG_D0_HI & b1_1=0 & b1_0=0; MEM_IMM16_SP_D2 { MEM_IMM16_SP_D2 = AREG_D0_HI; }",
        ":mov USP, AREG_D0_LO is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & AREG_D0_LO { AREG_D0_LO = USP; }",
        ":mov SSP, AREG_D0_LO is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & AREG_D0_LO { AREG_D0_LO = SSP; }",
        ":mov MSP, AREG_D0_LO is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=0 & AREG_D0_LO { AREG_D0_LO = MSP; }",
        ":mov PC, AREG_D0_LO is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=1 & AREG_D0_LO { AREG_D0_LO = PC; }",
        ":mov AREG_D0_HI, USP is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & AREG_D0_HI & b1_1=0 & b1_0=0 { USP = AREG_D0_HI; }",
        ":mov AREG_D0_HI, SSP is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & AREG_D0_HI & b1_1=0 & b1_0=1 { SSP = AREG_D0_HI; }",
        ":mov AREG_D0_HI, MSP is b0_any=0xF0; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & AREG_D0_HI & b1_1=1 & b1_0=0 { MSP = AREG_D0_HI; }",
        ":mov EPSW, DREG_D0_LO is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=0 & b1_3=1 & b1_2=1 & DREG_D0_LO { DREG_D0_LO = zext(EPSW); }",
        ":mov DREG_D0_HI, EPSW is b0_any=0xF2; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & DREG_D0_HI & b1_1=0 & b1_0=1 { EPSW = DREG_D0_HI:2; }",
        ":mov AREG_D0_2, RREG_B1_LO is b0_any=0xF5; b1_7=0 & b1_6=0 & AREG_D0_2 & RREG_B1_LO { RREG_B1_LO = AREG_D0_2; }",
        ":mov DREG_D0_2, RREG_B1_LO is b0_any=0xF5; b1_7=0 & b1_6=1 & DREG_D0_2 & RREG_B1_LO { RREG_B1_LO = DREG_D0_2; }",
        ":mov RREG_B1_MID, AREG_D0_LO is b0_any=0xF5; b1_7=1 & b1_6=0 & RREG_B1_MID & AREG_D0_LO { AREG_D0_LO = RREG_B1_MID; }",
        ":mov RREG_B1_MID, DREG_D0_LO is b0_any=0xF5; b1_7=1 & b1_6=1 & RREG_B1_MID & DREG_D0_LO { DREG_D0_LO = RREG_B1_MID; }",
        ":mov RREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0x08; RREG_B2_HI & RREG_B2_LO { RREG_B2_LO = RREG_B2_HI; }",
        ":mov XRREG_B2_HI, RREG_B2_LO is b0_any=0xF9; b1_any=0xE8; XRREG_B2_HI & RREG_B2_LO { RREG_B2_LO = XRREG_B2_HI; }",
        ":mov RREG_B2_HI, XRREG_B2_LO is b0_any=0xF9; b1_any=0xF8; RREG_B2_HI & XRREG_B2_LO { XRREG_B2_LO = RREG_B2_HI; }",
        ":mov SIMM16_B23, DREG_S1_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=0 & b0_3=1 & b0_2=1 & DREG_S1_LO; SIMM16_B23 { DREG_S1_LO = sext(SIMM16_B23); }",
        ":mov IMM16_B23, AREG_S1_LO is b0_7=0 & b0_6=0 & b0_5=1 & b0_4=0 & b0_3=0 & b0_2=1 & AREG_S1_LO; IMM16_B23 { AREG_S1_LO = zext(IMM16_B23); }",
        ":mov IMM32_B2345, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=1 & b1_2=1 & DREG_D0_LO; IMM32_B2345 { DREG_D0_LO = IMM32_B2345; }",
        ":mov IMM32_B2345, AREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=1 & b1_3=1 & b1_2=1 & AREG_D0_LO; IMM32_B2345 { AREG_D0_LO = IMM32_B2345; }",
        ":mov MEM_IMM32_AREG_D4, DREG_D0_HI is b0_any=0xFC; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=0 & MEM_IMM32_AREG_D4 & DREG_D0_HI { DREG_D0_HI = MEM_IMM32_AREG_D4; }",
        ":mov MEM_IMM32_SP_D4, DREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & DREG_D0_LO; MEM_IMM32_SP_D4 { DREG_D0_LO = MEM_IMM32_SP_D4; }",
        ":mov MEM_IMM32_AREG_D4, AREG_D0_HI is b0_any=0xFC; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & MEM_IMM32_AREG_D4 & AREG_D0_HI { AREG_D0_HI = MEM_IMM32_AREG_D4; }",
        ":mov MEM_IMM32_SP_D4, AREG_D0_LO is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & AREG_D0_LO; MEM_IMM32_SP_D4 { AREG_D0_LO = MEM_IMM32_SP_D4; }",
        ":mov DREG_D0_HI, MEM_IMM32_AREG_D4 is b0_any=0xFC; b1_7=0 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & MEM_IMM32_AREG_D4 { MEM_IMM32_AREG_D4 = DREG_D0_HI; }",
        ":mov DREG_D0_HI, MEM_IMM32_SP_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & DREG_D0_HI & b1_1=0 & b1_0=1; MEM_IMM32_SP_D4 { MEM_IMM32_SP_D4 = DREG_D0_HI; }",
        ":mov AREG_D0_HI, MEM_IMM32_AREG_D4 is b0_any=0xFC; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & AREG_D0_HI & MEM_IMM32_AREG_D4 { MEM_IMM32_AREG_D4 = AREG_D0_HI; }",
        ":mov AREG_D0_HI, MEM_IMM32_SP_D4 is b0_any=0xFC; b1_7=1 & b1_6=0 & b1_5=0 & b1_4=1 & AREG_D0_HI & b1_1=0 & b1_0=0; MEM_IMM32_SP_D4 { MEM_IMM32_SP_D4 = AREG_D0_HI; }",
        ":mov MEM_SD8N_SHIFT8_AREG_D1, SP is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & MEM_SD8N_SHIFT8_AREG_D1 { SP = MEM_SD8N_SHIFT8_AREG_D1; }",
        ":mov SP, MEM_SD8N_SHIFT8_AREG_D1 is b0_any=0xF8; b1_7=1 & b1_6=1 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & MEM_SD8N_SHIFT8_AREG_D1 { MEM_SD8N_SHIFT8_AREG_D1 = SP; }",
        ":mov SIMM8_B3, RREG_RN02_EQ is b0_any=0xFB; b1_any=0x08; RREG_RN02_EQ; SIMM8_B3 { RREG_RN02_EQ = sext(SIMM8_B3); }",
        ":mov SIMM24_B345, RREG_RN02_EQ is b0_any=0xFD; b1_any=0x08; RREG_RN02_EQ; SIMM24_B345 { RREG_RN02_EQ = sext(SIMM24_B345); }",
        ":mov IMM32HI8_B3456, RREG_RN02_EQ is b0_any=0xFE; b1_any=0x08; RREG_RN02_EQ; IMM32HI8_B3456 { RREG_RN02_EQ = IMM32HI8_B3456; }",
        ":mov IMM8_B3, XRREG_RN02_EQ is b0_any=0xFB; b1_any=0xF8; XRREG_RN02_EQ; IMM8_B3 { XRREG_RN02_EQ = zext(IMM8_B3); }",
        ":mov IMM24_B345, XRREG_RN02_EQ is b0_any=0xFD; b1_any=0xF8; XRREG_RN02_EQ; IMM24_B345 { XRREG_RN02_EQ = zext(IMM24_B345); }",
        ":mov IMM32HI8_B3456, XRREG_RN02_EQ is b0_any=0xFE; b1_any=0xF8; XRREG_RN02_EQ; IMM32HI8_B3456 { XRREG_RN02_EQ = IMM32HI8_B3456; }",
    ]
    lines.extend(mov_phase312)
    lines.append("")
    lines.append("# Phase 3.13: fmov family (AM33_2)")
    lines.append("")
    fmov_phase313 = [
        ":fmov MEM_RREG_HI_D6, FSM0_D6 is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & b1_1=0 & MEM_RREG_HI_D6 & FSM0_D6 { FSM0_D6 = MEM_RREG_HI_D6; }",
        ":fmov MEMINC_RREG_HI_D6, FSM0_D6 is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & b1_1=1 & MEMINC_RREG_HI_D6 & FSM0_D6 { FSM0_D6 = MEMINC_RREG_HI_D6; RREG_B2_HI = RREG_B2_HI + 4; }",
        ":fmov MEM_SP_HI_D6, FSM0_D6 is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & b1_1=0 & MEM_SP_HI_D6 & FSM0_D6 { FSM0_D6 = MEM_SP_HI_D6; }",
        ":fmov RREG_B2_HI, FSM0_D6 is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & b1_1=1 & RREG_B2_HI & FSM0_D6 { FSM0_D6 = RREG_B2_HI; }",
        ":fmov FSM1_D6, MEM_RREG_D6 is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & b1_0=0 & FSM1_D6 & MEM_RREG_D6 { MEM_RREG_D6 = FSM1_D6; }",
        ":fmov FSM1_D6, MEMINC_RREG_D6 is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & b1_0=1 & FSM1_D6 & MEMINC_RREG_D6 { MEMINC_RREG_D6 = FSM1_D6; RREG_B2_LO = RREG_B2_LO + 4; }",
        ":fmov FSM1_D6, MEM_SP_D6 is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & b1_0=0 & FSM1_D6 & MEM_SP_D6 { MEM_SP_D6 = FSM1_D6; }",
        ":fmov FSM1_D6, RREG_B2_LO is b0_any=0xF9; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & b1_0=1 & FSM1_D6 & RREG_B2_LO { RREG_B2_LO = FSM1_D6; }",
        ":fmov FSM1_D6, FSM0_D6 is b0_any=0xF9; b1_7=0 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=0 & b1_2=0 & FSM1_D6 & FSM0_D6 { FSM0_D6 = FSM1_D6; }",
        ":fmov MEM_RREG_HI_D6, FDM0_D6 is b0_any=0xF9; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & b1_1=0 & b2_0=0 & MEM_RREG_HI_D6 & FDM0_D6 { FDM0_D6 = MEM_RREG_HI_D6; }",
        ":fmov MEMINC_RREG_HI_D6, FDM0_D6 is b0_any=0xF9; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & b1_1=1 & b2_0=0 & MEMINC_RREG_HI_D6 & FDM0_D6 { FDM0_D6 = MEMINC_RREG_HI_D6; RREG_B2_HI = RREG_B2_HI + 8; }",
        ":fmov MEM_SP_HI_D6, FDM0_D6 is b0_any=0xF9; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & b1_1=0 & b2_0=0 & MEM_SP_HI_D6 & FDM0_D6 { FDM0_D6 = MEM_SP_HI_D6; }",
        ":fmov FDM1_D6, MEM_RREG_D6 is b0_any=0xF9; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & b1_0=0 & b2_4=0 & FDM1_D6 & MEM_RREG_D6 { MEM_RREG_D6 = FDM1_D6; }",
        ":fmov FDM1_D6, MEMINC_RREG_D6 is b0_any=0xF9; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & b1_0=1 & b2_4=0 & FDM1_D6 & MEMINC_RREG_D6 { MEMINC_RREG_D6 = FDM1_D6; RREG_B2_LO = RREG_B2_LO + 8; }",
        ":fmov FDM1_D6, MEM_SP_D6 is b0_any=0xF9; b1_7=1 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & b1_0=0 & b2_4=0 & FDM1_D6 & MEM_SP_D6 { MEM_SP_D6 = FDM1_D6; }",
        ":fmov RREG_B2_HI, FPCR is b0_any=0xF9; b1_any=0xB5; b2_3=0 & b2_2=0 & b2_1=0 & b2_0=0 & RREG_B2_HI { FPCR = RREG_B2_HI; }",
        ":fmov FPCR, RREG_B2_LO is b0_any=0xF9; b1_any=0xB7; b2_7=0 & b2_6=0 & b2_5=0 & b2_4=0 & RREG_B2_LO { RREG_B2_LO = FPCR; }",
        ":fmov FDM1_D6, FDM0_D6 is b0_any=0xF9; b1_7=1 & b1_6=1 & b1_5=0 & b1_4=0 & b1_3=0 & b1_2=0 & b2_4=0 & b2_0=0 & FDM1_D6 & FDM0_D6 { FDM0_D6 = FDM1_D6; }",
        ":fmov MEM_SD8_RREG_HI_D7, FSM2_D789 is b0_any=0xFB; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & b1_1=0 & FSM2_D789; MEM_SD8_RREG_HI_D7 { FSM2_D789 = MEM_SD8_RREG_HI_D7; }",
        ":fmov MEMINC2_SIMM8_RREG_HI_D7, FSM2_D789 is b0_any=0xFB; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=0 & b1_1=1 & FSM2_D789; MEMINC2_SIMM8_RREG_HI_D7 { FSM2_D789 = MEMINC2_SIMM8_RREG_HI_D7; local inc:4 = "
        + inc_simm8
        + "; "
        + postinc_rhi
        + " }",
        ":fmov MEM_IMM8_SP_HI_D7, FSM2_D789 is b0_any=0xFB; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=0 & b1_3=0 & b1_2=1 & b1_1=0 & FSM2_D789; MEM_IMM8_SP_HI_D7 { FSM2_D789 = MEM_IMM8_SP_HI_D7; }",
        ":fmov MEM_RI_RREG_D7, FSN1_D7 is b0_any=0xFB; b1_any=0x27; b3_3=0 & b3_2=0 & b3_0=0 & MEM_RI_RREG_D7 & FSN1_D7 { FSN1_D7 = MEM_RI_RREG_D7; }",
        ":fmov FSM3_D789, MEM_SD8_RREG_D7 is b0_any=0xFB; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & b1_0=0 & FSM3_D789; MEM_SD8_RREG_D7 { MEM_SD8_RREG_D7 = FSM3_D789; }",
        ":fmov FSM3_D789, MEMINC2_SIMM8_RREG_D7 is b0_any=0xFB; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=0 & b1_0=1 & FSM3_D789; MEMINC2_SIMM8_RREG_D7 { MEMINC2_SIMM8_RREG_D7 = FSM3_D789; local inc:4 = "
        + inc_simm8
        + "; "
        + postinc_rlo
        + " }",
        ":fmov FSM3_D789, MEM_IMM8_SP_D7 is b0_any=0xFB; b1_7=0 & b1_6=0 & b1_5=1 & b1_4=1 & b1_3=0 & b1_2=1 & b1_0=0 & FSM3_D789; MEM_IMM8_SP_D7 { MEM_IMM8_SP_D7 = FSM3_D789; }",
        ":fmov FSN1_D7, MEM_RI_RREG_D7 is b0_any=0xFB; b1_any=0x37; b3_3=0 & b3_2=0 & b3_0=0 & FSN1_D7 & MEM_RI_RREG_D7 { MEM_RI_RREG_D7 = FSN1_D7; }",
        ":fmov MEM_RI_RREG_D7, FDN1_D7 is b0_any=0xFB; b1_any=0x47; b3_4=0 & b3_3=0 & b3_2=0 & b3_0=0 & MEM_RI_RREG_D7 & FDN1_D7 { FDN1_D7 = MEM_RI_RREG_D7; }",
        ":fmov FDN1_D7, MEM_RI_RREG_D7 is b0_any=0xFB; b1_any=0x57; b3_4=0 & b3_3=0 & b3_2=0 & b3_0=0 & FDN1_D7 & MEM_RI_RREG_D7 { MEM_RI_RREG_D7 = FDN1_D7; }",
        ":fmov MEM_SD8_RREG_HI_D7, FDM2_D789 is b0_any=0xFB; b1_any=0xA0; b2_0=0 & MEM_SD8_RREG_HI_D7 & FDM2_D789 { FDM2_D789 = MEM_SD8_RREG_HI_D7; }",
        ":fmov MEMINC2_SIMM8_RREG_HI_D7, FDM2_D789 is b0_any=0xFB; b1_any=0xA2; b2_0=0 & MEMINC2_SIMM8_RREG_HI_D7 & FDM2_D789 { FDM2_D789 = MEMINC2_SIMM8_RREG_HI_D7; local inc:4 = "
        + inc_simm8
        + "; "
        + postinc_rhi
        + " }",
        ":fmov MEM_IMM8_SP_HI_D7, FDM2_D789 is b0_any=0xFB; b1_any=0xA4; b2_0=0 & MEM_IMM8_SP_HI_D7 & FDM2_D789 { FDM2_D789 = MEM_IMM8_SP_HI_D7; }",
        ":fmov FDM3_D789, MEM_SD8_RREG_D7 is b0_any=0xFB; b1_any=0xB0; b2_4=0 & FDM3_D789; MEM_SD8_RREG_D7 { MEM_SD8_RREG_D7 = FDM3_D789; }",
        ":fmov FDM3_D789, MEMINC2_SIMM8_RREG_D7 is b0_any=0xFB; b1_any=0xB1; b2_4=0 & FDM3_D789; MEMINC2_SIMM8_RREG_D7 { MEMINC2_SIMM8_RREG_D7 = FDM3_D789; local inc:4 = "
        + inc_simm8
        + "; "
        + postinc_rlo
        + " }",
        ":fmov FDM3_D789, MEM_IMM8_SP_D7 is b0_any=0xFB; b1_any=0xB4; b2_4=0 & FDM3_D789; MEM_IMM8_SP_D7 { MEM_IMM8_SP_D7 = FDM3_D789; }",
        ":fmov MEM_SD24_RREG_HI_D8, FSM2_D789 is b0_any=0xFD; b1_any=0x20; MEM_SD24_RREG_HI_D8 & FSM2_D789 { FSM2_D789 = MEM_SD24_RREG_HI_D8; }",
        ":fmov MEMINC2_IMM24_RREG_HI_D8, FSM2_D789 is b0_any=0xFD; b1_any=0x22; MEMINC2_IMM24_RREG_HI_D8 & FSM2_D789 { FSM2_D789 = MEMINC2_IMM24_RREG_HI_D8; local inc:4 = "
        + inc_u24
        + "; "
        + postinc_rhi
        + " }",
        ":fmov MEM_IMM24_SP_HI_D8, FSM2_D789 is b0_any=0xFD; b1_any=0x24; MEM_IMM24_SP_HI_D8 & FSM2_D789 { FSM2_D789 = MEM_IMM24_SP_HI_D8; }",
        ":fmov FSM3_D789, MEM_SD24_RREG_D8 is b0_any=0xFD; b1_any=0x30; FSM3_D789 & MEM_SD24_RREG_D8 { MEM_SD24_RREG_D8 = FSM3_D789; }",
        ":fmov FSM3_D789, MEMINC2_IMM24_RREG_D8 is b0_any=0xFD; b1_any=0x31; FSM3_D789 & MEMINC2_IMM24_RREG_D8 { MEMINC2_IMM24_RREG_D8 = FSM3_D789; local inc:4 = "
        + inc_u24
        + "; "
        + postinc_rlo
        + " }",
        ":fmov FSM3_D789, MEM_IMM24_SP_D8 is b0_any=0xFD; b1_any=0x34; FSM3_D789 & MEM_IMM24_SP_D8 { MEM_IMM24_SP_D8 = FSM3_D789; }",
        ":fmov MEM_SD24_RREG_HI_D8, FDM2_D789 is b0_any=0xFD; b1_any=0xA0; b2_0=0 & MEM_SD24_RREG_HI_D8 & FDM2_D789 { FDM2_D789 = MEM_SD24_RREG_HI_D8; }",
        ":fmov MEMINC2_IMM24_RREG_HI_D8, FDM2_D789 is b0_any=0xFD; b1_any=0xA2; b2_0=0 & MEMINC2_IMM24_RREG_HI_D8 & FDM2_D789 { FDM2_D789 = MEMINC2_IMM24_RREG_HI_D8; local inc:4 = "
        + inc_u24
        + "; "
        + postinc_rhi
        + " }",
        ":fmov MEM_IMM24_SP_HI_D8, FDM2_D789 is b0_any=0xFD; b1_any=0xA4; b2_0=0 & MEM_IMM24_SP_HI_D8 & FDM2_D789 { FDM2_D789 = MEM_IMM24_SP_HI_D8; }",
        ":fmov FDM3_D789, MEM_SD24_RREG_D8 is b0_any=0xFD; b1_any=0xB0; b2_4=0 & FDM3_D789 & MEM_SD24_RREG_D8 { MEM_SD24_RREG_D8 = FDM3_D789; }",
        ":fmov FDM3_D789, MEMINC2_IMM24_RREG_D8 is b0_any=0xFD; b1_any=0xB1; b2_4=0 & FDM3_D789 & MEMINC2_IMM24_RREG_D8 { MEMINC2_IMM24_RREG_D8 = FDM3_D789; local inc:4 = "
        + inc_u24
        + "; "
        + postinc_rlo
        + " }",
        ":fmov FDM3_D789, MEM_IMM24_SP_D8 is b0_any=0xFD; b1_any=0xB4; b2_4=0 & FDM3_D789 & MEM_IMM24_SP_D8 { MEM_IMM24_SP_D8 = FDM3_D789; }",
        ":fmov IMM32_B2345, FPCR is b0_any=0xFD; b1_any=0xB5; IMM32_B2345 { FPCR = IMM32_B2345; }",
        ":fmov MEM_IMM32HI8_RREG_HI_D9, FSM2_D789 is b0_any=0xFE; b1_any=0x20; MEM_IMM32HI8_RREG_HI_D9 & FSM2_D789 { FSM2_D789 = MEM_IMM32HI8_RREG_HI_D9; }",
        ":fmov MEMINC2_IMM32HI8_RREG_HI_D9, FSM2_D789 is b0_any=0xFE; b1_any=0x22; MEMINC2_IMM32HI8_RREG_HI_D9 & FSM2_D789 { FSM2_D789 = MEMINC2_IMM32HI8_RREG_HI_D9; local inc:4 = "
        + inc_u32
        + "; "
        + postinc_rhi
        + " }",
        ":fmov MEM_IMM32HI8_SP_HI_D9, FSM2_D789 is b0_any=0xFE; b1_any=0x24; MEM_IMM32HI8_SP_HI_D9 & FSM2_D789 { FSM2_D789 = MEM_IMM32HI8_SP_HI_D9; }",
        ":fmov IMM32HI8_B3456, FSM2_D789 is b0_any=0xFE; b1_any=0x26; b2_7=0 & b2_6=0 & b2_5=0 & b2_4=0 & FSM2_D789; IMM32HI8_B3456 { FSM2_D789 = IMM32HI8_B3456; }",
        ":fmov FSM3_D789, MEM_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x30; FSM3_D789 & MEM_IMM32HI8_RREG_D9 { MEM_IMM32HI8_RREG_D9 = FSM3_D789; }",
        ":fmov FSM3_D789, MEMINC2_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x31; FSM3_D789 & MEMINC2_IMM32HI8_RREG_D9 { MEMINC2_IMM32HI8_RREG_D9 = FSM3_D789; local inc:4 = "
        + inc_u32
        + "; "
        + postinc_rlo
        + " }",
        ":fmov FSM3_D789, MEM_IMM32HI8_SP_D9 is b0_any=0xFE; b1_any=0x34; FSM3_D789 & MEM_IMM32HI8_SP_D9 { MEM_IMM32HI8_SP_D9 = FSM3_D789; }",
        ":fmov MEM_IMM32HI8_RREG_HI_D9, FDM2_D789 is b0_any=0xFE; b1_any=0x40; b2_0=0 & MEM_IMM32HI8_RREG_HI_D9 & FDM2_D789 { FDM2_D789 = MEM_IMM32HI8_RREG_HI_D9; }",
        ":fmov MEMINC2_IMM32HI8_RREG_HI_D9, FDM2_D789 is b0_any=0xFE; b1_any=0x42; b2_0=0 & MEMINC2_IMM32HI8_RREG_HI_D9 & FDM2_D789 { FDM2_D789 = MEMINC2_IMM32HI8_RREG_HI_D9; local inc:4 = "
        + inc_u32
        + "; "
        + postinc_rhi
        + " }",
        ":fmov MEM_IMM32HI8_SP_HI_D9, FDM2_D789 is b0_any=0xFE; b1_any=0x44; b2_0=0 & MEM_IMM32HI8_SP_HI_D9 & FDM2_D789 { FDM2_D789 = MEM_IMM32HI8_SP_HI_D9; }",
        ":fmov FDM3_D789, MEM_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x50; b2_4=0 & FDM3_D789 & MEM_IMM32HI8_RREG_D9 { MEM_IMM32HI8_RREG_D9 = FDM3_D789; }",
        ":fmov FDM3_D789, MEMINC2_IMM32HI8_RREG_D9 is b0_any=0xFE; b1_any=0x51; b2_4=0 & FDM3_D789 & MEMINC2_IMM32HI8_RREG_D9 { MEMINC2_IMM32HI8_RREG_D9 = FDM3_D789; local inc:4 = "
        + inc_u32
        + "; "
        + postinc_rlo
        + " }",
        ":fmov FDM3_D789, MEM_IMM32HI8_SP_D9 is b0_any=0xFE; b1_any=0x54; b2_4=0 & FDM3_D789 & MEM_IMM32HI8_SP_D9 { MEM_IMM32HI8_SP_D9 = FDM3_D789; }",
    ]
    lines.extend(fmov_phase313)
    lines.append("")
    lines.append("# Phase 3.14: FP arithmetic/compare/convert families (AM33_2)")
    lines.append("")
    phase314_specs: List[Tuple[str, Tuple[str, int, int], str]] = [
        (":ftoi FSN3_D10, FSN1_D7", ("FMT_D10", 0xFB400000, 0xFFFF0F05), assign_body("FSN1_D7", "trunc(FSN3_D10)")),
        (":itof FSN3_D10, FSN1_D7", ("FMT_D10", 0xFB420000, 0xFFFF0F05), assign_body("FSN1_D7", "int2float(FSN3_D10)")),
        (":ftod FSN3_D10, FDN1_D7", ("FMT_D10", 0xFB520000, 0xFFFF0F15), assign_body("FDN1_D7", "float2float(FSN3_D10)")),
        (":dtof FDN3_D10, FSN1_D7", ("FMT_D10", 0xFB560000, 0xFFFF1F05), assign_body("FSN1_D7", "float2float(FDN3_D10)")),
        (":fabs FSN3_D10, FSN1_D7", ("FMT_D10", 0xFB440000, 0xFFFF0F05), assign_body("FSN1_D7", "abs(FSN3_D10)")),
        (":fabs FDN3_D10, FDN1_D7", ("FMT_D10", 0xFBC40000, 0xFFFF1F15), assign_body("FDN1_D7", "abs(FDN3_D10)")),
        (":fabs FSM0_D6", ("FMT_D6", 0x00F94400, 0x00FFFEF0), assign_body("FSM0_D6", "abs(FSM0_D6)")),
        (":fabs FDM0_D6", ("FMT_D6", 0x00F9C400, 0x00FFFEF1), assign_body("FDM0_D6", "abs(FDM0_D6)")),
        (":fneg FSN3_D10, FSN1_D7", ("FMT_D10", 0xFB460000, 0xFFFF0F05), assign_body("FSN1_D7", "f- FSN3_D10")),
        (":fneg FDN3_D10, FDN1_D7", ("FMT_D10", 0xFBC60000, 0xFFFF1F15), assign_body("FDN1_D7", "f- FDN3_D10")),
        (":fneg FSM0_D6", ("FMT_D6", 0x00F94600, 0x00FFFEF0), assign_body("FSM0_D6", "f- FSM0_D6")),
        (":fneg FDM0_D6", ("FMT_D6", 0x00F9C600, 0x00FFFEF1), assign_body("FDM0_D6", "f- FDM0_D6")),
        (":frsqrt FSN3_D10, FSN1_D7", ("FMT_D10", 0xFB500000, 0xFFFF0F05), assign_body("FSN1_D7", "int2float(1:4) f/ sqrt(FSN3_D10)")),
        (":frsqrt FDN3_D10, FDN1_D7", ("FMT_D10", 0xFBD00000, 0xFFFF1F15), assign_body("FDN1_D7", "int2float(1:8) f/ sqrt(FDN3_D10)")),
        (":frsqrt FSM0_D6", ("FMT_D6", 0x00F95000, 0x00FFFEF0), assign_body("FSM0_D6", "int2float(1:4) f/ sqrt(FSM0_D6)")),
        (":frsqrt FDM0_D6", ("FMT_D6", 0x00F9D000, 0x00FFFEF1), assign_body("FDM0_D6", "int2float(1:8) f/ sqrt(FDM0_D6)")),
        (":fsqrt FSN3_D10, FSN1_D7", ("FMT_D10", 0xFB540000, 0xFFFF0F05), assign_body("FSN1_D7", "sqrt(FSN3_D10)")),
        (":fsqrt FDN3_D10, FDN1_D7", ("FMT_D10", 0xFBD40000, 0xFFFF1F15), assign_body("FDN1_D7", "sqrt(FDN3_D10)")),
        (":fsqrt FSM0_D6", ("FMT_D6", 0x00F95200, 0x00FFFEF0), assign_body("FSM0_D6", "sqrt(FSM0_D6)")),
        (":fsqrt FDM0_D6", ("FMT_D6", 0x00F9D200, 0x00FFFEF1), assign_body("FDM0_D6", "sqrt(FDM0_D6)")),
        (":fcmp FSM1_D6, FSM0_D6", ("FMT_D6", 0x00F95400, 0x00FFFC00), "{ }"),
        (":fcmp FDM1_D6, FDM0_D6", ("FMT_D6", 0x00F9D400, 0x00FFFC11), "{ }"),
        (":fcmp IMM32HI8_B3456, FSM3_D789", ("FMT_D9", 0xFE350000, 0xFFFD0F00), "{ }"),
        (":fadd FSN3_D10, FSN2_D10, FSN1_D7", ("FMT_D10", 0xFB600000, 0xFFFF0001), assign_body("FSN1_D7", "FSN3_D10 f+ FSN2_D10")),
        (":fadd FDN3_D10, FDN2_D10, FDN1_D7", ("FMT_D10", 0xFBE00000, 0xFFFF1111), assign_body("FDN1_D7", "FDN3_D10 f+ FDN2_D10")),
        (":fadd FSM1_D6, FSM0_D6", ("FMT_D6", 0x00F96000, 0x00FFFC00), assign_body("FSM0_D6", "FSM0_D6 f+ FSM1_D6")),
        (":fadd FDM1_D6, FDM0_D6", ("FMT_D6", 0x00F9E000, 0x00FFFC11), assign_body("FDM0_D6", "FDM0_D6 f+ FDM1_D6")),
        (":fadd IMM32HI8_B3456, FSM3_D789, FSM2_D789", ("FMT_D9", 0xFE600000, 0xFFFC0000), assign_body("FSM2_D789", "IMM32HI8_B3456 f+ FSM3_D789")),
        (":fsub FSN3_D10, FSN2_D10, FSN1_D7", ("FMT_D10", 0xFB640000, 0xFFFF0001), assign_body("FSN1_D7", "FSN3_D10 f- FSN2_D10")),
        (":fsub FDN3_D10, FDN2_D10, FDN1_D7", ("FMT_D10", 0xFBE40000, 0xFFFF1111), assign_body("FDN1_D7", "FDN3_D10 f- FDN2_D10")),
        (":fsub FSM1_D6, FSM0_D6", ("FMT_D6", 0x00F96400, 0x00FFFC00), assign_body("FSM0_D6", "FSM0_D6 f- FSM1_D6")),
        (":fsub FDM1_D6, FDM0_D6", ("FMT_D6", 0x00F9E400, 0x00FFFC11), assign_body("FDM0_D6", "FDM0_D6 f- FDM1_D6")),
        (":fsub IMM32HI8_B3456, FSM3_D789, FSM2_D789", ("FMT_D9", 0xFE640000, 0xFFFC0000), assign_body("FSM2_D789", "IMM32HI8_B3456 f- FSM3_D789")),
        (":fmul FSN3_D10, FSN2_D10, FSN1_D7", ("FMT_D10", 0xFB700000, 0xFFFF0001), assign_body("FSN1_D7", "FSN3_D10 f* FSN2_D10")),
        (":fmul FDN3_D10, FDN2_D10, FDN1_D7", ("FMT_D10", 0xFBF00000, 0xFFFF1111), assign_body("FDN1_D7", "FDN3_D10 f* FDN2_D10")),
        (":fmul FSM1_D6, FSM0_D6", ("FMT_D6", 0x00F97000, 0x00FFFC00), assign_body("FSM0_D6", "FSM0_D6 f* FSM1_D6")),
        (":fmul FDM1_D6, FDM0_D6", ("FMT_D6", 0x00F9F000, 0x00FFFC11), assign_body("FDM0_D6", "FDM0_D6 f* FDM1_D6")),
        (":fmul IMM32HI8_B3456, FSM3_D789, FSM2_D789", ("FMT_D9", 0xFE700000, 0xFFFC0000), assign_body("FSM2_D789", "IMM32HI8_B3456 f* FSM3_D789")),
        (":fdiv FSN3_D10, FSN2_D10, FSN1_D7", ("FMT_D10", 0xFB740000, 0xFFFF0001), assign_body("FSN1_D7", "FSN3_D10 f/ FSN2_D10")),
        (":fdiv FDN3_D10, FDN2_D10, FDN1_D7", ("FMT_D10", 0xFBF40000, 0xFFFF1111), assign_body("FDN1_D7", "FDN3_D10 f/ FDN2_D10")),
        (":fdiv FSM1_D6, FSM0_D6", ("FMT_D6", 0x00F97400, 0x00FFFC00), assign_body("FSM0_D6", "FSM0_D6 f/ FSM1_D6")),
        (":fdiv FDM1_D6, FDM0_D6", ("FMT_D6", 0x00F9F400, 0x00FFFC11), assign_body("FDM0_D6", "FDM0_D6 f/ FDM1_D6")),
        (":fdiv IMM32HI8_B3456, FSM3_D789, FSM2_D789", ("FMT_D9", 0xFE740000, 0xFFFC0000), assign_body("FSM2_D789", "IMM32HI8_B3456 f/ FSM3_D789")),
    ]
    phase_manual_keys |= {key for _, key, _ in phase314_specs}
    for head, key, body in phase314_specs:
        append_keyed_constructor(head, key, body)
    lines.append("")
    lines.append("# Phase 3.15: mul/mac/dcpf families (AM33/AM33_2)")
    lines.append("")
    phase315_specs: List[Tuple[str, Tuple[str, int, int]]] = [
        (":mul DREG_D0_HI, DREG_D0_LO", ("FMT_D0", 0x0000F240, 0x0000FFF0)),
        (":mul RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F9A900, 0x00FFFF00)),
        (":mul RREG_B2_HI, RREG_B2_LO, RREG_B3_HI, RREG_B3_LO", ("FMT_D7", 0xFBAD0000, 0xFFFF0000)),
        (":mul SIMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFBA90000, 0xFFFF0000)),
        (":mul SIMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFDA90000, 0xFFFF0000)),
        (":mul IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFEA90000, 0xFFFF0000)),
        (":mulu DREG_D0_HI, DREG_D0_LO", ("FMT_D0", 0x0000F250, 0x0000FFF0)),
        (":mulu RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F9B900, 0x00FFFF00)),
        (":mulu RREG_B2_HI, RREG_B2_LO, RREG_B3_HI, RREG_B3_LO", ("FMT_D7", 0xFBBD0000, 0xFFFF0000)),
        (":mulu IMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFBB90000, 0xFFFF0000)),
        (":mulu IMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFDB90000, 0xFFFF0000)),
        (":mulu IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFEB90000, 0xFFFF0000)),
        (":mac RREG_B2_HI, RREG_B2_LO, RREG_B3_HI, RREG_B3_LO", ("FMT_D7", 0xFB0F0000, 0xFFFF0000)),
        (":mac RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F90B00, 0x00FFFF00)),
        (":mac SIMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFB0B0000, 0xFFFF0000)),
        (":mac SIMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFD0B0000, 0xFFFF0000)),
        (":mac IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFE0B0000, 0xFFFF0000)),
        (":macu RREG_B2_HI, RREG_B2_LO, RREG_B3_HI, RREG_B3_LO", ("FMT_D7", 0xFB1F0000, 0xFFFF0000)),
        (":macu RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F91B00, 0x00FFFF00)),
        (":macu IMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFB1B0000, 0xFFFF0000)),
        (":macu IMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFD1B0000, 0xFFFF0000)),
        (":macu IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFE1B0000, 0xFFFF0000)),
        (":macb RREG_B2_HI, RREG_B2_LO, RREG_B3_HI", ("FMT_D7", 0xFB2F0000, 0xFFFF000F)),
        (":macb RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F92B00, 0x00FFFF00)),
        (":macb SIMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFB2B0000, 0xFFFF0000)),
        (":macb SIMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFD2B0000, 0xFFFF0000)),
        (":macb IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFE2B0000, 0xFFFF0000)),
        (":macbu RREG_B2_HI, RREG_B2_LO, RREG_B3_HI", ("FMT_D7", 0xFB3F0000, 0xFFFF000F)),
        (":macbu RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F93B00, 0x00FFFF00)),
        (":macbu IMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFB3B0000, 0xFFFF0000)),
        (":macbu IMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFD3B0000, 0xFFFF0000)),
        (":macbu IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFE3B0000, 0xFFFF0000)),
        (":mach RREG_B2_HI, RREG_B2_LO, RREG_B3_HI, RREG_B3_LO", ("FMT_D7", 0xFB4F0000, 0xFFFF0000)),
        (":mach RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F94B00, 0x00FFFF00)),
        (":mach SIMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFB4B0000, 0xFFFF0000)),
        (":mach SIMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFD4B0000, 0xFFFF0000)),
        (":mach IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFE4B0000, 0xFFFF0000)),
        (":machu RREG_B2_HI, RREG_B2_LO, RREG_B3_HI, RREG_B3_LO", ("FMT_D7", 0xFB5F0000, 0xFFFF0000)),
        (":machu RREG_B2_HI, RREG_B2_LO", ("FMT_D6", 0x00F95B00, 0x00FFFF00)),
        (":machu IMM8_B3, RREG_RN02_EQ", ("FMT_D7", 0xFB5B0000, 0xFFFF0000)),
        (":machu IMM24_B345, RREG_RN02_EQ", ("FMT_D8", 0xFD5B0000, 0xFFFF0000)),
        (":machu IMM32HI8_B3456, RREG_RN02_EQ", ("FMT_D9", 0xFE5B0000, 0xFFFF0000)),
        (":dcpf MEM_RREG_HI_D6", ("FMT_D6", 0x00F9A600, 0x00FFFF0F)),
        (":dcpf MEM_SP_HI_D6", ("FMT_D6", 0x00F9A700, 0x00FFFFFF)),
        (":dcpf MEM_RI_RREG_D7", ("FMT_D7", 0xFBA60000, 0xFFFF00FF)),
        (":dcpf MEM_SD8_RREG_HI_D7", ("FMT_D7", 0xFBA70000, 0xFFFF0F00)),
        (":dcpf MEM_SD24_RREG_HI_D8", ("FMT_D8", 0xFDA70000, 0xFFFF0F00)),
        (":dcpf MEM_IMM32HI8_RREG_HI_D9", ("FMT_D9", 0xFE460000, 0xFFFF0F00)),
    ]
    phase_manual_keys |= {key for _, key in phase315_specs}
    for head, key in phase315_specs:
        append_keyed_constructor(head, key)
    lines.append("")
    lines.append("# Phase 3.17: AM33 pair-op aliases (add/cmp/sub/mov families)")
    lines.append("")
    phase317_families: List[Tuple[str, int, str]] = [
        ("add_add", 0xF7000000, "simm"),
        ("add_sub", 0xF7200000, "simm"),
        ("add_cmp", 0xF7400000, "simm"),
        ("add_mov", 0xF7600000, "simm"),
        ("add_asr", 0xF7800000, "imm"),
        ("add_lsr", 0xF7A00000, "imm"),
        ("add_asl", 0xF7C00000, "imm"),
        ("cmp_add", 0xF7010000, "simm"),
        ("cmp_sub", 0xF7210000, "simm"),
        ("cmp_mov", 0xF7610000, "simm"),
        ("cmp_asr", 0xF7810000, "imm"),
        ("cmp_lsr", 0xF7A10000, "imm"),
        ("cmp_asl", 0xF7C10000, "imm"),
        ("sub_add", 0xF7020000, "simm"),
        ("sub_sub", 0xF7220000, "simm"),
        ("sub_cmp", 0xF7420000, "simm"),
        ("sub_mov", 0xF7620000, "simm"),
        ("sub_asr", 0xF7820000, "imm"),
        ("sub_lsr", 0xF7A20000, "imm"),
        ("sub_asl", 0xF7C20000, "imm"),
        ("mov_add", 0xF7030000, "simm"),
        ("mov_sub", 0xF7230000, "simm"),
        ("mov_cmp", 0xF7430000, "simm"),
        ("mov_mov", 0xF7630000, "simm"),
        ("mov_asr", 0xF7830000, "imm"),
        ("mov_lsr", 0xF7A30000, "imm"),
        ("mov_asl", 0xF7C30000, "imm"),
    ]
    phase317_specs: List[Tuple[str, Tuple[str, int, int]]] = []
    for mnemonic, base, op2kind in phase317_families:
        op2 = "SIMM4_B2" if op2kind == "simm" else "IMM4_B2"
        phase317_specs.extend(
            [
                (
                    f":{mnemonic} RREG_B3_HI, RREG_B3_LO, RREG_B2_HI, RREG_B2_LO",
                    ("FMT_D10", base + 0x00000000, 0xFFFF0000),
                ),
                (
                    f":{mnemonic} RREG_B3_HI, RREG_B3_LO, {op2}, RREG_B2_LO",
                    ("FMT_D10", base + 0x00100000, 0xFFFF0000),
                ),
                (
                    f":{mnemonic} SIMM4_B3, RREG_B3_LO, RREG_B2_HI, RREG_B2_LO",
                    ("FMT_D10", base + 0x00040000, 0xFFFF0000),
                ),
                (
                    f":{mnemonic} SIMM4_B3, RREG_B3_LO, {op2}, RREG_B2_LO",
                    ("FMT_D10", base + 0x00140000, 0xFFFF0000),
                ),
            ]
        )
    phase_manual_keys |= {key for _, key in phase317_specs}
    for head, key in phase317_specs:
        append_keyed_constructor(head, key)
    lines.append("")
    lines.append("# Phase 3.18: remaining AM33 pair-op aliases + D10 mov_l* condition aliases")
    lines.append("")
    phase318_families: List[Tuple[str, int, str]] = [
        ("and_add", 0xF7080000, "simm"),
        ("and_sub", 0xF7280000, "simm"),
        ("and_cmp", 0xF7480000, "simm"),
        ("and_mov", 0xF7680000, "simm"),
        ("and_asr", 0xF7880000, "imm"),
        ("and_lsr", 0xF7A80000, "imm"),
        ("and_asl", 0xF7C80000, "imm"),
        ("dmach_add", 0xF7090000, "simm"),
        ("dmach_sub", 0xF7290000, "simm"),
        ("dmach_cmp", 0xF7490000, "simm"),
        ("dmach_mov", 0xF7690000, "simm"),
        ("dmach_asr", 0xF7890000, "imm"),
        ("dmach_lsr", 0xF7A90000, "imm"),
        ("dmach_asl", 0xF7C90000, "imm"),
        ("xor_add", 0xF70A0000, "simm"),
        ("xor_sub", 0xF72A0000, "simm"),
        ("xor_cmp", 0xF74A0000, "simm"),
        ("xor_mov", 0xF76A0000, "simm"),
        ("xor_asr", 0xF78A0000, "imm"),
        ("xor_lsr", 0xF7AA0000, "imm"),
        ("xor_asl", 0xF7CA0000, "imm"),
        ("swhw_add", 0xF70B0000, "simm"),
        ("swhw_sub", 0xF72B0000, "simm"),
        ("swhw_cmp", 0xF74B0000, "simm"),
        ("swhw_mov", 0xF76B0000, "simm"),
        ("swhw_asr", 0xF78B0000, "imm"),
        ("swhw_lsr", 0xF7AB0000, "imm"),
        ("swhw_asl", 0xF7CB0000, "imm"),
        ("or_add", 0xF70C0000, "simm"),
        ("or_sub", 0xF72C0000, "simm"),
        ("or_cmp", 0xF74C0000, "simm"),
        ("or_mov", 0xF76C0000, "simm"),
        ("or_asr", 0xF78C0000, "imm"),
        ("or_lsr", 0xF7AC0000, "imm"),
        ("or_asl", 0xF7CC0000, "imm"),
        ("sat16_add", 0xF70D0000, "simm"),
        ("sat16_sub", 0xF72D0000, "simm"),
        ("sat16_cmp", 0xF74D0000, "simm"),
        ("sat16_mov", 0xF76D0000, "simm"),
        ("sat16_asr", 0xF78D0000, "imm"),
        ("sat16_lsr", 0xF7AD0000, "imm"),
        ("sat16_asl", 0xF7CD0000, "imm"),
    ]
    phase318_specs: List[Tuple[str, Tuple[str, int, int]]] = []
    for mnemonic, base, op2kind in phase318_families:
        op2 = "SIMM4_B2" if op2kind == "simm" else "IMM4_B2"
        phase318_specs.extend(
            [
                (
                    f":{mnemonic} RREG_B3_HI, RREG_B3_LO, RREG_B2_HI, RREG_B2_LO",
                    ("FMT_D10", base + 0x00000000, 0xFFFF0000),
                ),
                (
                    f":{mnemonic} RREG_B3_HI, RREG_B3_LO, {op2}, RREG_B2_LO",
                    ("FMT_D10", base + 0x00100000, 0xFFFF0000),
                ),
            ]
        )
    phase318_movl: List[Tuple[str, int, str | None]] = [
        ("mov_llt", 0xF7E00000, "((($(NF) == 1) ^ ($(VF) == 1)) == 1)"),
        ("mov_lgt", 0xF7E00001, "($(ZF) == 0) && ((($(NF) == 1) ^ ($(VF) == 1)) == 0)"),
        ("mov_lge", 0xF7E00002, "((($(NF) == 1) ^ ($(VF) == 1)) == 0)"),
        ("mov_lle", 0xF7E00003, "($(ZF) == 1) || ((($(NF) == 1) ^ ($(VF) == 1)) == 1)"),
        ("mov_lcs", 0xF7E00004, "($(CF) == 1)"),
        ("mov_lhi", 0xF7E00005, "($(CF) == 0) && ($(ZF) == 0)"),
        ("mov_lcc", 0xF7E00006, "($(CF) == 0)"),
        ("mov_lls", 0xF7E00007, "($(CF) == 1) || ($(ZF) == 1)"),
        ("mov_leq", 0xF7E00008, "($(ZF) == 1)"),
        ("mov_lne", 0xF7E00009, "($(ZF) == 0)"),
        ("mov_lra", 0xF7E0000A, None),
    ]
    phase318_movl_specs: List[Tuple[str, Tuple[str, int, int], str]] = []
    for mnemonic, opcode, cond in phase318_movl:
        phase318_movl_specs.append(
            (
                f":{mnemonic} MEMINC2_SIMM4_RN4_D10, RREG_B3_HI",
                ("FMT_D10", opcode, 0xFFFF000F),
                loop_back_body(cond),
            )
        )
    phase_manual_keys |= {key for _, key in phase318_specs}
    phase_manual_keys |= {key for _, key, _ in phase318_movl_specs}
    for head, key in phase318_specs:
        append_keyed_constructor(head, key)
    for head, key, body in phase318_movl_specs:
        append_keyed_constructor(head, key, body)
    lines.append("")
    lines.append("# Auto-generated from GNU binutils m10300-opc.c")
    lines.append("# Generic fallback constructors (non-control-flow) are mnemonic-only.")
    lines.append("")

    for e in kept:
        key = (e.fmt, e.opcode, e.mask)
        if e.name.lower() == "setlb":
            length, base_constraints = constructor_constraints(e)
            pattern = constraints_to_pattern(length, base_constraints)
            lines.append(
                f":{sanitize_mnemonic(e.name)} is {pattern} "
                "{ LIR = *:4 inst_next; LAR = inst_next + 4; }"
            )
            continue
        if e.name.lower() in MANUAL_MNEMONICS or key in MANUAL_KEYS or key in phase_manual_keys:
            continue
        try:
            length, base_constraints = constructor_constraints(e)
        except ValueError:
            continue
        mnemonic = sanitize_mnemonic(e.name)

        variants: List[Dict[int, List[Tuple[int, int]]]] = []
        if needs_split_s0_non_equal(e):
            # 1-byte forms are valid only when register selector pairs differ.
            for low in range(4):
                for high in range(4):
                    if low == high:
                        continue
                    variants.append(
                        {
                            0: [
                                (0, low & 1),
                                (1, (low >> 1) & 1),
                                (2, high & 1),
                                (3, (high >> 1) & 1),
                            ]
                        }
                    )
        elif needs_split_s1_equal(e):
            # 2-byte immediate forms are valid only when selector pairs match.
            for pair in range(4):
                variants.append(
                    {
                        0: [
                            (0, pair & 1),
                            (1, (pair >> 1) & 1),
                            (2, pair & 1),
                            (3, (pair >> 1) & 1),
                        ]
                    }
                )
        else:
            variants.append({})

        for extra in variants:
            pattern = constraints_to_pattern(length, base_constraints, extra=extra)
            lines.append(
                f":{mnemonic} is {pattern} {{ }}  "
                f"# {e.fmt} {e.machine} opcode=0x{e.opcode:08x} mask=0x{e.mask:08x}"
            )

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--opc-source",
        type=Path,
        required=True,
        help="Path to opcodes/m10300-opc.c from binutils",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output .slaspec path",
    )
    args = parser.parse_args()

    entries = parse_opcode_entries(args.opc_source)
    spec = render_slaspec(entries)
    args.out.write_text(spec, encoding="utf-8")

    keys = {(e.fmt, e.opcode, e.mask) for e in entries}
    print(
        f"Generated {args.out} with {len(keys)} unique opcode patterns "
        f"from {len(entries)} table rows"
    )


if __name__ == "__main__":
    main()
