#!/usr/bin/env python3
"""Generate a small ABI-focused MN103 ELF for decompiler regression tests.

The binary is synthetic on purpose. It exercises:
- D0/D1 argument passing
- 32-bit scalar returns in D0
- 64-bit scalar returns in D1:D0
- 64-bit argument passing in D1:D0
- pointer returns in A0
- call/return flow across a tiny caller/callee graph
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def _parse_u32(value: str) -> int:
    value = value.strip().lower()
    if value.startswith("0x"):
        return int(value, 16)
    return int(value, 10)


def _write_le32(buf: bytearray, offset: int, value: int) -> None:
    buf[offset : offset + 4] = struct.pack("<I", value & 0xFFFFFFFF)


def _ins_nop() -> bytes:
    return b"\xCB"


def _ins_rets() -> bytes:
    return b"\xF0\xFC"


def _ins_calls_rel16(target: int, inst_addr: int) -> bytes:
    rel = (target - inst_addr) & 0xFFFF
    return b"\xFA\xFF" + struct.pack("<H", rel)


def _ins_mov_imm32_d0(imm32: int) -> bytes:
    return b"\xFC\xCC" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_mov_imm32_a0(imm32: int) -> bytes:
    return b"\xFC\xDC" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_mov_mem_imm32_a0_to_d1(addr: int) -> bytes:
    # Load D1 from an absolute address using A0 as a zeroed base register.
    return b"\xFC\x04" + struct.pack("<I", addr & 0xFFFFFFFF)


def _ins_sub_d1_d0() -> bytes:
    return b"\xF1\x04"


def _ins_add_imm32_d0(imm32: int) -> bytes:
    return b"\xFC\xC0" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_cmp_imm32_d0(imm32: int) -> bytes:
    return b"\xFC\xC8" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_cmp_imm32_a0(imm32: int) -> bytes:
    return b"\xFC\xD8" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _emit(buf: bytearray, addr: int, blob: bytes) -> None:
    buf[addr : addr + len(blob)] = blob


def _fill_nops(buf: bytearray, start: int, end: int) -> None:
    buf[start:end] = _ins_nop() * max(0, end - start)


def build_demo_image(
    entry: int,
    sum_fn: int,
    ret32_fn: int,
    ret64_fn: int,
    take64_fn: int,
    retptr_fn: int,
    d1_arg_addr: int,
    ret64_hi_addr: int,
    ptr_target: int,
    image_size: int,
) -> bytearray:
    image = bytearray([0xCB] * image_size)

    # Small data block used by the ABI functions.
    _write_le32(image, d1_arg_addr, 0x00000010)
    _write_le32(image, ret64_hi_addr, 0x55667788)
    _write_le32(image, ptr_target, 0xCAFEBABE)

    # abi_entry:
    #   D0 = 0x20
    #   D1 = *(d1_arg_addr)
    #   calls abi_sum_fn
    #   compares the sum result
    #   calls the scalar/pointer-return functions
    #   feeds the 64-bit return from abi_ret64_fn straight into abi_take64_fn
    #   consumes their results so the decompiler has to model the call outputs
    caller_parts = []
    cursor = entry

    def append(blob: bytes) -> None:
        nonlocal cursor
        caller_parts.append(blob)
        cursor += len(blob)

    append(_ins_mov_imm32_d0(0x00000020))
    append(_ins_mov_imm32_a0(0x00000000))
    append(_ins_mov_mem_imm32_a0_to_d1(d1_arg_addr))
    append(_ins_calls_rel16(sum_fn, cursor))
    append(_ins_cmp_imm32_d0(0x00000010))
    append(_ins_calls_rel16(ret32_fn, cursor))
    append(_ins_calls_rel16(retptr_fn, cursor))
    append(_ins_calls_rel16(ret64_fn, cursor))
    append(_ins_calls_rel16(take64_fn, cursor))
    append(_ins_cmp_imm32_a0(ptr_target))
    append(_ins_rets())

    _emit(image, entry, b"".join(caller_parts))

    # abi_sum_fn: use D0/D1 as inputs and return D0 - D1 in D0.
    _emit(image, sum_fn, _ins_sub_d1_d0() + _ins_rets())

    # abi_ret32_fn: return a known scalar in D0.
    _emit(image, ret32_fn, _ins_mov_imm32_d0(0x11223344) + _ins_rets())

    # abi_ret64_fn: return a known 64-bit value in D1:D0.
    ret64 = b"".join(
        [
            _ins_mov_imm32_d0(0x99AABBCC),
            _ins_mov_imm32_a0(0x00000000),
            _ins_mov_mem_imm32_a0_to_d1(ret64_hi_addr),
            _ins_rets(),
        ]
    )
    _emit(image, ret64_fn, ret64)

    # abi_take64_fn: consume a 64-bit input in D1:D0 so the decompiler has to
    # keep the join-modelled argument alive.
    _emit(image, take64_fn, _ins_sub_d1_d0() + _ins_rets())

    # abi_retptr_fn: return a pointer in A0.
    _emit(image, retptr_fn, _ins_mov_imm32_a0(ptr_target) + _ins_rets())

    return image


def make_elf32_exec_mn10300(raw_image: bytes, entry: int, segment_vaddr: int = 0) -> bytes:
    e_ident = bytes(
        [
            0x7F,
            ord("E"),
            ord("L"),
            ord("F"),
            1,  # ELFCLASS32
            1,  # ELFDATA2LSB
            1,  # EV_CURRENT
            0,  # SYSV
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    )

    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        2,  # ET_EXEC
        89,  # EM_MN10300
        1,
        entry,
        52,
        0,
        0,
        52,
        32,
        1,
        0,
        0,
        0,
    )

    phdr = struct.pack(
        "<IIIIIIII",
        1,  # PT_LOAD
        0x1000,
        segment_vaddr,
        segment_vaddr,
        len(raw_image),
        len(raw_image),
        0x7,  # RWX demo segment
        0x1000,
    )

    pad = b"\x00" * (0x1000 - len(elf_header) - len(phdr))
    return elf_header + phdr + pad + raw_image


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an MN103 ABI demo binary.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("tmp_mn103_abi_demo"),
        help="Output directory for the ABI demo artifacts.",
    )
    parser.add_argument("--entry", default="0x00002000")
    parser.add_argument("--sum-fn", default="0x00002040")
    parser.add_argument("--ret32-fn", default="0x00002080")
    parser.add_argument("--ret64-fn", default="0x000020c0")
    parser.add_argument("--take64-fn", default="0x000020e0")
    parser.add_argument("--retptr-fn", default="0x00002100")
    parser.add_argument("--d1-arg-addr", default="0x00003004")
    parser.add_argument("--ret64-hi-addr", default="0x00003000")
    parser.add_argument("--ptr-target", default="0x00003010")
    parser.add_argument("--image-size", default="0x00004000")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    entry = _parse_u32(args.entry)
    sum_fn = _parse_u32(args.sum_fn)
    ret32_fn = _parse_u32(args.ret32_fn)
    ret64_fn = _parse_u32(args.ret64_fn)
    take64_fn = _parse_u32(args.take64_fn)
    retptr_fn = _parse_u32(args.retptr_fn)
    d1_arg_addr = _parse_u32(args.d1_arg_addr)
    ret64_hi_addr = _parse_u32(args.ret64_hi_addr)
    ptr_target = _parse_u32(args.ptr_target)
    image_size = _parse_u32(args.image_size)

    image = build_demo_image(
        entry=entry,
        sum_fn=sum_fn,
        ret32_fn=ret32_fn,
        ret64_fn=ret64_fn,
        take64_fn=take64_fn,
        retptr_fn=retptr_fn,
        d1_arg_addr=d1_arg_addr,
        ret64_hi_addr=ret64_hi_addr,
        ptr_target=ptr_target,
        image_size=image_size,
    )

    bin_path = out_dir / "mn103_abi_demo.bin"
    elf_path = out_dir / "mn103_abi_demo.elf"
    manifest_path = out_dir / "mn103_abi_demo.manifest.txt"
    readme_path = out_dir / "mn103_abi_demo.README.txt"

    bin_path.write_bytes(image)
    elf_path.write_bytes(make_elf32_exec_mn10300(image, entry=entry, segment_vaddr=0))

    manifest_path.write_text(
        "\n".join(
            [
                "name=mn103_abi_demo",
                f"entry=0x{entry:08x}",
                f"abi_entry=0x{entry:08x}",
                f"abi_sum_fn=0x{sum_fn:08x}",
                f"abi_ret32_fn=0x{ret32_fn:08x}",
                f"abi_ret64_fn=0x{ret64_fn:08x}",
                f"abi_take64_fn=0x{take64_fn:08x}",
                f"abi_retptr_fn=0x{retptr_fn:08x}",
                f"d1_arg_addr=0x{d1_arg_addr:08x}",
                f"ret64_hi_addr=0x{ret64_hi_addr:08x}",
                f"ptr_target=0x{ptr_target:08x}",
                "expect_sum_params=2",
                "expect_ret32=0x11223344",
                "expect_ret64_hi=0x55667788",
                "expect_ret64_lo=0x99aabbcc",
                "expect_ret64_wide=1",
                "expect_take64_wide=1",
                f"expect_retptr=0x{ptr_target:08x}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    readme_path.write_text(
        "\n".join(
            [
                "MN103 ABI Demo",
                "==============",
                "",
                "Purpose:",
                "- Headless ABI / decompiler regression coverage for MN103 Ghidra support.",
                "",
                "Files:",
                f"- {bin_path.name}",
                f"- {elf_path.name}",
                f"- {manifest_path.name}",
                "",
                "Import guidance:",
                "1) Import the ELF file directly.",
                "2) Use the checked-in mn10300:LE:32:default language.",
                "",
                "The manifest records the function entry points and expected values used",
                "by the headless assertion script.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Wrote: {bin_path}")
    print(f"Wrote: {elf_path}")
    print(f"Wrote: {manifest_path}")
    print(f"Wrote: {readme_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
