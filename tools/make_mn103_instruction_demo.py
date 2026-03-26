#!/usr/bin/env python3
"""Generate an instruction-heavy synthetic MN103 ELF for decoder testing.

This is intentionally not real firmware. It is a deterministic corpus with
mixed instruction families so staged SLEIGH ports can be validated quickly.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path
from typing import Dict, List


def _parse_u32(value: str) -> int:
    value = value.strip().lower()
    if value.startswith("0x"):
        return int(value, 16)
    return int(value, 10)


def _write_le32(buf: bytearray, offset: int, value: int) -> None:
    buf[offset : offset + 4] = struct.pack("<I", value & 0xFFFFFFFF)


def _load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fp:
        rows = list(csv.DictReader(fp))
    if not rows:
        raise ValueError(f"No rows found in {path}")
    return rows


def _ins_nop() -> bytes:
    return b"\xCB"


def _ins_pi() -> bytes:
    return b"\xFF"


def _ins_jmp_abs(addr: int) -> bytes:
    return b"\xDC" + struct.pack("<I", addr & 0xFFFFFFFF)


def _ins_bra_self() -> bytes:
    # bra with rel8=0 targets inst_start, giving an explicit local infinite loop.
    return b"\xCA\x00"


def _ins_call16(imm16: int) -> bytes:
    return b"\xCD" + struct.pack("<H", imm16 & 0xFFFF)


def _ins_call32(addr: int) -> bytes:
    return b"\xDD" + struct.pack("<I", addr & 0xFFFFFFFF)


def _ins_mov_simm8_d0(imm: int) -> bytes:
    return bytes([0x80, imm & 0xFF])


def _ins_mov_imm8_a0(imm: int) -> bytes:
    return bytes([0x90, imm & 0xFF])


def _ins_mov_d1_a0() -> bytes:
    return b"\xF1\xE4"


def _ins_mov_a1_d0() -> bytes:
    return b"\xF1\xD4"


def _ins_mov_imm32_d0(imm32: int) -> bytes:
    return b"\xFC\xCC" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_mov_imm32_a0(imm32: int) -> bytes:
    return b"\xFC\xDC" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_movu_imm8_r2eq(imm: int) -> bytes:
    return bytes([0xFB, 0x18, 0x22, imm & 0xFF])


def _ins_movu_imm32_r3eq(imm32: int) -> bytes:
    return b"\xFE\x18\x33" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_mov_imm8_xr4eq(imm: int) -> bytes:
    return bytes([0xFB, 0xF8, 0x44, imm & 0xFF])


def _ins_mov_imm32_xr1eq(imm32: int) -> bytes:
    return b"\xFE\xF8\x11" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_mov_r1_r0() -> bytes:
    return b"\xF9\x08\x10"


def _ins_mov_xr2_r1() -> bytes:
    return b"\xF9\xE8\x21"


def _ins_mov_r1_xr2() -> bytes:
    return b"\xF9\xF8\x12"


def _ins_fmov_r5_fpcr() -> bytes:
    # b2 high nibble selects source r-register, low nibble must be 0.
    return b"\xF9\xB5\x50"


def _ins_fmov_fpcr_r4() -> bytes:
    # b2 low nibble selects destination r-register, high nibble must be 0.
    return b"\xF9\xB7\x04"


def _ins_mov_mem_a0_to_a1() -> bytes:
    return b"\xF0\x04"


def _ins_mov_a1_to_mem_a0() -> bytes:
    return b"\xF0\x14"


def _ins_mov_mem_imm16_sp_to_d0(off16: int) -> bytes:
    return b"\xFA\xB4" + struct.pack("<H", off16 & 0xFFFF)


def _ins_mov_d1_to_mem_imm16_sp(off16: int) -> bytes:
    return b"\xFA\x95" + struct.pack("<H", off16 & 0xFFFF)


def _ins_mov_abs32_to_d0(addr: int) -> bytes:
    return b"\xFC\xA4" + struct.pack("<I", addr & 0xFFFFFFFF)


def _ins_mov_d1_to_abs32(addr: int) -> bytes:
    return b"\xFC\x85" + struct.pack("<I", addr & 0xFFFFFFFF)


def _ins_mov_mem_imm32_a0_to_d1(off32: int) -> bytes:
    return b"\xFC\x04" + struct.pack("<I", off32 & 0xFFFFFFFF)


def _ins_mov_d1_to_mem_imm32_a0(off32: int) -> bytes:
    return b"\xFC\x14" + struct.pack("<I", off32 & 0xFFFFFFFF)


def _ins_fmov_fs3_fs1() -> bytes:
    return b"\xF9\x40\x31"


def _ins_fmov_fd2_fd4() -> bytes:
    return b"\xF9\xC0\x24"


def _ins_fmov_mem_r3_to_fs1() -> bytes:
    return b"\xF9\x20\x31"


def _ins_add_simm8_d0(imm: int) -> bytes:
    return bytes([0x28, imm & 0xFF])


def _ins_add_simm8_sp(imm: int) -> bytes:
    return bytes([0xF8, 0xFE, imm & 0xFF])


def _ins_add_imm32_d0(imm32: int) -> bytes:
    return b"\xFC\xC0" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_sub_d1_d0() -> bytes:
    return b"\xF1\x04"


def _ins_cmp_simm8_d0(imm: int) -> bytes:
    return bytes([0xA0, imm & 0xFF])


def _ins_cmp_imm32_d0(imm32: int) -> bytes:
    return b"\xFC\xC8" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def _ins_and_imm8_d0(imm: int) -> bytes:
    return bytes([0xF8, 0xE0, imm & 0xFF])


def _ins_or_imm8_d0(imm: int) -> bytes:
    return bytes([0xF8, 0xE4, imm & 0xFF])


def _ins_xor_imm16_d0(imm16: int) -> bytes:
    return b"\xFA\xE8" + struct.pack("<H", imm16 & 0xFFFF)


def _ins_not_d0() -> bytes:
    return b"\xF2\x30"


def _emit_mixed_handler_blob(
    buf: bytearray,
    base: int,
    size: int,
    seed: int,
    image_size: int,
) -> None:
    imm8 = (0x31 + seed * 7) & 0xFF
    imm32_a = (0x1000 + seed * 0x40) & 0xFFFFFFFF
    # Keep A0/data references in a non-code region to avoid misleading code XREFs.
    imm32_b = (0xC000 + ((seed * 0x80) & 0x0FFF)) & 0xFFFFFFFF
    sp_off16 = (0x0040 + seed * 4) & 0xFFFF
    arith32_a = (0x12340000 | ((seed * 0x31) & 0xFFFF)) & 0xFFFFFFFF
    arith32_b = (0x00AA0000 | ((seed * 0x13) & 0xFFFF)) & 0xFFFFFFFF
    arith8_a = (0x10 + seed) & 0xFF
    arith8_b = (0x22 + seed) & 0xFF
    arith8_c = (0x55 ^ seed) & 0xFF
    arith8_d = (0x33 + (seed * 3)) & 0xFF
    arith16 = (0x0F0F ^ (seed * 0x0101)) & 0xFFFF

    seq = b"".join(
        [
            _ins_mov_simm8_d0(imm8),
            _ins_mov_imm8_a0(imm8 ^ 0x55),
            _ins_mov_imm32_d0(imm32_a),
            _ins_mov_imm32_a0(imm32_b),
            _ins_mov_mem_a0_to_a1(),
            _ins_mov_a1_to_mem_a0(),
            _ins_mov_mem_imm16_sp_to_d0(sp_off16),
            _ins_mov_d1_to_mem_imm16_sp((sp_off16 + 4) & 0xFFFF),
            _ins_fmov_r5_fpcr(),
            _ins_add_imm32_d0(arith32_a),
            _ins_cmp_imm32_d0(arith32_b),
            _ins_add_simm8_d0(arith8_a),
            _ins_add_simm8_sp(arith8_b),
            _ins_sub_d1_d0(),
            _ins_cmp_simm8_d0(arith8_c),
            _ins_and_imm8_d0(arith8_d),
            _ins_or_imm8_d0(arith8_d ^ 0x5A),
            _ins_xor_imm16_d0(arith16),
            _ins_not_d0(),
        ]
    )
    terminator = _ins_bra_self()

    if base >= image_size or base + size > image_size:
        return

    if size <= len(terminator):
        blob = bytearray(terminator[:size])
    else:
        body_max = size - len(terminator)
        blob = bytearray(seq[:body_max] + terminator)
    if len(blob) < size:
        blob.extend(_ins_nop() * (size - len(blob)))
    buf[base : base + size] = blob


def build_demo_image(
    syscalls: List[Dict[str, str]],
    exceptions: List[Dict[str, str]],
    vector_base: int,
    syscall_table_base: int,
    exception_handler_base: int,
    syscall_handler_base: int,
    handler_size: int,
    image_size: int,
) -> bytearray:
    image = bytearray([0x00] * image_size)

    # Exception vectors: 8-byte Linux-style stubs (jmp + rel32 + nop nop nop).
    for idx, ex in enumerate(exceptions):
        code = _parse_u32(ex["code_hex"])
        vec_addr = vector_base + code
        if vec_addr < 0 or vec_addr + 8 > image_size:
            continue

        target = exception_handler_base + idx * handler_size
        rel = (target - vec_addr) & 0xFFFFFFFF
        image[vec_addr] = 0xDC
        _write_le32(image, vec_addr + 1, rel)
        image[vec_addr + 5 : vec_addr + 8] = b"\xCB\xCB\xCB"

        _emit_mixed_handler_blob(
            image,
            base=target,
            size=handler_size,
            seed=idx,
            image_size=image_size,
        )

    # Syscall table: 32-bit function pointers.
    for row in syscalls:
        index = int(row["index"])
        entry_addr = syscall_table_base + index * 4
        target = syscall_handler_base + index * handler_size
        if entry_addr + 4 <= image_size:
            _write_le32(image, entry_addr, target)

    # Syscall handler blobs.
    for row in syscalls:
        index = int(row["index"])
        target = syscall_handler_base + index * handler_size
        _emit_mixed_handler_blob(
            image,
            base=target,
            size=handler_size,
            seed=0x100 + index,
            image_size=image_size,
        )

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

    e_type = 2  # ET_EXEC
    e_machine = 89  # EM_MN10300
    e_version = 1
    e_entry = entry
    e_phoff = 52
    e_shoff = 0
    e_flags = 0
    e_ehsize = 52
    e_phentsize = 32
    e_phnum = 1
    e_shentsize = 0
    e_shnum = 0
    e_shstrndx = 0

    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    )

    p_type = 1  # PT_LOAD
    p_offset = 0x1000
    p_vaddr = segment_vaddr
    p_paddr = segment_vaddr
    p_filesz = len(raw_image)
    p_memsz = len(raw_image)
    p_flags = 0x7  # RWX demo segment
    p_align = 0x1000

    phdr = struct.pack(
        "<IIIIIIII",
        p_type,
        p_offset,
        p_vaddr,
        p_paddr,
        p_filesz,
        p_memsz,
        p_flags,
        p_align,
    )

    pad = b"\x00" * (p_offset - len(elf_header) - len(phdr))
    return elf_header + phdr + pad + raw_image


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build instruction-heavy MN103 demo binary.")
    parser.add_argument(
        "--symbols-dir",
        type=Path,
        default=Path("tmp_mn103_linux416/ghidra_symbols"),
        help="Directory containing generated MN103 Linux CSVs.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("tmp_mn103_samples"),
        help="Output directory for demo binary artifacts.",
    )
    parser.add_argument("--vector-base", default="0x00000000")
    parser.add_argument("--syscall-table-base", default="0x00001000")
    parser.add_argument("--exception-handler-base", default="0x00002000")
    parser.add_argument("--syscall-handler-base", default="0x00004000")
    parser.add_argument("--handler-size", type=int, default=64)
    parser.add_argument("--image-size", default="0x00010000")
    parser.add_argument("--name", default="mn103_instruction_mix_demo")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    symbols_dir = args.symbols_dir.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    syscalls_csv = symbols_dir / "mn103_linux416_syscalls.csv"
    exceptions_csv = symbols_dir / "mn103_linux416_exception_vectors.csv"
    if not syscalls_csv.exists() or not exceptions_csv.exists():
        raise FileNotFoundError(
            "Missing required CSVs in symbols dir. Expected:\n"
            f"  - {syscalls_csv}\n"
            f"  - {exceptions_csv}"
        )

    syscalls = _load_csv(syscalls_csv)
    exceptions = _load_csv(exceptions_csv)

    vector_base = _parse_u32(args.vector_base)
    syscall_table_base = _parse_u32(args.syscall_table_base)
    exception_handler_base = _parse_u32(args.exception_handler_base)
    syscall_handler_base = _parse_u32(args.syscall_handler_base)
    image_size = _parse_u32(args.image_size)

    image = build_demo_image(
        syscalls=syscalls,
        exceptions=exceptions,
        vector_base=vector_base,
        syscall_table_base=syscall_table_base,
        exception_handler_base=exception_handler_base,
        syscall_handler_base=syscall_handler_base,
        handler_size=args.handler_size,
        image_size=image_size,
    )

    stem = args.name
    bin_path = out_dir / f"{stem}.bin"
    elf_path = out_dir / f"{stem}.elf"
    map_path = out_dir / f"{stem}_map.json"
    readme_path = out_dir / f"{stem}.README.txt"

    bin_path.write_bytes(image)

    entry = exception_handler_base
    elf_bytes = make_elf32_exec_mn10300(image, entry=entry, segment_vaddr=0)
    elf_path.write_bytes(elf_bytes)

    manifest = {
        "name": stem,
        "format": {
            "raw_bin": str(bin_path),
            "elf32_exec": str(elf_path),
        },
        "addresses": {
            "vector_base": f"0x{vector_base:08x}",
            "sys_call_table": f"0x{syscall_table_base:08x}",
            "exception_handler_base": f"0x{exception_handler_base:08x}",
            "syscall_handler_base": f"0x{syscall_handler_base:08x}",
            "entry": f"0x{entry:08x}",
        },
        "sizes": {
            "image_size": f"0x{image_size:08x}",
            "handler_size": args.handler_size,
        },
        "counts": {
            "syscalls": len(syscalls),
            "exceptions": len(exceptions),
        },
        "notes": [
            "Synthetic decoder-validation artifact for MN103 Ghidra language development.",
            "Contains mixed instruction families (jmp/call/mov/movu/fmov + nops).",
            "Not production firmware and not semantically meaningful program logic.",
        ],
    }
    map_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    readme_path.write_text(
        "\n".join(
            [
                "MN103 Instruction-Mix Demo",
                "==========================",
                "",
                "Purpose:",
                "- Quick visual decoder validation in Ghidra during staged SLEIGH porting.",
                "",
                "Files:",
                f"- {bin_path.name}",
                f"- {elf_path.name}",
                f"- {map_path.name}",
                "",
                "Import guidance:",
                "1) Import the ELF file directly.",
                "2) Choose language: mn10300:LE:32:default.",
                "",
                "Label script inputs:",
                f"- sys_call_table: 0x{syscall_table_base:08x}",
                f"- vector base:    0x{vector_base:08x}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Wrote: {bin_path}")
    print(f"Wrote: {elf_path}")
    print(f"Wrote: {map_path}")
    print(f"Wrote: {readme_path}")
    print(f"Syscalls: {len(syscalls)}")
    print(f"Exceptions: {len(exceptions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
