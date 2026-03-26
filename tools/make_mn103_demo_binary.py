#!/usr/bin/env python3
"""Generate a synthetic MN103 demo binary for quick Ghidra testing.

The output is intentionally simple: vector stubs + syscall table + handler
blobs, built from the Linux-derived CSV symbol lists.
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


def load_syscalls(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fp:
        rows = list(csv.DictReader(fp))
    if not rows:
        raise ValueError(f"No syscall rows found in {path}")
    return rows


def load_exceptions(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fp:
        rows = list(csv.DictReader(fp))
    if not rows:
        raise ValueError(f"No exception rows found in {path}")
    return rows


def _write_le32(buf: bytearray, offset: int, value: int) -> None:
    buf[offset : offset + 4] = struct.pack("<I", value & 0xFFFFFFFF)


def _emit_nop_blob(buf: bytearray, base: int, size: int, tag: int) -> None:
    # 0xCB is used as NOP filler in the Linux MN10300 vector code.
    blob = bytearray([0xCB] * size)
    if size >= 4:
        blob[0:4] = struct.pack("<I", tag & 0xFFFFFFFF)
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

    # Exception vectors: 8-byte stubs matching Linux shape:
    #   dc <rel32> cb cb cb
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
        if target + handler_size <= image_size:
            _emit_nop_blob(image, target, handler_size, tag=0xE0000000 | idx)

    # Syscall table: 32-bit function pointers.
    for row in syscalls:
        index = int(row["index"])
        entry_addr = syscall_table_base + index * 4
        target = syscall_handler_base + index * handler_size
        if entry_addr + 4 <= image_size:
            _write_le32(image, entry_addr, target)

    # Fill syscall handler stubs.
    for row in syscalls:
        index = int(row["index"])
        target = syscall_handler_base + index * handler_size
        if target + handler_size <= image_size:
            _emit_nop_blob(image, target, handler_size, tag=0xD0000000 | index)

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
    p_flags = 0x7  # RWX (simple demo)
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
    parser = argparse.ArgumentParser(description="Build synthetic MN103 demo binary.")
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
    parser.add_argument("--handler-size", type=int, default=16)
    parser.add_argument("--image-size", default="0x00010000")
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

    syscalls = load_syscalls(syscalls_csv)
    exceptions = load_exceptions(exceptions_csv)

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

    bin_path = out_dir / "mn103_linux_style_demo.bin"
    elf_path = out_dir / "mn103_linux_style_demo.elf"
    map_path = out_dir / "mn103_linux_style_demo_map.json"
    readme_path = out_dir / "README.demo.txt"

    bin_path.write_bytes(image)

    entry = exception_handler_base
    elf_bytes = make_elf32_exec_mn10300(image, entry=entry, segment_vaddr=0)
    elf_path.write_bytes(elf_bytes)

    manifest = {
        "name": "mn103_linux_style_demo",
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
            "Synthetic test artifact for Ghidra language/labeling workflow.",
            "Instruction bytes are placeholder NOP-heavy blobs, not a real firmware.",
        ],
    }
    map_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    readme_path.write_text(
        "\n".join(
            [
                "MN103 Demo Binary",
                "================",
                "",
                "Files:",
                f"- {bin_path.name}",
                f"- {elf_path.name}",
                f"- {map_path.name}",
                "",
                "Import guidance:",
                "1) Preferred: import the ELF file directly.",
                "2) Or import raw BIN at base address 0x00000000.",
                "3) Set language to mn10300:LE:32:default.",
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
