#!/usr/bin/env python3
"""Extract Linux MN10300 syscall/exception symbols into Ghidra-friendly files.

Inputs expected from the compact Linux 4.16 MN10300 reference tree:
  - arch/mn10300/include/asm/exceptions.h
  - arch/mn10300/kernel/entry.S
  - arch/mn10300/kernel/traps.c

Outputs:
  - mn103_linux416_syscalls.csv
  - mn103_linux416_exception_vectors.csv
  - mn103_linux416_intr_stub_calls.csv
  - mn103_linux416_labels.py  (Ghidra script)
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


EXCEPTIONS_HEADER_REL = Path("arch/mn10300/include/asm/exceptions.h")
ENTRY_S_REL = Path("arch/mn10300/kernel/entry.S")
TRAPS_C_REL = Path("arch/mn10300/kernel/traps.c")


@dataclass(frozen=True)
class ExceptionCode:
    name: str
    code: int
    comment: str
    line: int


@dataclass(frozen=True)
class SyscallEntry:
    index: int
    symbol: str
    comment: str
    line: int


@dataclass(frozen=True)
class StubCall:
    file: str
    line: int
    api: str
    code_expr: str
    resolved_code_name: Optional[str]
    resolved_code: Optional[int]
    handler: str


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_exception_codes(path: Path) -> List[ExceptionCode]:
    pattern = re.compile(
        r"^\s*(EXCEP_[A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+)\s*,\s*(?:/\*\s*(.*?)\s*\*/)?\s*$"
    )
    results: List[ExceptionCode] = []
    for line_no, line in enumerate(_read_text(path).splitlines(), start=1):
        match = pattern.match(line)
        if not match:
            continue
        name = match.group(1)
        code = int(match.group(2), 16)
        comment = (match.group(3) or "").strip()
        results.append(ExceptionCode(name=name, code=code, comment=comment, line=line_no))
    if not results:
        raise ValueError(f"Could not parse any EXCEP_* codes from {path}")
    return results


def parse_syscall_table(path: Path) -> List[SyscallEntry]:
    lines = _read_text(path).splitlines()
    start_line = None
    start_idx = None
    for idx, line in enumerate(lines):
        if re.search(r"^\s*ENTRY\(sys_call_table\)\s*$", line):
            start_idx = idx + 1
            start_line = idx + 1
            break
    if start_idx is None:
        raise ValueError(f"Could not find ENTRY(sys_call_table) in {path}")

    long_pattern = re.compile(r"^\s*\.long\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    comment_pattern = re.compile(r"/\*\s*(.*?)\s*\*/")
    entries: List[SyscallEntry] = []
    index = 0

    for rel_idx, line in enumerate(lines[start_idx:], start=0):
        if "nr_syscalls=" in line:
            break
        match = long_pattern.match(line)
        if not match:
            continue
        symbol = match.group(1)
        comment_match = comment_pattern.search(line)
        comment = (comment_match.group(1).strip() if comment_match else "")
        if re.fullmatch(r"\d+", comment):
            # Keep semantic notes (for example "old break syscall holder"),
            # but drop pure index-marker comments such as "/* 120 */".
            comment = ""
        entries.append(
            SyscallEntry(
                index=index,
                symbol=symbol,
                comment=comment,
                line=(start_line or 0) + rel_idx,
            )
        )
        index += 1

    if not entries:
        raise ValueError(f"Found syscall table marker, but no .long entries in {path}")
    return entries


def _extract_c_function_body(text: str, signature_pattern: str) -> str:
    signature_match = re.search(signature_pattern, text)
    if not signature_match:
        raise ValueError(f"Could not find function signature pattern: {signature_pattern}")
    body_start = text.find("{", signature_match.end())
    if body_start < 0:
        raise ValueError(f"Could not find function body start for pattern: {signature_pattern}")

    depth = 0
    for idx in range(body_start, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[body_start + 1 : idx]
    raise ValueError(f"Could not find function body end for pattern: {signature_pattern}")


def parse_trap_init_handlers(path: Path) -> Dict[str, str]:
    body = _extract_c_function_body(
        _read_text(path),
        r"\bvoid\s+__init\s+trap_init\s*\(\s*void\s*\)",
    )
    pattern = re.compile(
        r"set_excp_vector\(\s*(EXCEP_[A-Z0-9_]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;"
    )
    handlers: Dict[str, str] = {}
    for match in pattern.finditer(body):
        handlers[match.group(1)] = match.group(2)
    return handlers


def resolve_code_expression(
    expr: str, exception_by_name: Dict[str, ExceptionCode]
) -> Tuple[Optional[str], Optional[int]]:
    expr = expr.strip()
    if expr in exception_by_name:
        ex = exception_by_name[expr]
        return ex.name, ex.code

    irq_level_const = re.fullmatch(r"NUM2EXCEP_IRQ_LEVEL\(\s*(\d+)\s*\)", expr)
    if irq_level_const and "EXCEP_IRQ_LEVEL0" in exception_by_name:
        level = int(irq_level_const.group(1))
        code = exception_by_name["EXCEP_IRQ_LEVEL0"].code + (level * 8)
        name = f"EXCEP_IRQ_LEVEL{level}"
        return name, code

    return None, None


def collect_stub_calls(
    linux_root: Path, exception_by_name: Dict[str, ExceptionCode]
) -> List[StubCall]:
    pattern = re.compile(
        r"(?P<api>__set_intr_stub|set_intr_stub)\s*"
        r"\(\s*(?P<code>[^,]+?)\s*,\s*(?P<handler>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;",
        re.DOTALL,
    )

    calls: List[StubCall] = []
    for path in linux_root.rglob("*"):
        if not path.is_file() or path.suffix not in {".c", ".S", ".h"}:
            continue
        text = _read_text(path)
        for match in pattern.finditer(text):
            code_expr = " ".join(match.group("code").split())
            resolved_name, resolved_code = resolve_code_expression(
                code_expr, exception_by_name
            )
            line = text.count("\n", 0, match.start()) + 1
            rel_path = path.relative_to(linux_root).as_posix()
            calls.append(
                StubCall(
                    file=rel_path,
                    line=line,
                    api=match.group("api"),
                    code_expr=code_expr,
                    resolved_code_name=resolved_name,
                    resolved_code=resolved_code,
                    handler=match.group("handler"),
                )
            )

    calls.sort(key=lambda item: (item.file, item.line, item.api))
    return calls


def _safe_label_text(text: str) -> str:
    cleaned = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            cleaned.append(ch)
        else:
            cleaned.append("_")
    joined = "".join(cleaned)
    if joined and joined[0].isdigit():
        return "_" + joined
    return joined


def write_syscalls_csv(path: Path, entries: Sequence[SyscallEntry]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            ["index", "table_offset_hex", "symbol", "label_suggestion", "source_line", "comment"]
        )
        for entry in entries:
            writer.writerow(
                [
                    entry.index,
                    f"0x{entry.index * 4:04x}",
                    entry.symbol,
                    f"linux_syscall_{entry.index:03d}_{_safe_label_text(entry.symbol)}",
                    entry.line,
                    entry.comment,
                ]
            )


def write_exception_vectors_csv(
    path: Path,
    exceptions: Sequence[ExceptionCode],
    trap_handlers: Dict[str, str],
    stub_handler_map: Dict[str, Sequence[str]],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            [
                "code_name",
                "code_hex",
                "vector_index",
                "vector_offset_hex",
                "default_exception_table_handler",
                "trap_init_handler",
                "stub_handlers",
                "description",
                "source_line",
            ]
        )
        for ex in exceptions:
            writer.writerow(
                [
                    ex.name,
                    f"0x{ex.code:06x}",
                    ex.code >> 3,
                    f"0x{ex.code:06x}",
                    "uninitialised_exception",
                    trap_handlers.get(ex.name, ""),
                    ";".join(stub_handler_map.get(ex.name, [])),
                    ex.comment,
                    ex.line,
                ]
            )


def write_intr_stub_calls_csv(path: Path, calls: Sequence[StubCall]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            [
                "file",
                "line",
                "api",
                "code_expr",
                "resolved_code_name",
                "resolved_code_hex",
                "handler",
            ]
        )
        for call in calls:
            writer.writerow(
                [
                    call.file,
                    call.line,
                    call.api,
                    call.code_expr,
                    call.resolved_code_name or "",
                    (f"0x{call.resolved_code:06x}" if call.resolved_code is not None else ""),
                    call.handler,
                ]
            )


def _format_py_string(value: str) -> str:
    return repr(value)


def generate_ghidra_script(
    path: Path,
    syscalls: Sequence[SyscallEntry],
    exceptions: Sequence[ExceptionCode],
    trap_handlers: Dict[str, str],
    stub_handler_map: Dict[str, Sequence[str]],
    source_root: Path,
) -> None:
    now_utc = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    script_lines: List[str] = []
    script_lines.append("# Generated by extract_linux_mn103_symbols.py")
    script_lines.append("#@category MN10300")
    script_lines.append("")
    script_lines.append('"""')
    script_lines.append("Apply Linux 4.16 MN10300 syscall/exception labels.")
    script_lines.append(f"Generated: {now_utc}")
    script_lines.append(f"Source root: {source_root}")
    script_lines.append('"""')
    script_lines.append("")
    script_lines.append("SYSCALLS = [")
    for entry in syscalls:
        script_lines.append(
            f"    ({entry.index}, {_format_py_string(entry.symbol)}),"
        )
    script_lines.append("]")
    script_lines.append("")
    script_lines.append("EXCEPTIONS = [")
    for ex in exceptions:
        trap_handler = trap_handlers.get(ex.name, "")
        stub_handlers = list(stub_handler_map.get(ex.name, []))
        script_lines.append("    {")
        script_lines.append(f"        'name': {_format_py_string(ex.name)},")
        script_lines.append(f"        'code': 0x{ex.code:06x},")
        script_lines.append(f"        'comment': {_format_py_string(ex.comment)},")
        script_lines.append(
            f"        'trap_handler': {_format_py_string(trap_handler)},"
        )
        script_lines.append(
            "        'stub_handlers': ["
            + ", ".join(_format_py_string(item) for item in stub_handlers)
            + "],"
        )
        script_lines.append("    },")
    script_lines.append("]")
    script_lines.append("")
    script_lines.append("def _safe_label(text):")
    script_lines.append("    out = []")
    script_lines.append("    for ch in text:")
    script_lines.append("        if ch.isalnum() or ch == '_':")
    script_lines.append("            out.append(ch)")
    script_lines.append("        else:")
    script_lines.append("            out.append('_')")
    script_lines.append("    label = ''.join(out)")
    script_lines.append("    if label and label[0].isdigit():")
    script_lines.append("        return '_' + label")
    script_lines.append("    return label")
    script_lines.append("")
    script_lines.append("def _ensure_label(addr, name):")
    script_lines.append("    st = currentProgram.getSymbolTable()")
    script_lines.append("    for sym in st.getSymbols(addr):")
    script_lines.append("        if sym.getName() == name:")
    script_lines.append("            return False")
    script_lines.append("    createLabel(addr, name, True)")
    script_lines.append("    return True")
    script_lines.append("")
    script_lines.append("def apply_syscall_labels():")
    script_lines.append("    if not askYesNo('MN103 Linux Symbols', 'Apply syscall table labels?'):")
    script_lines.append("        println('Skipped syscall table labeling.')")
    script_lines.append("        return 0")
    script_lines.append("    base = askAddress('sys_call_table', 'Address of sys_call_table')")
    script_lines.append("    count = 0")
    script_lines.append("    for index, symbol in SYSCALLS:")
    script_lines.append("        addr = base.add(index * 4)")
    script_lines.append("        label = 'linux_syscall_%03d_%s' % (index, _safe_label(symbol))")
    script_lines.append("        if _ensure_label(addr, label):")
    script_lines.append("            count += 1")
    script_lines.append("    println('Applied %d syscall labels.' % count)")
    script_lines.append("    return count")
    script_lines.append("")
    script_lines.append("def apply_exception_vector_labels():")
    script_lines.append("    if not askYesNo('MN103 Linux Symbols', 'Apply exception vector labels?'):")
    script_lines.append("        println('Skipped exception vector labeling.')")
    script_lines.append("        return 0")
    script_lines.append("    base = askAddress('Vector Base', 'Address of interrupt/exception vector base')")
    script_lines.append("    count = 0")
    script_lines.append("    for entry in EXCEPTIONS:")
    script_lines.append("        addr = base.add(entry['code'])")
    script_lines.append("        label = 'linux_vec_%s' % _safe_label(entry['name'].lower())")
    script_lines.append("        if _ensure_label(addr, label):")
    script_lines.append("            count += 1")
    script_lines.append("    println('Applied %d exception vector labels.' % count)")
    script_lines.append("    return count")
    script_lines.append("")
    script_lines.append("def main():")
    script_lines.append("    total = 0")
    script_lines.append("    total += apply_syscall_labels()")
    script_lines.append("    total += apply_exception_vector_labels()")
    script_lines.append("    println('Done. Total new labels: %d' % total)")
    script_lines.append("")
    script_lines.append("main()")
    script_lines.append("")

    path.write_text("\n".join(script_lines), encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract Linux 4.16 MN10300 symbols for Ghidra use."
    )
    parser.add_argument(
        "--linux-root",
        type=Path,
        default=Path("tmp_mn103_linux416"),
        help="Path to compact Linux MN10300 tree (default: %(default)s)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: <linux-root>/ghidra_symbols)",
    )
    return parser.parse_args(argv)


def _assert_required_files(linux_root: Path) -> None:
    required = [
        linux_root / EXCEPTIONS_HEADER_REL,
        linux_root / ENTRY_S_REL,
        linux_root / TRAPS_C_REL,
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing required Linux MN10300 files:\n" + "\n".join(missing))


def _build_stub_handler_map(calls: Iterable[StubCall]) -> Dict[str, Sequence[str]]:
    mapping: Dict[str, set[str]] = defaultdict(set)
    for call in calls:
        if call.resolved_code_name:
            mapping[call.resolved_code_name].add(call.handler)
    return {key: sorted(values) for key, values in mapping.items()}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    linux_root = args.linux_root.resolve()
    out_dir = (args.out_dir.resolve() if args.out_dir else (linux_root / "ghidra_symbols"))
    out_dir.mkdir(parents=True, exist_ok=True)

    _assert_required_files(linux_root)

    exceptions = parse_exception_codes(linux_root / EXCEPTIONS_HEADER_REL)
    exception_by_name = {item.name: item for item in exceptions}
    syscalls = parse_syscall_table(linux_root / ENTRY_S_REL)
    trap_handlers = parse_trap_init_handlers(linux_root / TRAPS_C_REL)
    intr_stub_calls = collect_stub_calls(linux_root / Path("arch/mn10300"), exception_by_name)
    stub_handler_map = _build_stub_handler_map(intr_stub_calls)

    syscalls_csv = out_dir / "mn103_linux416_syscalls.csv"
    vectors_csv = out_dir / "mn103_linux416_exception_vectors.csv"
    stubs_csv = out_dir / "mn103_linux416_intr_stub_calls.csv"
    ghidra_script = out_dir / "mn103_linux416_labels.py"

    write_syscalls_csv(syscalls_csv, syscalls)
    write_exception_vectors_csv(vectors_csv, exceptions, trap_handlers, stub_handler_map)
    write_intr_stub_calls_csv(stubs_csv, intr_stub_calls)
    generate_ghidra_script(
        ghidra_script,
        syscalls,
        exceptions,
        trap_handlers,
        stub_handler_map,
        source_root=linux_root,
    )

    print(f"Wrote: {syscalls_csv}")
    print(f"Wrote: {vectors_csv}")
    print(f"Wrote: {stubs_csv}")
    print(f"Wrote: {ghidra_script}")
    print(f"Syscalls parsed: {len(syscalls)}")
    print(f"Exception codes parsed: {len(exceptions)}")
    print(f"Intr stub calls parsed: {len(intr_stub_calls)}")
    print(f"trap_init handler assignments: {len(trap_handlers)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
