# Matsushita / Panasonic MN10300 processor definition for Ghidra

This module is a generated MN10300 language package for Ghidra.
It was generated from upstream GNU binutils opcode metadata and is intended to
get you immediately unstuck when importing/disassembling MN10300/AM33 binaries
while keeping the build path reproducible.

## Development note

This repository was developed with assistance from AI coding tools. The
extension is useful for analysis and regression testing, but it should still
be reviewed and validated by a human developer before any production use or
security-sensitive deployment.

## Compatibility note (Ghidra 12.0.4)

As of March 26, 2026, the packaged `data/languages/mn103.slaspec` is the
active compile-safe spec used by the extension.
It compiles and loads reliably in Ghidra 12.0.4 and is validated against the
current demo, firmware, and public-blob regression corpora.

The larger development snapshot is preserved as:
- `data/languages/mn103_full_experimental.slaspec`

That archival file is not selected by `mn103.ldefs`.

## What this gives you now

Current active default (`mn103.slaspec`) provides:
- New language ID: `mn10300:LE:32:default`
- Reliable language load/import on Ghidra 12.0.4
- GCC-oriented default call model: `D0`/`D1` are the first argument words,
  `A0` is the pointer return register, `D0` mirrors scalar returns, and
  `D2`/`D3`/`A2`/`SP` are preserved
- Stable bootstrap decode (`nop`, `pi`, `jmp`/`call`, generic one-byte fallback)
- Step-3 control-flow operand rendering for `call`/`ret` extended forms:
  - `call target,[reglist],imm8`
  - `ret [reglist],imm8` / `retf [reglist],imm8`
  - `ret`/`retf` now model frame-unwind return via `(SP + imm8)` and update `SP += imm8 + 4`
- Exception/syscall event modeling:
  - `trap` / `syscall` / `break` now emit explicit `CALLOTHER` p-code hooks
  - AM33 `syscall imm4` form now renders immediate operand
- Staged `mov` coverage for key register/immediate families
- Staged `movu` immediate coverage for AM33 `R` forms
- Selected non-memory `fmov` `fpcr` transfer forms
- Non-AM33 `movbu` / `movhu` memory families for common Linux patterns:
  - base `(an)` forms
  - signed displacement `(sd8,an)` / `(sd16,an)` forms
  - stack-relative `(sp)` / `(imm8,sp)` / `(imm16,sp)` forms
  - indexed `(di,an)` forms
  - absolute `imm16` / `imm32` and `(imm32,an)` forms
- Additional high-frequency core decode families:
  - `movm` SP/USP register-list forms with stack-layout p-code for modeled reg subsets
  - `clr` (base D-register form)
  - `setlb` plus loop-condition aliases `lcc`/`leq`/`lne` with conditional loop-back flow
  - `lsr` (`dm1,dn0` and `imm8,dn0` forms)
  - `btst` immediate-to-D-register forms (`imm8`/`imm16`/`imm32`)
  - `addc` / `subc` core + AM33 `R` immediate/register forms (`imm8`/`imm24`/`imm32`)
  - `inc` / `inc4` base + AM33 `R` forms
  - `asr` / `asl` base + AM33 `R` immediate/register forms
  - `asl2`, `swaph`, and `mulu` core + AM33 `R` forms
  - AM33 Linux-used D10 pair-op forms:
    `add_add`, `sub_sub`, `mov_asl`, `or_asl`, `or_lsr`, `or_asr`, `xor_cmp`
  - `bset` / `bclr` for base `(an)` plus selected shifted-displacement and absolute forms

The detailed phase coverage listed below is the build-up that led to the
current active spec. The archived experimental snapshot is retained only as a
historical reference.

- New language ID: `mn10300:LE:32:default`
- Decoder coverage for **961 unique opcode patterns** (deduplicated from 1129 table rows)
- Support for base MN10300 encodings and many AM30/AM33 encodings
- Phase-2 control-flow support for key families:
  - conditional branches (`beq`/`bne`/.../`bra`)
  - jumps/calls (`jmp`, `call`, `calls`)
  - returns (`ret`, `retf`, `rets`, `rti`, `rtm`)
- Operand rendering + p-code for the above control-flow families
- Phase-3 core arithmetic/data-move support (selected forms):
  - `mov` immediate/register + PSW/MDR/SP transfer forms
  - `add`/`sub` core register forms
  - `cmp` immediate/register forms
  - baseline flag updates (`ZF/NF/CF/VF`) for the covered arithmetic forms
- Phase-3.1 `mov` memory support (selected forms):
  - base register forms: `(am)/(an)` loads and stores
  - stack forms: `(sp)` and `(imm8,sp)` loads and stores
  - displacement forms: `(sd8,an)` and `(sd16,an)` style loads and stores
  - absolute forms: `(imm16)` loads and stores
- Phase-3.2 advanced `mov` memory support (selected forms):
  - indexed `DI` forms `(di,an)` loads and stores
  - absolute `imm32` memory loads and stores
  - AM33 `R`-register memory forms for selected D6/D7/D8 `(rN)`, `(sd8,rN)`, `(sd24,rN)`, and absolute `imm8/imm24` memory forms
- Phase-3.3 advanced arithmetic support:
  - `add`/`sub`/`cmp` SP forms and wide immediate forms (`imm16`, `imm24`, `imm32_high8`)
  - AM33 `R`-register immediate/register forms, including selected 3-operand D7 forms
- Phase-3.4 carry/logic support:
  - `addc`/`subc` AM30/AM33 forms (register, immediate, selected D7 3-operand forms)
  - `and`/`or`/`xor`/`not` forms with baseline flag updates for covered forms
- Phase-3.5 AM33 `mov` memory edge support:
  - `MEMINC` / `MEMINC2` forms (including post-increment p-code updates)
  - `RI` indexed memory forms
  - `IMM32_HIGH8` memory families, including absolute/base/SP variants
- Phase-3.6 AM33 `movbu` / `movhu` memory support:
  - byte/halfword unsigned load-store forms across D6/D7/D8/D9 AM33 families
  - `RI` indexed and `IMM32_HIGH8` absolute/base/SP forms
  - `movhu` `MEMINC` / `MEMINC2` families with post-increment p-code updates
- Phase-3.7 non-AM33 `movbu` / `movhu` memory support:
  - D0/D1/D2/S2/D4 byte/halfword unsigned load-store families
  - base, displacement, stack-relative, indexed `DI`, and absolute `imm16/imm32` forms
- Phase-3.8 unary/data-conversion support (selected forms):
  - AM33 `movu` immediate-to-`R` forms (`imm8`, `imm24`, `imm32_high8`)
  - `ext`/`extb`/`extbu`/`exth`/`exthu` forms across base and AM33 covered encodings
  - `clr`, `inc`, and `inc4` covered base + AM33 forms
- Phase-3.9 shift-family support (selected forms):
  - `asr`/`lsr`/`asl` base + AM33 forms across D0/D1/D6/D7/D8/D9 coverage points
  - covered 3-operand AM33 D7 shift forms (`rm2`, `rn0`, `rd2`)
  - baseline shift p-code includes result + `ZF/NF/CF/VF` updates
- Phase-3.10 bit-test/set/clear support (selected forms):
  - `btst` covered for register and selected memory forms (D1/D2/D4/D7/D8/D9 + D2/D3/D5 memory variants)
  - `bset`/`bclr` covered for base register-memory and selected absolute/displaced memory variants
  - baseline bit p-code updates PSW flags for `btst` and applies memory bit writes for `bset`/`bclr`
- Phase-3.11 S0 `cmp` no-match coverage:
  - full non-equal S0 register-pair expansions for `cmp dm1,dn0` and `cmp am1,an0`
  - removes remaining S0 `cmp` fallback constructors while preserving no-match encoding constraints
- Phase-3.12 `mov` family coverage expansion:
  - S0 no-match register-pair expansions for `mov dm1,dn0` and `mov am1,an0`
  - AM33 system/control/XR forms (`usp`/`ssp`/`msp`/`pc`/`epsw`, `rn`/`xrn`) and remaining wide immediate/memory variants
  - remaining `mov` fallback constructors removed
- Phase-3.13 `fmov` family coverage:
  - AM33_2 `fmov` constructors across D6/D7/D8/D9/D4 forms, including `fpcr` transfers and immediate forms
  - floating-point register operand rendering (`fs*`/`fd*`) and XR/system register rendering added for disassembly coverage
- Phase-3.14 FP arithmetic/compare/convert coverage:
  - AM33_2 constructors for `ftoi`/`itof`/`ftod`/`dtof`, `fabs`/`fneg`/`frsqrt`/`fsqrt`, `fcmp`, and `fadd`/`fsub`/`fmul`/`fdiv`
  - D10 FP operand rendering expanded with `FSN2`/`FSN3`/`FDN2`/`FDN3` decoding
- Phase-3.15 DSP mul/mac/dcpf coverage:
  - AM33 constructors for `mul`/`mulu` and `mac`/`macu`/`macb`/`macbu`/`mach`/`machu` across D0/D6/D7/D8/D9 families
  - AM33_2 constructors for `dcpf` across D6/D7/D8/D9 memory forms
  - AM33 fourth-operand `R` register rendering added for covered D7 forms
- Phase-3.17 AM33 pair-op alias coverage:
  - constructors added for `add_*`, `cmp_*`, `sub_*`, and `mov_*` alias families across `*_add`, `*_sub`, `*_cmp`, `*_mov`, `*_asr`, `*_lsr`, and `*_asl`
  - D10 nibble operand rendering added for `RM6`/`RN4` + `RM2`/`RN0` and `SIMM4_6`/`SIMM4_2`/`IMM4_2` variants
- Phase-3.18 AM33 pair-op alias coverage:
  - constructors added for `and_*`, `or_*`, `xor_*`, `swhw_*`, `sat16_*`, and `dmach_*` families across `*_add`, `*_sub`, `*_cmp`, `*_mov`, `*_asr`, `*_lsr`, and `*_asl`
  - D10 conditional alias constructors added for `mov_llt`/`mov_lgt`/`mov_lge`/`mov_lle`/`mov_lcs`/`mov_lhi`/`mov_lcc`/`mov_lls`/`mov_leq`/`mov_lne`/`mov_lra`
- Phase-3.18 fallback audit snapshot:
  - fallback constructors reduced to 216 total (from 311 after phase 3.17)
  - AM33 pair-op alias families (`add_*`, `cmp_*`, `sub_*`, `mov_*`, `and_*`, `or_*`, `xor_*`, `swhw_*`, `sat16_*`, `dmach_*`) and `mov_l*` condition aliases are now fallback-free

## Current limitations

- The remaining open work is mostly semantic and release-quality; the current
  demo/firmware/real-blob corpora are decode-clean.
- `MEMINC`/`MEMINC2` and `fmov` post-increment behavior is modeled explicitly,
  but the exact hardware intent is still inferred from opcode layout.
- Some advanced AM33 pair-op aliases and undefined opcode families are still fallback for now
- Memory-form `add/sub/cmp` semantics are still intentionally minimal
- `bnc`/`bns` condition mapping currently follows MN102-style `NF` behavior (inference)
- AM33 overlap aliases follow binutils table precedence (first-match retained)
- Bit-memory `btst`/`bset`/`bclr` flag behavior now follows the manual more closely: `VF`/`CF` clear, `NF`/`ZF` track the logical test result, and the byte memory side effects remain modeled explicitly

This is deliberate for version `0.6`: branch/call/return behavior was modeled first,
then core arithmetic/data-move register forms, then selected `mov` memory forms,
then selected indexed/IMM32/AM33-R memory forms, then selected unary/extension
families, then selected shift families, then selected bit-test/set/clear and S0
`cmp` no-match forms, then floating-point `fmov` + arithmetic/convert families,
then selected AM33 DSP mul/mac/dcpf families, then AM33 pair-op alias families
(`add/cmp/sub/mov`, `and/or/xor/swhw/sat16/dmach`) plus D10 `mov_l*`
condition aliases. Full memory coverage and extended AM33 semantics continue
incrementally.

## Sources used (primary)

- GNU binutils opcode table: <https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/opcodes/m10300-opc.c>
- GNU binutils operand/header definitions: <https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/include/opcode/mn10300.h>
- GNU binutils disassembler logic (format/byte-layout behavior): <https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/opcodes/m10300-dis.c>

## Regenerating `mn103.slaspec`

From repository root:

```bash
./tools/fetch_binutils_sources.sh ./tmp_mn103

python3 tools/gen_mn103_slaspec.py \
  --opc-source tmp_mn103/m10300-opc.c \
  --out ghidra-mn103/data/languages/mn103.slaspec
```

## Compact Linux MN10300 Reference Tree (Optional)

If you want a small Linux-side reference corpus (arch code only), fetch Linux
4.16 `arch/mn10300` into a compact local tree:

```bash
./tools/fetch_linux_mn103_refs.sh ./tmp_mn103_linux416
```

This downloads the official Linux 4.16 source tarball and extracts only:
- `arch/mn10300`
- `MAINTAINERS`
- `COPYING`

## Public NVIDIA Firmware Corpus (Optional)

If you want a broader public sample set beyond the bundled demos and the
current online blobs, fetch a pinned snapshot from NVIDIA's public firmware
tree:

```bash
./tools/fetch_public_nvidia_mn103_samples.sh ./tmp_mn103_public_nvidia_samples
```

The corpus includes multiple `fecs_inst.bin` and `gpccs_inst.bin` images from
the `gp102`, `gp104`, and `tu102` families, all pinned to a fixed snapshot of
`nvidia-staging`.

## Public Panasonic Product Firmware Corpus (Optional)

If you want a more varied real-product sample set, fetch a small Panasonic
camera/camcorder corpus from official support pages:

```bash
./tools/fetch_public_panasonic_mn103_samples.sh ./tmp_mn103_public_panasonic_samples
```

Or run the fetch + analysis wrapper:

```bash
./tools/run_public_panasonic_profile.sh
```

This corpus currently includes firmware images from:
- DMC-FP3
- DC-FZ80/FZ81/FZ82/FZ83
- HX-A1M
- HX-A100
- HC-MDH3

The files are regular firmware payloads, not encrypted blobs. In quick checks
they show recognizable container headers and Ghidra begins normal disassembly
and decompilation on them.

## Extract Linux MN10300 Symbols For Ghidra (Optional)

Generate compact, import-friendly syscall/vector metadata from the Linux
MN10300 tree:

```bash
python3 tools/extract_linux_mn103_symbols.py \
  --linux-root ./tmp_mn103_linux416
```

By default this writes to `./tmp_mn103_linux416/ghidra_symbols/`:
- `mn103_linux416_syscalls.csv`
- `mn103_linux416_exception_vectors.csv`
- `mn103_linux416_intr_stub_calls.csv`
- `mn103_linux416_labels.py`

Usage in Ghidra:
1. Open Script Manager and run `mn103_linux416_labels.py`
2. Provide `sys_call_table` address to label syscall entries
3. Provide interrupt vector base address to label exception vectors

## Build and install

For a one-shot rebuild using the bundled Ghidra Gradle wrapper:

```bash
./tools/rebuild_mn103_extension.sh
```

Pass `--regen-spec` if you also want to regenerate
`data/languages/mn103.slaspec` from `tmp_mn103/m10300-opc.c` first.

If you prefer the manual path, the extension can still be built with the
Ghidra install's bundled wrapper or a compatible local `gradle`:

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" buildExtension
```

Install the produced ZIP from `dist/` via `File -> Install Extensions...` in Ghidra.

## Real-Blob Decode Regression (Optional)

Run a quick unknown-opcode regression over real public NVIDIA firmware blobs
wrapped as `EM_MN10300` ELFs:

```bash
./tools/run_real_blob_regression.sh \
  ./tmp_mn103_online_samples \
  ./tmp_mn103_headless/real_blob_regression
```

Outputs:
- `real_blob_regression_report.txt` (human summary)
- `unknown_summaries.txt` (per-file unknown ratios)
- `unknown_top_per_file.txt` (top unknown bytes per file)
- `unknown_top_aggregate.txt` (aggregate unknown bytes)

For a one-shot gate over the firmware corpus, the real blobs, the demo
corpus, and the optional public corpora:

```bash
./tools/check_mn103_corpus.sh
```

The Panasonic stage in that gate uses a smaller representative subset so the
full check stays practical, while the full optional Panasonic corpus remains
available through `run_public_panasonic_profile.sh`.
