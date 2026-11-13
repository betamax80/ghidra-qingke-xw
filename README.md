# ghidra-qingke-xw

A Ghidra 12.1.4 extension that adds one language, `RISCV:LE:32:QingKe-XW`, for code built for WCH's QingKe RISC-V
cores. It decodes:

- **XW**, WCH's compressed byte and half-word loads and stores (LLVM's `Xwchc`: `qk.c.lbu`, `qk.c.sb`, `qk.c.lhu`,
  `qk.c.sh`, `qk.c.lbusp`, `qk.c.lhusp`, `qk.c.sbsp`, `qk.c.shsp`; GCC's `xw`);
- the ratified bit-manipulation extensions **Zba, Zbb, Zbs, Zbc**, with p-code (Ghidra 12.1.4 has only the 0.92
  draft, under draft names and with no p-code);
- **Zicond** (`czero.eqz`, `czero.nez`);
- WCH's custom instructions **`mcpy`**, **`mrsl`**, **`mrslu`**, **`wexti`** and the delay instruction (shown as
  `qk.delay`).

Ghidra's own RISC-V languages have no XW. On WCH code they read XW parcels as double-float `c.fld`/`c.fsd`/
`c.fldsp`/`c.fsdsp` (wrong register file and wrong offsets) or as bad instructions. In WCH's `libwchnet.a`, all
1,160 XW instructions come out wrong under `RISCV:LE:32:default`; with this language all 1,160 match `llvm-objdump`.

This is not a WCH, Ghidra or NSA project, and none of them endorses it.

## Which chips

Code for QingKe cores whose toolchain `-march` includes `xw`. WCH's own per-chip table in MounRiver Studio gives
`rv32imac_zba_zbb_zbc_zbs_..._xw` for the CH32V4x7 (QingKe V3V) and `rv32imafc_zba_zbb_zbc_zbs_xw` for the
CH32H417. The checks below used CH32V407/V467 code and a CH32V467. Zicond was confirmed on CH32V467 silicon; on
cores without Zb, Zicond or the custom instructions those encodings are illegal, so decoding them costs nothing.

Not decoded: F, D, Q (so the `c.fld`/`c.fsd` slots XW takes stay free; `c.flw`/`c.fsw` are not decoded either), V
(the V3V's vector unit), P, K, Zbkb and Zcb. XW reuses Zcb's encoding space, so a QingKe language must never be
given Zcb. Code built with hardware float (for example for the CH32H417's F) will show its F instructions as bad.

## Install

You need Ghidra **12.1.4** (Ghidra refuses an extension built for another version).

- **Release zip:** File > Install Extensions > `+` > choose `QingKeXW-1.1.1-ghidra_12.1.4.zip` > restart Ghidra.
  For headless use, unzip it so that the folder lands at `<Ghidra user settings>/Extensions/QingKeXW/`
  (Windows: `%APPDATA%\ghidra\ghidra_12.1.4_PUBLIC\Extensions\QingKeXW\`).
- **From source (Python 3.10 or later):**

  ```
  python tools/build.py --ghidra /path/to/ghidra_12.1.4_PUBLIC --install
  ```

  This checks that the copied Ghidra files still match your Ghidra, compiles the `.sla` with Ghidra's own SLEIGH
  compiler, writes `release/QingKeXW-1.1.1-ghidra_12.1.4.zip` (reproducible: the same sources give the same zip)
  and copies the extension into your Ghidra user settings. `GHIDRA_INSTALL_DIR` can stand in for `--ghidra`.

Nothing in the Ghidra installation is changed. To remove the extension, uninstall it in the GUI or delete the
`QingKeXW` folder.

**Pin the language when importing.** WCH objects carry an ordinary RISC-V ELF header, so Ghidra will not pick this
language by itself. In the import dialog, set Language to `RISCV:LE:32:QingKe-XW` (compiler `gcc`); headless:
`-processor RISCV:LE:32:QingKe-XW -cspec gcc`.

## The language

| | |
|---|---|
| Language ID | `RISCV:LE:32:QingKe-XW`, language version 1.1; compiler spec `gcc` (Ghidra's soft-float `riscv32.cspec`) |
| Instruction sets | RV32I, M, A, C, Zicsr, Zifencei, privileged; Zba, Zbb, Zbs, Zbc; Zicond; XW; WCH custom |
| Source | `QingKeXW/data/languages/`: `qingke-xw.slaspec`, `qingke.instr.sinc`, `qingke.xw.sinc`, `qingke.zb.sinc`, `qingke.zicond.sinc`, `qingke.wch.sinc`, `qingke-xw.ldefs`, plus copies of Ghidra's RISC-V files (listed in `NOTICE`) |

Carry-less multiply (`clmul`, `clmulh`, `clmulr`) has no p-code operation, so it is a named operation
(`rd = clmul(rs1, rs2)`).

WCH's custom instructions:

| Instruction | Encoding | Source | In Ghidra |
|---|---|---|---|
| `mcpy rs1, rs2, rs3` | MISC-MEM (0x0F), funct3 111, rd 0, bits 26:25 = 00, rs3 = bits 31:27 | WCH's GCC 15 binutils; CH32V407 RM V1.3 9.2.1.4 | rs1 = source end (exclusive), rs2 = source, rs3 = destination: the compiler's order, confirmed on a CH32V467 (the RM's labels are the other way round). The copy is the named operation `mcpy(dst, src, end)`; rs3 becomes dst + (end - src), as measured; rs2 afterwards is the named operation `mcpy_src_after` |
| `mrsl`, `mrslu`, `wexti rd, rs1, rs2, imm5` | custom-0 (0x0B), funct3 000, bits 26:25 = 11 / 10 / 00, imm5 = bits 31:27 | WCH's GCC 15 binutils | Named operations; their meaning is not documented, and a CH32V467 traps all three as illegal |
| `qk.delay match, rs1, imm12, div, sel` | custom-0, funct3 001; match = bits 11:9 (001 load, 010 store, 011 ldst, 100 delay, 110 all, 111 csr; 000/101 reserved, not decoded), div bit 8, sel bit 7 | CH32V407 RM V1.3 9.2.1.3 | Named operation `qk_delay(...)`; writes no register. WCH's tools have no mnemonic for it; `qk.delay` is this language's name |

Other custom-0..3 words keep Ghidra's placeholder decodes (`custom0`, `custom0.rd.rs1`, ...).

## How it was checked

`proof/xwproof.py` (Python, run with `python -I`) builds this repository's extension, installs it into a private
settings directory under its work directory and runs Ghidra headless against that, so it tests this build and not
whatever you have installed. `llvm-objdump` (LLVM 23.1.5, `--mattr=+m,+a,+c,+xwchc,+zba,+zbb,+zbc,+zbs,+zicond
-M no-aliases`) is the reference decoder; WCH's GCC 15 objdump is the reference for WCH's custom instructions.

```
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC  LLVM_BIN=/path/to/llvm/bin \
WCH_TOOLCHAIN_BIN=/path/to/wch-gcc15/bin  python -I proof/xwproof.py all /tmp/qkwork
```

| Proof | What | Needs |
|---|---|---|
| `sweep16` | all 49,152 16-bit parcels: llvm-objdump over the whole space, a hand transcription of WCH's XW encoding table, LLVM's operand limits, and the p-code of every `qk.*` decode (one zero-extended load or one store of the right width at base + offset); each check must catch a planted fault | LLVM; optionally `LLVM_MC_TESTS` (llvm-project's `llvm/test/MC/RISCV`) to add LLVM's own Xwchc MC tests |
| `testobj` | an object assembled by LLVM's MC assembler (every XW form, register and offset; RV32IMAC and Zicsr; every Zba/Zbb/Zbs/Zbc/Zicond form and shift amount), through Ghidra's ELF loader, instruction by instruction | LLVM (clang) |
| `sweep32` | 141,376 32-bit words: every funct7 x funct3 of OP, every imm12 of OP-IMM, every funct3 x bits 31:25 x bits 11:7 of custom-0 and MISC-MEM, 40,000 random words there | LLVM, `WCH_TOOLCHAIN_BIN` |
| `emu` | the p-code of every Zba/Zbb/Zbs/Zicond instruction (every shift amount) run one step in Ghidra's emulator against reference models written from the specifications; the named operations' operands; `mcpy`'s registers against seven silicon measurements | LLVM, `WCH_TOOLCHAIN_BIN` |
| `libwchnet`, `decompile` | every instruction of WCH's `libwchnet.a` (CH32V407 EVT V1.4, sha256 `5c1feadc…02b3cd84`), both ways; its objects through the decompiler | `LIBWCHNET` (not included here) |
| `images`, `decompile-images` | your own firmware ELFs, every function, both ways; and through the decompiler | `QINGKE_ELFS` |

Exit codes: 0 pass, 1 fail, 2 could not check, 3 skipped because an optional input was not given. A skip is
never counted as a pass; `all` prints a summary and exits 0 only if every proof ran and passed.

Results for 1.1.1 (13 Nov 2026), in `proof/results/`:

| Proof | Result |
|---|---|
| `sweep16` | PASS: the 8,704 parcels in XW's slots agree with llvm-objdump, the hand transcription, LLVM's limits and LLVM's Xwchc MC tests; the p-code check passes; every planted fault is caught. 177 inherited differences elsewhere (below) |
| `testobj` | PASS: 9,086 instructions compared, 8,712 of them XW, 0 mismatches |
| `sweep32` | PASS: 141,376 words, 0 mismatches on the new instructions, all 39 new mnemonics met; 3 inherited differences (below) |
| `emu` | PASS: 10,008 emulator cases, 0 differ |
| `libwchnet` | PASS: 14,094 instructions, 1,160 of them XW, 0 mismatches. Under `RISCV:LE:32:default` the same bytes give 1,160 mismatches (1,150 as `c.fld`/`c.fsd`/`c.fldsp`/`c.fsdsp`, 10 as bad instructions) |
| `decompile` | PASS: 246 of 246 functions decompile, no float types, no read-before-set registers (`RISCV:LE:32:default`: 40 in 34 functions) |
| `images`, `decompile-images` | PASS on two in-house CH32V467 firmware images (one GCC 15, one clang 23 build): 41,011 instructions, 0 mismatches (`RISCV:LE:32:default`: 1,227); 847 functions decompile with no `halt_unimplemented()` (default: 294 calls in 217 functions). The images and their per-image results are not published |

Each proof's full output is in `proof/results/<proof>.txt`, except the two that ran on unpublished firmware.

Comparison rule: Ghidra's alias spellings (`mv`, `li`, `ret`, `jr`, `csrr`, CSR numbers vs names, `c.lui`'s 6-bit
field, ...) are mapped to llvm's no-alias form by explicit rules in `canon()`, each counted in the results; then
the mnemonic and every operand must be equal.

### Known differences inherited from Ghidra's RV32I/RVC (not changed here)

Over the whole 16-bit space, 177 parcels outside the XW slots decode differently from llvm-objdump; all are
reserved encodings or hints: `0x0000` (`c.unimp`, left undecoded by Ghidra on purpose), `c.addi zero, imm` (63;
llvm's `c.nop imm` hints), `c.slli64`/`c.srli64`/`c.srai64` (48; llvm's shift-by-zero hints), `c.lwsp zero, ...`
(64) and `c.jr zero` (1), which are reserved. In the 32-bit sweep, 3 words differ: `ori zero, rs1, imm` with
imm[4:0] = 1 or 3, which llvm prints as the Zicbop hints `prefetch.r`/`prefetch.w`.

## Upstream

- Zicond for Ghidra's own RISC-V languages: issue
  [NationalSecurityAgency/ghidra#10205](https://github.com/NationalSecurityAgency/ghidra/issues/10205), pull request
  [#10206](https://github.com/NationalSecurityAgency/ghidra/pull/10206). Until it is merged, Ghidra's draft `cmov` decodes `czero.eqz`'s encoding and `czero.nez` is not
  decoded.
- XW in Ghidra: pull request
  [NationalSecurityAgency/ghidra#6390](https://github.com/NationalSecurityAgency/ghidra/pull/6390) (open). This
  repository uses LLVM's `qk.c.*` names and keeps XW in its own language variant, since XW takes the compressed-D
  slots and Zcb's space.
- Ghidra pull request [#8848](https://github.com/NationalSecurityAgency/ghidra/pull/8848) (open) moves Ghidra's
  bit manipulation to the ratified B extension.

## Moving to a newer Ghidra

The SLEIGH source carries over. Re-copy the Ghidra files (their hashes are in `tools/build.py`), set `version=` in
`QingKeXW/extension.properties` and `GHIDRA_VERSION` in `tools/build.py`, rebuild and rerun the proofs.

## Versions

- 1.1.1 (13 Nov 2026): first public release, Apache-2.0. The language is the same as 1.1.0 (comments changed);
  the proofs now build and test the extension in a private settings directory and take their tools and optional
  inputs from environment variables.
- 1.1.0 (12 Nov 2026): ratified Zba/Zbb/Zbs/Zbc with p-code in place of Ghidra's draft bitmanip, Zicond, WCH custom
  instructions.
- 1.0.0 (11 Nov 2026): XW.

## Licence

Apache License 2.0 (`LICENSE`). The Ghidra files copied in, and the one modified copy, are listed in `NOTICE`;
they are Ghidra's, under the same licence. No code or data from WCH or LLVM is included: the XW and custom-
instruction encodings were written from WCH's published encoding table, WCH's reference manual and the behaviour
of WCH's and LLVM's tools, and the proofs read LLVM's test files and WCH's library only from paths you give them.
