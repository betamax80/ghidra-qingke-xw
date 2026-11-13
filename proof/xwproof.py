#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SEL (Mark Thurston). Part of ghidra-qingke-xw.
"""Proofs for the QingKe-XW Ghidra language. Run with `python -I`.

    python -I proof/xwproof.py sweep16   <work>   every 16-bit parcel: the references, llvm-objdump, Ghidra
    python -I proof/xwproof.py testobj   <work>   llvm-mc test object vs llvm-objdump, instruction by instruction
    python -I proof/xwproof.py sweep32   <work>   141,376 32-bit words in OP, OP-IMM, custom-0 and MISC-MEM:
                                                   llvm-objdump, WCH's objdump and the RM's delay table vs Ghidra
    python -I proof/xwproof.py emu       <work>   the p-code of Zba/Zbb/Zbs/Zicond run in Ghidra's emulator
                                                   against reference models; named operations' operands
    python -I proof/xwproof.py libwchnet <work>   WCH's libwchnet.a, every instruction, both ways      (optional)
    python -I proof/xwproof.py decompile <work>   libwchnet.a's objects through the decompiler          (optional)
    python -I proof/xwproof.py images    <work>   your own firmware ELFs, every function, both ways      (optional)
    python -I proof/xwproof.py decompile-images <work>   the same ELFs through the decompiler           (optional)
    python -I proof/xwproof.py all       <work>   every proof above, then a summary

Configuration (environment variables):
    GHIDRA_INSTALL_DIR   Ghidra 12.1.4 (required). Each run first builds this repository's extension with
                         tools/build.py and installs it into <work>/settings, which headless Ghidra is pointed at
                         (-Dapplication.settingsdir), so the proofs test this build, not whatever is installed.
    LLVM_BIN             directory holding llvm-objdump, llvm-objcopy and clang (LLVM 23.1.5); default: PATH
    WCH_TOOLCHAIN_BIN    directory holding WCH's riscv32-wch-elf-as/-objdump (GCC 15 toolchain v1.4); needed by
                         sweep32 and emu, which are SKIPPED without it
    LLVM_MC_TESTS        llvm-project's llvm/test/MC/RISCV directory (xwchc-*.s); an extra reference for sweep16,
                         left out (and said so) without it. Those files are not copied into this repository.
    LIBWCHNET            WCH's libwchnet.a from the CH32V407 EVT V1.4 (EXAM/ETH/NetLib), sha256 checked; the
                         libwchnet and decompile proofs are SKIPPED without it. It is not in this repository.
    QINGKE_ELFS          firmware ELFs for images / decompile-images, separated by the OS path separator;
                         SKIPPED without it.

Each writes proof/results/<name>.txt (a summary) and keeps its big tables in <work>. Exit 0 = every check passed,
1 = a check failed, 2 = could not check (a tool, reference or input was missing or not the recorded file), 3 =
skipped (an optional input was not given; not a pass).

llvm-objdump (LLVM 23.1.5, --mattr=+m,+a,+c,+xwchc,+zba,+zbb,+zbc,+zbs,+zicond, -M no-aliases) is the reference
decoder; WCH's GCC 15 objdump is the reference for WCH's custom instructions, which LLVM does not know. Ghidra is
run headless only (support/analyzeHeadless, -noanalysis), at low priority, after the machine's CPU load is under
90% (checked on Windows only).

Comparison: Ghidra's text is turned into llvm's no-alias spelling by the explicit rules in `canon()` (each rule only
renames an alias to the instruction it stands for, or reorders an operand; every use is counted and reported), then
mnemonic and every operand must be equal. Numbers compare as integers; branch targets are made section-relative,
modulo 2^32 (llvm prints a target before the section start as a 32-bit address).
"""
from __future__ import annotations

import collections
import hashlib
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "proof" / "results"
SCRIPTS = REPO / "proof" / "ghidra_scripts"


def _env_path(name: str) -> Path | None:
    v = os.environ.get(name)
    return Path(v) if v else None


GHIDRA = _env_path("GHIDRA_INSTALL_DIR")
LLVM = _env_path("LLVM_BIN")
LANG = "RISCV:LE:32:QingKe-XW"
BASELINE = "RISCV:LE:32:default"
MATTR = "+m,+a,+c,+xwchc,+zba,+zbb,+zbc,+zbs,+zicond"
LOW_PRIORITY = {"creationflags": 0x00004000} if os.name == "nt" else {}   # BELOW_NORMAL_PRIORITY_CLASS
WCH_BIN = _env_path("WCH_TOOLCHAIN_BIN")       # WCH GCC 15 toolchain v1.4 (binutils)
WCH_ARCH = "rv32imac_zicsr_zifencei_zba_zbb_zbc_zbs_zicond"
WCH_CUSTOM = {"mcpy", "mrsl", "mrslu", "wexti"}
RM_DELAY = "CH32V407 RM V1.3 (EN) 9.2.1.3, printed p.61"
IMAGES = [(f"elf{i}-{Path(p).stem}", Path(p))
          for i, p in enumerate(p for p in os.environ.get("QINGKE_ELFS", "").split(os.pathsep) if p)]
LLVM_MC_TESTS = _env_path("LLVM_MC_TESTS")     # llvm-project/llvm/test/MC/RISCV
LIBWCHNET = _env_path("LIBWCHNET")
LIBWCHNET_SHA = "5c1feadcc555ecf39d529bfe2945737ec917d8e310a8b526fb19485902b3cd84"
SETTINGS: Path | None = None                   # set by prepare(): the isolated Ghidra settings directory

ABI = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
       "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"]
XW_FORMS = ["qk.c.lbu", "qk.c.sb", "qk.c.lhu", "qk.c.sh", "qk.c.lbusp", "qk.c.lhusp", "qk.c.sbsp", "qk.c.shsp"]
BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "jal", "c.j", "c.jal", "c.beqz", "c.bnez"}


class CouldNotCheck(Exception):
    pass


class Skipped(Exception):
    """An optional input was not given. Reported as SKIPPED (exit 3), never as a pass."""


# ----------------------------------------------------------------------------------------------- tools and runs

def tool(name: str) -> str:
    """An LLVM tool from LLVM_BIN, else from PATH. `name` may carry .exe; it is dropped off Windows."""
    base = name[:-4] if name.endswith(".exe") else name
    if LLVM:
        for cand in (LLVM / name, LLVM / base, LLVM / (base + ".exe")):
            if cand.exists():
                return str(cand)
        raise CouldNotCheck(f"{base} not found in LLVM_BIN={LLVM}")
    found = shutil.which(base)
    if not found:
        raise CouldNotCheck(f"{base} not found on PATH (set LLVM_BIN)")
    return found


def wch_tool(name: str) -> str:
    if not WCH_BIN:
        raise Skipped("WCH_TOOLCHAIN_BIN is not set (WCH's GCC 15 binutils are the reference for WCH's custom "
                      "instructions)")
    base = name[:-4] if name.endswith(".exe") else name
    for cand in (WCH_BIN / name, WCH_BIN / base, WCH_BIN / (base + ".exe")):
        if cand.exists():
            return str(cand)
    raise CouldNotCheck(f"{base} not found in WCH_TOOLCHAIN_BIN={WCH_BIN}")


def run(cmd, **kw) -> str:
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                       **LOW_PRIORITY, **kw)
    if r.returncode != 0:
        raise CouldNotCheck(f"{cmd[0]} exited {r.returncode}: {r.stderr[-2000:]}")
    return r.stdout


def headless(cmd_tail: list, log: Path) -> subprocess.CompletedProcess:
    """analyzeHeadless with the isolated settings directory prepare() made (this repository's build only)."""
    if SETTINGS is None:
        raise CouldNotCheck("prepare() has not built and installed the extension")
    exe = GHIDRA / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    env = dict(os.environ)
    env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = f"-Dapplication.settingsdir={SETTINGS}"
    r = subprocess.run([str(c) for c in [exe, *cmd_tail]], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, env=env, **LOW_PRIORITY)
    log.write_text(r.stdout + r.stderr, encoding="utf-8")
    return r


def prepare(work: Path) -> None:
    """Build the extension from this repository and install it into <work>/settings only."""
    global SETTINGS
    if GHIDRA is None:
        raise CouldNotCheck("set GHIDRA_INSTALL_DIR to a Ghidra 12.1.4 installation")
    spec = importlib.util.spec_from_file_location("qkbuild", REPO / "tools" / "build.py")
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    try:
        g = b.ghidra_dir(str(GHIDRA))
        b.build(g)
    except b.CouldNotCheck as e:
        raise CouldNotCheck(str(e))
    settings = (work / "settings").resolve()
    if settings.exists():
        shutil.rmtree(settings)
    b.install(b.settings_parents(settings))
    SETTINGS = settings


def cpu_load() -> float:
    if os.name != "nt":
        return 0.0
    out = subprocess.run(["typeperf", r"\Processor(_Total)\% Processor Time", "-sc", "3"],
                         capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout
    vals = [float(m) for m in re.findall(r',"([0-9.]+)"', out)]
    return sum(vals) / len(vals) if vals else 0.0


def wait_for_cpu(limit: float = 90.0, max_wait_s: int = 3600) -> None:
    t0 = time.time()
    while True:
        load = cpu_load()
        if load <= limit:
            print(f"  CPU {load:.0f}% - going ahead")
            return
        if time.time() - t0 > max_wait_s:
            raise CouldNotCheck(f"CPU stayed above {limit}% for {max_wait_s} s")
        print(f"  CPU {load:.0f}% > {limit}% - waiting 60 s")
        time.sleep(60)


def llvm_version() -> str:
    out = run([tool("llvm-objdump.exe"), "--version"])
    m = re.search(r"LLVM version (\S+)", out)
    return m.group(1) if m else "?"


def ghidra_dump(work: Path, inp: Path, out_tsv: Path, lang: str, raw: bool, regions: Path | None = None) -> None:
    """Import `inp` into a throw-away headless project and run DumpLinear on it."""
    wait_for_cpu()
    proj = work / "ghidra-project"
    proj.mkdir(parents=True, exist_ok=True)
    name = f"p{os.getpid()}_{int(time.time())}"
    cmd = [proj, name, "-import", inp]
    if raw:
        cmd += ["-loader", "BinaryLoader", "-loader-baseAddr", "0x0"]
    cmd += ["-processor", lang, "-cspec", "gcc", "-noanalysis", "-max-cpu", "2",
            "-scriptPath", SCRIPTS, "-postScript", "DumpLinear.java", out_tsv]
    if regions:
        cmd.append(regions)
    cmd.append("-deleteProject")
    if out_tsv.exists():
        out_tsv.unlink()
    t0 = time.time()
    r = headless(cmd, work / (out_tsv.stem + ".headless.log"))
    if r.returncode != 0 or not out_tsv.exists() or "DumpLinear:" not in r.stdout:
        raise CouldNotCheck(f"Ghidra headless failed (exit {r.returncode}); see {out_tsv.stem}.headless.log")
    line = [ln for ln in r.stdout.splitlines() if "DumpLinear:" in ln][-1]
    print(f"  Ghidra {lang}: {line.split('DumpLinear:')[1].strip()} ({time.time() - t0:.0f} s)")


# ----------------------------------------------------------------------------------------------- parsing

def num(t: str):
    t = t.strip()
    try:
        return int(t, 0)
    except ValueError:
        return t.lower()


def split_ops(s: str) -> list:
    """'a0, -4(sp)' -> ['a0', -4, 'sp']; symbol annotations '<...>' dropped."""
    s = re.sub(r"\s*<[^>]*>", "", s).strip()
    if not s:
        return []
    out = []
    for part in s.split(","):
        part = part.strip()
        m = re.fullmatch(r"(.*)\((\w+)\)", part)
        if m:
            out += [num(m.group(1) or "0"), m.group(2).lower()]
        else:
            out.append(num(part))
    return out


def parse_ghidra(tsv: Path):
    """-> (language, {(region, off): (len, bytes, mnem, ops, pcode)}, {region: abs_start})"""
    lang, insns, starts = None, {}, {}
    with open(tsv, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("# language\t"):
                lang = line.split("\t")[1]
                continue
            if line.startswith("# region\t"):
                _, name, start = line.split("\t")
                starts[name] = int(start, 16)
                continue
            region, off, ln, b, text, pc = line.split("\t")
            if text == "BAD":
                mnem, ops = None, []
            else:
                mnem, _, rest = text.partition(" ")
                mnem, ops = mnem.lower(), split_ops(rest)
            insns[(region, int(off, 16))] = (int(ln), b, mnem, ops, pc)
    return lang, insns, starts


# llvm-objdump 23 prints a RISC-V parcel as one little-endian word ("2000", "00d44783"); older versions as bytes.
LLVM_LINE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8}|[0-9a-f]{4}|(?:[0-9a-f]{2} )+)\s*(.*)$")


def word_to_bytes(w: str) -> str:
    w = w.replace(" ", "") if " " in w else bytes.fromhex(w)[::-1].hex()
    return w


def parse_llvm(text: str, section_map=None):
    """llvm-objdump -d output -> {(section, off): (bytes, mnem, ops)}; mnem None for <unknown>."""
    out, sec = {}, None
    for line in text.splitlines():
        if line.startswith("Disassembly of section "):
            sec = line[len("Disassembly of section "):].rstrip(":")
            if section_map:
                sec = section_map(sec)
            continue
        m = LLVM_LINE.match(line)
        if not m or sec is None:
            continue
        off, b, rest = int(m.group(1), 16), word_to_bytes(m.group(2)), m.group(3)
        parts = rest.split("\t", 1)
        mnem = parts[0].strip().lower()
        if mnem.startswith("<unknown>") or not mnem:
            out[(sec, off)] = (b, None, [])
        else:
            out[(sec, off)] = (b, mnem, split_ops(parts[1] if len(parts) > 1 else ""))
    return out


# ----------------------------------------------------------------------------------------------- canonical form

FENCE_BITS = {"i": 8, "o": 4, "r": 2, "w": 1}


def fence_set(v):
    if isinstance(v, int):
        return v
    return sum(FENCE_BITS[c] for c in v if c in FENCE_BITS)


# CSR names llvm-objdump prints -> numbers (Ghidra prints the number). The RISC-V privileged spec's addresses.
CSR_NUM = {
    "fflags": 0x001, "frm": 0x002, "fcsr": 0x003, "cycle": 0xC00, "time": 0xC01, "instret": 0xC02,
    "cycleh": 0xC80, "timeh": 0xC81, "instreth": 0xC82,
    "mstatus": 0x300, "misa": 0x301, "medeleg": 0x302, "mideleg": 0x303, "mie": 0x304, "mtvec": 0x305,
    "mcounteren": 0x306, "mstatush": 0x310, "mscratch": 0x340, "mepc": 0x341, "mcause": 0x342, "mtval": 0x343,
    "mip": 0x344, "mvendorid": 0xF11, "marchid": 0xF12, "mimpid": 0xF13, "mhartid": 0xF14, "mcycle": 0xB00,
    "minstret": 0xB02, "mcycleh": 0xB80, "minstreth": 0xB82, "mcountinhibit": 0x320,
    "dcsr": 0x7B0, "dpc": 0x7B1, "dscratch0": 0x7B2, "dscratch1": 0x7B3,
    "tselect": 0x7A0, "tdata1": 0x7A1, "tdata2": 0x7A2, "tdata3": 0x7A3,
}
CSR_RW = {"csrr": None, "csrs": "csrrs", "csrc": "csrrc", "csrw": "csrrw",
          "csrsi": "csrrsi", "csrci": "csrrci", "csrwi": "csrrwi"}
# Ghidra's F-CSR aliases (riscv.csr.sinc): name -> (base mnemonic, csr, form)
FCSR = {"frcsr": ("csrrs", 3, "rd"), "frflags": ("csrrs", 1, "rd"), "frrm": ("csrrs", 2, "rd"),
        "fscsr": ("csrrw", 3, "rs"), "fsflags": ("csrrw", 1, "rs"), "fsrm": ("csrrw", 2, "rs"),
        "fsflagsi": ("csrrwi", 1, "rs"), "fsrmi": ("csrrwi", 2, "rs")}
U32 = 0xFFFFFFFF


def canon(mnem: str, ops: list, abs_start: int):
    """Ghidra's spelling -> llvm's no-alias spelling. Returns (mnem, ops, rule or None)."""
    ops = list(ops)
    rule = None
    if mnem in BRANCHES and ops and isinstance(ops[-1], int):
        ops[-1] = (ops[-1] - abs_start) & U32
    if mnem == "csrr" and len(ops) == 2:
        return "csrrs", [ops[0], ops[1], "zero"], "csrr=csrrs rd,csr,zero"
    if mnem in CSR_RW and CSR_RW[mnem] and len(ops) == 2:
        return CSR_RW[mnem], ["zero", ops[0], ops[1]], f"{mnem}={CSR_RW[mnem]} zero,csr,x"
    if mnem in FCSR:
        base, csr, form = FCSR[mnem]
        if form == "rd" and len(ops) == 1:
            return base, [ops[0], csr, "zero"], f"{mnem}={base}"
        if form == "rs" and len(ops) == 1:
            return base, ["zero", csr, ops[0]], f"{mnem}={base}"
        if form == "rs" and len(ops) == 2:
            return base, [ops[0], csr, ops[1]], f"{mnem}={base}"
    if mnem == "ret" and not ops:                      # c.jr ra (16-bit) or jalr zero,0(ra) (32-bit): by length
        return "ret", ops, "ret"
    if mnem == "nop" and not ops:
        return "addi", ["zero", "zero", 0], "nop=addi zero,zero,0"
    if mnem == "mv" and len(ops) == 2:
        return "addi", [ops[0], ops[1], 0], "mv=addi rd,rs,0"
    if mnem == "li" and len(ops) == 2:
        return "addi", [ops[0], "zero", ops[1]], "li=addi rd,zero,imm"
    if mnem == "j" and len(ops) == 1:
        if isinstance(ops[0], int):
            ops[0] = (ops[0] - abs_start) & U32
        return "jal", ["zero", ops[0]], "j=jal zero,t"
    if mnem == "jr" and len(ops) == 1:
        return "jalr", ["zero", 0, ops[0]], "jr=jalr zero,0(rs)"
    if mnem == "jr" and len(ops) == 2:
        return "jalr", ["zero", ops[0], ops[1]], "jr imm(rs)=jalr zero,imm(rs)"
    if mnem == "jalr" and len(ops) == 3:
        return "jalr", [ops[0], ops[2], ops[1]], "jalr rd,rs,imm order"
    if mnem == "neg" and len(ops) == 2:
        return "sub", [ops[0], "zero", ops[1]], "neg=sub rd,zero,rs"
    if mnem == "not" and len(ops) == 2:
        return "xori", [ops[0], ops[1], -1], "not=xori rd,rs,-1"
    if mnem == "fence" and len(ops) == 2:
        return "fence", [fence_set(ops[0]), fence_set(ops[1])], "fence sets as bits"
    return mnem, ops, rule


def llvm_canon(mnem: str, ops: list, length: int):
    ops = list(ops)
    if mnem == "fence" and len(ops) == 2:
        return mnem, [fence_set(ops[0]), fence_set(ops[1])]
    if mnem in BRANCHES and ops and isinstance(ops[-1], int):
        ops[-1] &= U32
    if mnem.startswith("csrr") and len(ops) == 3 and isinstance(ops[1], str) and ops[1] in CSR_NUM:
        ops[1] = CSR_NUM[ops[1]]
    return mnem, ops


def compare(ghidra, llvm, starts, region_of=lambda s: s):
    """Instruction by instruction. Returns (stats Counter, classes {class: Counter(example key)}, examples)."""
    stats = collections.Counter()
    classes = collections.defaultdict(collections.Counter)
    examples = {}
    rules = collections.Counter()
    keys = sorted(set(ghidra) | set(llvm))
    for key in keys:
        g, l = ghidra.get(key), llvm.get(key)
        if g is None or l is None:
            cls = "boundary: only llvm has an instruction here" if g is None else \
                  "boundary: only Ghidra has an instruction here"
            stats["mismatch"] += 1
            classes[cls][(l or g)[1] if l else g[2]] += 1
            examples.setdefault(cls, (key, g, l))
            continue
        glen, gbytes, gm, gops, _ = g
        lbytes, lm, lops = l
        stats["compared"] += 1
        if gbytes != lbytes[:len(gbytes)] or len(lbytes) != 2 * glen:
            cls = "bytes or length differ"
            stats["mismatch"] += 1
            classes[cls][f"{gm} / {lm}"] += 1
            examples.setdefault(cls, (key, g, l))
            continue
        if lm and lm.startswith("qk."):
            stats["llvm XW"] += 1
        if gm is None and lm is None:
            stats["match (both undecoded)"] += 1
            continue
        if gm is None:
            cls = "llvm decodes, Ghidra BAD"
            stats["mismatch"] += 1
            classes[cls][lm] += 1
            examples.setdefault(cls + " " + lm, (key, g, l))
            continue
        if lm is None:
            cls = "Ghidra decodes, llvm <unknown>"
            stats["mismatch"] += 1
            classes[cls][gm] += 1
            examples.setdefault(cls + " " + gm, (key, g, l))
            continue
        abs_start = starts.get(region_of(key[0]), 0)
        cm, cops, rule = canon(gm, gops, abs_start)
        lm2, lops2 = llvm_canon(lm, lops, glen)
        if cm.startswith("csrr") and len(cops) == 3 and isinstance(cops[1], str) and cops[1] in CSR_NUM:
            cops = [cops[0], CSR_NUM[cops[1]], cops[2]]          # Ghidra names a few CSRs too
            rule = rule or "CSR name = CSR number"
        if lm.startswith("csrr") and lops2 != lops and not rule:
            rule = "CSR name = CSR number"
        if cm == "ret":                                    # Ghidra's ret: c.jr ra or jalr zero, 0(ra)
            cm, cops = ("c.jr", ["ra"]) if glen == 2 else ("jalr", ["zero", 0, "ra"])
        if cm == "c.lui" and lm2 == "c.lui" and len(cops) == 2 and len(lops2) == 2 \
                and isinstance(cops[1], int) and isinstance(lops2[1], int):
            # Ghidra shows the 6-bit field (nzimm[17:12]); llvm the 20-bit sign-extended value.
            f = cops[1]
            if 0 <= f < 0x40 and lops2[1] == (f | 0xFFFC0 if f & 0x20 else f):
                rule = "c.lui 6-bit field = llvm 20-bit value"
                cops = [cops[0], lops2[1]]
        if (cm, cops) == (lm2, lops2):
            if rule:
                rules[rule] += 1
                stats["match (by a stated spelling rule)"] += 1
            else:
                stats["match"] += 1
            if lm.startswith("qk."):
                stats["llvm XW matched"] += 1
            continue
        stats["mismatch"] += 1
        if cm != lm2:
            cls = "mnemonic differs"
            classes[cls][f"Ghidra {gm} / llvm {lm}"] += 1
            examples.setdefault(f"{cls}: {gm}/{lm}", (key, g, l))
        else:
            cls = "operands differ"
            classes[cls][lm] += 1
            examples.setdefault(f"{cls}: {lm}", (key, g, l))
    return stats, classes, examples, rules


def report_compare(title, stats, classes, examples, rules) -> list[str]:
    out = [f"## {title}", ""]
    for k in ("compared", "match", "match (by a stated spelling rule)", "match (both undecoded)", "mismatch",
              "llvm XW", "llvm XW matched"):
        out.append(f"- {k}: {stats.get(k, 0):,}")
    if rules:
        out.append("- spelling rules used: " + ", ".join(f"{r} x{n}" for r, n in rules.most_common()))
    if classes:
        out.append("")
        out.append("Mismatches by class:")
        for cls, ctr in classes.items():
            out.append(f"- {cls}: {sum(ctr.values()):,}  (" +
                       ", ".join(f"{k} x{n}" for k, n in ctr.most_common(12)) +
                       (", ..." if len(ctr) > 12 else "") + ")")
        out.append("")
        out.append("One example per class (key, Ghidra, llvm):")
        for cls, ex in list(examples.items())[:60]:
            out.append(f"- {cls}: {ex}")
    out.append("")
    return out


# ----------------------------------------------------------------------------------------------- references

def wch_table(h: int):
    """WCH's XW encoding table (an image WCH posted in LLVM discourse thread 79392), transcribed by hand.
    Columns are parcel bits 15..0. -> (form, reg, imm, base) or None."""
    op, f3 = h & 3, (h >> 13) & 7
    bit = lambda i: (h >> i) & 1
    r_low = ABI[8 + ((h >> 2) & 7)]           # rd' / rs2', bits 4:2
    rs1 = ABI[8 + ((h >> 7) & 7)]             # rs1', bits 9:7
    u21 = ((h >> 5) & 3) << 1                 # uimm[2:1] at 6:5
    if f3 == 1 and op == 0:                   # c.lbu  001 uimm[0|4:3] rs1' uimm[2:1] rd' 00
        return "qk.c.lbu", r_low, (bit(12) | u21 | (((h >> 10) & 3) << 3)), rs1
    if f3 == 1 and op == 2:                   # c.lhu  001 uimm[5|4:3] rs1' uimm[2:1] rd' 10
        return "qk.c.lhu", r_low, (u21 | (((h >> 10) & 7) << 3)), rs1
    if f3 == 5 and op == 0:                   # c.sb   101 uimm[0|4:3] rs1' uimm[2:1] rs2' 00
        return "qk.c.sb", r_low, (bit(12) | u21 | (((h >> 10) & 3) << 3)), rs1
    if f3 == 5 and op == 2:                   # c.sh   101 uimm[5|4:3] rs1' uimm[2:1] rs2' 10
        return "qk.c.sh", r_low, (u21 | (((h >> 10) & 7) << 3)), rs1
    if f3 == 4 and op == 0 and ((h >> 11) & 3) == 0:
        f2 = (h >> 5) & 3                     # 00 lbusp, 01 lhusp, 10 sbsp, 11 shsp
        if f2 in (0, 2):                      # uimm[3:0] at 10:7
            imm = (h >> 7) & 0xF
        else:                                 # uimm[3:1|4] at 10:7
            imm = (((h >> 8) & 7) << 1) | (bit(7) << 4)
        return ["qk.c.lbusp", "qk.c.lhusp", "qk.c.sbsp", "qk.c.shsp"][f2], r_low, imm, "sp"
    return None


def llvm_fixture(name: str) -> list[str]:
    """One of LLVM's own Xwchc MC tests, read from the user's llvm-project checkout (LLVM_MC_TESTS). They are
    Apache-2.0 WITH LLVM-exception and are not copied into this repository."""
    p = LLVM_MC_TESTS / name
    if not p.exists():
        raise CouldNotCheck(f"{p} missing (LLVM_MC_TESTS must be llvm-project's llvm/test/MC/RISCV)")
    return p.read_text(encoding="utf-8").splitlines()


ENC2 = re.compile(r"encoding: \[0x([0-9a-f]{2}),0x([0-9a-f]{2})\]")


def fixture_cases(lines, pattern):
    out = []
    for i, line in enumerate(lines):
        m = re.match(pattern, line)
        if not m or not i:
            continue
        enc = ENC2.search(lines[i - 1])
        if not enc:
            continue
        h = int(enc.group(1), 16) | (int(enc.group(2), 16) << 8)
        out.append((line.strip(), h))
    return out


def xw_of(entry):
    """A Ghidra entry -> (form, reg, imm, base) if it is a qk.* decode."""
    if entry is None or entry[2] is None or not entry[2].startswith("qk."):
        return None
    ops = entry[3]
    return (entry[2], ops[0], ops[1], ops[2]) if len(ops) == 3 else (entry[2], "?", "?", "?")


def pcode_ok(form, reg, imm, base, pcode: str) -> bool:
    """The p-code must access `width` bytes at base+imm, zero-extend loads into reg, store reg's low bytes."""
    width = 2 if "h" in form.split(".")[-1][:2] else 1      # lbu/lbusp/sb/sbsp -> 1, lhu/lhusp/sh/shsp -> 2
    reg_vn = lambda r, size=4: ("register", 0x2000 + 4 * ABI.index(r), size)
    vn = lambda s: (lambda p: (p[0], int(p[1], 16), int(p[2])))([x.strip() for x in s.strip()[1:-1].split(",")])
    ops = []                                                 # (output varnode or None, opcode, [inputs])
    for o in pcode.split(" ; "):
        m = re.fullmatch(r"\s*(?:(\([^)]*\))|---)?\s*([A-Z_]+) (.*)", o)   # '---' = no output (STORE)
        if not m:
            return False
        ops.append((vn(m.group(1)) if m.group(1) else None, m.group(2),
                    [vn(x) for x in m.group(3).split(" , ")]))
    values = {}                                              # varnode -> what it holds: ("const", n) / ("reg", vn)
    ea = None
    for out, opc, ins in ops:
        if opc == "COPY" and ins[0][0] == "const":
            values[out] = ("const", ins[0][1])
        elif opc == "INT_ADD":
            terms = [values.get(i, ("const", i[1]) if i[0] == "const" else ("vn", i)) for i in ins]
            if sorted(terms, key=str) == sorted([("const", imm), ("vn", reg_vn(base))], key=str):
                ea = out
    if ea is None:
        return False
    loads = [(o, i) for o, c, i in ops if c == "LOAD"]
    stores = [i for o, c, i in ops if c == "STORE"]
    if form.split(".")[-1].startswith("l"):
        zext = [(o, i) for o, c, i in ops if c == "INT_ZEXT"]
        return (len(loads) == 1 and not stores and loads[0][1][1] == ea and loads[0][0][2] == width
                and len(zext) == 1 and zext[0][0] == reg_vn(reg) and zext[0][1][0] == loads[0][0])
    return (len(stores) == 1 and not loads and stores[0][1] == ea and stores[0][2] == reg_vn(reg, width))


# ----------------------------------------------------------------------------------------------- sweep16

def cmd_sweep16(work: Path) -> int:
    work.mkdir(parents=True, exist_ok=True)
    lines = [f"# sweep16: every 16-bit parcel ({time.strftime('%Y-%m-%d %H:%M')})", ""]
    parcels = [h for h in range(0x10000) if h & 3 != 3]
    blob = work / "parcels16.bin"
    blob.write_bytes(b"".join(struct.pack("<H", h) for h in parcels))
    region = work / "parcels16.regions.tsv"
    region.write_text(f"parcels\t0\t{2 * len(parcels):x}\n", encoding="utf-8")
    elf = work / "parcels16.o"
    run([tool("llvm-objcopy.exe"), "-I", "binary", "-O", "elf32-littleriscv",
         "--rename-section=.data=.text,alloc,load,readonly,code,contents", blob, elf])
    llvm_txt = run([tool("llvm-objdump.exe"), "-d", "-M", "no-aliases", f"--mattr={MATTR}", elf])
    (work / "parcels16.llvm.txt").write_text(llvm_txt, encoding="utf-8")
    llvm = parse_llvm(llvm_txt, section_map=lambda s: "parcels")
    if len(llvm) != len(parcels):
        raise CouldNotCheck(f"llvm-objdump gave {len(llvm)} lines for {len(parcels)} parcels")

    tsv = work / "parcels16.ghidra.tsv"
    ghidra_dump(work, blob, tsv, LANG, raw=True, regions=region)
    lang, ghidra, starts = parse_ghidra(tsv)
    if lang != LANG:
        raise CouldNotCheck(f"Ghidra used {lang}, not {LANG}")
    tsv0 = work / "parcels16.default.tsv"
    ghidra_dump(work, blob, tsv0, BASELINE, raw=True, regions=region)
    _, ghidra0, _ = parse_ghidra(tsv0)

    by_h = {h: ghidra.get(("parcels", 2 * i)) for i, h in enumerate(parcels)}
    by_h0 = {h: ghidra0.get(("parcels", 2 * i)) for i, h in enumerate(parcels)}
    llvm_h = {h: llvm.get(("parcels", 2 * i)) for i, h in enumerate(parcels)}
    fails = []

    # Reference 1 (optional): LLVM's own MC tests, read from the user's llvm-project checkout.
    if LLVM_MC_TESTS:
        valid = fixture_cases(llvm_fixture("xwchc-valid.s"), r"\s*qk\.c\.")
        bad_v = []
        for text, h in valid:
            want = (text.split()[0], *split_ops(text.split(None, 1)[1]))
            if xw_of(by_h.get(h)) != want:
                bad_v.append(f"{text} ({h:04x}): Ghidra {xw_of(by_h.get(h))}")
        comp_lines = llvm_fixture("xwchc-compress.s")
        comp = fixture_cases(comp_lines, r"\s*(lbu|lhu|sb|sh)\s")
        bad_c = []
        for text, h in comp:
            op, rest = text.split(None, 1)
            o = split_ops(rest)
            want = (f"qk.c.{op}" + ("sp" if o[2] == "sp" else ""), *o)
            if xw_of(by_h.get(h)) != want:
                bad_c.append(f"{text} ({h:04x}): Ghidra {xw_of(by_h.get(h))}")
        shas = ", ".join(f"{n} {hashlib.sha256((LLVM_MC_TESTS / n).read_bytes()).hexdigest()[:12]}"
                         for n in ("xwchc-valid.s", "xwchc-compress.s"))
        lines += [f"## Reference 1: LLVM's Xwchc MC tests (from the directory given by LLVM_MC_TESTS; sha256 "
                  f"{shas})", "",
                  f"- xwchc-valid.s: {len(valid) - len(bad_v)} of {len(valid)} encodings decode as the file says "
                  f"(expected 44)",
                  f"- xwchc-compress.s: {len(comp) - len(bad_c)} of {len(comp)} compressed encodings decode to the "
                  f"instruction written"]
        lines += [f"  - {x}" for x in (bad_v + bad_c)[:20]]
        if len(valid) != 44 or bad_v or not comp or bad_c:
            fails.append("LLVM MC tests")
    else:
        lines += ["## Reference 1: LLVM's Xwchc MC tests: NOT RUN (LLVM_MC_TESTS not set; the other references "
                  "below still apply)"]
    # xwchc-invalid.s's limits (registers x8-x15, offset ranges), exhaustively over Ghidra's decodes
    creg = set(ABI[8:16])
    n_qk, out_of_range = 0, []
    for h in parcels:
        x = xw_of(by_h[h])
        if not x:
            continue
        n_qk += 1
        form, reg, imm, base = x
        half = form in ("qk.c.lhu", "qk.c.sh", "qk.c.lhusp", "qk.c.shsp")
        sp = form.endswith("sp")
        lim = (30 if half else 15) if sp else (62 if half else 31)
        ok = reg in creg and (base == "sp" if sp else base in creg) and isinstance(imm, int) \
            and 0 <= imm <= lim and (imm % 2 == 0 or not half)
        if not ok:
            out_of_range.append(f"{h:04x} {x}")
    lines += ["", "## LLVM's operand limits (as in xwchc-invalid.s)", "",
              f"- {n_qk:,} parcels decode as qk.* (expected 8,704); {len(out_of_range)} outside LLVM's limits "
              f"(x8-x15; 0-31, even 0-62; sp forms base sp, 0-15, even 0-30)"]
    lines += [f"  - {x}" for x in out_of_range[:20]]
    if out_of_range or n_qk != 8704:
        fails.append("LLVM operand limits")

    # Reference 2: WCH's encoding table, transcribed.
    tab = {h: wch_table(h) for h in parcels}
    n_tab = sum(1 for v in tab.values() if v)
    dis_t = [h for h in parcels if tab[h] != xw_of(by_h[h])]
    lines += ["", "## Reference 2: WCH's XW encoding table (posted in LLVM discourse thread 79392), transcribed", "",
              f"- parcels the table defines as XW: {n_tab:,}; parcels where Ghidra differs from the table: {len(dis_t)}"]
    lines += [f"  - {h:04x}: table {tab[h]}, Ghidra {xw_of(by_h[h])}" for h in dis_t[:20]]
    if dis_t:
        fails.append("WCH table")

    # P-code: every qk.* decode loads/stores the right width at base+imm.
    bad_p = [h for h in parcels if xw_of(by_h[h]) and not pcode_ok(*xw_of(by_h[h]), by_h[h][4])]
    lines += ["", "## P-code of every qk.* decode", "",
              f"- {n_qk - len(bad_p):,} of {n_qk:,} have one LOAD (zero-extended into rd') or one STORE (rs2' low "
              f"byte/half) of the right width at base + offset"]
    lines += [f"  - {h:04x} {by_h[h][4]}" for h in bad_p[:5]]
    if bad_p:
        fails.append("p-code")

    # llvm-objdump over the whole 16-bit space.
    st, cl, ex, ru = compare(ghidra, llvm, starts)
    lines += [""] + report_compare(f"All {len(parcels):,} 16-bit parcels: Ghidra {LANG} vs llvm-objdump "
                                   f"{llvm_version()} --mattr={MATTR} -M no-aliases", st, cl, ex, ru)
    llvm_xw = {h for h in parcels if llvm_h[h][1] and llvm_h[h][1].startswith("qk.")}
    xw_space = {h for h in parcels if (h & 3, (h >> 13) & 7) in ((0, 1), (0, 5), (2, 1), (2, 5), (0, 4))}
    bad_xw = []
    for h in sorted(xw_space):
        g, l = by_h[h], llvm_h[h]
        gx = xw_of(g)
        lx = (l[1], *l[2]) if l[1] else None
        if gx != lx:
            bad_xw.append(f"{h:04x}: Ghidra {gx or g[2]}, llvm {lx}")
    lines += [f"XW space (q0 funct3 001/100/101, q2 funct3 001/101: {len(xw_space):,} parcels): llvm decodes "
              f"{len(llvm_xw):,} as qk.*; Ghidra agrees on every parcel of that space except {len(bad_xw)}"]
    lines += [f"  - {x}" for x in bad_xw[:20]]
    if len(llvm_xw) != 8704 or bad_xw:
        fails.append("llvm-objdump in the XW space")
    # where the table and llvm disagree (report, do not pick a side)
    tl = [h for h in parcels if tab[h] != ((llvm_h[h][1], *llvm_h[h][2]) if llvm_h[h][1] and
                                           llvm_h[h][1].startswith("qk.") else None)]
    lines += ["", f"WCH table vs llvm-objdump: {len(tl)} parcels disagree" +
              ("" if not tl else ": " + ", ".join(f"{h:04x}" for h in tl[:20]))]

    # Negative controls: each check must catch one planted wrong decode.
    h0 = 0xB43E                                   # qk.c.sh a5, 42(s0), decoded as c.fsdsp by the default language
    g = by_h[h0]
    planted = dict(by_h)
    planted[h0] = (g[0], g[1], g[2], [g[3][0], g[3][1] + 2, g[3][2]], g[4])
    caught = {
        "WCH table":sum(1 for h in parcels if tab[h] != xw_of(planted[h])) == 1,
        "llvm XW space": sum(1 for h in xw_space if xw_of(planted[h]) != ((llvm_h[h][1], *llvm_h[h][2])
                                                                         if llvm_h[h][1] else None)) == 1,
        "p-code": not pcode_ok(*xw_of(planted[h0]), g[4]),
    }
    lines += ["", f"Negative controls (planted {h0:04x} = {xw_of(g)} with the offset +2): " +
              ", ".join(f"{k} {'caught' if v else 'MISSED'}" for k, v in caught.items())]
    if not all(caught.values()):
        fails.append("a negative control was missed")

    # Before: Ghidra's own RV32 default language on the same parcels.
    before = collections.Counter()
    for h in sorted(llvm_xw):
        g0 = by_h0[h]
        before[g0[2] or "BAD"] += 1
    lines += ["", f"Before (Ghidra's {BASELINE} on the 8,704 XW parcels): " +
              ", ".join(f"{k} x{n:,}" for k, n in before.most_common())]

    lines += ["", "RESULT: " + ("PASS" if not fails else "FAIL: " + ", ".join(fails)) +
              f" (the XW checks; the {st.get('mismatch', 0)} mismatches outside the XW space are Ghidra's own RVC, "
              f"listed by class above)"]
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "sweep16.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if not fails else 1


# ----------------------------------------------------------------------------------------------- testobj

BASE_32 = """
lui a0, 0x12345
lui t6, 0xfffff
auipc a1, 0x80000
auipc zero, 1
jal ra, 2048
jal zero, -4
jal t0, 1048574
jalr ra, 0(a5)
jalr zero, 12(t0)
jalr zero, 0(ra)
jalr t1, -2048(s11)
beq a0, a1, 16
bne s0, s1, -16
blt t0, t1, 4094
bge a2, zero, -4096
bltu a3, a4, 8
bgeu zero, a5, 12
lb a0, -2048(sp)
lh a1, 2047(gp)
lw t3, 0(tp)
lbu s2, 13(s3)
lhu s4, -2(s5)
lbu a5, 5(s1)
lhu a4, 62(a0)
sb a6, -1(a7)
sh s6, 100(s7)
sw s8, -4(s9)
sb s0, 5(s1)
sh s0, 10(s1)
addi a0, a0, -2048
addi zero, zero, 0
addi a0, zero, 5
addi a1, a2, 0
addi t2, t2, 2047
slti a0, a1, -1
sltiu a0, a1, 1
xori a0, a1, -1
xori a0, a1, 255
ori a0, a1, 0x7ff
andi a0, a1, 0xff
slli a0, a1, 31
srli a0, a1, 1
srai a0, a1, 17
add a0, a1, a2
sub a0, a1, a2
sub a0, zero, a2
sll a0, a1, a2
slt a0, a1, a2
sltu a0, a1, a2
xor a0, a1, a2
srl a0, a1, a2
sra a0, a1, a2
or a0, a1, a2
and a0, a1, a2
fence rw, rw
fence iorw, iorw
fence r, w
fence w, r
ecall
ebreak
csrrw a0, mstatus, a1
csrrs a0, mtvec, zero
csrrc zero, mie, a2
csrrwi a0, mscratch, 5
csrrsi a0, mepc, 31
csrrci a0, mcause, 1
csrrs a0, 0x804, zero
mret
wfi
mul a0, a1, a2
mulh a0, a1, a2
mulhsu a0, a1, a2
mulhu a0, a1, a2
div a0, a1, a2
divu a0, a1, a2
rem a0, a1, a2
remu a0, a1, a2
lr.w a0, (a1)
lr.w.aq a0, (a1)
sc.w a0, a2, (a1)
sc.w.rl a0, a2, (a1)
amoswap.w a0, a2, (a1)
amoadd.w a0, a2, (a1)
amoxor.w a0, a2, (a1)
amoand.w a0, a2, (a1)
amoor.w a0, a2, (a1)
amomin.w a0, a2, (a1)
amomax.w a0, a2, (a1)
amominu.w a0, a2, (a1)
amomaxu.w.aqrl a0, a2, (a1)
"""

BASE_C = """
c.addi4spn a0, sp, 4
c.addi4spn s1, sp, 1020
c.lw a0, 0(a1)
c.lw s0, 124(a5)
c.sw a0, 64(s1)
c.nop
c.addi a0, -32
c.addi t0, 31
c.jal 2046
c.jal -2048
c.li a5, -1
c.li ra, 31
c.addi16sp sp, -512
c.addi16sp sp, 496
c.lui a5, 1
c.lui t0, 0xfffe0
c.lui s2, 31
c.srli a0, 1
c.srli s1, 31
c.srai a5, 7
c.andi a0, -1
c.andi s0, 15
c.sub a0, a1
c.xor s0, s1
c.or a4, a5
c.and a2, a3
c.j -2
c.j 2046
c.beqz a0, 254
c.beqz s1, -256
c.bnez a5, 2
c.slli a0, 1
c.slli t6, 31
c.lwsp a0, 0(sp)
c.lwsp ra, 252(sp)
c.jr ra
c.jr t0
c.mv a0, a1
c.mv s11, t6
c.ebreak
c.jalr a5
c.add a0, a1
c.add sp, t0
c.swsp a0, 0(sp)
c.swsp ra, 252(sp)
lbu a5, 5(s1)
lhu a4, 62(a0)
sb s0, 31(a0)
sh s0, 10(s1)
lbu a2, 15(sp)
lhu a3, 30(sp)
sb a4, 0(sp)
sh a5, 2(sp)
"""


def all_xw_lines() -> list[str]:
    regs = ABI[8:16]
    out = []
    for form, lim, step in (("qk.c.lbu", 31, 1), ("qk.c.sb", 31, 1), ("qk.c.lhu", 62, 2), ("qk.c.sh", 62, 2)):
        for r in regs:
            for b in regs:
                for imm in range(0, lim + 1, step):
                    out.append(f"{form} {r}, {imm}({b})")
    for form, lim, step in (("qk.c.lbusp", 15, 1), ("qk.c.sbsp", 15, 1), ("qk.c.lhusp", 30, 2),
                            ("qk.c.shsp", 30, 2)):
        for r in regs:
            for imm in range(0, lim + 1, step):
                out.append(f"{form} {r}, {imm}(sp)")
    return out


ZB_R = ["sh1add", "sh2add", "sh3add", "andn", "orn", "xnor", "max", "maxu", "min", "minu", "rol", "ror",
        "bclr", "bext", "binv", "bset", "clmul", "clmulh", "clmulr", "czero.eqz", "czero.nez"]
ZB_U = ["clz", "ctz", "cpop", "sext.b", "sext.h", "zext.h", "orc.b", "rev8"]
ZB_I = ["rori", "bclri", "bexti", "binvi", "bseti"]


def zb_lines() -> list[str]:
    """Every Zba/Zbb/Zbs/Zbc/Zicond form: R-type on three register sets, unary on two, immediates on every shamt."""
    out = []
    for op in ZB_R:
        for r in (("a0", "a1", "a2"), ("zero", "zero", "zero"), ("t6", "s11", "ra")):
            out.append(f"{op} {r[0]}, {r[1]}, {r[2]}")
    for op in ZB_U:
        for r in (("a0", "a1"), ("t6", "zero")):
            out.append(f"{op} {r[0]}, {r[1]}")
    for op in ZB_I:
        for sh in range(32):
            out.append(f"{op} a5, s1, {sh}")
    return out


def cmd_testobj(work: Path) -> int:
    work.mkdir(parents=True, exist_ok=True)
    lines = [f"# testobj: an LLVM MC test object, Ghidra vs llvm-objdump ({time.strftime('%Y-%m-%d %H:%M')})", ""]
    xw = all_xw_lines()
    zb = zb_lines()
    # .option push/pop, not norvc then rvc: in LLVM, norvc also drops Xwchc (it implies Zca) and rvc does not
    # bring it back.
    src = ["# generated by proof/xwproof.py testobj", "\t.text", "\t.option push", "\t.option norvc"]
    src += ["\t" + s for s in BASE_32.strip().splitlines()]
    src += ["\t" + s for s in zb]
    src += ["\t.option pop"]
    src += ["\t" + s for s in BASE_C.strip().splitlines()]
    src += ["\t" + s for s in xw]
    asm = work / "xw-test.s"
    asm.write_text("\n".join(src) + "\n", encoding="utf-8")
    obj = work / "xw-test.o"
    # The Windows LLVM 23.1.5 install has no llvm-mc.exe. `clang -cc1as` is the same MC assembler with the same
    # options (triple, one -target-feature per --mattr entry, no linker relaxation).
    feats = []
    for f in MATTR.split(","):
        feats += ["-target-feature", f]
    run([tool("clang.exe"), "-cc1as", "-triple", "riscv32-unknown-elf", *feats, "-filetype", "obj", "-o", obj, asm])
    relocs = run([tool("llvm-objdump.exe"), "-r", obj])
    if "RELOCATION RECORDS" in relocs:
        raise CouldNotCheck("the test object has relocations; Ghidra would patch its bytes")
    llvm_txt = run([tool("llvm-objdump.exe"), "-d", "-M", "no-aliases", f"--mattr={MATTR}", obj])
    (work / "xw-test.llvm.txt").write_text(llvm_txt, encoding="utf-8")
    llvm = parse_llvm(llvm_txt)
    tsv = work / "xw-test.ghidra.tsv"
    ghidra_dump(work, obj, tsv, LANG, raw=False)                     # the ELF loader, as a user would
    lang, ghidra, starts = parse_ghidra(tsv)
    if lang != LANG:
        raise CouldNotCheck(f"Ghidra used {lang}, not {LANG}")
    st, cl, ex, ru = compare(ghidra, llvm, starts)
    n_src = len(BASE_32.strip().splitlines()) + len(zb) + len(BASE_C.strip().splitlines()) + len(xw)
    zb_seen = collections.Counter(v[1] for v in llvm.values() if v[1] in set(ZB_R + ZB_U + ZB_I))
    lines += [f"- source: {asm.name}, {n_src:,} instructions ({len(xw):,} qk.* written out, every register and "
              f"offset; {len(BASE_32.strip().splitlines())} RV32IMA + Zicsr lines and {len(zb)} Zba/Zbb/Zbs/Zbc/"
              f"Zicond lines ({len(zb_seen)} mnemonics, every shamt) under .option norvc; "
              f"{len(BASE_C.strip().splitlines())} C lines, 8 of them lbu/lhu/sb/sh that llvm-mc compresses to XW)",
              f"- assembled: clang -cc1as (LLVM {llvm_version()}'s MC assembler; this install has no llvm-mc.exe), "
              f"features {MATTR}; no relocations; imported with Ghidra's ELF "
              f"loader, language pinned to {LANG}", ""]
    lines += report_compare("Ghidra vs llvm-objdump -M no-aliases", st, cl, ex, ru)
    ok = st.get("mismatch", 0) == 0 and st.get("llvm XW matched", 0) == len(xw) + 8 \
        and st.get("compared", 0) == n_src and sum(zb_seen.values()) == len(zb) \
        and len(zb_seen) == len(ZB_R + ZB_U + ZB_I)
    lines += [f"RESULT: {'PASS' if ok else 'FAIL'} (expects {n_src:,} compared, {len(xw) + 8:,} XW matched, "
              f"0 mismatches)"]
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "testobj.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok else 1


# ----------------------------------------------------------------------------------------------- libwchnet

def ar_members(data: bytes):
    if not data.startswith(b"!<arch>\n"):
        raise CouldNotCheck("not an ar archive")
    pos, longnames, out = 8, b"", []
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("ascii").strip()
        size = int(hdr[48:58].decode("ascii").strip())
        body = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
        if name == "//":
            longnames = body
            continue
        if name in ("/", "/SYM64/"):
            continue
        if name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            name = longnames[off:longnames.index(b"\n", off)].decode("ascii")
        out.append((name.rstrip("/"), body))
    return out


def elf_exec_sections(obj: bytes):
    if obj[:4] != b"\x7fELF" or obj[4] != 1 or obj[5] != 1:
        raise CouldNotCheck("not an ELF32 little-endian object")
    e_shoff, = struct.unpack_from("<I", obj, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", obj, 0x2E)
    shdrs = [struct.unpack_from("<IIIIIIIIII", obj, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    strtab = shdrs[e_shstrndx]
    names = obj[strtab[4]:strtab[4] + strtab[5]]
    out = []
    for sh in shdrs:
        name = names[sh[0]:names.index(b"\0", sh[0])].decode("ascii")
        if sh[1] == 1 and sh[2] & 0x4 and sh[5]:        # SHT_PROGBITS, SHF_EXECINSTR, non-empty
            out.append((name, obj[sh[4]:sh[4] + sh[5]]))
    return out


def libwchnet_bytes() -> bytes:
    if LIBWCHNET is None:
        raise Skipped("LIBWCHNET is not set (WCH's libwchnet.a from the CH32V407 EVT V1.4; not in this repository)")
    if not LIBWCHNET.exists():
        raise CouldNotCheck(f"LIBWCHNET={LIBWCHNET} does not exist")
    data = LIBWCHNET.read_bytes()
    if hashlib.sha256(data).hexdigest() != LIBWCHNET_SHA:
        raise CouldNotCheck("libwchnet.a is not the recorded file (sha256 differs)")
    return data


def cmd_libwchnet(work: Path) -> int:
    work.mkdir(parents=True, exist_ok=True)
    lines = [f"# libwchnet: WCH's networking blob, every instruction both ways ({time.strftime('%Y-%m-%d %H:%M')})", ""]
    data = libwchnet_bytes()
    members = ar_members(data)
    uniq = {}
    for name, body in members:
        if name in uniq and uniq[name] != body:
            raise CouldNotCheck(f"member {name} appears twice with different bytes")
        uniq[name] = body
    mdir = work / "members"
    mdir.mkdir(exist_ok=True)
    blob = bytearray()
    regions = []
    llvm = {}
    n_sections = 0
    for name, body in sorted(uniq.items()):
        p = mdir / name
        p.write_bytes(body)
        txt = run([tool("llvm-objdump.exe"), "-d", "-M", "no-aliases", f"--mattr={MATTR}", p])
        (mdir / (name + ".llvm.txt")).write_text(txt, encoding="utf-8")
        llvm.update(parse_llvm(txt, section_map=lambda s, n=name: f"{n}:{s}"))
        for sec, b in elf_exec_sections(body):
            while len(blob) % 4:
                blob += b"\0"
            regions.append((f"{name}:{sec}", len(blob), len(blob) + len(b)))
            blob += b
            n_sections += 1
    blob_p = work / "libwchnet-text.bin"
    blob_p.write_bytes(bytes(blob))
    reg_p = work / "libwchnet-text.regions.tsv"
    reg_p.write_text("".join(f"{n}\t{s:x}\t{e:x}\n" for n, s, e in regions), encoding="utf-8")
    llvm_xw = collections.Counter(v[1] for v in llvm.values() if v[1] and v[1].startswith("qk."))
    lines += [f"- libwchnet.a, CH32V407 EVT V1.4 ({len(data):,} B, sha256 {LIBWCHNET_SHA[:8]}…, matched): "
              f"{len(members)} archive "
              f"entries, {len(uniq)} distinct members (each stored twice, byte-identical), {n_sections} executable "
              f"sections, {len(blob):,} bytes of code",
              f"- llvm-objdump {llvm_version()} --mattr={MATTR} -M no-aliases, per member: {len(llvm):,} "
              f"instructions, {sum(llvm_xw.values()):,} XW (" +
              ", ".join(f"{k} {n}" for k, n in sorted(llvm_xw.items())) + ")",
              f"- Ghidra: the same section bytes, unrelocated, imported raw and swept section by section", ""]

    tsv = work / "libwchnet.ghidra.tsv"
    ghidra_dump(work, blob_p, tsv, LANG, raw=True, regions=reg_p)
    lang, ghidra, starts = parse_ghidra(tsv)
    if lang != LANG:
        raise CouldNotCheck(f"Ghidra used {lang}, not {LANG}")
    st, cl, ex, ru = compare(ghidra, llvm, starts)
    lines += report_compare(f"Ghidra {LANG} vs llvm-objdump", st, cl, ex, ru)

    tsv0 = work / "libwchnet.default.tsv"
    ghidra_dump(work, blob_p, tsv0, BASELINE, raw=True, regions=reg_p)
    _, ghidra0, starts0 = parse_ghidra(tsv0)
    st0, cl0, ex0, ru0 = compare(ghidra0, llvm, starts0)
    lines += report_compare(f"Before: Ghidra {BASELINE} vs llvm-objdump (the same bytes)", st0, cl0, {}, ru0)

    xw_total = sum(llvm_xw.values())
    ok = st.get("mismatch", 0) == 0 and xw_total == 1160 and st.get("llvm XW matched", 0) == 1160
    lines += [f"RESULT: {'PASS' if ok else 'FAIL'} (expects 1,160 XW, all matched, 0 mismatches)"]
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "libwchnet.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok else 1


# ----------------------------------------------------------------------------------------------- decompile (extra)

def cmd_decompile(work: Path) -> int:
    """Not one of the three proofs: libwchnet's 28 objects through Ghidra's ELF loader, auto-analysis and the
    decompiler, once per language. Soft-float code has no float types, so any in the C come from misdecodes."""
    work.mkdir(parents=True, exist_ok=True)
    data = libwchnet_bytes()
    objs = work / "objs"
    objs.mkdir(exist_ok=True)
    for name, body in dict(ar_members(data)).items():
        (objs / name).write_bytes(body)
    lines = [f"# decompile: libwchnet.a's objects through Ghidra's decompiler ({time.strftime('%Y-%m-%d %H:%M')})", ""]
    ok_all = True
    per_lang = {}
    for lang in (LANG, BASELINE):
        out = work / f"decompile-{lang.split(':')[-1]}.tsv"
        if out.exists():
            out.unlink()
        wait_for_cpu()
        proj = work / "ghidra-project"
        proj.mkdir(exist_ok=True)
        cmd = [proj, f"d{os.getpid()}_{int(time.time())}",
               "-import", objs, "-processor", lang, "-cspec", "gcc", "-max-cpu", "2",
               "-scriptPath", SCRIPTS, "-postScript", "DecompileCheck.java", out, "-deleteProject"]
        t0 = time.time()
        r = headless(cmd, work / f"decompile-{lang.split(':')[-1]}.headless.log")
        if r.returncode != 0 or not out.exists():
            raise CouldNotCheck(f"headless decompile run for {lang} failed (exit {r.returncode})")
        rows = [ln.split("\t") for ln in out.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
        # lwIP's own identifiers in_addr / in_addr_t match the in_* pattern; they are not registers.
        for r_ in rows:
            names_ = [n for n in r_[5].split(",") if n and n not in ("in_addr", "in_addr_t")]
            r_[4], r_[5] = str(len(names_)), ",".join(names_)
        langs = {ln.split("\t")[2] for ln in out.read_text(encoding="utf-8").splitlines() if ln.startswith("# lang")}
        progs = {r_[0] for r_ in rows}
        n_ok = sum(1 for r_ in rows if r_[2] == "ok")
        n_float = sum(1 for r_ in rows if r_[3] == "float")
        n_unset = sum(int(r_[4]) for r_ in rows)
        f_unset = sum(1 for r_ in rows if int(r_[4]))
        names = collections.Counter(n.split("_", 1)[1] for r_ in rows for n in r_[5].split(",") if n)
        per_lang[lang] = {(r_[0], r_[1]): int(r_[4]) for r_ in rows}
        lines.append(f"- {lang}: {len(progs)} objects with functions, {len(rows)} functions, {n_ok} decompiled, "
                     f"{len(rows) - n_ok} failed; {n_float} with float/double types; {f_unset} functions show "
                     f"{n_unset} in_*/unaff_* (read-before-set) registers ("
                     + ", ".join(f"{k} {v}" for k, v in names.most_common(8))
                     + f"); languages used: {', '.join(sorted(langs))}; {time.time() - t0:.0f} s")
        if lang == LANG and (n_ok != len(rows) or n_float or langs != {LANG}):
            ok_all = False
    xw, df = per_lang[LANG], per_lang[BASELINE]
    better = sum(1 for k in xw if k in df and xw[k] < df[k])
    worse = sum(1 for k in xw if k in df and xw[k] > df[k])
    lines += ["", f"Per function, read-before-set registers: fewer with {LANG} in {better}, more in {worse}, "
              f"the same in {len(xw) - better - worse}."]
    if worse:
        ok_all = False
    lines += ["", "RESULT: " + ("PASS" if ok_all else "FAIL") + f" ({LANG}: every function decompiles, no float "
              f"types, and no function has more read-before-set registers than under {BASELINE})"]
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "decompile.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok_all else 1


# ----------------------------------------------------------------------------------------------- sweep32

WCH_LINE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8}|[0-9a-f]{4})\s+(.*)$")
NEW_MNEMS = set(ZB_R + ZB_U + ZB_I) | WCH_CUSTOM | {"qk.delay"}


def parse_wch(text: str) -> dict:
    """WCH (GNU) objdump -d output -> {off: (bytes, mnem, ops)}; mnem None for .insn (undecoded)."""
    out = {}
    for line in text.splitlines():
        m = WCH_LINE.match(line)
        if not m:
            continue
        off, b, rest = int(m.group(1), 16), word_to_bytes(m.group(2)), m.group(3).strip()
        mnem, _, ops = rest.partition("\t")
        mnem = mnem.strip().lower()
        ops = re.sub(r"\s*#.*$", "", ops)
        if not mnem or mnem.startswith(".insn") or mnem.startswith(".word") or mnem == "unimp":
            out[off] = (b, None, [])
        else:
            out[off] = (b, mnem, split_ops(ops))
    return out


def rm_delay(w: int):
    """The delay instruction, transcribed from the RM V1.3 table (9.2.1.3, p.61). This language's operand names."""
    if w & 0x7F != 0x0B or (w >> 12) & 7 != 1:
        return None
    names = {1: "load", 2: "store", 3: "ldst", 4: "delay", 6: "all", 7: "csr"}
    m = (w >> 9) & 7
    if m not in names:
        return None
    return "qk.delay", [names[m], ABI[(w >> 15) & 31], w >> 20, (w >> 8) & 1, (w >> 7) & 1]


def sweep32_words() -> list[int]:
    import random
    words = []
    for f7 in range(128):                                       # OP: every funct7 x funct3, three register sets
        for f3 in range(8):
            for rd, rs1, rs2 in ((10, 11, 12), (0, 0, 0), (31, 27, 1)):
                words.append(f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | 0x33)
    for f3 in range(8):                                          # OP-IMM: every funct3 x imm12
        for imm in range(4096):
            words.append(imm << 20 | 11 << 15 | f3 << 12 | 10 << 7 | 0x13)
    for opc, rs1, rs2 in ((0x0B, 11, 12), (0x0F, 10, 11)):       # custom-0, MISC-MEM: funct3 x [31:25] x [11:7]
        for f3 in range(8):
            for hi in range(128):
                for lo in range(32):
                    words.append(hi << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | lo << 7 | opc)
    rnd = random.Random(20261112)                                # plus random words in the same four opcodes
    for _ in range(40000):
        words.append((rnd.getrandbits(32) & ~0x7F) | rnd.choice((0x33, 0x13, 0x0B, 0x0F)))
    return words


def cmd_sweep32(work: Path) -> int:
    wch_tool("riscv32-wch-elf-objdump.exe")              # Skipped without WCH's toolchain, before any work
    work.mkdir(parents=True, exist_ok=True)
    lines = [f"# sweep32: 32-bit words in OP, OP-IMM, custom-0 and MISC-MEM ({time.strftime('%Y-%m-%d %H:%M')})", ""]
    words = sweep32_words()
    blob = work / "words32.bin"
    blob.write_bytes(b"".join(struct.pack("<I", w) for w in words))
    regions = work / "words32.regions.tsv"
    regions.write_text("".join(f"w{i}\t{4 * i:x}\t{4 * i + 4:x}\n" for i in range(len(words))), encoding="utf-8")
    # llvm-objdump on the raw words
    elf = work / "words32.o"
    run([tool("llvm-objcopy.exe"), "-I", "binary", "-O", "elf32-littleriscv",
         "--rename-section=.data=.text,alloc,load,readonly,code,contents", blob, elf])
    llvm_txt = run([tool("llvm-objdump.exe"), "-d", "-M", "no-aliases", f"--mattr={MATTR}", elf])
    (work / "words32.llvm.txt").write_text(llvm_txt, encoding="utf-8")
    llvm = {off // 4: v for (_, off), v in parse_llvm(llvm_txt).items()}
    # WCH's objdump: the same words through WCH's assembler (.insn) with an arch attribute, then disassembled
    asm = work / "words32.wch.s"
    asm.write_text(f'\t.attribute arch, "{WCH_ARCH}"\n\t.text\n' +
                   "".join(f"\t.insn 4, {w:#010x}\n" for w in words), encoding="utf-8")
    wobj = work / "words32.wch.o"
    run([wch_tool("riscv32-wch-elf-as.exe"), f"-march={WCH_ARCH}", "-mno-relax", "-o", wobj, asm])
    wch_txt = run([wch_tool("riscv32-wch-elf-objdump.exe"), "-d", "-M", "no-aliases", wobj])
    (work / "words32.wch.txt").write_text(wch_txt, encoding="utf-8")
    wch = {off // 4: v for off, v in parse_wch(wch_txt).items()}
    if len(llvm) != len(words) or len(wch) != len(words):
        raise CouldNotCheck(f"{len(words)} words, llvm-objdump gave {len(llvm)}, WCH objdump {len(wch)}")
    for i, w in enumerate(words):
        if bytes.fromhex(llvm[i][0]) != struct.pack("<I", w) or bytes.fromhex(wch[i][0]) != struct.pack("<I", w):
            raise CouldNotCheck(f"word {i} ({w:08x}): the objdumps are out of step")
    tsv = work / "words32.ghidra.tsv"
    ghidra_dump(work, blob, tsv, LANG, raw=True, regions=regions)
    lang, gh, starts = parse_ghidra(tsv)
    if lang != LANG:
        raise CouldNotCheck(f"Ghidra used {lang}, not {LANG}")
    tsv0 = work / "words32.default.tsv"
    ghidra_dump(work, blob, tsv0, BASELINE, raw=True, regions=regions)
    _, gh0, _ = parse_ghidra(tsv0)

    def g_of(table, i):
        e = table.get((f"w{i}", 0))
        if e is None or e[0] != 4 or e[2] is None or e[2].startswith("custom"):
            return None                     # BAD, a 2-byte decode, or riscv.custom.sinc's placeholder
        m, o, _ = canon(e[2], e[3], 4 * i)
        return m, o

    st = collections.Counter()
    by_src = collections.Counter()
    classes = collections.defaultdict(collections.Counter)
    examples = {}
    new_seen = collections.Counter()
    placeholders = collections.Counter()
    bin_vs = collections.Counter()
    bin_classes = collections.Counter()
    for i, w in enumerate(words):
        l, b = llvm[i], wch[i]
        ref, src = None, "none"
        if l[1]:
            ref, src = llvm_canon(l[1], l[2], 4), "llvm-objdump"
        elif b[1] in WCH_CUSTOM:
            ref, src = (b[1], b[2]), "WCH objdump"
        elif rm_delay(w):
            ref, src = rm_delay(w), "RM V1.3 table"
        g = g_of(gh, i)
        e = gh.get((f"w{i}", 0))
        if e and e[2] and e[2].startswith("custom"):
            placeholders[e[2]] += 1
        by_src[src] += 1
        if ref and ref[0] in NEW_MNEMS:
            new_seen[ref[0]] += 1
        # the second oracle: GNU binutils (WCH's) on the words llvm decodes
        if l[1] and b[1]:
            bb = llvm_canon(b[1], b[2], 4)
            if bb == tuple(ref) or (bb[0], bb[1]) == (ref[0], ref[1]):
                bin_vs["agree"] += 1
            else:
                bin_vs["differ"] += 1
                bin_classes[f"llvm {ref[0]} / binutils {bb[0]}"] += 1
        elif l[1] and not b[1]:
            bin_vs["llvm only"] += 1
            bin_classes[f"binutils .insn for llvm {l[1]}"] += 1
        elif b[1] and not l[1] and b[1] not in WCH_CUSTOM:
            bin_vs["binutils only"] += 1
            bin_classes[f"binutils {b[1]} / llvm <unknown>"] += 1
        if ref is None and g is None:
            st["match (all undecoded)"] += 1
            continue
        if ref is None:
            cls = "Ghidra decodes, no reference does"
        elif g is None:
            cls = f"{src} decodes, Ghidra does not"
        elif (g[0], list(g[1])) == (ref[0], list(ref[1])):
            st[f"match ({src})"] += 1
            continue
        else:
            cls = "mnemonic differs" if g[0] != ref[0] else "operands differ"
        new = (ref and ref[0] in NEW_MNEMS) or (g and g[0] in NEW_MNEMS)
        key = ("NEW " if new else "base ") + cls
        st["mismatch, new instructions" if new else "mismatch, inherited base ISA"] += 1
        classes[key][f"{g[0] if g else '-'} / {ref[0] if ref else '-'}"] += 1
        examples.setdefault(f"{key}: {g[0] if g else '-'} / {ref[0] if ref else '-'}",
                            (f"{w:08x}", (e[2], e[3]) if e else None, ref))
    lines += [f"- {len(words):,} words: OP every funct7 x funct3 x 3 register sets (3,072); OP-IMM every funct3 x "
              f"imm12 (32,768); custom-0 and MISC-MEM every funct3 x bits 31:25 x bits 11:7 (32,768 each); 40,000 "
              f"random words in those opcodes (seed 20261112)",
              f"- references: llvm-objdump {llvm_version()} --mattr={MATTR} -M no-aliases; WCH's objdump "
              f"(GCC 15 toolchain v1.4, -M no-aliases, arch attribute {WCH_ARCH}) for {', '.join(sorted(WCH_CUSTOM))}; "
              f"the delay instruction from {RM_DELAY}",
              f"- reference per word: " + ", ".join(f"{k} {n:,}" for k, n in by_src.most_common()),
              f"- new-instruction words met (by reference): " + ", ".join(f"{k} {n:,}" for k, n in sorted(new_seen.items())),
              f"- Ghidra's riscv.custom.sinc placeholders (counted as undecoded): " +
              (", ".join(f"{k} {n:,}" for k, n in placeholders.most_common()) or "none"), ""]
    lines.append(f"## Ghidra {LANG} vs the references")
    lines.append("")
    for k in sorted(st):
        lines.append(f"- {k}: {st[k]:,}")
    if classes:
        lines += ["", "Mismatches by class (Ghidra / reference):"]
        for cls, ctr in sorted(classes.items()):
            lines.append(f"- {cls}: {sum(ctr.values()):,}  (" + ", ".join(f"{k} x{n}" for k, n in ctr.most_common(12))
                         + (", ..." if len(ctr) > 12 else "") + ")")
        lines += ["", "One example per class (word, Ghidra, reference):"]
        lines += [f"- {k}: {v}" for k, v in list(examples.items())[:40]]
    lines += ["", "## The second oracle: WCH's GNU objdump on the words llvm decodes (reported, not a gate)", "",
              "- " + ", ".join(f"{k} {n:,}" for k, n in bin_vs.most_common())]
    lines += [f"  - {k} x{n}" for k, n in bin_classes.most_common(15)]

    # Before: Ghidra's default language, and the old draft names
    before = collections.Counter()
    for i, w in enumerate(words):
        l = llvm[i]
        ref = (l[1] if l[1] else wch[i][1] if wch[i][1] in WCH_CUSTOM else ("qk.delay" if rm_delay(w) else None))
        if ref in NEW_MNEMS:
            e = gh0.get((f"w{i}", 0))
            before[(ref, e[2] if e and e[2] else "BAD")] += 1
    wrong = sum(n for (r, g), n in before.items() if r != g)
    lines += ["", f"Before: Ghidra's {BASELINE} on the {sum(before.values()):,} new-instruction words: {wrong:,} "
              f"not decoded as the reference says. By (reference, Ghidra): " +
              ", ".join(f"{r}->{g} x{n}" for (r, g), n in before.most_common(25))]

    # negative control: one planted wrong operand on a new instruction must be caught
    caught = None
    for i, w in enumerate(words):
        if wch[i][1] == "mcpy":
            e = gh[(f"w{i}", 0)]
            planted = (e[2], [e[3][1], e[3][0], e[3][2]])
            ref = (wch[i][1], wch[i][2])
            caught = planted != (ref[0], list(ref[1]))
            lines += ["", f"Negative control: word {w:08x} (mcpy) with rs1/rs2 swapped in Ghidra's text: "
                          f"{'caught' if caught else 'MISSED'}"]
            break
    new_bad = st.get("mismatch, new instructions", 0)
    ok = new_bad == 0 and caught and all(new_seen.get(m, 0) for m in NEW_MNEMS)
    lines += ["", f"RESULT: {'PASS' if ok else 'FAIL'} (0 mismatches on the new instructions, each of the "
                  f"{len(NEW_MNEMS)} new mnemonics met; {st.get('mismatch, inherited base ISA', 0):,} inherited "
                  f"base-ISA differences listed above)"]
    if not all(new_seen.get(m, 0) for m in NEW_MNEMS):
        lines.append("  never met: " + ", ".join(sorted(m for m in NEW_MNEMS if not new_seen.get(m))))
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "sweep32.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok else 1


# ----------------------------------------------------------------------------------------------- emu

M32 = 0xFFFFFFFF


def _s32(x):
    return x - (1 << 32) if x & 0x80000000 else x


def _rol(a, s):
    s &= 31
    return ((a << s) | (a >> ((32 - s) & 31))) & M32 if s else a


def _ror(a, s):
    s &= 31
    return ((a >> s) | (a << ((32 - s) & 31))) & M32 if s else a


def _sext(a, bits):
    a &= (1 << bits) - 1
    return (a - (1 << bits) if a >> (bits - 1) else a) & M32


# Reference models from the ratified specifications (Bitmanip 1.0.0 chapter 2, Zicond 1.0.0), written
# independently of the SLEIGH (Python integers, no shared code).
REF_R = {
    "sh1add": lambda a, b: ((a << 1) + b) & M32, "sh2add": lambda a, b: ((a << 2) + b) & M32,
    "sh3add": lambda a, b: ((a << 3) + b) & M32,
    "andn": lambda a, b: a & ~b & M32, "orn": lambda a, b: (a | ~b) & M32, "xnor": lambda a, b: ~(a ^ b) & M32,
    "max": lambda a, b: a if _s32(a) >= _s32(b) else b, "maxu": lambda a, b: max(a, b),
    "min": lambda a, b: a if _s32(a) <= _s32(b) else b, "minu": lambda a, b: min(a, b),
    "rol": lambda a, b: _rol(a, b), "ror": lambda a, b: _ror(a, b),
    "bclr": lambda a, b: a & ~(1 << (b & 31)) & M32, "bext": lambda a, b: (a >> (b & 31)) & 1,
    "binv": lambda a, b: a ^ (1 << (b & 31)), "bset": lambda a, b: a | (1 << (b & 31)),
    "czero.eqz": lambda a, b: 0 if b == 0 else a, "czero.nez": lambda a, b: a if b == 0 else 0,
}
REF_U = {
    "clz": lambda a: 32 - a.bit_length(), "ctz": lambda a: 32 if a == 0 else (a & -a).bit_length() - 1,
    "cpop": lambda a: bin(a).count("1"), "sext.b": lambda a: _sext(a, 8), "sext.h": lambda a: _sext(a, 16),
    "zext.h": lambda a: a & 0xFFFF,
    "orc.b": lambda a: sum((0xFF << (8 * i)) for i in range(4) if (a >> (8 * i)) & 0xFF),
    "rev8": lambda a: int.from_bytes(a.to_bytes(4, "little"), "big"),
}
REF_I = {"rori": _ror, "bclri": REF_R["bclr"], "bexti": REF_R["bext"], "binvi": REF_R["binv"],
         "bseti": REF_R["bset"]}
NAMED = {"clmul", "clmulh", "clmulr"}
# encodings: (opcode, funct3, funct7 or imm[11:0] or None, rs2 field or None)
ENC = {"sh1add": (0x33, 2, 0x10), "sh2add": (0x33, 4, 0x10), "sh3add": (0x33, 6, 0x10),
       "andn": (0x33, 7, 0x20), "orn": (0x33, 6, 0x20), "xnor": (0x33, 4, 0x20),
       "max": (0x33, 6, 0x05), "maxu": (0x33, 7, 0x05), "min": (0x33, 4, 0x05), "minu": (0x33, 5, 0x05),
       "rol": (0x33, 1, 0x30), "ror": (0x33, 5, 0x30), "bclr": (0x33, 1, 0x24), "bext": (0x33, 5, 0x24),
       "binv": (0x33, 1, 0x34), "bset": (0x33, 1, 0x14), "czero.eqz": (0x33, 5, 0x07), "czero.nez": (0x33, 7, 0x07),
       "clmul": (0x33, 1, 0x05), "clmulr": (0x33, 2, 0x05), "clmulh": (0x33, 3, 0x05)}
ENC_U = {"clz": (0x13, 1, 0x600), "ctz": (0x13, 1, 0x601), "cpop": (0x13, 1, 0x602), "sext.b": (0x13, 1, 0x604),
         "sext.h": (0x13, 1, 0x605), "orc.b": (0x13, 5, 0x287), "rev8": (0x13, 5, 0x698),
         "zext.h": (0x33, 4, 0x080)}
ENC_I = {"rori": (5, 0x30), "bclri": (1, 0x24), "bexti": (5, 0x24), "binvi": (1, 0x34), "bseti": (1, 0x14)}
# the silicon cases (measured on a CH32V467 evaluation board, 8 Nov 2026): (name, end, src, dst, rs1_after, rs3_after)
MCPY_SILICON = [("mcpy.order", 0x20000d40, 0x20000c40, 0x20002c80, 0x20000d40, 0x20002d80),
                ("mcpy.4096", 0x20001c40, 0x20000c40, 0x20002c80, 0x20001c40, 0x20003c80),
                ("mcpy.unaligned1001", 0x2000102a, 0x20000c41, 0x20002c83, 0x2000102a, 0x2000306c),
                ("mcpy.1", 0x20000c46, 0x20000c45, 0x20002c89, 0x20000c46, 0x20002c8a),
                ("mcpy.zero", 0x20000c40, 0x20000c40, 0x20002c80, 0x20000c40, 0x20002c80),
                ("mcpy.flashsrc", 0x00004b1c, 0x0000471c, 0x20002c80, 0x00004b1c, 0x20003080),
                ("mcpy.irq8192", 0x20002c40, 0x20000c40, 0x20002c80, 0x20002c40, 0x20004c80)]


def emu_cases():
    """-> (words, cases); each case (id, word index, a0, a1, a2, expect) with expect a function of the result."""
    import random
    rnd = random.Random(1112)
    edge = [0, 1, 2, 31, 32, 33, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFF, 0x12345678, 0x00FF00FF, 0x0000FF00]
    pairs = [(a, b) for a in edge for b in edge] + [(rnd.getrandbits(32), rnd.getrandbits(32)) for _ in range(120)]
    words, cases = [], []
    sentinel = 0xDEADBEEF

    def add_word(name, w):
        words.append((name, w))
        return len(words) - 1

    for name, (opc, f3, f7) in ENC.items():
        wi = add_word(name, f7 << 25 | 12 << 20 | 11 << 15 | f3 << 12 | 10 << 7 | opc)
        for a, b in pairs:
            if name in NAMED:
                cases.append((f"{name}:{a:x}:{b:x}", wi, sentinel, a, b,
                              ("named", [f"{name}({a:x},{b:x})->a0"], {"a0": 0x5EED0000, "a1": a, "a2": b})))
            else:
                cases.append((f"{name}:{a:x}:{b:x}", wi, sentinel, a, b,
                              ("value", [], {"a0": REF_R[name](a, b), "a1": a, "a2": b})))
    for name, (opc, f3, imm) in ENC_U.items():
        rs2 = 0
        wi = add_word(name, imm << 20 | 11 << 15 | f3 << 12 | 10 << 7 | opc)
        for a, b in pairs[:60]:
            cases.append((f"{name}:{a:x}:{b:x}", wi, sentinel, a, b,
                          ("value", [], {"a0": REF_U[name](a), "a1": a, "a2": b})))
    for name, (f3, hi) in ENC_I.items():
        for sh in range(32):
            wi = add_word(f"{name} {sh}", hi << 25 | sh << 20 | 11 << 15 | f3 << 12 | 10 << 7 | 0x13)
            for a in edge + [rnd.getrandbits(32) for _ in range(8)]:
                cases.append((f"{name}:{sh}:{a:x}", wi, sentinel, a, 0x5A5A,
                              ("value", [], {"a0": REF_I[name](a, sh), "a1": a, "a2": 0x5A5A})))
    # mcpy a0, a1, a2 = rs1 end, rs2 src, rs3 dst (0x60b5700f, WCH's assembler)
    wi = add_word("mcpy", 0x60B5700F)
    for nm, end, src, dst, rs1_after, rs3_after in MCPY_SILICON:
        cases.append((f"silicon {nm}", wi, end, src, dst,
                      ("named", [f"mcpy({dst:x},{src:x},{end:x})", f"mcpy_src_after({src:x},{end:x})->a1"],
                       {"a0": rs1_after, "a1": 0x5EED0001, "a2": rs3_after})))
    for nm, w, imm in (("mrsl", 0x06C5850B, 0), ("mrslu", 0x2CC5850B, 5), ("wexti", 0x28C5850B, 5),
                       ("mrsl", 0xFEC5850B, 31)):
        wi = add_word(f"{nm} {imm}", w)
        for a, b in pairs[:20]:
            cases.append((f"{nm}:{imm}:{a:x}:{b:x}", wi, sentinel, a, b,
                          ("named", [f"{nm}({a:x},{b:x},{imm:x})->a0"], {"a0": 0x5EED0000, "a1": a, "a2": b})))
    for match, imm, div, sel in ((6, 0x64, 0, 0), (1, 0x7FF, 1, 0), (7, 0xFFF, 0, 1), (4, 1, 1, 1)):
        w = imm << 20 | 11 << 15 | 1 << 12 | match << 9 | div << 8 | sel << 7 | 0x0B
        wi = add_word(f"qk.delay {match}", w)
        for a in (0, 500, 0xFFFFFFFF):
            cases.append((f"qk.delay:{match}:{imm:x}:{div}:{sel}:{a:x}", wi, sentinel, a, 0x77,
                          ("named", [f"qk_delay({match:x},{a:x},{imm:x},{div:x},{sel:x})"],
                           {"a0": sentinel, "a1": a, "a2": 0x77})))
    return words, cases


def emu_judge(cases, results):
    bad = []
    for cid, wi, a0, a1, a2, (kind, events, regs) in cases:
        r = results.get(cid)
        if r is None:
            bad.append((cid, "no result"))
            continue
        if r[0].startswith("ERROR"):
            bad.append((cid, r[0]))
            continue
        got = {"a0": int(r[0], 16), "a1": int(r[1], 16), "a2": int(r[2], 16)}
        ev = [e for e in r[4].split(";") if e] if len(r) > 4 else []
        if got != regs or ev != events or int(r[3], 16) != 4 * wi + 4:
            bad.append((cid, f"got {({k: hex(v) for k, v in got.items()})} events {ev} pc {r[3]}; want "
                             f"{({k: hex(v) for k, v in regs.items()})} events {events}"))
    return bad


def cmd_emu(work: Path) -> int:
    wch_tool("riscv32-wch-elf-objdump.exe")              # Skipped without WCH's toolchain, before any work
    work.mkdir(parents=True, exist_ok=True)
    lines = [f"# emu: p-code run in Ghidra's emulator against reference models ({time.strftime('%Y-%m-%d %H:%M')})", ""]
    words, cases = emu_cases()
    blob = work / "emu-words.bin"
    blob.write_bytes(b"".join(struct.pack("<I", w) for _, w in words))
    # each test word must be the instruction its name says, by llvm-objdump (standard) or WCH's objdump (custom)
    elf = work / "emu-words.o"
    run([tool("llvm-objcopy.exe"), "-I", "binary", "-O", "elf32-littleriscv",
         "--rename-section=.data=.text,alloc,load,readonly,code,contents", blob, elf])
    lt = {off // 4: v for (_, off), v in parse_llvm(run([tool("llvm-objdump.exe"), "-d", "-M", "no-aliases",
                                                           f"--mattr={MATTR}", elf])).items()}
    wt = {off // 4: v for off, v in parse_wch(run([wch_tool("riscv32-wch-elf-objdump.exe"), "-d", "-M",
                                                    "no-aliases", elf])).items()}
    wrong_word = []
    for i, (name, w) in enumerate(words):
        base = name.split()[0]
        want = lt[i][1] if base not in WCH_CUSTOM | {"qk.delay"} else wt[i][1]
        if base == "qk.delay":
            want = rm_delay(w)[0] if rm_delay(w) else None
        if want != base:
            wrong_word.append(f"{name} {w:08x}: reference says {want}")
    lines += [f"- {len(words)} instruction words (rd a0, rs1 a1, rs2 a2; every shamt for the immediate forms), each "
              f"confirmed as that instruction by llvm-objdump, WCH's objdump or the RM table: "
              f"{len(words) - len(wrong_word)} of {len(words)}"]
    lines += [f"  - {x}" for x in wrong_word]
    ctsv = work / "emu-cases.tsv"
    ctsv.write_text("".join(f"{c[0]}\t{4 * c[1]:x}\t{c[2]:x}\t{c[3]:x}\t{c[4]:x}\n" for c in cases), encoding="utf-8")
    out = work / "emu-out.tsv"
    if out.exists():
        out.unlink()
    wait_for_cpu()
    proj = work / "ghidra-project"
    proj.mkdir(exist_ok=True)
    cmd = [proj, f"e{os.getpid()}_{int(time.time())}", "-import", blob,
           "-loader", "BinaryLoader", "-loader-baseAddr", "0x0", "-processor", LANG, "-cspec", "gcc", "-noanalysis",
           "-max-cpu", "2", "-scriptPath", SCRIPTS, "-postScript", "EmuCheck.java", ctsv, out, "-deleteProject"]
    r = headless(cmd, work / "emu.headless.log")
    if r.returncode != 0 or not out.exists() or "EmuCheck:" not in r.stdout:
        raise CouldNotCheck(f"headless emulator run failed (exit {r.returncode}); see emu.headless.log")
    results = {}
    for ln in out.read_text(encoding="utf-8").splitlines():
        if ln.startswith("#"):
            if ln.split("\t")[1] != LANG:
                raise CouldNotCheck(f"emulator ran {ln}")
            continue
        f = ln.split("\t")
        results[f[0]] = f[1:]
    dup = len(cases) - len({c[0] for c in cases})
    if dup:
        raise CouldNotCheck(f"{dup} case ids are not unique")
    bad = emu_judge(cases, results)
    groups = collections.Counter(c[0].split(":")[0].split(" ")[0] if not c[0].startswith("silicon") else "mcpy"
                                 for c in cases)
    bad_groups = collections.Counter(b[0].split(":")[0].split(" ")[0] if not b[0].startswith("silicon") else "mcpy"
                                     for b in bad)
    lines += [f"- {len(cases):,} cases through Ghidra's p-code emulator (EmulatorHelper, one step each; a0 preset to "
              f"0xdeadbeef; a1/a2 and pc checked too): {len(cases) - len(bad):,} agree, {len(bad)} differ", ""]
    lines += ["| instruction | cases | differ | checked against |", "|---|---|---|---|"]
    for g, n in sorted(groups.items()):
        how = ("reference model (value)" if g in REF_R or g in REF_U or g in REF_I else
               "named operation's operands and output register" if g in NAMED or g in ("mrsl", "mrslu", "wexti") else
               "silicon (CH32V467, 8 Nov 2026): rs1 and rs3 after, plus the named copy's operands" if g == "mcpy" else
               "RM table operands; no register written" if g == "qk.delay" else "?")
        lines.append(f"| {g} | {n} | {bad_groups.get(g, 0)} | {how} |")
    lines += [f"- {cid}: {why}" for cid, why in bad[:25]]
    # negative controls: a wrong model and a wrong silicon value must each be caught
    planted = [(c[0], c[1], c[2], c[3], c[4], ("value", [], {**c[5][2], "a0": REF_R["rol"](c[3], c[4])}))
               for c in cases if c[0].startswith("ror:") and REF_R["rol"](c[3], c[4]) != REF_R["ror"](c[3], c[4])]
    planted2 = [(c[0], c[1], c[2], c[3], c[4], (c[5][0], c[5][1], {**c[5][2], "a2": c[5][2]["a2"] + 1}))
                for c in cases if c[0] == "silicon mcpy.order"]
    nc1, nc2 = len(emu_judge(planted, results)), len(emu_judge(planted2, results))
    lines += ["", f"Negative controls: ror judged with rol's model: {nc1} of {len(planted)} caught; mcpy.order with "
                  f"rs3_after + 1: {nc2} of {len(planted2)} caught"]
    ok = not bad and not wrong_word and nc1 == len(planted) and nc2 == len(planted2) and planted
    lines += ["", f"RESULT: {'PASS' if ok else 'FAIL'}"]
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "emu.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok else 1


# ----------------------------------------------------------------------------------------------- images

def elf_exec_sections_addr(obj: bytes):
    if obj[:4] != b"\x7fELF" or obj[4] != 1 or obj[5] != 1:
        raise CouldNotCheck("not an ELF32 little-endian file")
    e_shoff, = struct.unpack_from("<I", obj, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", obj, 0x2E)
    shdrs = [struct.unpack_from("<IIIIIIIIII", obj, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    strtab = shdrs[e_shstrndx]
    names = obj[strtab[4]:strtab[4] + strtab[5]]
    out = []
    for sh in shdrs:
        name = names[sh[0]:names.index(b"\0", sh[0])].decode("ascii")
        if sh[1] == 1 and sh[2] & 0x4 and sh[5]:
            out.append((name, sh[3], obj[sh[4]:sh[4] + sh[5]]))
    return out


def elf_functions(obj: bytes):
    """-> [(name, addr, bytes)] for every STT_FUNC symbol with a size inside an executable PROGBITS section, one
    per address (the first name), overlaps dropped."""
    e_shoff, = struct.unpack_from("<I", obj, 0x20)
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", obj, 0x2E)
    shdrs = [struct.unpack_from("<IIIIIIIIII", obj, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    symtab = [sh for sh in shdrs if sh[1] == 2]
    if not symtab:
        raise CouldNotCheck("the ELF has no symbol table")
    st = symtab[0]
    strs = shdrs[st[6]]
    names = obj[strs[4]:strs[4] + strs[5]]
    funcs = {}
    for i in range(st[5] // 16):
        st_name, value, size, info, _, shndx = struct.unpack_from("<IIIBBH", obj, st[4] + 16 * i)
        if info & 0xF != 2 or not size or shndx >= len(shdrs):
            continue
        sh = shdrs[shndx]
        if sh[1] != 1 or not sh[2] & 0x4:
            continue
        name = names[st_name:names.index(b"\0", st_name)].decode("ascii", "replace")
        if value not in funcs:
            funcs[value] = (name, value, obj[sh[4] + value - sh[3]:sh[4] + value - sh[3] + size])
    out, end = [], 0
    for v in sorted(funcs):
        if v >= end:
            out.append(funcs[v])
            end = v + len(funcs[v][2])
    return out


def cmd_images(work: Path) -> int:
    import bisect
    work.mkdir(parents=True, exist_ok=True)
    if not IMAGES:
        raise Skipped("QINGKE_ELFS is not set (your own QingKe firmware ELFs with symbols)")
    lines = [f"# images: firmware with Zb and XW, every instruction both ways ({time.strftime('%Y-%m-%d %H:%M')})",
             "", "Every function (STT_FUNC symbol with a size, in an executable section) is swept from its start by "
             "both decoders: its bytes are copied out raw, one after another, each padded to 4 bytes with 0x0000 "
             "parcels that are not compared, so mapping symbols cannot steer llvm-objdump and neither decoder "
             "can run on into the next function. (WCH's linker script puts read-only data inside .text, so a "
             "whole-section sweep would mostly compare strings.)", ""]
    blob, regions = bytearray(), []
    per_image = {}
    for tag, path in IMAGES:
        if not path.exists():
            raise CouldNotCheck(f"{path} missing")
        data = path.read_bytes()
        attr = run([tool("llvm-readobj.exe"), "--arch-specific", path])
        m = re.search(r"Value: (rv32\S+)", attr)
        funcs = elf_functions(data)
        n_bytes = 0
        for name, addr, b in funcs:
            regions.append((f"{tag}:{name}@{addr:x}", len(blob), len(blob) + len(b)))
            blob += b
            n_bytes += len(b)
            while len(blob) % 4:
                blob += b"\0\0"
        secs = [s[0] for s in elf_exec_sections_addr(data)]
        per_image[tag] = (path, hashlib.sha256(data).hexdigest(), m.group(1) if m else "(no arch attribute)",
                          secs, n_bytes, len(funcs))
    blob_p = work / "images-text.bin"
    blob_p.write_bytes(bytes(blob))
    reg_p = work / "images-text.regions.tsv"
    reg_p.write_text("".join(f"{n}\t{s:x}\t{e:x}\n" for n, s, e in regions), encoding="utf-8")
    o = work / "images-text.o"
    run([tool("llvm-objcopy.exe"), "-I", "binary", "-O", "elf32-littleriscv",
         "--rename-section=.data=.text,alloc,load,readonly,code,contents", blob_p, o])
    txt = run([tool("llvm-objdump.exe"), "-d", "-M", "no-aliases", f"--mattr={MATTR}", o])
    (work / "images-text.llvm.txt").write_text(txt, encoding="utf-8")
    starts_l = [r[1] for r in regions]
    llvm, outside, straddle = {}, 0, 0
    for (_, off), (b, mn, ops) in parse_llvm(txt).items():
        k = bisect.bisect_right(starts_l, off) - 1
        if k < 0 or off >= regions[k][2]:
            outside += 1                                  # padding between functions
            continue
        name, s, e = regions[k]
        if off + len(b) // 2 > e:
            straddle += 1                                 # a decode running past the function's end
        ops = list(ops)
        if mn in BRANCHES and ops and isinstance(ops[-1], int):
            ops[-1] = (ops[-1] - s) & U32                 # targets relative to the function, as canon() does
        llvm[(name, off - s)] = (b, mn, ops)
    for tag, (path, sha, arch, secs, n, nf) in per_image.items():
        mn = collections.Counter(v[1] for k, v in llvm.items() if k[0].startswith(tag + ":") and v[1])
        zb = {k: n_ for k, n_ in mn.items() if k in set(ZB_R + ZB_U + ZB_I)}
        xw = sum(n_ for k, n_ in mn.items() if k.startswith("qk."))
        lines += [f"- {tag}: {path.name} (sha256 {sha[:12]}…, {time.strftime('%Y-%m-%d', time.localtime(path.stat().st_mtime))}); "
                  f"arch {arch}; executable sections {', '.join(secs)}; {nf:,} functions, {n:,} bytes; llvm: "
                  f"{sum(mn.values()):,} "
                  f"instructions, {xw:,} XW, {sum(zb.values()):,} Zb/Zicond (" +
                  ", ".join(f"{k} {v}" for k, v in sorted(zb.items())) + ")"]
    lines += [f"- llvm-objdump lines in the padding (not compared): {outside:,}; llvm decodes running past a "
              f"function's end: {straddle}", ""]
    if straddle:
        raise CouldNotCheck(f"{straddle} llvm decodes run past a function's end: the sweep is out of step")
    tsv = work / "images.ghidra.tsv"
    ghidra_dump(work, blob_p, tsv, LANG, raw=True, regions=reg_p)
    lang, ghidra, starts = parse_ghidra(tsv)
    if lang != LANG:
        raise CouldNotCheck(f"Ghidra used {lang}, not {LANG}")
    st, cl, ex, ru = compare(ghidra, llvm, starts)
    lines += report_compare(f"Ghidra {LANG} vs llvm-objdump {llvm_version()} --mattr={MATTR}", st, cl, ex, ru)
    zb_match = sum(1 for k, v in llvm.items() if v[1] in set(ZB_R + ZB_U + ZB_I) and k in ghidra and
                   ghidra[k][2] == v[1])
    zb_total = sum(1 for v in llvm.values() if v[1] in set(ZB_R + ZB_U + ZB_I))
    lines.append(f"Zb/Zicond instructions with the same mnemonic in Ghidra: {zb_match:,} of {zb_total:,}")
    tsv0 = work / "images.default.tsv"
    ghidra_dump(work, blob_p, tsv0, BASELINE, raw=True, regions=reg_p)
    _, ghidra0, starts0 = parse_ghidra(tsv0)
    st0, cl0, _, ru0 = compare(ghidra0, llvm, starts0)
    lines += [""] + report_compare(f"Before: Ghidra {BASELINE} on the same bytes", st0, cl0, {}, ru0)
    ok = st.get("mismatch", 0) == 0 and zb_total > 0 and zb_match == zb_total
    lines += [f"RESULT: {'PASS' if ok else 'FAIL'} (0 mismatches, every Zb instruction named as llvm names it)"]
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "images.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok else 1


def cmd_decompile_images(work: Path) -> int:
    """Extra, not a proof: the QINGKE_ELFS firmware through Ghidra's ELF loader, auto-analysis and decompiler, per
    language. An instruction without p-code (Ghidra's draft bitmanip is all "unimpl") shows as halt_unimplemented()."""
    if not IMAGES:
        raise Skipped("QINGKE_ELFS is not set (your own QingKe firmware ELFs with symbols)")
    work.mkdir(parents=True, exist_ok=True)
    lines = [f"# decompile-images: firmware through Ghidra's decompiler ({time.strftime('%Y-%m-%d %H:%M')})", ""]
    elfs = work / "elfs"
    if elfs.exists():
        shutil.rmtree(elfs)
    elfs.mkdir()
    for tag, path in IMAGES:
        if not path.exists():
            raise CouldNotCheck(f"{path} missing")
        (elfs / f"{tag}.elf").write_bytes(path.read_bytes())
        lines.append(f"- {tag}: {path.name}, sha256 {hashlib.sha256(path.read_bytes()).hexdigest()[:12]}…")
    lines.append("")
    stats = {}
    for lang in (LANG, BASELINE):
        out = work / f"decompile-{lang.split(':')[-1]}.tsv"
        if out.exists():
            out.unlink()
        wait_for_cpu()
        proj = work / "ghidra-project"
        proj.mkdir(exist_ok=True)
        cmd = [proj, f"di{os.getpid()}_{int(time.time())}",
               "-import", elfs, "-processor", lang, "-cspec", "gcc", "-max-cpu", "2",
               "-scriptPath", SCRIPTS, "-postScript", "DecompileCheck.java", out, "-deleteProject"]
        t0 = time.time()
        r = headless(cmd, work / f"decompile-{lang.split(':')[-1]}.headless.log")
        if r.returncode != 0 or not out.exists():
            raise CouldNotCheck(f"headless decompile run for {lang} failed (exit {r.returncode})")
        rows = [ln.split("\t") for ln in out.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
        langs = {ln.split("\t")[2] for ln in out.read_text(encoding="utf-8").splitlines() if ln.startswith("# lang")}
        for tag, _ in IMAGES:
            rr = [x for x in rows if x[0] == f"{tag}.elf"]
            ok_ = sum(1 for x in rr if x[2] == "ok")
            halts = sum(int(x[7]) for x in rr if len(x) > 7)
            fh = sum(1 for x in rr if len(x) > 7 and int(x[7]))
            stats[(lang, tag)] = (len(rr), ok_, halts, fh)
            lines.append(f"- {lang}, {tag}: {len(rr)} functions, {ok_} decompiled, {len(rr) - ok_} failed; "
                         f"{fh} functions contain {halts} halt_unimplemented() calls")
        lines.append(f"  (languages used: {', '.join(sorted(langs))}; {time.time() - t0:.0f} s)")
        if lang == LANG and langs != {LANG}:
            raise CouldNotCheck(f"Ghidra used {langs}")
    ok = all(stats[(LANG, t)][2] == 0 and stats[(LANG, t)][0] == stats[(LANG, t)][1] and stats[(LANG, t)][0]
             for t, _ in IMAGES)
    lines += ["", "RESULT: " + ("PASS" if ok else "FAIL") + f" ({LANG}: every function decompiles and none contains "
                                                            f"halt_unimplemented)"]
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "decompile-images.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok else 1


CMDS = {"sweep16": cmd_sweep16, "testobj": cmd_testobj, "sweep32": cmd_sweep32, "emu": cmd_emu,
        "libwchnet": cmd_libwchnet, "decompile": cmd_decompile, "images": cmd_images,
        "decompile-images": cmd_decompile_images}
OUTCOME = {0: "PASS", 1: "FAIL", 2: "COULD NOT CHECK", 3: "SKIPPED"}


def run_one(name: str, work: Path) -> int:
    try:
        return CMDS[name](work / name)
    except Skipped as e:
        print(f"SKIPPED {name}: {e}")
        return 3
    except CouldNotCheck as e:
        print(f"COULD NOT CHECK {name}: {e}")
        return 2


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in [*CMDS, "all"]:
        print(__doc__)
        return 2
    work = Path(sys.argv[2]).resolve()
    work.mkdir(parents=True, exist_ok=True)
    try:
        prepare(work)
    except CouldNotCheck as e:
        print(f"COULD NOT CHECK: {e}")
        return 2
    if sys.argv[1] != "all":
        return run_one(sys.argv[1], work)
    codes = {name: run_one(name, work) for name in CMDS}
    print("\nSummary:")
    for name, code in codes.items():
        print(f"  {name:17s} {OUTCOME.get(code, code)}")
    worst = max(codes.values(), key=lambda c: {0: 0, 3: 1, 1: 3, 2: 2}[c])
    return worst


if __name__ == "__main__":
    sys.exit(main())
