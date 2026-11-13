#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SEL (Mark Thurston). Part of ghidra-qingke-xw.
"""Build (and optionally install) the QingKeXW Ghidra extension.

    python tools/build.py --ghidra <ghidra_12.1.4_PUBLIC>                 check, compile the .sla, write the zip
    python tools/build.py --ghidra <dir> --install                        ... and install into your Ghidra settings
    python tools/build.py --ghidra <dir> --install --settings-dir <dir>   ... into a separate settings directory

The Ghidra installation can also be given by the GHIDRA_INSTALL_DIR environment variable.

Steps:
1. Every file copied from Ghidra 12.1.4's RISCV module must still be byte-identical to the given Ghidra's (the
   list and hashes are in GHIDRA_FILES below); qingke.rvc.sinc is the one marked copy, and the Ghidra file it was
   made from is checked against its recorded hash. A difference stops the build (exit 2: could not check).
2. The .sla is compiled with Ghidra's own SLEIGH compiler (support/sleigh or sleigh.bat), at low priority.
3. release/QingKeXW-<version>-ghidra_12.1.4.zip holds the extension folder `QingKeXW/`, with a .sha256 beside it.
   The zip's timestamps are fixed, so a rebuild of the same sources gives the same zip.

Installing never touches the Ghidra installation. By default the folder goes to the user settings directory Ghidra
12 uses (Windows %APPDATA%/ghidra/ghidra_12.1.4_PUBLIC/Extensions; Linux $XDG_CONFIG_HOME or ~/.config/ghidra/...;
macOS ~/Library/ghidra/...), which both the GUI and analyzeHeadless read. With --settings-dir it goes under that
directory instead, for use with -Dapplication.settingsdir=<dir> (the proofs do this, so they test this build and
not whatever is installed).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXT = REPO / "QingKeXW"
LANGDIR = EXT / "data" / "languages"
GHIDRA_VERSION = "12.1.4"
VERSION = "1.1.1"
ZIP_DATE = (2026, 11, 13, 0, 0, 0)   # fixed, so a rebuild of the same sources gives the same zip
LOW_PRIORITY = {"creationflags": 0x00004000} if os.name == "nt" else {}   # BELOW_NORMAL_PRIORITY_CLASS

# Unmodified copies of Ghidra 12.1.4 files (Apache-2.0), sha256 at the time of copying (11 Nov 2026).
GHIDRA_FILES = {
    "riscv.csr.sinc": "2c57e6a8d5ee4f383174edbe7f1ab17675583732b4dbc87a515f44454c551232",
    "riscv.custom.sinc": "23a1823dfdc08e007f81cd363ccf5c5992c976c39cbd7627ab35773cdc691cd5",
    "riscv.priv.sinc": "5e881324774e2fafd33783644e000f374184e697ee5df64eaaffd2cbfec6d262",
    "riscv.reg.sinc": "cb48ddf1a4cb14bcd1aab232ae3371d9496d262ea445d3afc29dec3eab19f36c",
    "riscv.rv32a.sinc": "530ab457c9e2c16c6abf9c6be22dbb74f39e55e1808129625df2dcc90c632956",
    "riscv.rv32i.sinc": "e404ca813ce1694c1680fc3fc0495fdf4ceeb276f845f299575c656f1dfd0b23",
    "riscv.rv32m.sinc": "46a89396caad41521488b36b3b77a5903676a1906a44c2fb4379b1b1086a7786",
    "riscv.table.sinc": "e6daf6670dd419a404d752b1fc7b4de3b021938dbe78e08dd9473269a6e21a63",
    "riscv.zi.sinc": "aa438b3ce35865cb6e83e61ef3ef282f087d0535036d2ee3edb3471578901a48",
    "riscv32.cspec": "a1474ad5d4c8b263e91bad970b122ad4a0e10c8d895c8a105f4ce486253f7a4d",
    "riscv32.dwarf": "323eaf31e3e08f16c1dd8bc0de09c5a478a1caa74fe13bffd09a241ff6f9767f",
    "RV32.pspec": "12a651eaf6d4fa26391716362a747fa32b544f6cc0f918530c1e370f3e042890",
}
# qingke.rvc.sinc is Ghidra's riscv.rvc.sinc with one marked change (c.flw/c.flwsp need F).
RVC_ORIGINAL = ("riscv.rvc.sinc", "b01f8c3ed38005724c2d410701fbe5f64c7743f5a14dce228914ba3c7707df4b")


class CouldNotCheck(Exception):
    pass


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ghidra_dir(arg: str | None) -> Path:
    g = arg or os.environ.get("GHIDRA_INSTALL_DIR")
    if not g:
        raise CouldNotCheck("give the Ghidra installation with --ghidra or GHIDRA_INSTALL_DIR")
    g = Path(g).resolve()
    props = g / "Ghidra" / "application.properties"
    if not props.exists():
        raise CouldNotCheck(f"{g} is not a Ghidra installation (no Ghidra/application.properties)")
    version = next((ln.split("=", 1)[1].strip() for ln in props.read_text(encoding="utf-8").splitlines()
                    if ln.startswith("application.version=")), None)
    if version != GHIDRA_VERSION:
        raise CouldNotCheck(f"{g} is Ghidra {version}; this extension is built for {GHIDRA_VERSION} only")
    return g


def support_tool(ghidra: Path, name: str) -> Path:
    return ghidra / "support" / (name + (".bat" if os.name == "nt" else ""))


def check_copies(ghidra: Path) -> list[str]:
    glang = ghidra / "Ghidra" / "Processors" / "RISCV" / "data" / "languages"
    bad = []
    for name, want in GHIDRA_FILES.items():
        mine, theirs = LANGDIR / name, glang / name
        if not mine.exists() or sha256(mine) != want:
            bad.append(f"{name}: the repository copy is not the recorded file")
        if not theirs.exists() or sha256(theirs) != want:
            bad.append(f"{name}: the installed Ghidra's file differs (Ghidra changed?)")
    name, want = RVC_ORIGINAL
    if not (glang / name).exists() or sha256(glang / name) != want:
        bad.append(f"{name}: the installed Ghidra's file differs, so qingke.rvc.sinc must be re-derived")
    return bad


def compile_sla(ghidra: Path) -> Path:
    sla = LANGDIR / "qingke-xw.sla"
    if sla.exists():
        sla.unlink()
    r = subprocess.run([str(support_tool(ghidra, "sleigh")), "qingke-xw.slaspec", "qingke-xw.sla"],
                       cwd=LANGDIR, capture_output=True, text=True, stdin=subprocess.DEVNULL, **LOW_PRIORITY)
    log = r.stdout + r.stderr
    errors = [ln for ln in log.splitlines() if ln.startswith("ERROR")]
    if r.returncode != 0 or not sla.exists() or errors:
        print(log)
        raise SystemExit("SLEIGH compile failed")
    warns = [ln for ln in log.splitlines() if ln.startswith("WARN")]
    print(f"compiled {sla.name}: {sla.stat().st_size} bytes, {len(warns)} warnings (unreferenced tables etc.)")
    return sla


def make_zip() -> Path:
    out = REPO / "release" / f"QingKeXW-{VERSION}-ghidra_{GHIDRA_VERSION}.zip"
    out.parent.mkdir(exist_ok=True)
    files = sorted(p for p in EXT.rglob("*") if p.is_file())
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            info = zipfile.ZipInfo(str(Path("QingKeXW") / p.relative_to(EXT)).replace("\\", "/"),
                                   date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, p.read_bytes())
    digest = sha256(out)
    (out.parent / (out.name + ".sha256")).write_text(f"{digest}  {out.name}\n", encoding="ascii")
    print(f"wrote {out.relative_to(REPO)} ({out.stat().st_size} bytes) sha256 {digest}")
    return out


def default_settings_parent() -> Path:
    """The parent of ghidra_<version>_PUBLIC in Ghidra 12's default user settings location."""
    if os.name == "nt":
        return Path(os.environ["APPDATA"]) / "ghidra"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "ghidra"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return Path(xdg) / "ghidra" if xdg else Path.home() / ".config" / "ghidra"


def settings_parents(settings_dir: Path) -> list[Path]:
    """With -Dapplication.settingsdir=<dir>, Ghidra uses <dir>/ghidra, or <dir>/<user>-ghidra when <dir> is outside
    the user's home directory. Install into both, so either rule finds it."""
    return [settings_dir / "ghidra", settings_dir / f"{getpass.getuser()}-ghidra"]


def install(dest_parents: list[Path]) -> list[Path]:
    done = []
    for parent in dest_parents:
        dest = parent / f"ghidra_{GHIDRA_VERSION}_PUBLIC" / "Extensions" / "QingKeXW"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(EXT, dest)
        for p in EXT.rglob("*"):
            if p.is_file() and sha256(p) != sha256(dest / p.relative_to(EXT)):
                raise SystemExit(f"install copy differs: {p.name}")
        print(f"installed to {dest}")
        done.append(dest)
    return done


def build(ghidra: Path) -> None:
    bad = check_copies(ghidra)
    if bad:
        raise CouldNotCheck("\n  ".join(bad))
    print(f"{len(GHIDRA_FILES)} Ghidra files match Ghidra {GHIDRA_VERSION}; riscv.rvc.sinc unchanged upstream")
    compile_sla(ghidra)
    make_zip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Build (and optionally install) the QingKeXW Ghidra extension.")
    ap.add_argument("--ghidra", help="Ghidra 12.1.4 installation (default: $GHIDRA_INSTALL_DIR)")
    ap.add_argument("--install", action="store_true", help="install the built extension")
    ap.add_argument("--settings-dir", help="install under this -Dapplication.settingsdir instead of the default")
    a = ap.parse_args()
    try:
        ghidra = ghidra_dir(a.ghidra)
        build(ghidra)
    except CouldNotCheck as e:
        print(f"COULD NOT CHECK: {e}")
        return 2
    if a.install:
        parents = settings_parents(Path(a.settings_dir).resolve()) if a.settings_dir else [default_settings_parent()]
        install(parents)
    return 0


if __name__ == "__main__":
    sys.exit(main())
