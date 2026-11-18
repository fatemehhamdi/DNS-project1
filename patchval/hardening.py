"""ELF binary hardening inspection (checksec-style) with evidence.

Reports the status of NX, PIE, RELRO and Stack Canary for the *release*
binary and flags unintended changes between the base and patched builds
(e.g. a build-script edit silently disabling a protection). Each verdict
carries the concrete evidence it was derived from.

Caveats encoded in the output, per the brief:
  * PIE in the file does not prove ASLR is enabled in the runtime environment.
  * A canary symbol being present does not mean every function is protected.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


RELRO_NONE = "none"
RELRO_PARTIAL = "partial"
RELRO_FULL = "full"


@dataclass
class Hardening:
    binary_path: str
    nx: bool
    pie: bool
    relro: str
    canary: bool
    evidence: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "binary": self.binary_path,
            "nx": self.nx,
            "pie": self.pie,
            "relro": self.relro,
            "stack_canary": self.canary,
            "evidence": self.evidence,
            "notes": self.notes,
        }


def _readelf(args: list[str], path: str) -> str:
    try:
        proc = subprocess.run(["readelf", *args, path], capture_output=True,
                              text=True, timeout=30)
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def inspect(path: str) -> Hardening:
    headers = _readelf(["-hW"], path)
    segments = _readelf(["-lW"], path)
    dynamic = _readelf(["-dW"], path)
    symbols = _readelf(["-sW"], path)

    evidence = {}

    # --- NX (non-executable stack) ---
    nx = True
    gnu_stack_line = ""
    for line in segments.splitlines():
        if "GNU_STACK" in line:
            gnu_stack_line = line.strip()
            # flags are the RWE field; executable stack if 'E' present
            # format: GNU_STACK  0x... 0x... 0x... 0x... 0x... RW  0x10
            if " RWE " in f" {line} " or line.rstrip().endswith("RWE") or " E " in line:
                nx = False
            break
    evidence["gnu_stack"] = gnu_stack_line or "no GNU_STACK segment (NX assumed on)"

    # --- PIE ---
    etype = ""
    for line in headers.splitlines():
        if line.strip().startswith("Type:"):
            etype = line.split("Type:", 1)[1].strip()
            break
    pie = "DYN" in etype
    # A shared object without PT_INTERP is a library, not a PIE executable; but
    # for our targets (executables) DYN == PIE.
    has_interp = "INTERP" in segments
    if pie and not has_interp:
        # Could be a .so; keep pie True but note it.
        pass
    evidence["elf_type"] = etype

    # --- RELRO ---
    has_relro = "GNU_RELRO" in segments
    bind_now = False
    for line in dynamic.splitlines():
        if "BIND_NOW" in line or ("FLAGS" in line and "BIND_NOW" in line) or "(BIND_NOW)" in line:
            bind_now = True
        if "FLAGS_1" in line and "NOW" in line:
            bind_now = True
    if not has_relro:
        relro = RELRO_NONE
    elif bind_now:
        relro = RELRO_FULL
    else:
        relro = RELRO_PARTIAL
    evidence["gnu_relro"] = has_relro
    evidence["bind_now"] = bind_now

    # --- Stack canary ---
    canary = "__stack_chk_fail" in symbols
    evidence["stack_chk_fail_symbol"] = canary

    notes = [
        "PIE in the file does not prove ASLR is active in the runtime environment.",
        "Presence of a stack canary symbol does not guarantee every function is protected.",
    ]

    return Hardening(binary_path=path, nx=nx, pie=pie, relro=relro,
                     canary=canary, evidence=evidence, notes=notes)


@dataclass
class HardeningDelta:
    base: Hardening
    patched: Hardening
    changes: list[str] = field(default_factory=list)
    regressed: bool = False

    def summary(self) -> dict:
        return {
            "base": self.base.summary(),
            "patched": self.patched.summary(),
            "changes": self.changes,
            "protection_regressed": self.regressed,
        }


def compare(base: Hardening, patched: Hardening) -> HardeningDelta:
    """Flag protections that were weakened by the patch/build change."""
    changes: list[str] = []
    regressed = False

    def chk(name, b, p, weaker):
        nonlocal regressed
        if b != p:
            changes.append(f"{name}: {b} -> {p}")
            if weaker(b, p):
                regressed = True

    chk("NX", base.nx, patched.nx, lambda b, p: b and not p)
    chk("PIE", base.pie, patched.pie, lambda b, p: b and not p)
    chk("StackCanary", base.canary, patched.canary, lambda b, p: b and not p)
    order = {RELRO_NONE: 0, RELRO_PARTIAL: 1, RELRO_FULL: 2}
    chk("RELRO", base.relro, patched.relro, lambda b, p: order[p] < order[b])

    return HardeningDelta(base=base, patched=patched, changes=changes,
                          regressed=regressed)
