"""Turn a raw RunResult into structured, conservatively-classified evidence.

Three facts are recorded separately and never conflated (brief, sec. 3.2):
  * error type          -- a class (stack/heap overflow, UAF, ...), not a root cause
  * detection mechanism -- OS signal, binary hardening (canary / fortify), or a
                           sanitizer (ASan / UBSan)
  * termination         -- exit code, signal, timeout, resource limit

Every execution also gets a STATE used by the verdict logic:
  crash         confirmed memory-safety / security evidence: a sanitizer
                report, a canary or fortify abort, or SIGSEGV/SIGBUS/SIGFPE
  clean         the process exited normally (exit code judged later)
  unclassified  it stopped, but not in a way that proves a vulnerability:
                timeout, resource limit, SIGTERM/SIGKILL/..., a bare abort
                (e.g. assert) without hardening/sanitizer evidence, or the
                sanitizer exit code with no report
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .runner import RunResult

DET_SIGNAL = "os_signal"
DET_CANARY = "stack_canary"
DET_FORTIFY = "fortify"
DET_HEAP_CHECK = "glibc_heap_check"   # glibc malloc integrity checks
DET_ASAN = "sanitizer_asan"
DET_UBSAN = "sanitizer_ubsan"
DET_NONE = "none"

ET_STACK_BOF = "stack-buffer-overflow"
ET_HEAP_BOF = "heap-buffer-overflow"
ET_GLOBAL_BOF = "global-buffer-overflow"
ET_STACK_SMASH = "stack-smashing"
ET_UAF = "use-after-free"
ET_DOUBLE_FREE = "double-free"
ET_NULL_DEREF = "null-pointer-dereference"
ET_DIV_ZERO = "divide-by-zero"
ET_INT_OVERFLOW = "integer-overflow"
ET_BUFFER_OVERFLOW = "buffer-overflow"
ET_SEGV = "segmentation-fault"
ET_HEAP_CORRUPTION = "heap-corruption"
ET_UNKNOWN = "unknown"

STATE_CRASH = "crash"
STATE_CLEAN = "clean"
STATE_UNCLASSIFIED = "unclassified"

# signals that are, by themselves, evidence of a memory-safety crash
_CRASH_SIGNALS = {"SIGSEGV": ET_SEGV, "SIGBUS": ET_SEGV, "SIGFPE": ET_DIV_ZERO}


@dataclass
class Frame:
    index: int
    function: str | None
    file: str | None
    line: int | None
    raw: str
    relpath: str | None = None      # path relative to the version's source root


@dataclass
class CrashInfo:
    is_crash: bool
    error_type: str
    detection: str
    frames: list[Frame] = field(default_factory=list)
    termination_signal: str | None = None
    termination_exit: int | None = None
    timed_out: bool = False
    resource_limited: bool = False
    sanitizer_headline: str | None = None
    fingerprint: str = ""
    state: str = STATE_CLEAN
    access: str | None = None           # READ / WRITE (ASan)
    unclassified_reason: str | None = None

    def top_source_frame(self) -> Frame | None:
        for f in self.frames:
            if f.relpath is not None:
                return f
        return None

    def identity(self) -> tuple:
        """Crash identity used for 'same crash?' decisions across versions:
        error type + relative file + function + access kind. Line numbers are
        excluded on purpose because a patch shifts them."""
        top = self.top_source_frame()
        return (self.error_type,
                top.relpath if top else None,
                top.function if top else None,
                self.access)

    def summary(self) -> dict:
        return {
            "state": self.state,
            "is_crash": self.is_crash,
            "error_type": self.error_type,
            "detection": self.detection,
            "access": self.access,
            "termination": {
                "signal": self.termination_signal,
                "exit_code": self.termination_exit,
                "timed_out": self.timed_out,
                "resource_limited": self.resource_limited,
            },
            "unclassified_reason": self.unclassified_reason,
            "sanitizer_headline": self.sanitizer_headline,
            "fingerprint": self.fingerprint,
            "top_frames": [
                {"function": f.function, "file": f.relpath or f.file, "line": f.line}
                for f in self.frames[:6]
            ],
        }


_ASAN_ERROR_RE = re.compile(r"ERROR: AddressSanitizer: ([A-Za-z0-9\-]+)")
_ASAN_ACCESS_RE = re.compile(r"\b(READ|WRITE) of size \d+")
_ASAN_KIND_MAP = [
    ("dynamic-stack-buffer-overflow", ET_STACK_BOF),
    ("stack-buffer-overflow", ET_STACK_BOF),
    ("stack-buffer-underflow", ET_STACK_BOF),
    ("heap-buffer-overflow", ET_HEAP_BOF),
    ("global-buffer-overflow", ET_GLOBAL_BOF),
    ("heap-use-after-free", ET_UAF),
    ("use-after-poison", ET_UAF),
    ("double-free", ET_DOUBLE_FREE),
    ("attempting", ET_DOUBLE_FREE),
    ("stack-overflow", "stack-exhaustion"),
    ("segv", ET_SEGV),
]
_UBSAN_RE = re.compile(r"runtime error: (.+)")
# glibc malloc consistency-check aborts (heap metadata corruption detected)
_GLIBC_HEAP_RE = re.compile(
    r"^(?:malloc|free|realloc|calloc|malloc_consolidate|_int_malloc|_int_free|munmap_chunk)"
    r"\(\): .*$|^double free or corruption.*$|^corrupted (?:size vs\. prev_size|double-linked list).*$",
    re.MULTILINE)
_FRAME_RE = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+?):(\d+)(?::\d+)?\s*$")
_FRAME_NOLOC_RE = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)")


def _parse_frames(stderr: str) -> list[Frame]:
    frames: list[Frame] = []
    seen_zero = 0
    for line in stderr.splitlines():
        line = line.rstrip()
        m = _FRAME_RE.search(line)
        if m:
            idx = int(m.group(1))
            if idx == 0:
                seen_zero += 1
                if seen_zero > 1:       # only the FIRST stack (the faulting access)
                    break
            frames.append(Frame(idx, m.group(2), m.group(3), int(m.group(4)), line.strip()))
            continue
        m2 = _FRAME_NOLOC_RE.search(line)
        if m2:
            idx = int(m2.group(1))
            if idx == 0:
                seen_zero += 1
                if seen_zero > 1:
                    break
            frames.append(Frame(idx, m2.group(2), None, None, line.strip()))
    return frames


def normalize_frames(frames: list[Frame], source_root: str | None) -> None:
    """Fill Frame.relpath with the path relative to the version's source root.

    Frames outside the root (libc, sanitizer runtime, system headers) keep
    relpath=None, so they never take part in correlation. Matching is done on
    the normalized *relative path*, never on the basename alone.
    """
    root = os.path.realpath(source_root) if source_root else None
    for f in frames:
        if not f.file:
            continue
        low = f.file.lower()
        if "sanitizer_common" in low or "/libsanitizer/" in low or "compiler-rt" in low:
            continue
        if f.function and f.function.startswith(("__asan", "__ubsan", "__interceptor",
                                                 "__sanitizer", "___interceptor")):
            continue
        path = f.file
        if root is None:
            continue
        if os.path.isabs(path):
            real = os.path.realpath(path)
            if real == root or real.startswith(root + os.sep):
                f.relpath = os.path.relpath(real, root)
        else:
            norm = os.path.normpath(path)
            if not norm.startswith(".."):
                f.relpath = norm


def _fingerprint(ci: CrashInfo) -> str:
    top = ci.top_source_frame()
    loc = f"{top.function}@{top.relpath}:{top.line}" if top else ""
    return "|".join(x for x in (ci.error_type, loc, ci.access or "") if x)


def analyze(result: RunResult, mode_is_sanitized: bool,
            source_root: str | None = None) -> CrashInfo:
    stderr = result.stderr
    if result.timed_out:
        return CrashInfo(False, ET_UNKNOWN, DET_NONE, timed_out=True,
                         state=STATE_UNCLASSIFIED, unclassified_reason="timeout",
                         fingerprint="timeout")
    if result.oom_or_rlimit:
        return CrashInfo(False, ET_UNKNOWN, DET_NONE, resource_limited=True,
                         termination_signal=result.signal_name,
                         termination_exit=result.exit_code,
                         state=STATE_UNCLASSIFIED, unclassified_reason="resource limit",
                         fingerprint="resource_limit")

    frames = _parse_frames(stderr)
    normalize_frames(frames, source_root)

    def _crash(et, det, headline=None, access=None):
        ci = CrashInfo(True, et, det, frames=frames,
                       termination_signal=result.signal_name,
                       termination_exit=result.exit_code,
                       sanitizer_headline=headline, state=STATE_CRASH, access=access)
        ci.fingerprint = _fingerprint(ci)
        return ci

    m = _ASAN_ERROR_RE.search(stderr)
    if m:
        kind = m.group(1).lower()
        et = next((v for k, v in _ASAN_KIND_MAP if k in kind), None)
        if et is None:
            et = ET_BUFFER_OVERFLOW if "overflow" in kind else kind
        ma = _ASAN_ACCESS_RE.search(stderr)
        return _crash(et, DET_ASAN, f"AddressSanitizer: {kind}", ma.group(1) if ma else None)

    mu = _UBSAN_RE.search(stderr)
    if mu:
        desc = mu.group(1).lower()
        if "division by zero" in desc:
            et = ET_DIV_ZERO
        elif "out of bounds" in desc or "insufficient space" in desc:
            et = ET_BUFFER_OVERFLOW
        elif "overflow" in desc:
            et = ET_INT_OVERFLOW
        elif "null pointer" in desc:
            et = ET_NULL_DEREF
        else:
            et = "undefined-behavior"
        access = "WRITE" if desc.startswith("store") else ("READ" if desc.startswith("load") else None)
        return _crash(et, DET_UBSAN,
                      f"UndefinedBehaviorSanitizer: {mu.group(1).strip()[:120]}", access)

    if "stack smashing detected" in stderr:
        return _crash(ET_STACK_SMASH, DET_CANARY, "stack smashing detected (__stack_chk_fail)")
    if "buffer overflow detected" in stderr:
        return _crash(ET_BUFFER_OVERFLOW, DET_FORTIFY, "buffer overflow detected (_FORTIFY_SOURCE)")
    if result.signal_name == "SIGABRT":
        mh = _GLIBC_HEAP_RE.search(stderr)
        if mh:
            et = ET_DOUBLE_FREE if "double free" in mh.group(0) else ET_HEAP_CORRUPTION
            return _crash(et, DET_HEAP_CHECK, f"glibc: {mh.group(0).strip()[:100]}")

    if result.signal_name is not None:
        et = _CRASH_SIGNALS.get(result.signal_name)
        if et is not None:
            return _crash(et, DET_SIGNAL)
        # SIGABRT without sanitizer/canary/fortify text, SIGTERM, SIGILL, ...:
        # the program stopped, but that is not proof of a vulnerability.
        return CrashInfo(False, ET_UNKNOWN, DET_SIGNAL, frames=frames,
                         termination_signal=result.signal_name,
                         state=STATE_UNCLASSIFIED,
                         unclassified_reason=f"terminated by {result.signal_name} "
                                             "without security evidence",
                         fingerprint=f"signal:{result.signal_name}")

    if mode_is_sanitized and result.exit_code == 99:
        return CrashInfo(False, ET_UNKNOWN, DET_NONE, termination_exit=99,
                         state=STATE_UNCLASSIFIED,
                         unclassified_reason="sanitizer exit code without a parsable report",
                         fingerprint="sanitizer_exit")

    return CrashInfo(False, ET_UNKNOWN, DET_NONE, termination_exit=result.exit_code,
                     state=STATE_CLEAN, fingerprint="nocrash")
