"""Interpret a raw RunResult into structured crash evidence.

The brief requires several *independent* facts to be recorded and not
conflated:

  * Error type        -- stack/heap overflow, UAF, null-deref, div-by-zero ...
                         (this is NOT a root-cause analysis, just a class)
  * Detection method  -- OS signal, binary hardening (stack canary /
                         __stack_chk_fail), or a sanitizer (ASan/UBSan)
  * Termination       -- exit code, signal, stdout/stderr; a timeout or a
                         resource-limit hit is reported separately and does
                         NOT by itself count as an exploitable vulnerability.

We also extract the top stack frames (function, file, line) so that the
correlation stage can link the finding to the patch diff.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .runner import RunResult


# Detection mechanisms
DET_SIGNAL = "os_signal"
DET_CANARY = "stack_canary"          # __stack_chk_fail / "stack smashing detected"
DET_FORTIFY = "fortify"             # _FORTIFY_SOURCE __chk_fail / "buffer overflow detected"
DET_ASAN = "sanitizer_asan"
DET_UBSAN = "sanitizer_ubsan"
DET_NONE = "none"

# Normalised error-type vocabulary (a class, not a root cause)
ET_STACK_BOF = "stack-buffer-overflow"
ET_HEAP_BOF = "heap-buffer-overflow"
ET_GLOBAL_BOF = "global-buffer-overflow"
ET_STACK_SMASH = "stack-smashing"       # canary tripped
ET_UAF = "use-after-free"
ET_DOUBLE_FREE = "double-free"
ET_NULL_DEREF = "null-pointer-dereference"
ET_DIV_ZERO = "divide-by-zero"
ET_INT_OVERFLOW = "integer-overflow"
ET_BUFFER_OVERFLOW = "buffer-overflow"  # fortify-detected, stack/heap undetermined
ET_SEGV = "segmentation-fault"          # generic, mechanism-unknown
ET_ABORT = "abort"
ET_UNKNOWN = "unknown"


@dataclass
class Frame:
    index: int
    function: str | None
    file: str | None
    line: int | None
    raw: str


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
    # short human string of the sanitizer headline, if any
    sanitizer_headline: str | None = None
    # a stable fingerprint: (error_type, top meaningful frame location)
    fingerprint: str = ""

    def summary(self) -> dict:
        return {
            "is_crash": self.is_crash,
            "error_type": self.error_type,
            "detection": self.detection,
            "termination": {
                "signal": self.termination_signal,
                "exit_code": self.termination_exit,
                "timed_out": self.timed_out,
                "resource_limited": self.resource_limited,
            },
            "sanitizer_headline": self.sanitizer_headline,
            "fingerprint": self.fingerprint,
            "top_frames": [
                {"function": f.function, "file": f.file, "line": f.line}
                for f in self.frames[:6]
            ],
        }


# --- ASan / UBSan parsing -------------------------------------------------

_ASAN_ERROR_RE = re.compile(
    r"ERROR: AddressSanitizer: ([a-z0-9\-]+)", re.IGNORECASE)
_ASAN_KIND_MAP = {
    "stack-buffer-overflow": ET_STACK_BOF,
    "heap-buffer-overflow": ET_HEAP_BOF,
    "global-buffer-overflow": ET_GLOBAL_BOF,
    "stack-buffer-underflow": ET_STACK_BOF,
    "heap-use-after-free": ET_UAF,
    "use-after-poison": ET_UAF,
    "double-free": ET_DOUBLE_FREE,
    "attempting-free-on": ET_DOUBLE_FREE,
    "null-deref": ET_NULL_DEREF,
    "segv": ET_SEGV,
    "stack-overflow": ET_STACK_BOF,
    "dynamic-stack-buffer-overflow": ET_STACK_BOF,
}

_UBSAN_RE = re.compile(r"runtime error: (.+)")
# e.g. "#3 0x... in function /path/file.c:123:7"
_FRAME_RE = re.compile(
    r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+([^\s:]+):(\d+)(?::\d+)?")
# frame without file/line: "#4 0x... in func (/lib/libc.so+0x...)"
_FRAME_NOLOC_RE = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+\(")


def _parse_frames(stderr: str) -> list[Frame]:
    frames: list[Frame] = []
    for line in stderr.splitlines():
        m = _FRAME_RE.search(line)
        if m:
            frames.append(Frame(
                index=int(m.group(1)),
                function=m.group(2),
                file=m.group(3),
                line=int(m.group(4)),
                raw=line.strip(),
            ))
            continue
        m2 = _FRAME_NOLOC_RE.search(line)
        if m2:
            frames.append(Frame(
                index=int(m2.group(1)),
                function=m2.group(2),
                file=None,
                line=None,
                raw=line.strip(),
            ))
    frames.sort(key=lambda f: f.index)
    return frames


def _first_source_frame(frames: list[Frame]) -> Frame | None:
    """The shallowest frame that has source location and is not sanitizer/libc."""
    for f in frames:
        if f.file is None:
            continue
        low = f.file.lower()
        if "sanitizer" in low or "/libc" in low or low.endswith("libc.so"):
            continue
        if f.function and (f.function.startswith("__asan") or f.function.startswith("__ubsan")
                           or f.function.startswith("__interceptor")):
            continue
        return f
    # fallback: any frame with a location
    for f in frames:
        if f.file is not None:
            return f
    return None


def analyze(result: RunResult, mode_is_sanitized: bool) -> CrashInfo:
    """Produce structured crash evidence from a run."""
    stderr = result.stderr

    # Timeout / resource exhaustion are reported, never classified as a vuln.
    if result.timed_out:
        return CrashInfo(
            is_crash=False, error_type=ET_UNKNOWN, detection=DET_NONE,
            timed_out=True, termination_exit=None, fingerprint="timeout",
        )

    frames = _parse_frames(stderr)
    headline = None

    # 1) ASan headline
    m = _ASAN_ERROR_RE.search(stderr)
    if m:
        kind = m.group(1).lower()
        error_type = ET_UNKNOWN
        for key, val in _ASAN_KIND_MAP.items():
            if key in kind:
                error_type = val
                break
        if error_type == ET_UNKNOWN:
            if "segv" in kind:
                error_type = ET_SEGV
            elif "overflow" in kind:
                error_type = ET_BUFFER_OVERFLOW
            else:
                # Keep ASan's own precise label rather than losing information.
                error_type = kind
        headline = f"AddressSanitizer: {kind}"
        src = _first_source_frame(frames)
        fp = _fingerprint(error_type, src)
        return CrashInfo(
            is_crash=True, error_type=error_type, detection=DET_ASAN,
            frames=frames, termination_signal=result.signal_name,
            termination_exit=result.exit_code, sanitizer_headline=headline,
            fingerprint=fp,
        )

    # 2) UBSan runtime error
    mu = _UBSAN_RE.search(stderr)
    if mu:
        desc = mu.group(1).lower()
        if "division by zero" in desc or "divide by zero" in desc:
            error_type = ET_DIV_ZERO
        elif ("out of bounds" in desc or "insufficient space" in desc
              or "index" in desc and "bounds" in desc):
            # object-size / bounds checks: an out-of-bounds memory access
            error_type = ET_BUFFER_OVERFLOW
        elif "overflow" in desc and ("int" in desc or "signed" in desc or "unsigned" in desc):
            error_type = ET_INT_OVERFLOW
        elif "null pointer" in desc or "member access within null" in desc:
            error_type = ET_NULL_DEREF
        else:
            error_type = ET_UNKNOWN
        headline = f"UndefinedBehaviorSanitizer: {mu.group(1).strip()[:120]}"
        src = _first_source_frame(frames)
        return CrashInfo(
            is_crash=True, error_type=error_type, detection=DET_UBSAN,
            frames=frames, termination_signal=result.signal_name,
            termination_exit=result.exit_code, sanitizer_headline=headline,
            fingerprint=_fingerprint(error_type, src),
        )

    # 3a) Stack canary (binary hardening) -- works even in release builds
    if "stack smashing detected" in stderr or "__stack_chk_fail" in stderr:
        src = _first_source_frame(frames)
        return CrashInfo(
            is_crash=True, error_type=ET_STACK_SMASH, detection=DET_CANARY,
            frames=frames, termination_signal=result.signal_name or "SIGABRT",
            termination_exit=result.exit_code,
            sanitizer_headline="stack smashing detected (__stack_chk_fail)",
            fingerprint=_fingerprint(ET_STACK_SMASH, src),
        )

    # 3b) _FORTIFY_SOURCE runtime check (binary hardening) -- release builds.
    # glibc prints "*** buffer overflow detected ***" from __chk_fail.
    if "buffer overflow detected" in stderr or "__chk_fail" in stderr \
            or "__fortify_fail" in stderr:
        src = _first_source_frame(frames)
        return CrashInfo(
            is_crash=True, error_type=ET_BUFFER_OVERFLOW, detection=DET_FORTIFY,
            frames=frames, termination_signal=result.signal_name or "SIGABRT",
            termination_exit=result.exit_code,
            sanitizer_headline="buffer overflow detected (_FORTIFY_SOURCE)",
            fingerprint=_fingerprint(ET_BUFFER_OVERFLOW, src),
        )

    # 4) Bare OS signal (release build, no instrumentation)
    if result.signal_name is not None:
        sig = result.signal_name
        if result.oom_or_rlimit:
            return CrashInfo(
                is_crash=False, error_type=ET_UNKNOWN, detection=DET_SIGNAL,
                termination_signal=sig, resource_limited=True,
                fingerprint="resource_limit",
            )
        if sig == "SIGSEGV" or sig == "SIGBUS":
            error_type = ET_SEGV
        elif sig == "SIGFPE":
            error_type = ET_DIV_ZERO
        elif sig == "SIGABRT":
            error_type = ET_ABORT
        else:
            error_type = ET_UNKNOWN
        return CrashInfo(
            is_crash=True, error_type=error_type, detection=DET_SIGNAL,
            frames=frames, termination_signal=sig,
            termination_exit=None,
            fingerprint=_fingerprint(error_type, None, sig),
        )

    # 5) No crash
    return CrashInfo(
        is_crash=False, error_type=ET_UNKNOWN, detection=DET_NONE,
        termination_exit=result.exit_code, fingerprint="nocrash",
    )


def _fingerprint(error_type: str, src: Frame | None, extra: str = "") -> str:
    loc = ""
    if src is not None:
        fname = (src.file or "").split("/")[-1]
        loc = f"{src.function or '?'}@{fname}:{src.line or '?'}"
    return f"{error_type}|{loc}|{extra}".strip("|")
