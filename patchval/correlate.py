"""Patch-to-finding correlation.

Given a crash's stack frames and the patch diff, decide how strongly the
finding is linked to the code the patch changed. The brief is emphatic that
this must be evidence-based and conservative:

  * The crash location is not necessarily on a changed line (e.g. changing a
    length check in a caller can affect a crash in a callee).
  * Mere textual adjacency of a static warning to a change is NOT sufficient.
  * When evidence is insufficient, the correlation MUST be reported as
    'unclear' rather than asserting a link.

Confidence levels:
  strong  -- a crash frame lands on a changed line, or the crashing function
             is one the patch modified.
  weak    -- a crash frame is in a file the patch changed (or an immediate
             caller/callee is), but not at a changed line/function.
  unclear -- source frames exist but none touch changed code.
  none    -- no diff, or no usable source frames.
"""

from __future__ import annotations

from .crash import CrashInfo, Frame
from .diffparse import Diff, FileDiff
from .model import Correlation, CORR_STRONG, CORR_WEAK, CORR_UNCLEAR, CORR_NONE

# how many lines away from a changed line still counts as "near" (weak)
_NEAR = 3


def _source_frames(crash: CrashInfo) -> list[Frame]:
    out = []
    for f in crash.frames:
        if f.file is None:
            continue
        low = f.file.lower()
        if "sanitizer" in low or "libc" in low or "csu/" in low:
            continue
        if f.function and f.function.startswith(("__asan", "__ubsan", "__interceptor", "_start")):
            continue
        out.append(f)
    return out


def _line_on_change(fd: FileDiff, line: int) -> bool:
    return line in fd.added_lines


def _line_near_change(fd: FileDiff, line: int) -> bool:
    for s, e in fd.hunk_ranges:
        if s - _NEAR <= line <= e + _NEAR:
            return True
    for al in fd.added_lines:
        if abs(al - line) <= _NEAR:
            return True
    return False


def correlate(crash: CrashInfo, diff: Diff, side: str = "patched") -> Correlation:
    """Correlate a crash to the diff.

    `side` says which version produced the crash. Line-number matching is only
    meaningful for the *patched* side, because the diff's added-line numbers are
    in the new file's coordinate space. For a crash observed on the *base*
    version (e.g. explaining which change fixed it) we rely on file- and
    function-level matching and do not assert a spurious line hit.
    """
    use_lines = side != "base"
    if not diff.files:
        return Correlation(confidence=CORR_NONE,
                           explanation="no patch diff available to correlate against")

    frames = _source_frames(crash)
    if not frames:
        return Correlation(
            confidence=CORR_NONE,
            explanation="no symbolized source frames; cannot correlate to the diff",
        )

    changed_funcs: set[str] = set()
    for f in diff.files:
        changed_funcs.update(f.hunk_functions)

    matched_files: list[str] = []
    matched_funcs: list[str] = []
    matched_lines: list[str] = []
    strong = False
    weak = False

    for fr in frames:
        base = fr.file.split("/")[-1]
        fd = diff.by_basename(base)
        if fd is None:
            # function-name match even if file path differs
            if fr.function and fr.function in changed_funcs:
                strong = True
                matched_funcs.append(fr.function)
            continue
        matched_files.append(base)
        if use_lines and fr.line is not None and _line_on_change(fd, fr.line):
            strong = True
            matched_lines.append(f"{base}:{fr.line}")
        elif fr.function and (fr.function in fd.hunk_functions or fr.function in changed_funcs):
            strong = True
            matched_funcs.append(fr.function)
        elif use_lines and fr.line is not None and _line_near_change(fd, fr.line):
            weak = True
            matched_lines.append(f"{base}:{fr.line}(near)")
        else:
            weak = True  # crash is in a changed file but not at a changed site

    matched_files = sorted(set(matched_files))
    matched_funcs = sorted(set(matched_funcs))

    if strong:
        return Correlation(
            confidence=CORR_STRONG, matched_files=matched_files,
            matched_functions=matched_funcs, matched_lines=sorted(set(matched_lines)),
            explanation="a crash frame lands on code the patch changed "
                        "(changed line or modified function)",
        )
    if weak:
        return Correlation(
            confidence=CORR_WEAK, matched_files=matched_files,
            matched_functions=matched_funcs, matched_lines=sorted(set(matched_lines)),
            explanation="crash occurs in a file/region the patch touched but not "
                        "on a changed line or function; link is plausible but not proven",
        )
    return Correlation(
        confidence=CORR_UNCLEAR, matched_files=matched_files,
        matched_functions=matched_funcs, matched_lines=[],
        explanation="crash frames do not intersect the patched code; "
                    "correlation is unclear on available evidence",
    )
