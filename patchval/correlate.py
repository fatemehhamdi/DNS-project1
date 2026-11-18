"""Patch-to-finding correlation (brief sec. 3.1).

Inputs: the crash's stack frames (already normalized to paths RELATIVE to the
source root of the version that crashed) and the Diff (relative paths, base-
and patched-side line numbers, changed functions per side).

Matching uses exact normalized relative paths -- never basenames -- so
src/a/parser.c and src/b/parser.c are different files.

Relations, from strongest to weakest:
  crash_site_line      the faulting frame is on a changed line            -> strong
  crash_site_function  the faulting function was modified by the patch   -> strong
  caller_function      a caller on the crashing call path was modified   -> strong
                       only if behaviour differs between versions
                       (differential evidence, e.g. FIXED); otherwise weak
  file_only            a frame is in a changed file, no changed code on
                       the path                                          -> weak
  (none)               frames do not touch changed code                  -> unclear
"""

from __future__ import annotations

from .crash import CrashInfo
from .diffparse import Diff
from .model import Correlation, CORR_STRONG, CORR_WEAK, CORR_UNCLEAR, CORR_NONE

_CALLER_DEPTH = 6


def correlate(crash: CrashInfo, diff: Diff, side: str = "patched",
              differential: bool = False) -> Correlation:
    """side: which version produced the crash ('base' or 'patched')."""
    if not diff.files:
        return Correlation(CORR_NONE, explanation="no patch diff available", side=side)
    frames = [f for f in crash.frames if f.relpath is not None]
    if not frames:
        return Correlation(CORR_NONE, side=side,
                           explanation="no symbolized frames inside the project source; "
                                       "correlation impossible on this evidence")

    def lines_of(fd):
        return fd.old_changed if side == "base" else fd.new_changed

    def funcs_of(fd):
        return fd.old_functions if side == "base" else fd.new_functions

    top = frames[0]
    callers = frames[1:_CALLER_DEPTH]
    persists = "" if differential else \
        " -- yet the crash still occurs on the patched version, so the change does not cover this input path"
    touched_files = sorted({f.relpath for f in frames if diff.get(f.relpath)})

    fd = diff.get(top.relpath)
    if fd is not None:
        if top.line is not None and top.line in lines_of(fd):
            return Correlation(CORR_STRONG, [top.relpath], [top.function or "?"],
                               [f"{top.relpath}:{top.line}"], relation="crash_site_line",
                               side=side,
                               explanation=f"the faulting access ({top.function} at "
                                           f"{top.relpath}:{top.line}) is on a line the patch changed"
                                           + persists)
        if top.function and top.function in funcs_of(fd):
            return Correlation(CORR_STRONG, [top.relpath], [top.function], [],
                               relation="crash_site_function", side=side,
                               explanation=f"the faulting function {top.function} "
                                           f"({top.relpath}) was modified by the patch" + persists)

    for fr in callers:
        cfd = diff.get(fr.relpath)
        if cfd is not None and fr.function and fr.function in funcs_of(cfd):
            if differential:
                return Correlation(
                    CORR_STRONG, touched_files, [fr.function], [], relation="caller_function",
                    side=side,
                    explanation=(f"the crash manifests in {top.function} ({top.relpath}:{top.line}) "
                                 f"which the patch did not change, but the patch modified its caller "
                                 f"{fr.function} on the same call path, and the crash outcome differs "
                                 f"between base and patched: the fix is in the caller"))
            return Correlation(
                CORR_WEAK, touched_files, [fr.function], [], relation="caller_function",
                side=side,
                explanation=(f"the patch modified {fr.function}, a caller on the crashing path, "
                             f"but the crash in {top.function} still occurs: the change does not "
                             f"cover this input"))

    if touched_files:
        return Correlation(CORR_WEAK, touched_files, [], [], relation="file_only", side=side,
                           explanation="crash frames are in a file the patch changed, but no "
                                       "changed line/function lies on the crashing call path")
    return Correlation(CORR_UNCLEAR, [], [], [], side=side,
                       explanation="crash frames do not intersect the patched code; the link "
                                   "is unclear on the available evidence")
