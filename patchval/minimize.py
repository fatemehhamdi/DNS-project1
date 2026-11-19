"""Automatic test-case minimization (delta debugging).

Preservation criterion (brief sec. 3.3): the reduced input must produce the
SAME kind of error at the SAME location -- a non-zero exit is not enough.
The predicate re-runs the candidate (inside the sandbox) on the same binary
and requires an identical crash identity (error type, relative file,
function, access kind) AND the same faulting line (same binary, so line
numbers are comparable).
"""

from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable

from . import runner, crash
from .config import Config, TestCase
from .crash import CrashInfo, STATE_CRASH
from .sandbox import Sandbox


@dataclass
class MinimizeResult:
    original_size: int
    minimized_size: int
    minimized_path: str
    original_path: str
    iterations: int
    preserved_signature: str
    replays: list[str] = field(default_factory=list)
    stable: bool = False
    budget_exhausted: bool = False


def signature(ci: CrashInfo) -> str:
    if ci.state != STATE_CRASH:
        return f"NOCRASH:{ci.state}"
    top = ci.top_source_frame()
    line = top.line if top else None
    return "|".join(str(x) for x in ci.identity()) + f"|L{line}"


def make_predicate(binary: str, cfg: Config, test: TestCase, target_sig: str, san: bool,
                   sandbox: Sandbox | None, source_root: str,
                   extra: Callable[[str], bool] | None = None) -> Callable[[bytes], bool]:
    """extra(path) -> bool is an additional condition on the candidate input
    (e.g. 'the patched binary still exits cleanly'), evaluated only if the
    primary crash signature is preserved."""
    def pred(data: bytes) -> bool:
        if not data:
            return False
        fd, tmp = tempfile.mkstemp(suffix=".in")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            r = runner.run(binary, cfg, test, san, input_path=tmp, sandbox=sandbox)
            if signature(crash.analyze(r, san, source_root)) != target_sig:
                return False
            return extra(tmp) if extra is not None else True
        finally:
            os.unlink(tmp)
    return pred


def _ddmin(data: bytes, pred, deadline: float) -> tuple[bytes, int, bool]:
    iters, n, cur = 0, 2, data
    while len(cur) >= 2:
        chunk = max(1, len(cur) // n)
        start, removed = 0, False
        while start < len(cur):
            if time.monotonic() > deadline:
                return cur, iters, True
            cand = cur[:start] + cur[start + chunk:]
            iters += 1
            if cand and pred(cand):
                cur, removed = cand, True
                n = max(n - 1, 2)
            else:
                start += chunk
        if not removed:
            if n >= len(cur):
                break
            n = min(len(cur), n * 2)
    return cur, iters, False


def minimize(binary: str, cfg: Config, test: TestCase, original: CrashInfo, san: bool,
             out_dir: str, sandbox: Sandbox | None, source_root: str,
             budget_sec: float = 120.0,
             extra: Callable[[str], bool] | None = None) -> MinimizeResult | None:
    if test.input_file is None or not os.path.isfile(test.input_file):
        return None
    with open(test.input_file, "rb") as fh:
        data = fh.read()
    target_sig = signature(original)
    pred = make_predicate(binary, cfg, test, target_sig, san, sandbox, source_root, extra)
    if not pred(data):
        return None
    deadline = time.monotonic() + budget_sec
    small, iters, exhausted = _ddmin(data, pred, deadline)
    # final single-byte sweep
    i = 0
    buf = bytearray(small)
    while i < len(buf) and time.monotonic() < deadline:
        cand = bytes(buf[:i] + buf[i + 1:])
        if cand and pred(cand):
            del buf[i]
        else:
            i += 1
    small = bytes(buf)

    os.makedirs(out_dir, exist_ok=True)
    orig_p = os.path.join(out_dir, f"{test.id}.orig.bin")
    min_p = os.path.join(out_dir, f"{test.id}.min.bin")
    with open(orig_p, "wb") as fh:
        fh.write(data)
    with open(min_p, "wb") as fh:
        fh.write(small)

    reps = []
    for _ in range(max(3, cfg.replays)):
        r = runner.run(binary, cfg, test, san, input_path=min_p, sandbox=sandbox)
        sig = signature(crash.analyze(r, san, source_root))
        if extra is not None and not extra(min_p):
            sig = "OTHER_SIDE_CHANGED"
        reps.append(sig)
    return MinimizeResult(len(data), len(small), min_p, orig_p, iters, target_sig,
                          reps, all(x == target_sig for x in reps), exhausted)
