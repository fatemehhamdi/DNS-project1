"""Security and functional classification of patch behaviour.

This module turns paired base/patched evidence into the finding categories the
brief mandates:

  * FIXED               -- a reproducible error seen on base is no longer
                           observed on the patched version within test scope.
  * VULN_REMAINS        -- the same error class still reproduces after patching.
  * INCOMPLETE_FIX      -- the original crasher is blocked, but a sibling input
                           of the same vulnerability class still triggers it.
  * NEW_ISSUE           -- a confirmed crash appears on patched that did not
                           occur on base.
  * FUNC_REGRESSION     -- a valid input that passed its independent oracle on
                           base fails on the patched version.
  * INCONCLUSIVE        -- baseline not reproduced, unstable finding, or an
                           unclassified stop; evidence is insufficient to judge.

Guardrails from the brief that are enforced here:
  - The patched binary's *own* output is never the correctness oracle; a
    functional verdict compares against the test's independent expectation.
  - A single unclassified stop (timeout / bare non-zero exit with no crash
    evidence) does NOT confirm a vulnerability.
  - "Not observed in tests" is scope-limited, not a proof of absence.
  - Base and patched are always compared in *matching* build modes.
"""

from __future__ import annotations

from . import exitcodes
from .config import TestCase
from .crash import (
    CrashInfo, DET_ASAN, DET_UBSAN, DET_CANARY, DET_FORTIFY, DET_SIGNAL,
)
from .model import (
    TestRecord, Execution, Finding,
    FIXED, VULN_REMAINS, INCOMPLETE_FIX, NEW_ISSUE, INCONCLUSIVE,
    FUNC_REGRESSION, FUNC_OK, FUNC_BASELINE_BROKEN,
)

# Build modes
_SAN = "sanitized"
_REL = "release"

# Detection mechanisms that constitute *confirmed* security evidence
# (an unclassified bare SIGSEGV still counts as a memory-safety crash, but a
# plain non-zero exit or a timeout does not).
_CONFIRMING = {DET_ASAN, DET_UBSAN, DET_CANARY, DET_FORTIFY, DET_SIGNAL}


def _evidence(execs: dict, version: str) -> Execution | None:
    """Preferred representative execution for a version: sanitized first
    (richer, symbolized evidence), else release."""
    return execs.get((version, _SAN)) or execs.get((version, _REL))


def _confirmed_crash(ex: Execution | None) -> bool:
    if ex is None:
        return False
    ci = ex.crash
    if not ci.is_crash:
        return False
    # A bare SIGSEGV/SIGABRT with no sanitizer context is still a real crash,
    # but a resource limit or timeout is not.
    if ci.resource_limited or ci.timed_out:
        return False
    return ci.detection in _CONFIRMING


def _crash_in_any_mode(record: TestRecord, version: str) -> tuple[bool, Execution | None]:
    """A crash counts if observed in *either* matching build mode."""
    best = None
    for mode in (_SAN, _REL):
        ex = record.get(version, mode)
        if ex is not None and _confirmed_crash(ex):
            # prefer the one with source frames
            if best is None or (ex.crash.frames and not best.crash.frames):
                best = ex
    return (best is not None), best


def _same_vuln_class(a: CrashInfo, b: CrashInfo) -> bool:
    """Heuristic: same error type, and (if both have source frames) same top
    source location. Used to decide VULN_REMAINS vs NEW_ISSUE."""
    if a.error_type != b.error_type:
        return False
    # If both pin a source location, require it to match; otherwise accept the
    # type-level match (common for release-only bare signals).
    fa = a.frames[0] if a.frames else None
    fb = b.frames[0] if b.frames else None
    if fa and fb and fa.file and fb.file:
        same_file = fa.file.split("/")[-1] == fb.file.split("/")[-1]
        return same_file
    return True


# --- functional oracle ----------------------------------------------------

def oracle_pass(ex: Execution | None, test: TestCase) -> tuple[bool, str]:
    """Check an execution against the test's *independent* expectation.

    Importantly this never consults the patched version's output as truth;
    `test` carries the reference expectation defined at design time.
    """
    if ex is None:
        return False, "no execution"
    run = ex.run
    if run.timed_out:
        return False, "timed out"
    expect_exit = test.expect_exit if test.expect_exit is not None else 0
    if run.exit_code != expect_exit:
        got = run.exit_code if run.exit_code is not None else f"signal {run.signal_name}"
        return False, f"exit {got} != expected {expect_exit}"
    if test.stdout_equals is not None and run.stdout != test.stdout_equals:
        return False, "stdout did not equal expected"
    for needle in test.stdout_contains:
        if needle not in run.stdout:
            return False, f"stdout missing {needle!r}"
    for needle in test.stderr_contains:
        if needle not in run.stderr:
            return False, f"stderr missing {needle!r}"
    return True, "ok"


# --- per-test classification ----------------------------------------------

def classify_security_test(record: TestRecord) -> Finding:
    base_obs, base_ex = _crash_in_any_mode(record, "base")
    patched_obs, patched_ex = _crash_in_any_mode(record, "patched")

    base_ev = base_ex.crash.summary() if base_ex else (
        _evidence(record.executions, "base").crash.summary()
        if _evidence(record.executions, "base") else None)
    patched_ev = patched_ex.crash.summary() if patched_ex else (
        _evidence(record.executions, "patched").crash.summary()
        if _evidence(record.executions, "patched") else None)

    err = (base_ex or patched_ex).crash.error_type if (base_ex or patched_ex) else None
    det = (base_ex or patched_ex).crash.detection if (base_ex or patched_ex) else None

    if not base_obs:
        # Baseline did not reproduce the error for this input.
        if patched_obs:
            # Crash on patched but not base -> a genuinely new, confirmed issue.
            return Finding(
                test_id=record.test.id, axis="security", status=NEW_ISSUE,
                error_type=patched_ex.crash.error_type,
                detection=patched_ex.crash.detection,
                base_evidence=base_ev, patched_evidence=patched_ev,
                note="crash confirmed on patched version but not reproduced on base",
            )
        # Neither crashed. For a designated known crasher this is a problem
        # (can't establish a baseline); otherwise it's simply a clean input.
        if record.test.is_known_crasher:
            return Finding(
                test_id=record.test.id, axis="security", status=INCONCLUSIVE,
                error_type=None, detection=None,
                base_evidence=base_ev, patched_evidence=patched_ev,
                note="known crasher did not reproduce on base; baseline not established",
            )
        return Finding(
            test_id=record.test.id, axis="security", status=FIXED,
            error_type=None, detection=None,
            base_evidence=base_ev, patched_evidence=patched_ev,
            note="no crash on base or patched for this security input",
        )

    # base_obs is True from here.
    if patched_obs:
        if _same_vuln_class(base_ex.crash, patched_ex.crash):
            return Finding(
                test_id=record.test.id, axis="security", status=VULN_REMAINS,
                error_type=patched_ex.crash.error_type,
                detection=patched_ex.crash.detection,
                base_evidence=base_ev, patched_evidence=patched_ev,
                note="same error class still reproduces after patching",
            )
        # Different class on patched -> original may be gone but a new one appeared.
        return Finding(
            test_id=record.test.id, axis="security", status=NEW_ISSUE,
            error_type=patched_ex.crash.error_type,
            detection=patched_ex.crash.detection,
            base_evidence=base_ev, patched_evidence=patched_ev,
            note="patched version crashes with a different error class than base",
        )

    # base crashed, patched did not -> fixed for this input.
    return Finding(
        test_id=record.test.id, axis="security", status=FIXED,
        error_type=base_ex.crash.error_type, detection=base_ex.crash.detection,
        base_evidence=base_ev, patched_evidence=patched_ev,
        note="error reproduced on base is no longer observed on patched (this input)",
    )


def classify_functional_test(record: TestRecord) -> Finding:
    # Functional correctness is judged on the normal (release) binary first;
    # fall back to sanitized only if release is unavailable.
    base_ex = record.get("base", _REL) or record.get("base", _SAN)
    patched_ex = record.get("patched", _REL) or record.get("patched", _SAN)

    base_ok, base_reason = oracle_pass(base_ex, record.test)
    patched_ok, patched_reason = oracle_pass(patched_ex, record.test)

    base_ev = {"oracle_pass": base_ok, "reason": base_reason,
               "exit_code": base_ex.run.exit_code if base_ex else None,
               "signal": base_ex.run.signal_name if base_ex else None}
    patched_ev = {"oracle_pass": patched_ok, "reason": patched_reason,
                  "exit_code": patched_ex.run.exit_code if patched_ex else None,
                  "signal": patched_ex.run.signal_name if patched_ex else None}

    if not base_ok:
        return Finding(
            test_id=record.test.id, axis="functional", status=FUNC_BASELINE_BROKEN,
            base_evidence=base_ev, patched_evidence=patched_ev,
            note=f"baseline failed its own oracle ({base_reason}); cannot attribute to patch",
        )
    if base_ok and not patched_ok:
        return Finding(
            test_id=record.test.id, axis="functional", status=FUNC_REGRESSION,
            base_evidence=base_ev, patched_evidence=patched_ev,
            note=f"valid input passed on base but failed on patched ({patched_reason})",
        )
    return Finding(
        test_id=record.test.id, axis="functional", status=FUNC_OK,
        base_evidence=base_ev, patched_evidence=patched_ev,
        note="behaviour preserved on patched",
    )


# --- suite aggregation ----------------------------------------------------

def refine_incomplete_fix(findings: list[Finding]) -> None:
    """Relabel VULN_REMAINS as INCOMPLETE_FIX when at least one sibling of the
    same error class was FIXED -- i.e. the patch addressed one entry point but
    the same vulnerability class is still reachable via another input."""
    fixed_classes = {
        f.error_type for f in findings
        if f.axis == "security" and f.status == FIXED and f.error_type
    }
    for f in findings:
        if f.axis == "security" and f.status == VULN_REMAINS and f.error_type in fixed_classes:
            f.status = INCOMPLETE_FIX
            f.note = ("original entry point fixed, but the same vulnerability "
                      "class is still reachable via a different input")


def aggregate_exit_code(findings: list[Finding], analysis_complete: bool) -> int:
    """Collapse all findings into a single CI exit code using the documented
    priority 40 > 20 > 10 > 30 > 0."""
    codes: list[int] = []
    security_conclusive = False
    baseline_reproduced = False

    for f in findings:
        if f.axis == "security":
            if f.status in (VULN_REMAINS, INCOMPLETE_FIX, NEW_ISSUE):
                codes.append(exitcodes.VULN_OR_SECURITY)
                security_conclusive = True
            elif f.status == FIXED and f.error_type is not None:
                baseline_reproduced = True
                security_conclusive = True
            elif f.status == INCONCLUSIVE:
                codes.append(exitcodes.INCONCLUSIVE)
        elif f.axis == "functional":
            if f.status == FUNC_REGRESSION:
                codes.append(exitcodes.FUNC_REGRESSION)
            elif f.status == FUNC_BASELINE_BROKEN:
                codes.append(exitcodes.INCONCLUSIVE)

    if not analysis_complete:
        codes.append(exitcodes.INCONCLUSIVE)

    # If no security finding ever established a baseline crash and nothing
    # else fired, we cannot claim PASS honestly.
    if not security_conclusive and not codes:
        codes.append(exitcodes.INCONCLUSIVE)

    return exitcodes.resolve(codes)
