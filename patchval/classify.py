"""Security and functional classification of patch behaviour.

Base and patched are compared ONLY in matching build modes (release vs
release, sanitized vs sanitized). For every security test and every mode,
each side is reduced to a state:

  base:    CRASH (confirmed evidence) | NOCRASH | UNCLASSIFIED
  patched: CRASH | CLEAN (exit code documented as graceful) | UNCLASSIFIED

and the pair gives a per-mode verdict:

  base \\ patched   CRASH                      CLEAN          UNCLASSIFIED
  CRASH            same id -> REMAINS          FIXED          INCONCLUSIVE
                   other id -> NEW_ISSUE
  NOCRASH          NEW_ISSUE                   NOT_TRIGGERED  INCONCLUSIVE
  UNCLASSIFIED     NEW_ISSUE (baseline unk.)   INCONCLUSIVE   INCONCLUSIVE

A timeout, resource-limit hit, non-security signal, or an undocumented
non-zero exit on the patched side is therefore never read as "fixed".
Mode verdicts combine with REMAINS > NEW_ISSUE > INCONCLUSIVE > FIXED >
NOT_TRIGGERED. A FIXED / REMAINS / NEW_ISSUE result must then survive the
mandatory replays (apply_stability) or it becomes INCONCLUSIVE.

The functional oracle is the expectation written in the config at design
time -- never the patched program's own output.
"""

from __future__ import annotations

from . import exitcodes
from .config import TestCase
from .crash import STATE_CRASH, STATE_UNCLASSIFIED, CrashInfo
from .model import (
    TestRecord, Execution, Finding,
    FIXED, VULN_REMAINS, INCOMPLETE_FIX, NEW_ISSUE, INCONCLUSIVE, NOT_TRIGGERED, STALE,
    FUNC_REGRESSION, FUNC_OK, FUNC_BASELINE_BROKEN,
)

MODES = ("sanitized", "release")

B_CRASH, B_NOCRASH, B_UNCL = "CRASH", "NOCRASH", "UNCLASSIFIED"
P_CRASH, P_CLEAN, P_UNCL = "CRASH", "CLEAN", "UNCLASSIFIED"


def _graceful(test: TestCase, default: list[int]) -> list[int]:
    return test.graceful_exit_codes if test.graceful_exit_codes is not None else default


def base_state(ex: Execution) -> tuple[str, str]:
    ci = ex.crash
    if ci.state == STATE_CRASH:
        return B_CRASH, ci.fingerprint
    if ci.state == STATE_UNCLASSIFIED:
        return B_UNCL, ci.unclassified_reason or "unclassified stop"
    return B_NOCRASH, f"exit {ex.run.exit_code}"


def patched_state(ex: Execution, graceful: list[int]) -> tuple[str, str]:
    ci = ex.crash
    if ci.state == STATE_CRASH:
        return P_CRASH, ci.fingerprint
    if ci.state == STATE_UNCLASSIFIED:
        return P_UNCL, ci.unclassified_reason or "unclassified stop"
    if ex.run.exit_code in graceful:
        return P_CLEAN, f"exit {ex.run.exit_code} (graceful)"
    return P_UNCL, (f"exit {ex.run.exit_code} is not a documented graceful exit "
                    f"code {graceful}; cannot adjudicate")


def same_crash(a: CrashInfo, b: CrashInfo) -> tuple[bool, str]:
    """Same vulnerability? error type + relative file + function (+ access).

    Line numbers are deliberately excluded (a patch shifts them). When either
    side has no symbolized source frame (e.g. a bare signal in a release build)
    only the error type can be compared, and the basis says so.
    """
    ia, ib = a.identity(), b.identity()
    if ia[0] != ib[0]:
        return False, "different error type"
    if ia[1] is None or ib[1] is None:
        return True, "type-only (no symbolized location on one side)"
    if (ia[1], ia[2]) != (ib[1], ib[2]):
        return False, "same type, different location"
    if ia[3] and ib[3] and ia[3] != ib[3]:
        return False, "same location, different access kind"
    return True, "type+file+function"


def _mode_verdict(b_ex: Execution, p_ex: Execution, graceful: list[int]) -> dict:
    bs, bd = base_state(b_ex)
    ps, pd = patched_state(p_ex, graceful)
    v, basis = None, None
    if bs == B_CRASH:
        if ps == P_CRASH:
            same, basis = same_crash(b_ex.crash, p_ex.crash)
            v = VULN_REMAINS if same else NEW_ISSUE
        elif ps == P_CLEAN:
            v = FIXED
        else:
            v = INCONCLUSIVE
    elif bs == B_NOCRASH:
        v = {P_CRASH: NEW_ISSUE, P_CLEAN: NOT_TRIGGERED}.get(ps, INCONCLUSIVE)
    else:
        # base gave no usable evidence in this mode. If patched is clean this
        # mode simply has no baseline (it must not veto another mode's FIXED);
        # an unclassified patched run still blocks.
        v = {P_CRASH: NEW_ISSUE, P_CLEAN: NO_BASELINE}.get(ps, INCONCLUSIVE)
    return {"verdict": v, "base_state": bs, "base_detail": bd,
            "patched_state": ps, "patched_detail": pd, "identity_basis": basis}


def identity_matches(expected, observed: tuple) -> tuple[bool, str]:
    """Compare a recorded regression identity (type, file, function, access)
    with the identity observed on base. Line numbers are never compared."""
    exp = tuple(expected) + (None,) * (4 - len(expected))
    if exp[0] != observed[0]:
        return False, f"error type {observed[0]!r} != recorded {exp[0]!r}"
    if exp[1] is not None and observed[1] is not None and exp[1] != observed[1]:
        return False, f"file {observed[1]!r} != recorded {exp[1]!r}"
    if exp[1] is not None and observed[1] is None:
        return False, f"no symbolized location (recorded {exp[1]!r})"
    if exp[2] is not None and observed[2] is not None and exp[2] != observed[2]:
        return False, f"function {observed[2]!r} != recorded {exp[2]!r}"
    if exp[3] and observed[3] and exp[3] != observed[3]:
        return False, f"access {observed[3]!r} != recorded {exp[3]!r}"
    return True, "identity matches the recorded one"


def _expected_mode(origin: dict) -> str:
    m = origin.get("expected_mode")
    if m in MODES:
        return m
    ident = origin.get("expected_identity") or []
    return "sanitized" if len(ident) > 1 and ident[1] else "release"


NO_BASELINE = "NO_BASELINE"
_ORDER = [VULN_REMAINS, NEW_ISSUE, INCONCLUSIVE, FIXED, NO_BASELINE, NOT_TRIGGERED]


def classify_security_test(record: TestRecord, default_graceful: list[int] = (0,)) -> Finding:
    graceful = _graceful(record.test, list(default_graceful))
    per_mode = {}
    for m in MODES:
        b, p = record.get("base", m), record.get("patched", m)
        if b is not None and p is not None:
            per_mode[m] = _mode_verdict(b, p, graceful)
    if not per_mode:
        return Finding(record.test.id, "security", INCONCLUSIVE,
                       note="no matching base/patched executions available")

    verdicts = [d["verdict"] for d in per_mode.values()]
    status = next(s for s in _ORDER if s in verdicts)
    decisive = next(m for m in MODES if m in per_mode and per_mode[m]["verdict"] == status)
    b_ex, p_ex = record.get("base", decisive), record.get("patched", decisive)

    if status in (VULN_REMAINS, NEW_ISSUE):
        evidence_ex = p_ex
    elif status == FIXED:
        evidence_ex = b_ex
    else:
        evidence_ex = None

    notes = {
        VULN_REMAINS: "same crash (" + str(per_mode[decisive]["identity_basis"]) +
                      ") still reproduces on the patched version",
        NEW_ISSUE: "patched version shows a confirmed crash that differs from / "
                   "is absent on the base version",
        FIXED: "crash reproduced on base is not observed on patched; patched exited "
               "gracefully (scope: this input, this suite)",
        NOT_TRIGGERED: "no crash on base or patched for this input",
        INCONCLUSIVE: "; ".join(f"{m}: base {d['base_state']} ({d['base_detail']}), "
                                f"patched {d['patched_state']} ({d['patched_detail']})"
                                for m, d in per_mode.items() if d["verdict"] == INCONCLUSIVE),
    }
    if status == NO_BASELINE:
        status = INCONCLUSIVE
        notes[INCONCLUSIVE] = ("base produced no classifiable evidence in any mode: " +
                               "; ".join(f"{m}: {d['base_detail']}" for m, d in per_mode.items()))
    identity_mismatch = None
    origin = record.test.regression_origin or {}
    if origin.get("expected_identity"):
        # An auto-generated regression test is only valid evidence if the base
        # still fails with the RECORDED error (type/file/function/access).
        em = _expected_mode(origin)
        bex = record.get("base", em)
        if bex is not None and bex.crash.state == STATE_CRASH:
            ok, why = identity_matches(origin["expected_identity"], bex.crash.identity())
            if not ok:
                identity_mismatch = f"[{em}] {why}"
        if identity_mismatch and status in (FIXED, VULN_REMAINS, NEW_ISSUE, NOT_TRIGGERED):
            status = INCONCLUSIVE
            notes[INCONCLUSIVE] = ("regression test: base crash differs from the recorded "
                                   "identity (" + identity_mismatch + "); not adjudicated")
    if status == NOT_TRIGGERED and record.test.is_known_crasher:
        status = INCONCLUSIVE
        notes[INCONCLUSIVE] = "known crasher did not reproduce on base in any build mode; " \
                              "baseline not established"
    if status == INCONCLUSIVE and record.test.regression_origin:
        # an auto-generated regression test whose recorded base differs from the
        # current base is stale, not evidence about this patch.
        if record.test.regression_origin.get("base_drift"):
            status = STALE
            notes[STALE] = "regression test recorded against a different base source; not adjudicated"

    f = Finding(
        test_id=record.test.id, axis="security", status=status,
        error_type=evidence_ex.crash.error_type if evidence_ex else None,
        detection=evidence_ex.crash.detection if evidence_ex else None,
        base_evidence=b_ex.crash.summary() if b_ex else None,
        patched_evidence=p_ex.crash.summary() if p_ex else None,
        note=notes.get(status, ""),
    )
    f.per_mode = per_mode
    f.decisive_mode = decisive
    bcrash = next((record.get("base", m) for m in MODES
                   if record.get("base", m) is not None
                   and record.get("base", m).crash.state == STATE_CRASH), None)
    f.base_identity = bcrash.crash.identity()[:3] if bcrash else None
    return f


# ----------------------------------------------------------------- functional

def oracle_pass(ex: Execution | None, test: TestCase) -> tuple[bool, str]:
    if ex is None:
        return False, "no execution"
    run = ex.run
    if run.timed_out:
        return False, "timed out"
    if ex.crash.state == STATE_CRASH:
        return False, f"crashed ({ex.crash.error_type})"
    expect_exit = test.expect_exit if test.expect_exit is not None else 0
    if run.exit_code != expect_exit:
        got = run.exit_code if run.exit_code is not None else f"signal {run.signal_name}"
        return False, f"exit {got} != expected {expect_exit}"
    if test.stdout_equals is not None and run.stdout != test.stdout_equals:
        return False, f"stdout {run.stdout[:80]!r} != expected {test.stdout_equals[:80]!r}"
    for needle in test.stdout_contains:
        if needle not in run.stdout:
            return False, f"stdout missing {needle!r}"
    for needle in test.stderr_contains:
        if needle not in run.stderr:
            return False, f"stderr missing {needle!r}"
    return True, "ok"


def classify_functional_test(record: TestRecord) -> list[Finding]:
    """Functional verdict (+ a security NEW_ISSUE if a valid input newly crashes)."""
    per_mode = {}
    for m in MODES:
        b, p = record.get("base", m), record.get("patched", m)
        if b is None or p is None:
            continue
        bo, br = oracle_pass(b, record.test)
        po, pr = oracle_pass(p, record.test)
        per_mode[m] = {"base_pass": bo, "base_reason": br,
                       "patched_pass": po, "patched_reason": pr}
    out: list[Finding] = []
    if not per_mode:
        out.append(Finding(record.test.id, "functional", FUNC_BASELINE_BROKEN,
                           note="no matching executions"))
        return out

    regress = [m for m, d in per_mode.items() if d["base_pass"] and not d["patched_pass"]]
    broken = [m for m, d in per_mode.items() if not d["base_pass"]]
    if regress:
        m = regress[0]
        status, note = FUNC_REGRESSION, (f"valid input passed on base but failed on patched "
                                          f"[{m}]: {per_mode[m]['patched_reason']}")
    elif broken:
        m = broken[0]
        status, note = FUNC_BASELINE_BROKEN, (f"baseline failed its own oracle [{m}]: "
                                               f"{per_mode[m]['base_reason']}")
    else:
        status, note = FUNC_OK, "behaviour preserved in every build mode"
    f = Finding(record.test.id, "functional", status, note=note)
    f.per_mode = per_mode
    out.append(f)

    # A valid/boundary input that crashes only on the patched version is a
    # confirmed NEW security issue, independent of the functional verdict.
    for m in MODES:
        b, p = record.get("base", m), record.get("patched", m)
        if b is None or p is None:
            continue
        if p.crash.state == STATE_CRASH and b.crash.state != STATE_CRASH:
            nf = Finding(f"{record.test.id}", "security", NEW_ISSUE,
                         error_type=p.crash.error_type, detection=p.crash.detection,
                         base_evidence=b.crash.summary(), patched_evidence=p.crash.summary(),
                         note=f"functional input crashes only on the patched version [{m}]")
            nf.per_mode = {m: {"verdict": NEW_ISSUE}}
            nf.decisive_mode = m
            out.append(nf)
            break
    return out


# ------------------------------------------------------------ post-processing

def apply_stability(f: Finding, runs: list[str], expected: str) -> None:
    """Fold the mandatory replay results into the verdict.

    runs: one token per replay; expected: the token every replay must yield.
    Any deviation turns the finding INCONCLUSIVE (unstable).
    """
    stable = len(runs) > 0 and all(r == expected for r in runs)
    f.stability = dict(f.stability or {}, replays=runs, expected=expected,
                       stable=stable, count=len(runs))
    if not stable:
        f.note = (f"UNSTABLE: was {f.status}; replays {runs} did not all match "
                  f"{expected!r}. " + f.note)
        f.status = INCONCLUSIVE


def refine_incomplete_fix(findings: list[Finding]) -> None:
    """VULN_REMAINS -> INCOMPLETE_FIX when another input exposing the SAME base
    vulnerability (error type + file + function) was FIXED by this patch."""
    fixed_ids = {tuple(f.base_identity) for f in findings
                 if f.axis == "security" and f.status == FIXED and f.base_identity}
    for f in findings:
        if f.axis == "security" and f.status == VULN_REMAINS and f.base_identity \
                and tuple(f.base_identity) in fixed_ids:
            f.status = INCOMPLETE_FIX
            f.note = ("one input exposing this vulnerability is blocked, but the same "
                      "vulnerability (same type/file/function) is still reachable via this input")


def aggregate_exit_code(findings: list[Finding], analysis_complete: bool) -> int:
    """30 > 10 > 20 > 40 > 0. PASS additionally requires that at least one known
    crasher was reproduced on base and stably FIXED on patched."""
    codes: list[int] = []
    baseline_fixed = False
    for f in findings:
        if f.axis == "security":
            if f.status in (VULN_REMAINS, INCOMPLETE_FIX, NEW_ISSUE):
                codes.append(exitcodes.VULN_OR_SECURITY)
            elif f.status == INCONCLUSIVE:
                codes.append(exitcodes.INCONCLUSIVE)
            elif f.status == FIXED:
                if f.stability is None or not f.stability.get("stable"):
                    codes.append(exitcodes.INCONCLUSIVE)   # never PASS unverified
                else:
                    baseline_fixed = True
        elif f.axis == "functional":
            if f.status == FUNC_REGRESSION:
                codes.append(exitcodes.FUNC_REGRESSION)
            elif f.status == FUNC_BASELINE_BROKEN:
                codes.append(exitcodes.INCONCLUSIVE)
    if not analysis_complete:
        codes.append(exitcodes.INCONCLUSIVE)
    if not baseline_fixed:
        codes.append(exitcodes.INCONCLUSIVE)
    return exitcodes.resolve(codes)
