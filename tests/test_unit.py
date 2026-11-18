"""Unit tests for patchval's pure-logic modules (fast, no compilation)."""

import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchval import exitcodes, diffparse, crash, classify
from patchval.config import load, ConfigError
from patchval.runner import RunResult
from patchval.crash import CrashInfo, Frame
from patchval.model import (TestRecord, Execution, FIXED, VULN_REMAINS,
                            INCOMPLETE_FIX, NEW_ISSUE, INCONCLUSIVE,
                            FUNC_REGRESSION, FUNC_OK)
from patchval.config import TestCase


# ---------------- exit codes ----------------

def test_exitcode_priority():
    assert exitcodes.resolve([0]) == 0
    assert exitcodes.resolve([0, 20]) == 20
    assert exitcodes.resolve([0, 20, 10]) == 10
    assert exitcodes.resolve([10, 20, 30, 40]) == 30   # build error wins
    assert exitcodes.resolve([20, 40]) == 20           # regression over inconclusive
    assert exitcodes.resolve([40, 0]) == 40
    assert exitcodes.resolve([]) == 0


# ---------------- diff parsing ----------------

_SAMPLE_DIFF = textwrap.dedent("""\
    diff --git a/foo.c b/foo.c
    --- a/foo.c
    +++ b/foo.c
    @@ -10,6 +10,7 @@ void store_value(char *d)
         int j = 0;
    -    for (p = s; *p; ++p) d[j++] = *p;
    +    for (p = s; *p; ++p)
    +        if (j < 31) d[j++] = *p;
         d[j] = 0;
    """)


def test_diff_parse_added_lines_and_function():
    d = diffparse.parse(_SAMPLE_DIFF)
    fd = d.by_basename("foo.c")
    assert fd is not None
    assert "store_value" in fd.hunk_functions
    # the two '+' lines are added at new-file lines 11 and 12
    assert 11 in fd.added_lines and 12 in fd.added_lines


# ---------------- crash analysis ----------------

def _rr(stderr="", signal_name=None, signal_num=None, exit_code=0, timed_out=False, oom=False):
    return RunResult(
        test_id="t", returncode=exit_code, exit_code=exit_code,
        signal_num=signal_num, signal_name=signal_name, stdout="",
        stderr=stderr, wall_time=0.01, timed_out=timed_out, oom_or_rlimit=oom,
        command=["x"], input_desc="stdin",
    )


def test_crash_asan_heap_overflow_parsed():
    se = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..\n"
          "    #0 0x1 in accumulate /src/csvsum.c:20:5\n"
          "    #1 0x2 in process_row /src/csvsum.c:40:9\n")
    ci = crash.analyze(_rr(stderr=se, signal_name="SIGABRT", signal_num=6), True)
    assert ci.is_crash
    assert ci.error_type == "heap-buffer-overflow"
    assert ci.detection == crash.DET_ASAN
    assert ci.frames[0].function == "accumulate"
    assert ci.frames[0].line == 20


def test_crash_canary_vs_fortify():
    ci1 = crash.analyze(_rr(stderr="*** stack smashing detected ***: terminated",
                            signal_name="SIGABRT", signal_num=6), False)
    assert ci1.detection == crash.DET_CANARY
    ci2 = crash.analyze(_rr(stderr="*** buffer overflow detected ***: terminated",
                            signal_name="SIGABRT", signal_num=6), False)
    assert ci2.detection == crash.DET_FORTIFY


def test_timeout_is_not_a_crash():
    ci = crash.analyze(_rr(timed_out=True), True)
    assert not ci.is_crash
    assert ci.timed_out


def test_bare_sigsegv_is_crash_but_resource_limit_is_not():
    ci = crash.analyze(_rr(signal_name="SIGSEGV", signal_num=11), False)
    assert ci.is_crash and ci.error_type == crash.ET_SEGV
    ci2 = crash.analyze(_rr(signal_name="SIGKILL", signal_num=9, oom=True), False)
    assert not ci2.is_crash and ci2.resource_limited


# ---------------- classification ----------------

def _exec(version, mode, crashinfo, exit_code=0, stdout=""):
    rr = RunResult(test_id="t", returncode=exit_code, exit_code=exit_code,
                   signal_num=None, signal_name=None, stdout=stdout, stderr="",
                   wall_time=0.0, timed_out=False, oom_or_rlimit=False,
                   command=["x"], input_desc="")
    return Execution(version, mode, rr, crashinfo)


def _crash(et="heap-buffer-overflow", file="t.c", line=10):
    ci = CrashInfo(is_crash=True, error_type=et, detection=crash.DET_ASAN)
    ci.frames = [Frame(0, "f", file, line, "raw")]
    return ci


def _nocrash():
    return CrashInfo(is_crash=False, error_type="unknown", detection=crash.DET_NONE)


def test_security_fixed_when_base_crashes_patched_clean():
    t = TestCase(id="c", input_file=None, kind="security", is_known_crasher=True)
    rec = TestRecord(test=t)
    rec.executions[("base", "sanitized")] = _exec("base", "sanitized", _crash())
    rec.executions[("patched", "sanitized")] = _exec("patched", "sanitized", _nocrash())
    f = classify.classify_security_test(rec)
    assert f.status == FIXED


def test_security_vuln_remains_when_both_crash_same_class():
    t = TestCase(id="c", input_file=None, kind="security", is_known_crasher=True)
    rec = TestRecord(test=t)
    rec.executions[("base", "sanitized")] = _exec("base", "sanitized", _crash())
    rec.executions[("patched", "sanitized")] = _exec("patched", "sanitized", _crash())
    f = classify.classify_security_test(rec)
    assert f.status == VULN_REMAINS


def test_security_new_issue_when_patched_only():
    t = TestCase(id="c", input_file=None, kind="security", is_known_crasher=True)
    rec = TestRecord(test=t)
    rec.executions[("base", "sanitized")] = _exec("base", "sanitized", _nocrash())
    rec.executions[("patched", "sanitized")] = _exec("patched", "sanitized", _crash())
    f = classify.classify_security_test(rec)
    assert f.status == NEW_ISSUE


def test_incomplete_fix_relabelling():
    t1 = TestCase(id="c1", input_file=None, kind="security", is_known_crasher=True)
    t2 = TestCase(id="c2", input_file=None, kind="security", is_known_crasher=True)
    r1 = TestRecord(test=t1)
    r1.executions[("base", "sanitized")] = _exec("base", "sanitized", _crash())
    r1.executions[("patched", "sanitized")] = _exec("patched", "sanitized", _nocrash())
    r2 = TestRecord(test=t2)
    r2.executions[("base", "sanitized")] = _exec("base", "sanitized", _crash())
    r2.executions[("patched", "sanitized")] = _exec("patched", "sanitized", _crash())
    findings = [classify.classify_security_test(r1), classify.classify_security_test(r2)]
    classify.refine_incomplete_fix(findings)
    statuses = {f.test_id: f.status for f in findings}
    assert statuses["c1"] == FIXED
    assert statuses["c2"] == INCOMPLETE_FIX


def test_functional_regression_detection():
    t = TestCase(id="v", input_file=None, kind="valid", expect_exit=0,
                 stdout_contains=["OK"])
    rec = TestRecord(test=t)
    rec.executions[("base", "release")] = _exec("base", "release", _nocrash(), 0, "OK\n")
    rec.executions[("patched", "release")] = _exec("patched", "release", _nocrash(), 0, "BAD\n")
    f = classify.classify_functional_test(rec)
    assert f.status == FUNC_REGRESSION


def test_functional_ok():
    t = TestCase(id="v", input_file=None, kind="valid", expect_exit=0,
                 stdout_contains=["OK"])
    rec = TestRecord(test=t)
    rec.executions[("base", "release")] = _exec("base", "release", _nocrash(), 0, "OK\n")
    rec.executions[("patched", "release")] = _exec("patched", "release", _nocrash(), 0, "OK\n")
    f = classify.classify_functional_test(rec)
    assert f.status == FUNC_OK


def test_inconclusive_when_baseline_not_reproduced():
    t = TestCase(id="c", input_file=None, kind="security", is_known_crasher=True)
    rec = TestRecord(test=t)
    rec.executions[("base", "sanitized")] = _exec("base", "sanitized", _nocrash())
    rec.executions[("patched", "sanitized")] = _exec("patched", "sanitized", _nocrash())
    f = classify.classify_security_test(rec)
    assert f.status == INCONCLUSIVE


# ---------------- config validation ----------------

def test_config_missing_file():
    with pytest.raises(ConfigError):
        load("/nonexistent/x.yaml")


def test_config_rejects_missing_versions(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("name: x\nbuild:\n  command: gcc\n  binary: a\n")
    with pytest.raises(ConfigError):
        load(str(cfg))
