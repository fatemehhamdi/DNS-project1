"""Unit tests for crash evidence, patch diffs, and verdicts."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchval import classify, correlate, crash, diffparse, exitcodes
from patchval.config import ConfigError, TestCase, load
from patchval.crash import CrashInfo, Frame
from patchval.model import (Execution, Finding, TestRecord, FIXED, FUNC_OK,
                            FUNC_REGRESSION, INCOMPLETE_FIX, INCONCLUSIVE,
                            NEW_ISSUE, VULN_REMAINS)
from patchval.runner import RunResult


def rr(**kw):
    d = dict(test_id="t", returncode=0, exit_code=0, signal_num=None, signal_name=None,
             stdout="", stderr="", wall_time=0.0, timed_out=False, oom_or_rlimit=False,
             command=["x"], input_desc="stdin")
    d.update(kw)
    return RunResult(**d)


def asan_crash(func="f", rel="t.c", line=10, et="heap-buffer-overflow", access="WRITE"):
    ci = CrashInfo(True, et, crash.DET_ASAN, state=crash.STATE_CRASH, access=access)
    ci.frames = [Frame(0, func, "/src/" + rel, line, "", relpath=rel)]
    ci.fingerprint = f"{et}|{func}@{rel}:{line}"
    return ci


def ex(version, mode, ci, run=None):
    return Execution(version, mode, run or rr(), ci)


def clean():
    return CrashInfo(False, "unknown", crash.DET_NONE, state=crash.STATE_CLEAN)


def sec_record(base_ci, patched_ci, patched_run=None, graceful=None, modes=("sanitized",)):
    t = TestCase(id="c", input_file=None, kind="security", is_known_crasher=True,
                 graceful_exit_codes=graceful)
    rec = TestRecord(test=t)
    for m in modes:
        rec.executions[("base", m)] = ex("base", m, base_ci)
        rec.executions[("patched", m)] = ex("patched", m, patched_ci, patched_run)
    return rec


def stable(f):
    classify.apply_stability(f, ["ok", "ok", "ok"], "ok")
    return f


def test_defect1_timeout_on_patched_is_never_fixed_or_pass():
    to = rr(timed_out=True, exit_code=None)
    rec = sec_record(asan_crash(), crash.analyze(to, True), patched_run=to)
    f = classify.classify_security_test(rec)
    assert f.status == INCONCLUSIVE
    assert classify.aggregate_exit_code([f], True) == exitcodes.INCONCLUSIVE


def test_defect1b_undocumented_nonzero_exit_is_inconclusive():
    r7 = rr(exit_code=7, returncode=7)
    rec = sec_record(asan_crash(), crash.analyze(r7, True), patched_run=r7)
    f = classify.classify_security_test(rec)
    assert f.status == INCONCLUSIVE
    assert classify.aggregate_exit_code([f], True) == exitcodes.INCONCLUSIVE


def test_defect1c_documented_graceful_exit_is_fixed():
    r7 = rr(exit_code=7, returncode=7)
    rec = sec_record(asan_crash(), crash.analyze(r7, True), patched_run=r7, graceful=[0, 7])
    assert classify.classify_security_test(rec).status == FIXED


def test_defect2_same_basename_different_directory_is_not_strong():
    d = diffparse.parse("--- a/src/a/parser.c\n+++ b/src/a/parser.c\n@@ -1,2 +1,3 @@\n x\n+y\n z\n")
    ci = asan_crash(func="parse", rel="src/b/parser.c", line=2)
    c = correlate.correlate(ci, d, side="patched")
    assert c.confidence == "unclear"
    assert c.matched_files == []


def test_defect2b_frame_paths_are_normalized_relative_to_root(tmp_path):
    root = tmp_path / "proj"
    (root / "src" / "b").mkdir(parents=True)
    fr = [Frame(0, "parse", str(root / "src" / "b" / "parser.c"), 3, ""),
          Frame(1, "x", "/usr/include/stdio.h", 1, "")]
    crash.normalize_frames(fr, str(root))
    assert fr[0].relpath == os.path.join("src", "b", "parser.c")
    assert fr[1].relpath is None          # outside the project: excluded


def test_defect2c_crash_identity_uses_location_not_just_file():
    a = asan_crash(func="parse_a", rel="p.c", line=10)
    b = asan_crash(func="parse_b", rel="p.c", line=10)
    same, _ = classify.same_crash(a, b)
    assert not same


def test_defect3_unstable_replay_cannot_pass():
    rec = sec_record(asan_crash(), clean())
    f = classify.classify_security_test(rec)
    assert f.status == FIXED
    classify.apply_stability(f, ["ok", "patched#2:CRASH:x", "ok"], "ok")
    assert f.status == INCONCLUSIVE
    assert classify.aggregate_exit_code([f], True) == exitcodes.INCONCLUSIVE


def test_defect3b_fixed_without_replays_cannot_pass():
    f = Finding("c", "security", FIXED, error_type="x")     # stability never measured
    assert classify.aggregate_exit_code([f], True) == exitcodes.INCONCLUSIVE


def test_defect4_sigterm_is_not_a_security_crash():
    ci = crash.analyze(rr(signal_name="SIGTERM", signal_num=15, exit_code=None), False)
    assert not ci.is_crash and ci.state == crash.STATE_UNCLASSIFIED


def test_defect4b_bare_abort_without_evidence_is_unclassified():
    ci = crash.analyze(rr(signal_name="SIGABRT", signal_num=6, exit_code=None,
                          stderr="prog: x.c:3: main: Assertion `0' failed."), False)
    assert ci.state == crash.STATE_UNCLASSIFIED


def test_defect4c_segv_and_glibc_heap_check_are_crashes():
    assert crash.analyze(rr(signal_name="SIGSEGV", signal_num=11, exit_code=None), False).is_crash
    ci = crash.analyze(rr(signal_name="SIGABRT", signal_num=6, exit_code=None,
                          stderr="malloc(): corrupted top size\n"), False)
    assert ci.is_crash and ci.detection == crash.DET_HEAP_CHECK


def test_exitcode_priority():
    assert exitcodes.resolve([0]) == 0
    assert exitcodes.resolve([0, 20, 10]) == 10
    assert exitcodes.resolve([10, 20, 30, 40]) == 30
    assert exitcodes.resolve([20, 40]) == 20
    assert exitcodes.resolve([40, 0]) == 40


def test_vuln_remains_and_new_issue():
    f = classify.classify_security_test(sec_record(asan_crash(), asan_crash()))
    assert f.status == VULN_REMAINS
    f = classify.classify_security_test(sec_record(asan_crash(), asan_crash(func="other")))
    assert f.status == NEW_ISSUE
    rec = sec_record(clean(), asan_crash())
    rec.test.is_known_crasher = False
    assert classify.classify_security_test(rec).status == NEW_ISSUE


def test_matching_modes_only_and_patched_side_inconclusive_dominates():
    t = TestCase(id="c", input_file=None, kind="security", is_known_crasher=True)
    rec = TestRecord(test=t)
    rec.executions[("base", "sanitized")] = ex("base", "sanitized", asan_crash())
    rec.executions[("patched", "sanitized")] = ex("patched", "sanitized", clean())
    to = rr(timed_out=True, exit_code=None)
    rec.executions[("base", "release")] = ex("base", "release", clean())
    rec.executions[("patched", "release")] = ex("patched", "release", crash.analyze(to, False), to)
    f = classify.classify_security_test(rec)
    assert f.per_mode["sanitized"]["verdict"] == FIXED
    assert f.status == INCONCLUSIVE


def test_incomplete_fix_requires_same_vulnerability():
    r1 = sec_record(asan_crash(func="store"), clean())
    r2 = sec_record(asan_crash(func="store"), asan_crash(func="store"))
    r3 = sec_record(asan_crash(func="elsewhere"), asan_crash(func="elsewhere"))
    fs = [stable(classify.classify_security_test(r)) for r in (r1, r2, r3)]
    for f, rid in zip(fs, ("a", "b", "c")):
        f.test_id = rid
    classify.refine_incomplete_fix(fs)
    assert [f.status for f in fs] == [FIXED, INCOMPLETE_FIX, VULN_REMAINS]


def test_pass_requires_stable_fixed_crasher():
    f = stable(classify.classify_security_test(sec_record(asan_crash(), clean())))
    assert classify.aggregate_exit_code([f], True) == 0


def test_functional_regression_and_new_issue_on_valid_input():
    t = TestCase(id="v", input_file=None, kind="valid", expect_exit=0, stdout_contains=["OK"])
    rec = TestRecord(test=t)
    for m in ("release", "sanitized"):
        rec.executions[("base", m)] = ex("base", m, clean(), rr(stdout="OK\n"))
    rec.executions[("patched", "release")] = ex("patched", "release", clean(), rr(stdout="BAD\n"))
    rec.executions[("patched", "sanitized")] = ex("patched", "sanitized", asan_crash(), rr(exit_code=None))
    out = classify.classify_functional_test(rec)
    assert out[0].status == FUNC_REGRESSION
    assert any(f.axis == "security" and f.status == NEW_ISSUE for f in out)


def test_crash_parsing_asan_access_and_first_stack_only():
    se = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
          "WRITE of size 8 at 0x1 thread T0\n"
          "    #0 0x1 in accumulate /r/csvsum.c:26:5\n"
          "    #1 0x2 in process_row /r/csvsum.c:50:9\n"
          "allocated by thread T0 here:\n"
          "    #0 0x3 in calloc /x/asan_malloc_linux.cpp:77\n"
          "    #1 0x4 in main /r/csvsum.c:80\n")
    ci = crash.analyze(rr(stderr=se, signal_name="SIGABRT", signal_num=6, exit_code=None), True, "/r")
    assert ci.error_type == "heap-buffer-overflow" and ci.access == "WRITE"
    assert [f.function for f in ci.frames] == ["accumulate", "process_row"]
    assert ci.identity() == ("heap-buffer-overflow", "csvsum.c", "accumulate", "WRITE")


def test_diff_ignores_comment_only_changes_and_maps_functions(tmp_path):
    b = tmp_path / "b"; p = tmp_path / "p"; b.mkdir(); p.mkdir()
    (b / "x.c").write_text("int f(int a)\n{\n    return a; /* old */\n}\n\nint g(void)\n{\n    return 1;\n}\n")
    (p / "x.c").write_text("int f(int a)\n{\n    return a; /* new comment */\n}\n\nint g(void)\n{\n    return 2;\n}\n")
    d = diffparse.generate(str(b), str(p))
    fd = d.get("x.c")
    assert fd.functions == {"g"}
    assert fd.new_changed == {8} and fd.old_changed == {8}


def test_parse_patch_file_with_strip_and_both_sides():
    text = ("--- a/dir/x.c\n+++ b/dir/x.c\n@@ -3,3 +3,4 @@\n a\n-b\n+B\n+C\n c\n")
    d = diffparse.parse(text, strip=1)
    fd = d.get("dir/x.c")
    assert fd.old_changed == {4} and fd.new_changed == {4, 5}


def test_correlation_caller_fix_strong_only_with_differential():
    d = diffparse.Diff(files=[diffparse.FileDiff("c.c", new_changed={50}, old_changed={50},
                                                 old_functions={"process_row"},
                                                 new_functions={"process_row"})])
    ci = asan_crash(func="accumulate", rel="c.c", line=26)
    ci.frames.append(Frame(1, "process_row", "/s/c.c", 50, "", relpath="c.c"))
    assert correlate.correlate(ci, d, "base", differential=True).confidence == "strong"
    assert correlate.correlate(ci, d, "patched", differential=False).confidence == "weak"


def test_regression_test_with_different_base_identity_is_not_fixed():
    """A regression test must only be adjudicated if base still fails with the RECORDED error."""
    t = TestCase(id="reg1", input_file=None, kind="security", is_known_crasher=True,
                 regression_origin={"expected_identity": ["heap-buffer-overflow", "original.c",
                                                          "original", "READ"],
                                    "expected_mode": "sanitized", "base_drift": False})
    rec = TestRecord(test=t)
    other = asan_crash(func="completely_other_function", rel="other.c", access="WRITE")
    rec.executions[("base", "sanitized")] = ex("base", "sanitized", other)
    rec.executions[("patched", "sanitized")] = ex("patched", "sanitized", clean())
    f = classify.classify_security_test(rec, [0])
    assert f.status == INCONCLUSIVE and "recorded" in f.note
    assert classify.aggregate_exit_code([stable(f)], True) == exitcodes.INCONCLUSIVE


def test_regression_test_with_matching_identity_is_fixed():
    t = TestCase(id="reg2", input_file=None, kind="security", is_known_crasher=True,
                 regression_origin={"expected_identity": ["heap-buffer-overflow", "t.c", "f", "WRITE"],
                                    "expected_mode": "sanitized", "base_drift": False})
    rec = TestRecord(test=t)
    rec.executions[("base", "sanitized")] = ex("base", "sanitized", asan_crash())
    rec.executions[("patched", "sanitized")] = ex("patched", "sanitized", clean())
    assert classify.classify_security_test(rec, [0]).status == FIXED


def test_identity_matches_ignores_line_numbers():
    ok, _ = classify.identity_matches(["heap-buffer-overflow", "a.c", "f", "READ"],
                                      ("heap-buffer-overflow", "a.c", "f", "READ"))
    assert ok
    assert not classify.identity_matches(["heap-buffer-overflow", "a.c", "f", "READ"],
                                         ("heap-buffer-overflow", "a.c", "g", "READ"))[0]


def test_exit_code_priority_matches_brief_30_10_20_40_0():
    """Brief sec. 3.5: priority 30, 10, 20, 40, 0 (NOT 40 first)."""
    assert exitcodes.resolve([40, 20]) == 20
    assert exitcodes.resolve([40, 10]) == 10
    assert exitcodes.resolve([20, 10]) == 10
    assert exitcodes.resolve([30, 10, 20, 40, 0]) == 30
    assert exitcodes.resolve([40, 0]) == 40


def _rr(stderr="", signal_name=None, signal_num=None, exit_code=0, timed_out=False, oom=False):
    return RunResult(
        test_id="t", returncode=exit_code, exit_code=exit_code,
        signal_num=signal_num, signal_name=signal_name, stdout="",
        stderr=stderr, wall_time=0.01, timed_out=timed_out, oom_or_rlimit=oom,
        command=["x"], input_desc="stdin",
    )


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


def test_functional_ok():
    t = TestCase(id="v", input_file=None, kind="valid", expect_exit=0,
                 stdout_contains=["OK"])
    rec = TestRecord(test=t)
    rec.executions[("base", "release")] = ex("base", "release", clean(), rr(stdout="OK\n"))
    rec.executions[("patched", "release")] = ex("patched", "release", clean(), rr(stdout="OK\n"))
    f = classify.classify_functional_test(rec)
    assert f[0].status == FUNC_OK


def test_inconclusive_when_baseline_not_reproduced():
    t = TestCase(id="c", input_file=None, kind="security", is_known_crasher=True)
    rec = TestRecord(test=t)
    rec.executions[("base", "sanitized")] = ex("base", "sanitized", clean())
    rec.executions[("patched", "sanitized")] = ex("patched", "sanitized", clean())
    f = classify.classify_security_test(rec)
    assert f.status == INCONCLUSIVE


def test_config_missing_file():
    with pytest.raises(ConfigError):
        load("/nonexistent/x.yaml")
