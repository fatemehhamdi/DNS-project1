"""End-to-end tests: compile real targets inside the sandbox and assert verdicts.

Requires gcc with AddressSanitizer. Uses a temporary regression suite so the
repository's committed suite is not modified.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from patchval.config import load
from patchval.pipeline import run_pipeline, Options
from patchval import cli, sandbox as sbmod

T = os.path.join(ROOT, "targets")
pytestmark = [
    pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available"),
    # Targets are intentionally vulnerable: never run them on the bare host.
    pytest.mark.skipif(sbmod.select("auto").level == sbmod.LEVEL_NONE,
                       reason="no isolation backend (bwrap/unshare/container) available"),
]
MIN_BUDGET = 30

SCENARIOS = [
    ("vulnstr/config.correct.yaml", 0),
    ("vulnstr/config.incomplete.yaml", 10),
    ("vulnstr/config.regression.yaml", 20),
    ("vulnstr/config.incomplete.file.yaml", 10),     # input via file path
    ("vulnstr/config.regression.argv.yaml", 20),     # input via argv content
    ("vulnstr/config.correct.argv.yaml", 0),
    ("csvsum/config.correct.yaml", 0),
    ("csvsum/config.incomplete.yaml", 10),
    ("csvsum/config.regression.yaml", 20),
    ("cjson_minify/config.correct.yaml", 0),
    ("cjson_minify/config.incomplete.yaml", 10),
    ("cjson_minify/config.regression.yaml", 20),
]


@pytest.fixture
def tmp():
    d = tempfile.mkdtemp(prefix="pv_it_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.parametrize("cfg_rel,expected", SCENARIOS)
def test_scenario(cfg_rel, expected, tmp):
    cfg = load(os.path.join(T, cfg_rel))
    res = run_pipeline(cfg, tmp, os.path.join(tmp, "art"),
                       Options(do_minimize=True, minimize_budget_sec=MIN_BUDGET,
                               regression_suite=os.path.join(tmp, "suite", "suite.json")))
    assert res.exit_code == expected, [(f.test_id, f.status, f.note[:120]) for f in res.findings]
    # every (test, version, mode) execution is recorded with logs and input hash
    n_tests = len(cfg.functional_tests) + len(cfg.security_tests)
    assert len(res.executions) == 4 * n_tests
    for e in res.executions:
        assert os.path.isfile(os.path.join(tmp, "art", e["stderr_file"]))
        assert e["input_sha256"]
    assert res.isolation["backend"] in ("bwrap", "unshare", "container")


UNSEEN = [l.split() for l in open(os.path.join(ROOT, "unseen_patches", "expected.tsv"))
          if l.strip() and not l.startswith("#")]


@pytest.mark.parametrize("cfg_rel,patch,extra,expected", UNSEEN)
def test_unseen_patch_files(cfg_rel, patch, extra, expected, tmp):
    rc = cli.main(["-c", os.path.join(ROOT, cfg_rel),
                   "--patch", os.path.join(ROOT, "unseen_patches", patch),
                   "--work", tmp, "--minimize-budget", str(MIN_BUDGET),
                   "--regression-suite", "", "-q"])
    assert rc == int(expected)


def test_regression_loop_and_self_contained_bundle(tmp):
    """Run 1 records minimized inputs; run 2 loads and executes them; the
    bundle replays from another directory without patchval."""
    suite = os.path.join(tmp, "suite", "suite.json")
    cfg = load(os.path.join(T, "csvsum", "config.incomplete.yaml"))
    r1 = run_pipeline(cfg, os.path.join(tmp, "w1"), os.path.join(tmp, "a1"),
                      Options(do_minimize=True, minimize_budget_sec=60, regression_suite=suite))
    assert r1.exit_code == 10 and r1.regression_entries
    data = json.load(open(suite))
    assert data["tests"] and all(os.path.isfile(os.path.join(tmp, "suite", t["input"]))
                                 for t in data["tests"])

    cfg2 = load(os.path.join(T, "csvsum", "config.correct.yaml"))
    r2 = run_pipeline(cfg2, os.path.join(tmp, "w2"), os.path.join(tmp, "a2"),
                      Options(do_minimize=True, minimize_budget_sec=MIN_BUDGET,
                              regression_suite=suite))
    assert r2.regression_loaded, "regression tests from run 1 were not executed in run 2"
    loaded = {f.test_id: f.status for f in r2.findings if f.test_id in r2.regression_loaded}
    assert loaded and all(s == "FIXED" for s in loaded.values()), loaded
    assert r2.exit_code == 0

    bundle = r1.reproducers[0]["bundle_dir"]
    moved = os.path.join(tmp, "moved_bundle")
    shutil.copytree(bundle, moved)
    p = subprocess.run(["bash", os.path.join(moved, "replay.sh")], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    m = json.load(open(os.path.join(moved, "manifest.json")))
    assert m["source"]["base"]["tree_sha256"] and m["binary"]["base_sha256"]
    assert os.path.isfile(os.path.join(moved, "bin", "base.bin"))


def test_official_run_refuses_to_execute_without_isolation(tmp, monkeypatch):
    """No sandbox => exit 30 and the target is never built or run."""
    monkeypatch.setattr(sbmod, "select",
                        lambda requested="auto": sbmod.Sandbox("none", sbmod.LEVEL_NONE, "test"))
    cfg = load(os.path.join(T, "csvsum", "config.correct.yaml"))
    res = run_pipeline(cfg, tmp, os.path.join(tmp, "art"), Options())
    assert res.exit_code == 30 and not res.executions and not res.builds
    rc = cli.main(["-c", os.path.join(T, "csvsum", "config.correct.yaml"), "--work", tmp, "-q"])
    assert rc == 30


def test_no_minimize_can_never_pass(tmp):
    cfg = load(os.path.join(T, "csvsum", "config.correct.yaml"))
    res = run_pipeline(cfg, tmp, os.path.join(tmp, "art"),
                       Options(do_minimize=False, regression_suite=os.path.join(tmp, "s", "s.json")))
    assert res.exit_code == 40 and not res.analysis_complete


def test_replay_script_judges_by_finding_type(tmp):
    """FIXED bundle: confirmed (0); if the patched binary still crashed it must NOT be."""
    cfg = load(os.path.join(T, "csvsum", "config.correct.yaml"))
    res = run_pipeline(cfg, tmp, os.path.join(tmp, "art"),
                       Options(minimize_budget_sec=MIN_BUDGET,
                               regression_suite=os.path.join(tmp, "s", "s.json")))
    assert res.exit_code == 0 and res.reproducers
    bundle = res.reproducers[0]["bundle_dir"]
    m = json.load(open(os.path.join(bundle, "manifest.json")))
    assert m["finding_status"] == "FIXED" and m["expected_replay_outcome"]
    ok = subprocess.run(["bash", os.path.join(bundle, "replay.sh")], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad = os.path.join(tmp, "bad_bundle")
    shutil.copytree(bundle, bad)
    shutil.copy2(os.path.join(bad, "bin", "base.bin"), os.path.join(bad, "bin", "patched.bin"))
    r = subprocess.run(["bash", os.path.join(bad, "replay.sh")], capture_output=True, text=True)
    assert r.returncode == 10, r.stdout + r.stderr


def test_new_issue_gets_minimization_and_reproducer(tmp):
    art = os.path.join(tmp, "art")
    rc = cli.main(["-c", os.path.join(T, "csvsum", "config.correct.yaml"),
                   "--patch", os.path.join(ROOT, "unseen_patches", "csvsum_new_issue_oob_read.diff"),
                   "--work", tmp, "--artifacts", art, "--minimize-budget", str(MIN_BUDGET),
                   "--regression-suite", "", "-q"])
    assert rc == 10
    rep = json.load(open(os.path.join(art, "report.json")))
    new = [f for f in rep["findings"] if f["status"] == "NEW_ISSUE"]
    assert new and all(f["reproducer"] for f in new)
    assert any((f.get("stability") or {}).get("minimization") for f in new)
    bundle = new[0]["reproducer"]["bundle_dir"]
    r = subprocess.run(["bash", os.path.join(bundle, "replay.sh")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
