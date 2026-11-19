"""End-to-end orchestration.

  1. select sandbox            6. mandatory replays (>=3) -> stability -> verdict
  2. sandboxed builds (x4)     7. incomplete-fix refinement, correlation
  3. diff (tree or patch file) 8. minimization, reproducer bundles, regression suite
  4. load regression suite     9. ELF hardening
  5. run every test on every  10. exit code
     build, analyze, classify
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

from . import (builder, runner, crash, classify, correlate, diffparse, minimize,
               regression, hardening, exitcodes, sandbox as sbmod)
from .builder import MODE_RELEASE, MODE_SANITIZED
from .config import Config, TestCase
from .crash import STATE_CRASH
from .model import (TestRecord, Execution, Finding, FIXED, VULN_REMAINS,
                    INCOMPLETE_FIX, NEW_ISSUE)


@dataclass
class Options:
    do_minimize: bool = True
    minimize_budget_sec: float = 120.0
    sandbox: str | None = None             # override cfg.sandbox
    require_isolation: bool = True         # official runs REFUSE to execute targets on the bare host
    allow_no_isolation: bool = False       # development-only escape hatch (never for CI/grading)
    update_regression: bool = True
    regression_suite: str | None = None    # override cfg.regression_suite
    diff_file: str | None = None
    diff_strip: int = 1
    registry_dir: str | None = None        # writable persistent registry (Docker volume)


@dataclass
class PipelineResult:
    config_name: str
    builds: dict
    diff_summary: dict
    findings: list[Finding]
    hardening: dict
    reproducers: list[dict]
    regression_entries: list[dict]
    exit_code: int
    analysis_complete: bool
    executions: list[dict] = field(default_factory=list)
    isolation: dict = field(default_factory=dict)
    checks: dict = field(default_factory=dict)
    regression_loaded: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _token(ex: Execution, side: str, graceful) -> str:
    if side == "base":
        st, _ = classify.base_state(ex)
    else:
        st, _ = classify.patched_state(ex, graceful)
    if st == "CRASH":
        return "CRASH:" + "|".join(str(x) for x in ex.crash.identity())
    return st


def _sanitize(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def run_pipeline(cfg: Config, work_root: str, artifacts_root: str,
                 opts: Options | None = None, do_minimize: bool | None = None) -> PipelineResult:
    opts = opts or Options()
    if do_minimize is not None:
        opts.do_minimize = do_minimize
    if opts.regression_suite is not None:
        import dataclasses
        cfg = dataclasses.replace(cfg, regression_suite=opts.regression_suite or None)
    if opts.registry_dir and cfg.regression_suite:
        import dataclasses
        try:
            cfg = dataclasses.replace(
                cfg, regression_suite=regression.relocate_suite(cfg.regression_suite,
                                                                opts.registry_dir))
        except OSError as exc:
            return PipelineResult(cfg.name, {}, {}, [], {}, [], [],
                                  exitcodes.BUILD_OR_CONFIG_ERROR, False,
                                  errors=[f"registry directory {opts.registry_dir} unusable: {exc}"])
    os.makedirs(work_root, exist_ok=True)
    os.makedirs(artifacts_root, exist_ok=True)
    errors: list[str] = []
    checks = {"minimization": "enabled" if opts.do_minimize else "skipped (--no-minimize)",
              "replays_per_finding": cfg.replays}
    incomplete: list[str] = []          # mandatory checks that did not finish -> exit 40
    if not opts.do_minimize:
        incomplete.append("minimization skipped (--no-minimize): verdict cannot be PASS")

    # 1) sandbox
    sb = sbmod.select(opts.sandbox or cfg.sandbox)
    isolation = sb.summary()
    if sb.level == sbmod.LEVEL_NONE:
        errors.append(f"WARNING: no process isolation available ({sb.reason}); "
                      "runs are limited by rlimits/timeout only")
        if opts.require_isolation and not opts.allow_no_isolation:
            errors.append("isolation required but unavailable: refusing to execute the target "
                          "on the host (install bubblewrap, use scripts/run_in_docker.sh, or "
                          "pass --allow-no-isolation for local development only)")
            return PipelineResult(cfg.name, {}, {}, [], {}, [], [],
                                  exitcodes.BUILD_OR_CONFIG_ERROR, False,
                                  isolation=isolation, checks=checks, errors=errors)

    # 2) builds
    builds = builder.build_all(cfg, work_root, sb)
    build_summaries = {f"{v}/{m}": b.summary() for (v, m), b in builds.items()}
    failures = [f"{v}/{m}" for (v, m), b in builds.items() if not b.ok]
    for k in failures:
        errors.append(f"build failed: {k}")
    if failures:
        return PipelineResult(cfg.name, build_summaries, {}, [], {}, [], [],
                              exitcodes.BUILD_OR_CONFIG_ERROR, False,
                              isolation=isolation, checks=checks, errors=errors)
    roots = {"base": cfg.base.path, "patched": cfg.patched.path}
    base_tree = builds[("base", MODE_RELEASE)].source["tree_sha256"]

    # 3) diff
    diff_file = opts.diff_file or (cfg.diff_file if cfg.diff_mode == "file" else None)
    if diff_file:
        with open(diff_file, "r", encoding="utf-8", errors="replace") as fh:
            diff = diffparse.parse(fh.read(), cfg.base.path, cfg.patched.path, opts.diff_strip)
    else:
        diff = diffparse.generate(cfg.base.path, cfg.patched.path)
    with open(os.path.join(artifacts_root, "patch.diff"), "w", encoding="utf-8") as fh:
        fh.write(diff.raw)

    # 4) regression suite from previous runs
    reg_tests = regression.load_regression_tests(cfg, base_tree)
    known_sha = set()
    for t in cfg.security_tests:
        if t.input_file:
            known_sha.add(hashlib.sha256(open(t.input_file, "rb").read()).hexdigest())
    reg_tests = [t for t in reg_tests
                 if hashlib.sha256(open(t.input_file, "rb").read()).hexdigest() not in known_sha]
    security_tests = list(cfg.security_tests) + reg_tests

    # 5) execute everything
    logs_dir = os.path.join(artifacts_root, "logs")
    records: dict[str, TestRecord] = {}
    executions: list[dict] = []
    for test in cfg.functional_tests + security_tests:
        rec = TestRecord(test=test)
        for (version, mode), b in builds.items():
            san = mode == MODE_SANITIZED
            r = runner.run(b.binary_path, cfg, test, san, sandbox=sb)
            ci = crash.analyze(r, san, roots[version])
            rec.executions[(version, mode)] = Execution(version, mode, r, ci)
            d = os.path.join(logs_dir, _sanitize(test.id))
            os.makedirs(d, exist_ok=True)
            stem = os.path.join(d, f"{version}-{mode}")
            with open(stem + ".stdout", "w", encoding="utf-8") as fh:
                fh.write(r.stdout)
            with open(stem + ".stderr", "w", encoding="utf-8") as fh:
                fh.write(r.stderr)
            executions.append({
                "test_id": test.id, "test_kind": test.kind, "version": version, "mode": mode,
                "build": f"{version}/{mode}", "binary_sha256": b.binary_sha256,
                **r.summary(), "analysis": ci.summary(),
                "stdout_file": os.path.relpath(stem + ".stdout", artifacts_root),
                "stderr_file": os.path.relpath(stem + ".stderr", artifacts_root),
            })
        records[test.id] = rec

    findings: list[Finding] = []
    for t in security_tests:
        findings.append(classify.classify_security_test(records[t.id], cfg.graceful_exit_codes))
    for t in cfg.functional_tests:
        findings.extend(classify.classify_functional_test(records[t.id]))

    # 6) mandatory replays fold into the verdict
    for f in findings:
        if f.axis != "security" or f.status not in (FIXED, VULN_REMAINS, NEW_ISSUE):
            continue
        rec = records[f.test_id]
        m = f.decisive_mode
        b = builds[("base", m)]
        p = builds[("patched", m)]
        san = m == MODE_SANITIZED
        graceful = rec.test.graceful_exit_codes if rec.test.graceful_exit_codes is not None \
            else cfg.graceful_exit_codes
        obs = []
        sides = [("base", b), ("patched", p)] if f.status == FIXED else [("patched", p)]
        if f.status == VULN_REMAINS:
            sides = [("base", b), ("patched", p)]
        for side, build in sides:
            expected = _token(rec.get(side, m), side, graceful)
            for i in range(cfg.replays):
                r = runner.run(build.binary_path, cfg, rec.test, san, sandbox=sb)
                ex = Execution(side, m, r, crash.analyze(r, san, roots[side]))
                obs.append({"side": side, "replay": i + 1, "observed": _token(ex, side, graceful),
                            "expected": expected})
        tokens = [o["observed"] for o in obs]
        stable = all(o["observed"] == o["expected"] for o in obs)
        classify.apply_stability(f, ["ok" if o["observed"] == o["expected"] else
                                     f"{o['side']}#{o['replay']}:{o['observed']}" for o in obs], "ok")
        f.stability["observations"] = obs
        f.stability["mode"] = m

    # 7) incomplete fix + correlation
    classify.refine_incomplete_fix(findings)
    for f in findings:
        if f.axis != "security" or f.test_id not in records:
            continue
        rec = records[f.test_id]
        if f.status == FIXED:
            side, differential = "base", True
        elif f.status in (VULN_REMAINS, INCOMPLETE_FIX):
            side, differential = "patched", False
        elif f.status == NEW_ISSUE:
            side, differential = "patched", True
        else:
            continue
        ex = next((rec.get(side, mm) for mm in (MODE_SANITIZED, MODE_RELEASE)
                   if rec.get(side, mm) is not None and rec.get(side, mm).crash.state == STATE_CRASH
                   and rec.get(side, mm).crash.top_source_frame() is not None), None) \
            or next((rec.get(side, mm) for mm in (MODE_SANITIZED, MODE_RELEASE)
                     if rec.get(side, mm) is not None
                     and rec.get(side, mm).crash.state == STATE_CRASH), None)
        if ex is not None:
            f.correlation = correlate.correlate(ex.crash, diff, side=side, differential=differential)

    # 8) minimization, reproducers, regression suite
    #    FIXED / VULN_REMAINS / INCOMPLETE_FIX are reproduced on base; NEW_ISSUE is
    #    reproduced on the PATCHED binary (the error does not exist on base).
    reproducers, reg_entries = [], []
    for f in findings:
        if f.axis != "security" or f.status not in (FIXED, VULN_REMAINS, INCOMPLETE_FIX, NEW_ISSUE):
            continue
        rec = records.get(f.test_id)
        if rec is None or rec.test.input_file is None:
            continue
        side = "patched" if f.status == NEW_ISSUE else "base"
        mode = MODE_SANITIZED if (rec.get(side, MODE_SANITIZED) and
                                  rec.get(side, MODE_SANITIZED).crash.state == STATE_CRASH) \
            else MODE_RELEASE
        cex = rec.get(side, mode)
        if cex is None or cex.crash.state != STATE_CRASH:
            incomplete.append(f"{f.test_id}: no confirmed crash on {side}/{mode} to reproduce")
            continue
        minim = None
        # The reduced input must keep the WHOLE finding intact, not just the base crash:
        #   FIXED            -> patched must still be crash-free with a graceful exit
        #   VULN_REMAINS/... -> patched must still crash with the same identity
        #   NEW_ISSUE        -> base must still NOT show that crash
        other_side = "base" if side == "patched" else "patched"
        graceful_t = (rec.test.graceful_exit_codes if rec.test.graceful_exit_codes is not None
                      else cfg.graceful_exit_codes)
        crash_identity = cex.crash.identity()
        status_now = f.status

        def other_ok(path, _side=other_side, _mode=mode, _status=status_now, _t=rec.test,
                     _g=graceful_t, _ident=crash_identity):
            r2 = runner.run(builds[(_side, _mode)].binary_path, cfg, _t, _mode == MODE_SANITIZED,
                            input_path=path, sandbox=sb)
            ci2 = crash.analyze(r2, _mode == MODE_SANITIZED, roots[_side])
            if _status == FIXED:
                st, _ = classify.patched_state(Execution(_side, _mode, r2, ci2), _g)
                return st == "CLEAN"
            if _status == NEW_ISSUE:
                return not (ci2.state == STATE_CRASH and classify.same_crash(ci2, cex.crash)[0])
            return ci2.state == STATE_CRASH and ci2.identity()[:3] == _ident[:3]

        if opts.do_minimize:
            try:
                minim = minimize.minimize(builds[(side, mode)].binary_path, cfg, rec.test,
                                          cex.crash, mode == MODE_SANITIZED,
                                          os.path.join(artifacts_root, "minimized"), sb,
                                          roots[side], opts.minimize_budget_sec, extra=other_ok)
            except Exception as exc:
                errors.append(f"minimize {f.test_id}: {exc}")
                minim = None
            if minim is None:
                incomplete.append(f"{f.test_id}: minimization failed or did not preserve the error")
            elif not minim.stable:
                incomplete.append(f"{f.test_id}: minimized input is not a stable reproducer")
        if minim is not None:
            f.stability = dict(f.stability or {}, minimization={
                "original_size": minim.original_size, "minimized_size": minim.minimized_size,
                "iterations": minim.iterations, "stable": minim.stable,
                "replays": minim.replays, "budget_exhausted": minim.budget_exhausted})
        repl = [o["observed"] for o in (f.stability or {}).get("observations", [])]
        try:
            bundle = regression.build_reproducer(
                cfg, rec.test, f.status, mode, builds[("base", mode)], builds[("patched", mode)],
                cex.crash.summary(), cex.run.summary(), minim, repl,
                os.path.join(artifacts_root, "reproducers"), crash_side=side,
                graceful=(rec.test.graceful_exit_codes if rec.test.graceful_exit_codes is not None
                          else cfg.graceful_exit_codes))
        except OSError as exc:
            errors.append(f"reproducer {f.test_id}: {exc}")
            incomplete.append(f"{f.test_id}: reproducer bundle could not be written")
            continue
        f.reproducer = bundle
        reproducers.append(bundle)
        if opts.update_regression and f.status in (FIXED, VULN_REMAINS, INCOMPLETE_FIX) \
                and (f.stability or {}).get("stable", True):
            use_min = minim is not None and minim.stable
            try:
                entry = regression.register(cfg, rec.test,
                                            minim.minimized_path if use_min else rec.test.input_file,
                                            cex.crash.identity(), cex.crash.summary(), base_tree,
                                            use_min, mode)
            except OSError as exc:
                entry = None
                errors.append(f"could not update regression suite {cfg.regression_suite}: {exc}")
                incomplete.append(f"{f.test_id}: regression test could not be stored in "
                                  f"{cfg.regression_suite} ({exc})")
            if entry:
                reg_entries.append(entry)

    # 9) hardening
    hb = hardening.inspect(builds[("base", MODE_RELEASE)].binary_path)
    hp = hardening.inspect(builds[("patched", MODE_RELEASE)].binary_path)
    hdelta = hardening.compare(hb, hp)
    if hdelta.regressed:
        errors.append("WARNING: binary hardening weakened by the patch: "
                      + ", ".join(hdelta.changes))

    # 10) verdict
    analysis_complete = not incomplete
    for msg in incomplete:
        errors.append("INCOMPLETE: " + msg)
    checks["incomplete_checks"] = incomplete
    exit_code = classify.aggregate_exit_code(findings, analysis_complete=analysis_complete)
    return PipelineResult(
        config_name=cfg.name, builds=build_summaries, diff_summary=diff.summary(),
        findings=findings, hardening=hdelta.summary(), reproducers=reproducers,
        regression_entries=reg_entries, exit_code=exit_code, analysis_complete=analysis_complete,
        executions=executions, isolation=isolation, checks=checks,
        regression_loaded=[t.id for t in reg_tests], errors=errors)
