"""Render a PipelineResult as structured JSON and a readable developer report."""

from __future__ import annotations

import json

from . import exitcodes, __version__
from .pipeline import PipelineResult


def to_json(result: PipelineResult) -> dict:
    return {
        "tool": "patchval", "tool_version": __version__,
        "target": result.config_name,
        "verdict": {"exit_code": result.exit_code,
                    "label": exitcodes.NAMES.get(result.exit_code, "UNKNOWN"),
                    "analysis_complete": result.analysis_complete},
        "scope_note": ("Verdicts are limited to the documented test suite; absence of an "
                       "error in these tests is not proof that no vulnerability exists."),
        "isolation": result.isolation,
        "checks": result.checks,
        "builds": result.builds,
        "diff": result.diff_summary,
        "findings": [f.summary() for f in result.findings],
        "executions": result.executions,
        "hardening": result.hardening,
        "reproducers": result.reproducers,
        "regression": {"loaded_from_suite": result.regression_loaded,
                       "added_to_suite": result.regression_entries},
        "errors": result.errors,
    }


def write_json(result: PipelineResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_json(result), fh, indent=2)


def to_text(result: PipelineResult) -> str:
    L: list[str] = []
    code = result.exit_code
    L.append("=" * 76)
    L.append(f"  patchval {__version__} :: {result.config_name}")
    L.append("=" * 76)
    L.append(f"VERDICT: exit {code} ({exitcodes.NAMES.get(code, '?')})")
    iso = result.isolation or {}
    L.append(f"Isolation: {iso.get('backend')} [{iso.get('level')}] network={iso.get('network')}"
             + (f"  ({iso.get('reason')})" if iso.get("reason") else ""))
    L.append(f"Checks: minimization {result.checks.get('minimization')}, "
             f"{result.checks.get('replays_per_finding')} replays per finding")
    L.append("")
    L.append("Builds:")
    for key, b in result.builds.items():
        src = b.get("source") or {}
        commit = (src.get("git_commit") or "-")[:10] + ("+dirty" if src.get("git_dirty") else "")
        L.append(f"  {key:18s} {'ok' if b['ok'] else 'FAILED':6s} "
                 f"bin={(b.get('binary_sha256') or '-')[:12]}  src={src.get('tree_sha256', '-')[:12]}"
                 f"  commit={commit}")
        if not b["ok"] and b.get("stderr_tail"):
            for ln in b["stderr_tail"].strip().splitlines()[-3:]:
                L.append(f"      ! {ln[:110]}")
    L.append("")

    sec = [f for f in result.findings if f.axis == "security"]
    if sec:
        L.append("Security findings:")
        for f in sec:
            L.append(f"  [{f.status}] {f.test_id}"
                     + (f"  type={f.error_type}" if f.error_type else "")
                     + (f"  via={f.detection}" if f.detection else ""))
            for m, d in (f.per_mode or {}).items():
                if "base_state" in d:
                    L.append(f"      {m:9s}: base {d['base_state']:12s} patched "
                             f"{d['patched_state']:12s} -> {d['verdict']}")
            if f.stability and "replays" in f.stability:
                st = "stable" if f.stability.get("stable") else "UNSTABLE"
                L.append(f"      replays : {f.stability.get('count')}x {st}")
            mn = (f.stability or {}).get("minimization")
            if mn:
                L.append(f"      minimized: {mn['original_size']} -> {mn['minimized_size']} bytes "
                         f"({'stable' if mn['stable'] else 'UNSTABLE'})")
            if f.correlation:
                c = f.correlation
                where = ", ".join(c.matched_lines or c.matched_functions or c.matched_files) or "-"
                L.append(f"      patch link: {c.confidence} ({c.relation or '-'}, {c.side}) [{where}]")
                L.append(f"        {c.explanation}")
            if f.note:
                L.append(f"      note: {f.note[:300]}")
            if f.reproducer:
                L.append(f"      bundle: {f.reproducer['bundle_dir']}")
        L.append("")

    func = [f for f in result.findings if f.axis == "functional"]
    if func:
        L.append("Functional findings (independent oracle):")
        for f in func:
            L.append(f"  [{f.status}] {f.test_id}"
                     + ("" if f.status == "FUNC_OK" else f"  -- {f.note[:160]}"))
        L.append("")

    h = result.hardening or {}
    if h:
        hp = h.get("patched", {})
        L.append("Binary hardening (patched release build):")
        if hp.get("valid") is False:
            L.append(f"  unknown: {hp.get('error')}")
        else:
            L.append(f"  NX={hp.get('nx')} PIE={hp.get('pie')} RELRO={hp.get('relro')} "
                     f"StackCanary={hp.get('stack_canary')}")
        if h.get("changes"):
            L.append(f"  changes vs base: {', '.join(h['changes'])}"
                     + ("  <-- PROTECTION WEAKENED" if h.get("protection_regressed") else ""))
        L.append("")

    L.append(f"Regression suite: {len(result.regression_loaded)} test(s) loaded from earlier runs, "
             f"{len(result.regression_entries)} recorded by this run.")
    if result.errors:
        L.append("Warnings / errors:")
        for e in result.errors:
            L.append(f"  ! {e}")
    L.append("")
    L.append("Scope: results hold for the documented test suite only.")
    L.append("Exit codes: 0=PASS 10=VULN/NEW_ISSUE 20=FUNC_REGRESSION 30=BUILD/CONFIG 40=INCONCLUSIVE")
    return "\n".join(L)
