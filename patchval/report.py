"""Render a PipelineResult as structured JSON and a readable developer report."""

from __future__ import annotations

import json

from . import exitcodes
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .pipeline import PipelineResult
from .model import (FIXED, VULN_REMAINS, INCOMPLETE_FIX, NEW_ISSUE, INCONCLUSIVE,
                    FUNC_REGRESSION, FUNC_OK, FUNC_BASELINE_BROKEN)

_STATUS_LABEL = {
    FIXED: "FIXED",
    VULN_REMAINS: "VULN REMAINS",
    INCOMPLETE_FIX: "INCOMPLETE FIX",
    NEW_ISSUE: "NEW ISSUE",
    INCONCLUSIVE: "INCONCLUSIVE",
    FUNC_REGRESSION: "FUNCTIONAL REGRESSION",
    FUNC_OK: "OK",
    FUNC_BASELINE_BROKEN: "BASELINE BROKEN",
}


def to_json(result: PipelineResult) -> dict:
    return {
        "tool": "patchval",
        "target": result.config_name,
        "verdict": {
            "exit_code": result.exit_code,
            "label": exitcodes.NAMES.get(result.exit_code, "UNKNOWN"),
            "analysis_complete": result.analysis_complete,
        },
        "builds": result.builds,
        "diff": result.diff_summary,
        "findings": [f.summary() for f in result.findings],
        "hardening": result.hardening,
        "reproducers": result.reproducers,
        "regression_tests": result.regression_entries,
        "errors": result.errors,
    }


def to_text(result: PipelineResult) -> str:
    L: list[str] = []
    code = result.exit_code
    label = exitcodes.NAMES.get(code, "UNKNOWN")
    L.append("=" * 70)
    L.append(f"  patchval report :: target '{result.config_name}'")
    L.append("=" * 70)
    L.append(f"VERDICT: exit {code} ({label})"
             + ("" if result.analysis_complete else "  [analysis INCOMPLETE]"))
    L.append("")

    # Builds
    L.append("Builds:")
    for key, b in result.builds.items():
        ok = "ok" if b["ok"] else "FAILED"
        sha = (b.get("binary_sha256") or "")[:12]
        L.append(f"  - {key:18s} {ok:7s} sha256={sha}")
        if not b["ok"] and b.get("stderr_tail"):
            tail = b["stderr_tail"].strip().splitlines()[-1:] or [""]
            L.append(f"      ! {tail[0][:100]}")
    L.append("")

    # Security findings
    sec = [f for f in result.findings if f.axis == "security"]
    if sec:
        L.append("Security findings:")
        for f in sec:
            lbl = _STATUS_LABEL.get(f.status, f.status)
            L.append(f"  [{lbl}] test '{f.test_id}'"
                     + (f"  type={f.error_type}" if f.error_type else "")
                     + (f"  via={f.detection}" if f.detection else ""))
            if f.note:
                L.append(f"      note: {f.note}")
            if f.correlation:
                c = f.correlation
                loc = ", ".join(c.matched_lines or c.matched_functions or c.matched_files) or "-"
                L.append(f"      patch-correlation: {c.confidence}  [{loc}]")
                L.append(f"        {c.explanation}")
            if f.stability:
                st = "stable" if f.stability.get("stable") else "UNSTABLE"
                L.append(f"      reproducer: {st}  "
                         f"min {f.stability.get('original_size')}->"
                         f"{f.stability.get('minimized_size')} bytes")
            if f.reproducer:
                L.append(f"      bundle: {f.reproducer.get('bundle_dir')}")
        L.append("")

    # Functional findings
    func = [f for f in result.findings if f.axis == "functional"]
    if func:
        L.append("Functional findings:")
        for f in func:
            lbl = _STATUS_LABEL.get(f.status, f.status)
            L.append(f"  [{lbl}] test '{f.test_id}'")
            if f.status != FUNC_OK and f.note:
                L.append(f"      note: {f.note}")
        L.append("")

    # Hardening
    if result.hardening:
        hp = result.hardening.get("patched", {})
        L.append("Binary hardening (patched release build):")
        L.append(f"  NX={hp.get('nx')}  PIE={hp.get('pie')}  "
                 f"RELRO={hp.get('relro')}  StackCanary={hp.get('stack_canary')}")
        changes = result.hardening.get("changes") or []
        if changes:
            flag = "  <-- REGRESSION" if result.hardening.get("protection_regressed") else ""
            L.append(f"  changes vs base: {', '.join(changes)}{flag}")
        L.append("")

    # Regression tests
    if result.regression_entries:
        L.append(f"Generated {len(result.regression_entries)} regression test(s) "
                 f"and {len(result.reproducers)} reproducer bundle(s).")
        L.append("")

    if result.errors:
        L.append("Errors/warnings:")
        for e in result.errors:
            L.append(f"  ! {e}")
        L.append("")

    L.append("Exit-code legend: 0=PASS 10=VULN/SECURITY 20=FUNC_REGRESSION "
             "30=BUILD/CONFIG 40=INCONCLUSIVE")
    return "\n".join(L)


def write_json(result: PipelineResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_json(result), fh, indent=2)
