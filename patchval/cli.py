"""Command-line entry point.

    python3 -m patchval -c targets/csvsum/config.correct.yaml
    python3 -m patchval -c <cfg> --patch new_fix.diff        # unseen patch file
    python3 -m patchval -c <cfg> --patched /path/to/tree     # unseen patched tree

The process exit code is the verdict (0/10/20/30/40).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

from . import __version__, exitcodes, report
from .config import load, with_versions, ConfigError
from .pipeline import run_pipeline, Options


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="patchval",
                                description="Security patch validation and regression testing for CI/CD.")
    p.add_argument("--config", "-c", required=True, help="target configuration (YAML/JSON)")
    p.add_argument("--base", help="override the base source directory")
    p.add_argument("--patched", help="override the patched source directory")
    p.add_argument("--patch", help="unified/git diff to apply to a copy of base; the result "
                                   "becomes the patched version (and the diff is used for correlation)")
    p.add_argument("--strip", type=int, default=1, help="path components to strip from --patch (like patch -p)")
    p.add_argument("--work", help="build/work directory (default: temp dir)")
    p.add_argument("--artifacts", help="reproducers/logs/minimized inputs (default: <work>/artifacts)")
    p.add_argument("--json", help="write the structured JSON report here")
    p.add_argument("--sandbox", choices=["auto", "bwrap", "unshare", "none"],
                   help="isolation backend (default: from config, usually auto)")
    p.add_argument("--require-isolation", action="store_true", default=True,
                   help="(default) fail with exit 30 if no isolation backend is available")
    p.add_argument("--allow-no-isolation", action="store_true",
                   help="DEVELOPMENT ONLY: allow running targets with rlimits only (no "
                        "namespace/container isolation). Never use in CI or for grading.")
    p.add_argument("--regression-suite", help="override the persistent regression suite file "
                                              "('' disables)")
    p.add_argument("--registry-dir", default=os.environ.get("PATCHVAL_REGISTRY_DIR"),
                   help="writable persistent directory for regression suites (default env "
                        "PATCHVAL_REGISTRY_DIR); the shipped suites are copied there once")
    p.add_argument("--no-update-regression", action="store_true",
                   help="read the regression suite but do not add new tests to it")
    p.add_argument("--no-minimize", action="store_true", help="DEVELOPMENT ONLY: skip minimization; the run is then flagged "
                                                   "incomplete and can never return 0")
    p.add_argument("--minimize-budget", type=float, default=120.0, help="seconds per minimization")
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--version", action="version", version=f"patchval {__version__}")
    return p


def _apply_patch(base_dir: str, patch_file: str, strip: int, work: str) -> str:
    dst = os.path.join(work, "patched_src")
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(base_dir, dst)
    with open(patch_file, "rb") as fh:
        p = subprocess.run(["patch", f"-p{strip}", "--batch", "--forward", "--silent",
                            "-d", dst], stdin=fh, capture_output=True, text=True)
    if p.returncode != 0:
        raise ConfigError(f"patch did not apply cleanly: {(p.stdout + p.stderr).strip()[:400]}")
    return dst


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    work = os.path.abspath(a.work or tempfile.mkdtemp(prefix="patchval_"))
    os.makedirs(work, exist_ok=True)
    artifacts = os.path.abspath(a.artifacts or os.path.join(work, "artifacts"))
    try:
        cfg = load(a.config)
        if a.base:
            cfg = with_versions(cfg, base=a.base)
        if a.patch:
            if a.patched:
                raise ConfigError("use either --patch or --patched, not both")
            pdir = _apply_patch(cfg.base.path, os.path.abspath(a.patch), a.strip, work)
            cfg = with_versions(cfg, patched=pdir,
                                name_suffix=os.path.splitext(os.path.basename(a.patch))[0])
        elif a.patched:
            cfg = with_versions(cfg, patched=a.patched,
                                name_suffix=os.path.basename(os.path.normpath(a.patched)))
    except ConfigError as exc:
        sys.stderr.write(f"patchval: configuration error: {exc}\n")
        return exitcodes.BUILD_OR_CONFIG_ERROR

    opts = Options(do_minimize=not a.no_minimize, minimize_budget_sec=a.minimize_budget,
                   sandbox=a.sandbox, require_isolation=True,
                   allow_no_isolation=a.allow_no_isolation,
                   update_regression=not a.no_update_regression,
                   regression_suite=a.regression_suite,
                   diff_file=os.path.abspath(a.patch) if a.patch else None,
                   diff_strip=a.strip, registry_dir=a.registry_dir)
    try:
        result = run_pipeline(cfg, work, artifacts, opts)
    except Exception as exc:
        import traceback
        sys.stderr.write(f"patchval: internal error: {exc}\n")
        traceback.print_exc(file=sys.stderr)
        return exitcodes.BUILD_OR_CONFIG_ERROR

    if a.json:
        report.write_json(result, a.json)
    else:
        report.write_json(result, os.path.join(artifacts, "report.json"))
    if not a.quiet:
        print(report.to_text(result))
    sys.stderr.write(f"patchval: verdict exit {result.exit_code} "
                     f"({exitcodes.NAMES.get(result.exit_code)})  artifacts={artifacts}\n")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
