"""Build both program versions in two independent build modes.

The brief is explicit that a *release* build and an *instrumented/sanitized*
build must never be conflated: a crash may be visible only under a sanitizer,
or may manifest differently in the optimized release binary. So for every
(version, mode) pair we produce a separate binary and record its hash, build
command, and flags. All later comparisons are done between *matching* modes
(release-vs-release, sanitized-vs-sanitized).
"""

from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
from dataclasses import dataclass

from .config import Config, VersionSpec

MODE_RELEASE = "release"
MODE_SANITIZED = "sanitized"
MODES = (MODE_RELEASE, MODE_SANITIZED)


@dataclass
class BuildResult:
    version: str          # "base" | "patched"
    mode: str             # "release" | "sanitized"
    ok: bool
    binary_path: str | None
    binary_sha256: str | None
    command: str
    cflags: str
    stdout: str
    stderr: str
    returncode: int

    def summary(self) -> dict:
        return {
            "version": self.version,
            "mode": self.mode,
            "ok": self.ok,
            "binary_path": self.binary_path,
            "binary_sha256": self.binary_sha256,
            "command": self.command,
            "cflags": self.cflags,
            "returncode": self.returncode,
            # keep stderr tail for debugging build failures
            "stderr_tail": self.stderr[-2000:] if self.stderr else "",
        }


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _render(template: str, mapping: dict[str, str]) -> str:
    out = template
    for k, v in mapping.items():
        out = out.replace("{" + k + "}", v)
    return out


def build_one(cfg: Config, version: VersionSpec, mode: str, work_root: str) -> BuildResult:
    """Build a single (version, mode) and return its result."""
    cflags = cfg.cflags_release if mode == MODE_RELEASE else cfg.cflags_sanitized
    out_dir = os.path.join(work_root, version.name, mode)
    os.makedirs(out_dir, exist_ok=True)
    out_bin = os.path.join(out_dir, "target.bin")

    mapping = {
        "src": version.path,
        "out": out_bin,
        "cflags": cflags,
        "mode": mode,
        "builddir": out_dir,
    }
    command = _render(cfg.build_command, mapping)
    binary_path_tmpl = _render(cfg.binary_rel, mapping)
    # binary path may be relative to the build dir
    if not os.path.isabs(binary_path_tmpl):
        binary_path = os.path.join(out_dir, binary_path_tmpl)
    else:
        binary_path = binary_path_tmpl

    env = dict(os.environ)
    # Deterministic, non-recovering sanitizer behaviour during build-time checks.
    proc = subprocess.run(
        command,
        shell=True,
        cwd=out_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    ok = proc.returncode == 0 and os.path.isfile(binary_path)
    sha = _sha256(binary_path) if ok else None
    return BuildResult(
        version=version.name,
        mode=mode,
        ok=ok,
        binary_path=binary_path if ok else None,
        binary_sha256=sha,
        command=command,
        cflags=cflags,
        stdout=proc.stdout,
        stderr=proc.stderr,
        returncode=proc.returncode,
    )


def build_all(cfg: Config, work_root: str) -> dict[tuple[str, str], BuildResult]:
    """Build every (version, mode) combination.

    Returns a dict keyed by (version_name, mode).
    """
    results: dict[tuple[str, str], BuildResult] = {}
    for version in (cfg.base, cfg.patched):
        for mode in MODES:
            try:
                results[(version.name, mode)] = build_one(cfg, version, mode, work_root)
            except subprocess.TimeoutExpired as exc:
                results[(version.name, mode)] = BuildResult(
                    version=version.name, mode=mode, ok=False, binary_path=None,
                    binary_sha256=None,
                    command=str(exc.cmd), cflags="", stdout="", stderr="build timed out",
                    returncode=-1,
                )
    return results
