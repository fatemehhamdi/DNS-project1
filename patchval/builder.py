"""Build both program versions in two independent build modes, sandboxed.

release   : the normal optimized build, keeps the real binary hardening.
sanitized : ASan + UBSan instrumented build (FORTIFY disabled so ASan is the
            reporter and produces symbolized frames).

Builds run inside the selected sandbox: the source tree is read-only, only
the per-build output directory is writable and there is no network. For
every (version, mode) we record the command, flags, SHA-256 of the binary,
the exact source identity and the shared libraries the binary needs.
"""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
from dataclasses import dataclass, field

from .config import Config, VersionSpec
from .provenance import source_id
from .sandbox import Sandbox

MODE_RELEASE = "release"
MODE_SANITIZED = "sanitized"
MODES = (MODE_RELEASE, MODE_SANITIZED)


@dataclass
class BuildResult:
    version: str
    mode: str
    ok: bool
    binary_path: str | None
    binary_sha256: str | None
    command: str
    cflags: str
    stdout: str
    stderr: str
    returncode: int
    source_root: str = ""
    source: dict = field(default_factory=dict)
    runtime_libs: list[str] = field(default_factory=list)
    sandbox: str = "none"

    def summary(self) -> dict:
        return {
            "version": self.version, "mode": self.mode, "ok": self.ok,
            "binary_path": self.binary_path, "binary_sha256": self.binary_sha256,
            "command": self.command, "cflags": self.cflags, "returncode": self.returncode,
            "source": self.source, "runtime_libs": self.runtime_libs,
            "sandbox": self.sandbox,
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


def _ldd(path: str) -> list[str]:
    try:
        p = subprocess.run(["ldd", path], capture_output=True, text=True, timeout=15)
        return [l.strip() for l in p.stdout.splitlines() if l.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def build_one(cfg: Config, version: VersionSpec, mode: str, work_root: str,
              sandbox: Sandbox | None = None) -> BuildResult:
    cflags = cfg.cflags_release if mode == MODE_RELEASE else cfg.cflags_sanitized
    out_dir = os.path.abspath(os.path.join(work_root, version.name, mode))
    os.makedirs(out_dir, exist_ok=True)
    out_bin = os.path.join(out_dir, "target.bin")
    if os.path.exists(out_bin):
        os.unlink(out_bin)
    mapping = {"src": version.path, "out": out_bin, "cflags": cflags,
               "mode": mode, "builddir": out_dir}
    command = _render(cfg.build_command, mapping)
    binary_path = _render(cfg.binary_rel, mapping)
    if not os.path.isabs(binary_path):
        binary_path = os.path.join(out_dir, binary_path)

    argv = ["/bin/sh", "-c", command]
    if sandbox is not None:
        argv = sandbox.wrap(argv, ro_paths=[version.path], rw_paths=[out_dir], cwd=out_dir)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "HOME": "/tmp", "TMPDIR": "/tmp"}
    proc = subprocess.Popen(argv, cwd=out_dir, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        so, se = proc.communicate(timeout=cfg.build_timeout_sec)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        so, se = proc.communicate()
        se = (se or "") + "\npatchval: build timed out"
    ok = proc.returncode == 0 and os.path.isfile(binary_path)
    return BuildResult(
        version=version.name, mode=mode, ok=ok,
        binary_path=binary_path if ok else None,
        binary_sha256=_sha256(binary_path) if ok else None,
        command=command, cflags=cflags, stdout=so or "", stderr=se or "",
        returncode=proc.returncode, source_root=version.path,
        source=source_id(version.path), runtime_libs=_ldd(binary_path) if ok else [],
        sandbox=sandbox.backend if sandbox else "none",
    )


def build_all(cfg: Config, work_root: str, sandbox: Sandbox | None = None
              ) -> dict[tuple[str, str], BuildResult]:
    results = {}
    for version in (cfg.base, cfg.patched):
        for mode in MODES:
            results[(version.name, mode)] = build_one(cfg, version, mode, work_root, sandbox)
    return results
