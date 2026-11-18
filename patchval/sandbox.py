"""Isolated execution backends for builds and target runs.

The brief requires tests to run in an isolated environment with resource
limits. patchval wraps every build command and every target execution in one
of these backends:

  bwrap    bubblewrap: new user/pid/net/ipc/uts namespaces, no network,
           read-only system dirs, only the binary/input visible, a private
           writable scratch dir, process tree killed with the sandbox.
  unshare  util-linux unshare: new user/pid/net namespaces (no network,
           private pid space); filesystem is NOT restricted -> weaker.
  none     rlimits + timeout only. Used only when explicitly requested or
           when no backend works; the report records the isolation level and
           --require-isolation turns its absence into exit 30.

Resource limits (address space / CPU / file size / core / process count)
are applied in every backend via setrlimit in the child before exec.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

LEVEL_FULL = "full"            # namespaces + filesystem restriction (bwrap)
LEVEL_PARTIAL = "partial"      # namespaces, host filesystem visible (unshare)
LEVEL_NONE = "rlimits-only"

_SYSTEM_RO = ["/usr", "/etc/alternatives", "/etc/ld.so.cache", "/etc/ld.so.conf",
              "/etc/ld.so.conf.d"]
# merged-/usr symlinks or real dirs, depending on the distribution
_MAYBE_LINKS = ["/bin", "/sbin", "/lib", "/lib64", "/lib32"]


@dataclass
class Sandbox:
    backend: str          # "bwrap" | "unshare" | "none"
    level: str
    reason: str = ""

    def summary(self) -> dict:
        net = "disabled" if self.backend in ("bwrap", "unshare") else "host"
        if self.backend == "container":
            net = "disabled (verified: no non-loopback interface)" if _no_network() else "ENABLED"
        return {"backend": self.backend, "level": self.level, "reason": self.reason,
                "network": net,
                "filesystem": ("read-only system + private scratch" if self.backend == "bwrap"
                               else "host (not restricted)"),
                "pid_namespace": self.backend in ("bwrap", "unshare")}

    # ---------------------------------------------------------------- wrapping
    def wrap(self, argv: list[str], *, ro_paths: list[str], rw_paths: list[str],
             cwd: str) -> list[str]:
        """Return argv prefixed with the sandbox launcher.

        ro_paths: host paths made visible read-only at the same location.
        rw_paths: host paths made visible writable at the same location.
        """
        if self.backend == "bwrap":
            cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                   "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
            for p in _SYSTEM_RO:
                if os.path.exists(p):
                    cmd += ["--ro-bind", p, p]
            for p in _MAYBE_LINKS:
                if os.path.islink(p):
                    cmd += ["--symlink", os.readlink(p), p]
                elif os.path.isdir(p):
                    cmd += ["--ro-bind", p, p]
            seen = set()
            for p in ro_paths:
                p = os.path.abspath(p)
                if p in seen or not os.path.exists(p):
                    continue
                seen.add(p)
                cmd += ["--ro-bind", p, p]
            for p in rw_paths:
                p = os.path.abspath(p)
                if p in seen or not os.path.exists(p):
                    continue
                seen.add(p)
                cmd += ["--bind", p, p]
            cmd += ["--chdir", cwd, "--"]
            return cmd + argv
        if self.backend == "unshare":
            return ["unshare", "--user", "--map-root-user", "--net", "--pid",
                    "--fork", "--kill-child", "--mount-proc", "--"] + argv
        return argv


def _no_network() -> bool:
    """True if the current network namespace has no interface besides lo."""
    try:
        with open("/proc/net/dev") as fh:
            names = [l.split(":")[0].strip() for l in fh.readlines()[2:]]
        return all(n == "lo" for n in names)
    except OSError:
        return False


def _probe(cmd: list[str]) -> bool:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=15)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def select(requested: str = "auto") -> Sandbox:
    """Pick a working backend. 'auto' prefers bwrap, then unshare, then none."""
    true_bin = shutil.which("true") or "/usr/bin/true"
    order = ["bwrap", "unshare"] if requested == "auto" else [requested]
    failures = []
    for name in order:
        if name == "none":
            return Sandbox("none", LEVEL_NONE, "explicitly requested")
        if shutil.which(name) is None:
            failures.append(f"{name}: not installed")
            continue
        sb = Sandbox(name, LEVEL_FULL if name == "bwrap" else LEVEL_PARTIAL)
        if _probe(sb.wrap([true_bin], ro_paths=[], rw_paths=[], cwd="/")):
            return sb
        failures.append(f"{name}: present but not usable (namespaces denied?)")
    if os.environ.get("PATCHVAL_CONTAINER") == "1" and requested == "auto":
        # patchval itself runs in a dedicated container (see scripts/run_in_docker.sh):
        # the container is the isolation boundary. Network isolation is verified.
        lvl = LEVEL_FULL if _no_network() else LEVEL_PARTIAL
        return Sandbox("container", lvl, "running inside a dedicated resource-limited container"
                       + ("" if lvl == LEVEL_FULL else "; WARNING: container has network access"))
    return Sandbox("none", LEVEL_NONE, "; ".join(failures) or "no backend")
