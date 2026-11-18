"""Sandboxed execution of a target binary against one input.

Every execution is isolated with resource limits (CPU time, address space,
output size, and a wall-clock timeout) so that a buggy or looping target
cannot wedge the pipeline. We capture exactly what the brief asks for:
exit code, terminating signal, stdout, stderr, wall time, and whether a
resource/time limit was hit -- each reported separately, because "the program
stopped" is not the same as "an exploitable vulnerability exists".
"""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import time
from dataclasses import dataclass, field

from .config import Config, TestCase


# Signal number -> name, for the subset relevant to crash analysis.
_SIGNAL_NAMES = {
    signal.SIGSEGV: "SIGSEGV",
    signal.SIGABRT: "SIGABRT",
    signal.SIGFPE: "SIGFPE",
    signal.SIGILL: "SIGILL",
    signal.SIGBUS: "SIGBUS",
    signal.SIGKILL: "SIGKILL",
    signal.SIGTERM: "SIGTERM",
    getattr(signal, "SIGSYS", 31): "SIGSYS",
}


@dataclass
class RunResult:
    test_id: str
    returncode: int                 # process return code (negative if killed by signal, Python convention normalised below)
    exit_code: int | None           # normal exit code, or None if killed by signal
    signal_num: int | None
    signal_name: str | None
    stdout: str
    stderr: str
    wall_time: float
    timed_out: bool
    oom_or_rlimit: bool
    command: list[str]
    input_desc: str
    env_overrides: dict = field(default_factory=dict)

    @property
    def crashed(self) -> bool:
        """True if the process was terminated abnormally (signal) or a
        sanitizer forced a non-zero abort exit. Timeouts are *not* crashes."""
        if self.timed_out:
            return False
        if self.signal_num is not None:
            return True
        return False

    def summary(self) -> dict:
        return {
            "test_id": self.test_id,
            "exit_code": self.exit_code,
            "signal": self.signal_name,
            "wall_time": round(self.wall_time, 4),
            "timed_out": self.timed_out,
            "oom_or_rlimit": self.oom_or_rlimit,
            "command": self.command,
            "input": self.input_desc,
            "env": self.env_overrides,
            "stdout_tail": self.stdout[-4000:],
            "stderr_tail": self.stderr[-8000:],
        }


def _limits(mem_limit_mb: int, cpu_sec: int, apply_as_limit: bool):
    """Return a preexec_fn applying rlimits in the child before exec.

    apply_as_limit controls RLIMIT_AS. It MUST be False for sanitized builds:
    AddressSanitizer reserves a very large *virtual* shadow-memory region
    (tens of terabytes of address space), which a hard RLIMIT_AS would make
    fail at startup. For sanitized builds we bound *resident* memory through
    ASan's own hard_rss_limit_mb instead (see _sanitizer_env).
    """
    def _apply():  # pragma: no cover - runs in child process
        # New process group so timeout kills the whole group.
        os.setsid()
        mem_bytes = mem_limit_mb * 1024 * 1024
        if apply_as_limit:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):
                pass
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec + 1))
        except (ValueError, OSError):
            pass
        # Cap written file size to avoid disk-fill (64 MiB).
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
        except (ValueError, OSError):
            pass
        # No core dumps.
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass
    return _apply


def _sanitizer_env(mode_is_sanitized: bool, mem_limit_mb: int) -> dict:
    """Deterministic, machine-parseable sanitizer output.

    abort_on_error=1 makes ASan terminate via SIGABRT so the signal is a
    reliable crash witness; exitcode is a fallback for environments where
    abort is suppressed. hard_rss_limit_mb bounds resident memory (RLIMIT_AS
    cannot be used together with ASan's huge virtual shadow mapping).
    """
    if not mode_is_sanitized:
        return {}
    rss = max(64, mem_limit_mb)
    common = (
        f"abort_on_error=1:exitcode=99:print_stacktrace=1:detect_leaks=0:"
        f"handle_segv=1:hard_rss_limit_mb={rss}"
    )
    env = {
        "ASAN_OPTIONS": common + ":symbolize=1:halt_on_error=1",
        "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:abort_on_error=1",
    }
    # Only forward a symbolizer path if one is actually configured.
    sym = os.environ.get("ASAN_SYMBOLIZER_PATH")
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym
    return env


def build_argv(binary_path: str, cfg: Config, test: TestCase, input_path: str | None) -> tuple[list[str], str]:
    """Construct argv and describe how input is delivered."""
    argv = [binary_path]
    argv.extend(cfg.argv_template)
    argv.extend(test.argv)
    desc = ""
    if cfg.input_mode == "argv":
        if input_path is not None:
            argv.append(input_path)
            desc = f"argv path={os.path.basename(input_path)}"
        else:
            desc = "argv (no input file)"
    elif cfg.input_mode == "file":
        if input_path is not None:
            argv.append(input_path)
            desc = f"file arg={os.path.basename(input_path)}"
        else:
            desc = "file (none)"
    else:  # stdin
        desc = "stdin" + (f"={os.path.basename(input_path)}" if input_path else " (empty)")
    return argv, desc


def run(binary_path: str, cfg: Config, test: TestCase, mode_is_sanitized: bool,
        input_path: str | None = None) -> RunResult:
    """Execute one test case against one binary and capture full evidence."""
    if input_path is None:
        input_path = test.input_file
    argv, input_desc = build_argv(binary_path, cfg, test, input_path)

    stdin_bytes = b""
    if cfg.input_mode == "stdin" and input_path is not None:
        with open(input_path, "rb") as fh:
            stdin_bytes = fh.read()

    env = dict(os.environ)
    overrides = _sanitizer_env(mode_is_sanitized, cfg.mem_limit_mb)
    env.update(overrides)

    cpu_sec = max(1, int(cfg.timeout_sec) + 1)
    start = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            argv,
            input=stdin_bytes,
            capture_output=True,
            timeout=cfg.timeout_sec,
            env=env,
            preexec_fn=_limits(cfg.mem_limit_mb, cpu_sec, apply_as_limit=not mode_is_sanitized),
        )
        returncode = proc.returncode
        out_b, err_b = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 0
        out_b = exc.stdout or b""
        err_b = exc.stderr or b""
    wall = time.monotonic() - start

    stdout = out_b.decode("utf-8", "replace")
    stderr = err_b.decode("utf-8", "replace")

    exit_code: int | None
    signal_num: int | None
    signal_name: int | None
    oom = False
    if timed_out:
        exit_code = None
        signal_num = None
        signal_name = None
    elif returncode < 0:
        signal_num = -returncode
        signal_name = _SIGNAL_NAMES.get(signal_num, f"SIG{signal_num}")
        exit_code = None
        if signal_num == signal.SIGKILL:
            # Most likely the rlimit/OOM killer or CPU limit.
            oom = True
    else:
        exit_code = returncode
        signal_num = None
        signal_name = None
        # RLIMIT_CPU delivers SIGXCPU/SIGKILL; RLIMIT_AS surfaces as the target's
        # own allocation failure. A sanitizer OOM uses exitcode 99 too, but
        # ASan prints "out of memory"; leave fine-grained detection to crash.py.

    return RunResult(
        test_id=test.id,
        returncode=returncode,
        exit_code=exit_code,
        signal_num=signal_num,
        signal_name=signal_name,
        stdout=stdout,
        stderr=stderr,
        wall_time=wall,
        timed_out=timed_out,
        oom_or_rlimit=oom,
        command=argv,
        input_desc=input_desc,
        env_overrides=overrides,
    )
