"""Isolated execution of a target binary against one input.

Each run:
  * is wrapped by the selected sandbox backend (see sandbox.py),
  * gets rlimits (address space for release builds, CPU, file size, core,
    process count) and a wall-clock timeout,
  * runs in its own session; on timeout the WHOLE process group is killed
    (and bwrap's --die-with-parent/pid-namespace removes any survivors),
  * writes stdout/stderr to files inside a private scratch dir, so the
    file-size limit also bounds output volume.

Recorded evidence: exit code, terminating signal, timeout, resource-limit
hit, wall time, full command, input delivery mode and SHA-256 of the input.
"""

from __future__ import annotations

import hashlib
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from .config import Config, TestCase
from .sandbox import Sandbox

_OUTPUT_CAP = 1 << 20          # bytes of stdout/stderr kept in memory per run

_SIGNAL_NAMES = {s.value: s.name for s in signal.Signals}


@dataclass
class RunResult:
    test_id: str
    returncode: int
    exit_code: int | None
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
    input_sha256: str | None = None
    sandbox: str = "none"
    output_truncated: bool = False

    def summary(self) -> dict:
        return {
            "test_id": self.test_id,
            "exit_code": self.exit_code,
            "signal": self.signal_name,
            "timed_out": self.timed_out,
            "resource_limited": self.oom_or_rlimit,
            "wall_time": round(self.wall_time, 4),
            "command": self.command,
            "input": self.input_desc,
            "input_sha256": self.input_sha256,
            "sandbox": self.sandbox,
            "env": self.env_overrides,
            "output_truncated": self.output_truncated,
            "stdout_tail": self.stdout[-4000:],
            "stderr_tail": self.stderr[-8000:],
        }


def _user_proc_count() -> int:
    uid = os.getuid()
    n = 0
    try:
        for d in os.listdir("/proc"):
            if d.isdigit():
                try:
                    if os.stat(f"/proc/{d}").st_uid == uid:
                        n += 1
                except OSError:
                    pass
    except OSError:
        pass
    return n


def limits_fn(mem_limit_mb: int, cpu_sec: int, apply_as_limit: bool, max_procs: int):
    """preexec_fn applying rlimits in the child.

    RLIMIT_AS is skipped for sanitized builds: ASan reserves a huge *virtual*
    shadow region; resident memory is bounded with hard_rss_limit_mb instead.
    RLIMIT_NPROC counts all processes of the uid, so it is set relative to the
    current count (current + max_procs) to bound fork bombs without breaking
    a busy desktop session.
    """
    nproc = _user_proc_count() + max_procs

    def _apply():  # pragma: no cover - runs in the child
        mem = mem_limit_mb * 1024 * 1024
        pairs = [
            (resource.RLIMIT_CPU, (cpu_sec, cpu_sec + 1)),
            (resource.RLIMIT_FSIZE, (64 << 20, 64 << 20)),
            (resource.RLIMIT_CORE, (0, 0)),
            (resource.RLIMIT_NPROC, (nproc, nproc)),
        ]
        if apply_as_limit:
            pairs.append((resource.RLIMIT_AS, (mem, mem)))
        for res, val in pairs:
            try:
                resource.setrlimit(res, val)
            except (ValueError, OSError):
                pass
    return _apply


def sanitizer_env(mode_is_sanitized: bool, mem_limit_mb: int) -> dict:
    if not mode_is_sanitized:
        return {}
    rss = max(64, mem_limit_mb)
    env = {
        "ASAN_OPTIONS": ("abort_on_error=1:exitcode=99:print_stacktrace=1:"
                         "detect_leaks=0:handle_segv=1:symbolize=1:halt_on_error=1:"
                         f"hard_rss_limit_mb={rss}"),
        "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:abort_on_error=1",
    }
    sym = os.environ.get("ASAN_SYMBOLIZER_PATH")
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym
    return env


def _sha256_file(path: str | None) -> str | None:
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def build_argv(binary_path: str, cfg: Config, test: TestCase,
               input_path: str | None) -> tuple[list[str], str, bytes]:
    """argv, human description of delivery, and bytes for stdin.

    stdin : file content is written to the program's stdin.
    file  : the input FILE PATH is passed as an argument ({input} placeholder
            in argv_template, else appended).
    argv  : the file CONTENT is passed as argument(s) ({input_data}
            placeholder, else appended); with input.argv_split == "lines"
            every line becomes its own argument. NUL bytes cannot appear in
            argv, so content is cut at the first NUL (recorded).
    """
    data = b""
    if input_path is not None:
        with open(input_path, "rb") as fh:
            data = fh.read()

    args: list[str] = []
    mode = cfg.input_mode
    desc = mode
    content_args: list[str] = []
    if mode == "argv":
        raw = data.split(b"\0", 1)[0]
        if b"\0" in data:
            desc += " (truncated at NUL)"
        text = raw.decode("utf-8", "surrogateescape")
        if cfg.argv_split == "lines":
            content_args = [ln for ln in text.splitlines() if ln != ""]
        else:
            content_args = [text.rstrip("\n")]
    placeholder_used = False
    for a in cfg.argv_template + test.argv:
        if a == "{input}" and mode == "file":
            args.append(input_path or "")
            placeholder_used = True
        elif a == "{input_data}" and mode == "argv":
            args.extend(content_args)
            placeholder_used = True
        else:
            args.append(a)
    if not placeholder_used:
        if mode == "file" and input_path is not None:
            args.append(input_path)
        elif mode == "argv":
            args.extend(content_args)

    if input_path is not None:
        desc += f" <- {os.path.basename(input_path)}"
    stdin_bytes = data if mode == "stdin" else b""
    return [binary_path] + args, desc, stdin_bytes


def run(binary_path: str, cfg: Config, test: TestCase, mode_is_sanitized: bool,
        input_path: str | None = None, sandbox: Sandbox | None = None) -> RunResult:
    if input_path is None:
        input_path = test.input_file
    argv, desc, stdin_bytes = build_argv(binary_path, cfg, test, input_path)

    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/tmp"}
    overrides = sanitizer_env(mode_is_sanitized, cfg.mem_limit_mb)
    env.update(overrides)

    scratch = tempfile.mkdtemp(prefix="pv_run_")
    out_path = os.path.join(scratch, "stdout")
    err_path = os.path.join(scratch, "stderr")
    ro = [binary_path] + ([input_path] if input_path else [])
    sb = sandbox
    full_argv = sb.wrap(argv, ro_paths=ro, rw_paths=[scratch], cwd=scratch) if sb else argv

    cpu_sec = max(1, int(cfg.timeout_sec) + 1)
    timed_out = False
    start = time.monotonic()
    with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
        proc = subprocess.Popen(
            full_argv, stdin=subprocess.PIPE, stdout=fo, stderr=fe, cwd=scratch,
            env=env, start_new_session=True,
            preexec_fn=limits_fn(cfg.mem_limit_mb, cpu_sec,
                                 apply_as_limit=not mode_is_sanitized,
                                 max_procs=cfg.max_procs),
        )
        try:
            proc.communicate(input=stdin_bytes, timeout=cfg.timeout_sec)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)   # whole process group
            except ProcessLookupError:
                pass
            proc.wait()
        except BrokenPipeError:
            proc.wait()
    wall = time.monotonic() - start
    rc = proc.returncode

    def _read(p):
        with open(p, "rb") as fh:
            b = fh.read(_OUTPUT_CAP + 1)
        return b[:_OUTPUT_CAP].decode("utf-8", "replace"), len(b) > _OUTPUT_CAP
    stdout, t1 = _read(out_path)
    stderr, t2 = _read(err_path)
    shutil.rmtree(scratch, ignore_errors=True)

    exit_code = signal_num = signal_name = None
    oom = False
    if not timed_out:
        if rc < 0:
            signal_num = -rc
        elif sb and sb.backend in ("bwrap", "unshare") and 128 < rc <= 128 + 64 \
                and (rc - 128) in _SIGNAL_NAMES:
            # the launcher reports a signal-killed child as exit 128+signal
            signal_num = rc - 128
        else:
            exit_code = rc
        if signal_num is not None:
            signal_name = _SIGNAL_NAMES.get(signal_num, f"SIG{signal_num}")
            if signal_num in (signal.SIGKILL, signal.SIGXCPU, signal.SIGXFSZ):
                oom = True
        if "hard rss limit exhausted" in stderr or "out of memory" in stderr.lower() \
                and "AddressSanitizer" in stderr:
            oom = True

    return RunResult(
        test_id=test.id, returncode=rc, exit_code=exit_code, signal_num=signal_num,
        signal_name=signal_name, stdout=stdout, stderr=stderr, wall_time=wall,
        timed_out=timed_out, oom_or_rlimit=oom, command=argv, input_desc=desc,
        env_overrides=overrides, input_sha256=_sha256_file(input_path),
        sandbox=sb.backend if sb else "none", output_truncated=t1 or t2,
    )
