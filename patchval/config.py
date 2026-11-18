"""Configuration loading and validation.

A core design requirement from the project brief: adding a *new* target must
require only a configuration change (build command, binary path, how input is
delivered, and the test set) -- never a code change inside the tool. This
module defines and validates that configuration contract.

The config is YAML (JSON is also accepted since JSON is a subset). All
relative paths are resolved against the directory containing the config file,
so a config is self-contained and relocatable.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False


class ConfigError(Exception):
    """Raised for any malformed or incomplete configuration.

    The caller maps this to exit code 30 (BUILD_OR_CONFIG_ERROR).
    """


@dataclass
class TestCase:
    __test__ = False  # not a pytest test class
    id: str
    input_file: str | None          # absolute path, or None for empty stdin
    kind: str                       # "valid" | "boundary" | "invalid" | "security"
    argv: list[str] = field(default_factory=list)
    expect_exit: int | None = None          # expected exit code (functional oracle)
    expect_signal: str | None = None        # e.g. "SIGSEGV" (rare, for invalid)
    stdout_contains: list[str] = field(default_factory=list)
    stdout_equals: str | None = None
    stderr_contains: list[str] = field(default_factory=list)
    # For security tests: this input reproduced the known bug on the base.
    is_known_crasher: bool = False
    description: str = ""


@dataclass
class VersionSpec:
    name: str          # "base" | "patched"
    path: str          # absolute source directory


@dataclass
class Config:
    name: str
    config_dir: str
    base: VersionSpec
    patched: VersionSpec
    build_command: str
    binary_rel: str
    cflags_release: str
    cflags_sanitized: str
    input_mode: str                 # "stdin" | "file" | "argv"
    argv_template: list[str]
    timeout_sec: float
    mem_limit_mb: int
    functional_tests: list[TestCase]
    security_tests: list[TestCase]
    diff_mode: str                  # "auto" | "file"
    diff_file: str | None
    language: str                   # "c" | "cpp" (informational)

    @property
    def all_tests(self) -> list[TestCase]:
        return self.functional_tests + self.security_tests


_VALID_INPUT_MODES = {"stdin", "file", "argv"}
_VALID_KINDS = {"valid", "boundary", "invalid", "security"}


def _abspath(config_dir: str, p: str) -> str:
    if os.path.isabs(p):
        return p
    return os.path.normpath(os.path.join(config_dir, p))


def _require(d: dict, key: str, ctx: str) -> Any:
    if key not in d:
        raise ConfigError(f"missing required key '{key}' in {ctx}")
    return d[key]


def _parse_test(raw: dict, config_dir: str, default_kind: str) -> TestCase:
    if not isinstance(raw, dict):
        raise ConfigError(f"test entry must be a mapping, got {type(raw).__name__}")
    tid = _require(raw, "id", "test")
    kind = raw.get("kind", default_kind)
    if kind not in _VALID_KINDS:
        raise ConfigError(f"test '{tid}': invalid kind '{kind}'")
    input_file = raw.get("input_file")
    if input_file is not None:
        input_file = _abspath(config_dir, input_file)
        if not os.path.isfile(input_file):
            raise ConfigError(f"test '{tid}': input_file not found: {input_file}")
    expect = raw.get("expect", {}) or {}
    stdout_contains = expect.get("stdout_contains", [])
    if isinstance(stdout_contains, str):
        stdout_contains = [stdout_contains]
    stderr_contains = expect.get("stderr_contains", [])
    if isinstance(stderr_contains, str):
        stderr_contains = [stderr_contains]
    return TestCase(
        id=str(tid),
        input_file=input_file,
        kind=kind,
        argv=[str(a) for a in raw.get("argv", [])],
        expect_exit=expect.get("exit_code"),
        expect_signal=expect.get("signal"),
        stdout_contains=[str(s) for s in stdout_contains],
        stdout_equals=expect.get("stdout_equals"),
        stderr_contains=[str(s) for s in stderr_contains],
        is_known_crasher=bool(raw.get("known_crasher", default_kind == "security" and raw.get("known_crasher", False))),
        description=str(raw.get("description", "")),
    )


def load(path: str) -> Config:
    """Load and validate a target configuration file."""
    if not os.path.isfile(path):
        raise ConfigError(f"config file not found: {path}")
    config_dir = os.path.dirname(os.path.abspath(path))
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    data: Any
    try:
        if _HAVE_YAML:
            data = yaml.safe_load(text)
        else:  # pragma: no cover
            data = json.loads(text)
    except Exception as exc:
        raise ConfigError(f"could not parse config: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("top-level config must be a mapping")

    name = str(_require(data, "name", "config"))

    versions = _require(data, "versions", "config")
    if not isinstance(versions, dict) or "base" not in versions or "patched" not in versions:
        raise ConfigError("config.versions must define 'base' and 'patched'")
    base_path = _abspath(config_dir, _require(versions["base"], "path", "versions.base"))
    patched_path = _abspath(config_dir, _require(versions["patched"], "path", "versions.patched"))
    for p, label in ((base_path, "base"), (patched_path, "patched")):
        if not os.path.isdir(p):
            raise ConfigError(f"versions.{label}.path is not a directory: {p}")

    build = _require(data, "build", "config")
    build_command = str(_require(build, "command", "build"))
    binary_rel = str(_require(build, "binary", "build"))
    cflags_release = str(build.get("cflags_release", "-O2 -g"))
    cflags_sanitized = str(build.get(
        "cflags_sanitized",
        "-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer "
        "-fno-sanitize-recover=all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0",
    ))

    inp = data.get("input", {}) or {}
    input_mode = str(inp.get("mode", "stdin"))
    if input_mode not in _VALID_INPUT_MODES:
        raise ConfigError(f"input.mode must be one of {_VALID_INPUT_MODES}")
    argv_template = [str(a) for a in inp.get("argv_template", [])]

    run = data.get("run", {}) or {}
    timeout_sec = float(run.get("timeout_sec", 10))
    mem_limit_mb = int(run.get("mem_limit_mb", 512))
    if timeout_sec <= 0:
        raise ConfigError("run.timeout_sec must be positive")

    tests = data.get("tests", {}) or {}
    functional = [_parse_test(t, config_dir, "valid") for t in tests.get("functional", [])]
    security = [_parse_test(t, config_dir, "security") for t in tests.get("security", [])]
    # Mark security crashers unless explicitly overridden.
    for t in security:
        if t.kind == "security" and not t.stdout_contains and t.expect_exit is None:
            t.is_known_crasher = True

    diff = data.get("diff", {}) or {}
    diff_mode = str(diff.get("mode", "auto"))
    diff_file = diff.get("file")
    if diff_file is not None:
        diff_file = _abspath(config_dir, diff_file)
    if diff_mode not in {"auto", "file"}:
        raise ConfigError("diff.mode must be 'auto' or 'file'")
    if diff_mode == "file" and (diff_file is None or not os.path.isfile(diff_file)):
        raise ConfigError("diff.mode is 'file' but diff.file is missing")

    if not functional and not security:
        raise ConfigError("config must define at least one test")

    return Config(
        name=name,
        config_dir=config_dir,
        base=VersionSpec("base", base_path),
        patched=VersionSpec("patched", patched_path),
        build_command=build_command,
        binary_rel=binary_rel,
        cflags_release=cflags_release,
        cflags_sanitized=cflags_sanitized,
        input_mode=input_mode,
        argv_template=argv_template,
        timeout_sec=timeout_sec,
        mem_limit_mb=mem_limit_mb,
        functional_tests=functional,
        security_tests=security,
        diff_mode=diff_mode,
        diff_file=diff_file,
        language=str(data.get("language", "c")),
    )
