"""Unit tests for execution settings and isolation."""

import json
import os
import sys
from dataclasses import replace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchval import runner, sandbox
from patchval.config import ConfigError, TestCase, load


def _load_test_config(tmp_path):
    for name in ("base", "patched"):
        (tmp_path / name).mkdir()
    (tmp_path / "sample.txt").write_text("mode=demo\n")
    config = tmp_path / "target.json"
    config.write_text(json.dumps({
        "name": "test",
        "versions": {"base": {"path": "base"}, "patched": {"path": "patched"}},
        "build": {"command": "true", "binary": "target"},
        "tests": {"functional": [{"id": "sample", "input_file": "sample.txt"}]},
    }))
    return load(str(config))


def test_defect3c_config_rejects_fewer_than_three_replays(tmp_path):
    (tmp_path / "b").mkdir(); (tmp_path / "p").mkdir()
    (tmp_path / "i").write_text("x")
    cfg = tmp_path / "c.yaml"
    cfg.write_text("name: x\nversions: {base: {path: b}, patched: {path: p}}\n"
                   "build: {command: 'true', binary: x}\nrun: {replays: 2}\n"
                   "tests: {security: [{id: s, input_file: i, known_crasher: true}]}\n")
    with pytest.raises(ConfigError):
        load(str(cfg))


def test_defect6_timeout_kills_whole_process_group(tmp_path):
    import shutil, subprocess, time
    if not shutil.which("gcc"):
        pytest.skip("gcc missing")
    src = tmp_path / "h.c"
    src.write_text("#include <unistd.h>\nint main(void){if(fork()==0){for(;;)sleep(1);}for(;;)sleep(1);}\n")
    binp = tmp_path / "hangbin"
    subprocess.run(["gcc", str(src), "-o", str(binp)], check=True)
    cfg = _load_test_config(tmp_path)
    cfg = replace(cfg, timeout_sec=1)
    r = runner.run(str(binp), cfg, TestCase(id="h", input_file=None, kind="valid"), False,
                   sandbox=sandbox.Sandbox("none", sandbox.LEVEL_NONE))
    time.sleep(0.3)
    left = subprocess.run(["pgrep", "-f", str(binp)], capture_output=True, text=True).stdout.split()
    assert r.timed_out and left == []


def test_input_modes_build_correct_argv(tmp_path):
    inp = tmp_path / "in.txt"; inp.write_text("a=1\nb=2\n")
    cfg = _load_test_config(tmp_path)
    t = TestCase(id="t", input_file=str(inp), kind="valid")
    argv, _, stdin = runner.build_argv("/bin/x", replace(cfg, input_mode="stdin"), t, str(inp))
    assert argv == ["/bin/x"] and stdin == b"a=1\nb=2\n"
    argv, _, stdin = runner.build_argv("/bin/x", replace(
        cfg, input_mode="file", argv_template=["-f", "{input}"]), t, str(inp))
    assert argv == ["/bin/x", "-f", str(inp)] and stdin == b""
    argv, _, _ = runner.build_argv("/bin/x", replace(
        cfg, input_mode="argv", argv_split="lines"), t, str(inp))
    assert argv == ["/bin/x", "a=1", "b=2"]
    argv, _, _ = runner.build_argv("/bin/x", replace(cfg, input_mode="argv"), t, str(inp))
    assert argv == ["/bin/x", "a=1\nb=2"]


def test_sandbox_blocks_writes_outside_scratch(tmp_path):
    sb = sandbox.select("bwrap")
    if sb.backend != "bwrap":
        pytest.skip("bwrap not usable here")
    target = tmp_path / "should_not_exist"
    scratch = tmp_path / "scratch"; scratch.mkdir()
    import subprocess
    cmd = sb.wrap(["/bin/sh", "-c", f"touch {target}; touch {scratch}/ok"],
                  ro_paths=[], rw_paths=[str(scratch)], cwd=str(scratch))
    subprocess.run(cmd, capture_output=True)
    assert not target.exists() and (scratch / "ok").exists()


def test_config_rejects_missing_versions(tmp_path):
    with pytest.raises(ConfigError):
        load("/nonexistent/x.yaml")
    cfg = tmp_path / "c.yaml"
    cfg.write_text("name: x\nbuild:\n  command: gcc\n  binary: a\n")
    with pytest.raises(ConfigError):
        load(str(cfg))
