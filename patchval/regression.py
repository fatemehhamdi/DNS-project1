"""Reproducer bundles and the persistent regression-test loop (brief sec. 3.3).

Reproducer bundle (one directory per confirmed finding) -- self-contained:
  manifest.json       source identity (git commit + dirty flag + tree sha256),
                      binary sha256, build command/flags, env, run command,
                      input delivery mode, expected crash identity, replays
  bin/base.bin        the exact binary that crashed (+ bin/patched.bin)
  lib/                sanitizer runtime libraries the binary links against
  src/base, src/patched   snapshot of both source trees
  input.orig.bin / input.min.bin
  build.sh            rebuilds bin/base.bin from src/base with the recorded command
  replay.sh           replays N>=3 times, checks the SAME error class and the
                      SAME faulting function appear each time, and checks the
                      patched binary does not reproduce it. Exit 0 = reproduced.

Regression loop: confirmed inputs (minimized when available) are appended to
the persistent suite file named in the config (regression.suite). Every later
run loads that suite and executes its entries as security tests: they must
still crash the base version and must not crash the patched version.
"""

from __future__ import annotations

import datetime
import glob
import hashlib
import json
import os
import shlex
import shutil

from .config import Config, TestCase

SUITE_VERSION = 2


def _sha256(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _copy_tree(src: str, dst: str) -> None:
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("*.o", "*.bin", "__pycache__"))


def _sanitizer_libs(ldd_lines: list[str]) -> list[str]:
    out = []
    for l in ldd_lines:
        parts = l.split("=>")
        if len(parts) == 2:
            path = parts[1].strip().split(" ")[0]
            name = os.path.basename(path)
            if any(k in name for k in ("libasan", "libubsan", "liblsan", "libtsan",
                                       "libclang_rt", "libstdc++", "libgcc_s")):
                if os.path.isfile(path):
                    out.append(path)
    return out


def _check_expr(crash: dict) -> tuple[str, str]:
    """grep patterns that must appear in stderr for the same crash."""
    det = crash.get("detection")
    et = crash.get("error_type") or ""
    head = crash.get("sanitizer_headline") or ""
    if det == "sanitizer_asan":
        kind = head.split("AddressSanitizer:", 1)[-1].strip() or et
        cls = f"AddressSanitizer: {kind}"
    elif det == "sanitizer_ubsan":
        cls = "runtime error:"
    elif det == "stack_canary":
        cls = "stack smashing detected"
    elif det == "fortify":
        cls = "buffer overflow detected"
    else:
        cls = ""
    frames = crash.get("top_frames") or []
    fn = next((f["function"] for f in frames if f.get("file") and f.get("function")), "")
    return cls, fn


def _invoke_line(cfg: Config, bin_expr: str) -> str:
    fixed = " ".join(shlex.quote(a) for a in cfg.argv_template
                     if a not in ("{input}", "{input_data}"))
    if cfg.input_mode == "stdin":
        return f'{bin_expr} {fixed} < "$INPUT"'
    if cfg.input_mode == "file":
        return f'{bin_expr} {fixed} "$INPUT"'
    if cfg.argv_split == "lines":
        return (f'ARGS=(); while IFS= read -r l || [ -n "$l" ]; do [ -n "$l" ] && ARGS+=("$l"); '
                f'done < "$INPUT"; {bin_expr} {fixed} "${{ARGS[@]}}"')
    return f'{bin_expr} {fixed} "$(cat "$INPUT")"'


# finding status -> (expectation on base, expectation on patched)
_EXPECT = {
    "FIXED": ("repro", "clean"),
    "VULN_REMAINS": ("repro", "repro"),
    "INCOMPLETE_FIX": ("repro", "repro"),
    "NEW_ISSUE": ("none", "repro"),
}
_DESC = {"repro": "reproduces the recorded error (class + function) in all N replays",
         "clean": "does NOT reproduce it AND exits gracefully in all N replays",
         "none": "does NOT reproduce the error in any replay"}
_BASE_CHECK = {
    "repro": '[ "$base_rep" -eq "$N" ] || verdict=10',
    "none": '[ "$base_rep" -eq 0 ] || verdict=10',
}
_PATCHED_CHECK = {
    "repro": '[ -x "$HERE/bin/patched.bin" ] && [ "$pat_rep" -eq "$N" ] || verdict=10',
    "clean": '[ -x "$HERE/bin/patched.bin" ] && [ "$pat_rep" -eq 0 ] && [ "$pat_clean" -eq "$N" ] || verdict=10',
}


def _expected_outcome(status: str) -> dict:
    b, p = _EXPECT.get(status, _EXPECT["FIXED"])
    return {"base": _DESC[b], "patched": _DESC[p]}


def build_reproducer(cfg: Config, test: TestCase, finding_status: str, mode: str,
                     base_build, patched_build, crash_summary: dict, run_summary: dict,
                     minim, replays: list[str], out_root: str, crash_side: str = "base",
                     graceful: list[int] | None = None) -> dict:
    bdir = os.path.join(out_root, test.id)
    if os.path.isdir(bdir):
        shutil.rmtree(bdir)
    os.makedirs(os.path.join(bdir, "bin"))
    os.makedirs(os.path.join(bdir, "lib"))

    shutil.copy2(base_build.binary_path, os.path.join(bdir, "bin", "base.bin"))
    if patched_build is not None and patched_build.ok:
        shutil.copy2(patched_build.binary_path, os.path.join(bdir, "bin", "patched.bin"))
    libs = _sanitizer_libs(base_build.runtime_libs)
    for lib in libs:
        shutil.copy2(lib, os.path.join(bdir, "lib", os.path.basename(lib)))
    _copy_tree(cfg.base.path, os.path.join(bdir, "src", "base"))
    _copy_tree(cfg.patched.path, os.path.join(bdir, "src", "patched"))

    orig = os.path.join(bdir, "input.orig.bin")
    shutil.copy2(minim.original_path if minim else test.input_file, orig)
    inp_name = "input.orig.bin"
    if minim is not None:
        shutil.copy2(minim.minimized_path, os.path.join(bdir, "input.min.bin"))
        if minim.stable:
            inp_name = "input.min.bin"

    cls, fn = _check_expr(crash_summary)
    manifest = {
        "bundle_format": 2,
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "target": cfg.name, "test_id": test.id, "finding_status": finding_status,
        "build_mode": mode,
        "source": {"base": base_build.source,
                   "patched": patched_build.source if patched_build else None},
        "binary": {"base_sha256": base_build.binary_sha256,
                   "patched_sha256": patched_build.binary_sha256 if patched_build else None,
                   "runtime_libs_ldd": base_build.runtime_libs,
                   "bundled_libs": [os.path.basename(l) for l in libs]},
        "build": {"command": base_build.command, "cflags": base_build.cflags,
                  "template": cfg.build_command},
        "run": {"input_mode": cfg.input_mode, "argv_split": cfg.argv_split,
                "argv_template": cfg.argv_template, "command": run_summary.get("command"),
                "env": run_summary.get("env"), "timeout_sec": cfg.timeout_sec,
                "input_used_by_replay": inp_name},
        "inputs": {"original": {"file": "input.orig.bin", "sha256": _sha256(orig),
                                "size": os.path.getsize(orig)},
                   "minimized": ({"file": "input.min.bin",
                                  "sha256": _sha256(os.path.join(bdir, "input.min.bin")),
                                  "size": minim.minimized_size, "stable": minim.stable,
                                  "iterations": minim.iterations,
                                  "preserved_signature": minim.preserved_signature,
                                  "replays": minim.replays} if minim else None)},
        "crash_side": crash_side,
        "graceful_exit_codes": list(graceful) if graceful is not None else list(cfg.graceful_exit_codes),
        "expected_replay_outcome": _expected_outcome(finding_status),
        "expected": {"crash": crash_summary, "stderr_must_contain": [x for x in (cls, fn) if x]},
        "replays_during_analysis": replays,
    }
    with open(os.path.join(bdir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    env = run_summary.get("env") or {}
    env_exports = "\n".join(f"export {k}={shlex.quote(v)}" for k, v in env.items())
    build_cmd = cfg.build_command.replace("{cflags}", base_build.cflags) \
        .replace("{src}", '"$HERE/src/base"').replace("{out}", '"$HERE/bin/base.bin"') \
        .replace("{builddir}", '"$HERE/bin"').replace("{mode}", mode)
    with open(os.path.join(bdir, "build.sh"), "w") as fh:
        fh.write(f"""#!/usr/bin/env bash
# Rebuild the vulnerable base binary from the bundled source snapshot.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
{build_cmd}
echo "rebuilt: $HERE/bin/base.bin  sha256=$(sha256sum "$HERE/bin/base.bin" | cut -d' ' -f1)"
echo "recorded sha256: {base_build.binary_sha256}  (may differ if the toolchain differs)"
""")
    must = [x for x in (cls, fn) if x]
    checks = " && ".join(f'grep -qF -- {shlex.quote(m)} "$ERR"' for m in must) or "[ $rc -ne 0 ]"
    tmo = int(cfg.timeout_sec)
    invoke = _invoke_line(cfg, f'${{ISO[@]+"${{ISO[@]}}"}} timeout {tmo} "$BIN"')
    gr = " ".join(str(c) for c in (graceful if graceful is not None else cfg.graceful_exit_codes))
    exp_base, exp_patched = _EXPECT[finding_status if finding_status in _EXPECT else "FIXED"]
    with open(os.path.join(bdir, "replay.sh"), "w") as fh:
        fh.write(f"""#!/usr/bin/env bash
# Replay finding '{test.id}' of target '{cfg.name}' ({mode} build).
# Recorded finding status: {finding_status}
#
# Exit 0 only if EVERY condition for this finding type holds in all N replays:
#   base    : {_DESC[exp_base]}
#   patched : {_DESC[exp_patched]}
# Exit 10 = verdict of the recorded finding NOT confirmed, 30 = no isolation available.
#
# The binaries are untrusted/vulnerable: they run ONLY inside an isolation backend
# (bwrap > unshare --net, or inside the patchval container). Set
# PATCHVAL_ALLOW_UNSAFE_REPLAY=1 to override for local debugging only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
N="${{1:-3}}"
[ "$N" -ge 3 ] || N=3
INPUT="$HERE/{inp_name}"
GRACEFUL="{gr}"
export LD_LIBRARY_PATH="$HERE/lib${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"
{env_exports}

# ---- isolation ---------------------------------------------------------
ISO=()
BW=()
if command -v bwrap >/dev/null 2>&1; then
  BW=(bwrap --unshare-all --die-with-parent --new-session --proc /proc --dev /dev --tmpfs /tmp
      --ro-bind /usr /usr --ro-bind "$HERE" "$HERE")
  for d in /lib /lib64 /bin /sbin; do
    if [ -L "$d" ]; then BW+=(--symlink "$(readlink "$d")" "$d");
    elif [ -d "$d" ]; then BW+=(--ro-bind "$d" "$d"); fi
  done
  [ -e /etc/ld.so.cache ] && BW+=(--ro-bind /etc/ld.so.cache /etc/ld.so.cache)
fi
if [ "${{#BW[@]}}" -gt 0 ] && "${{BW[@]}}" true >/dev/null 2>&1; then
  ISO=("${{BW[@]}}")
  ISOLATION="bwrap"
elif command -v unshare >/dev/null 2>&1 && unshare --user --map-root-user --net --pid --fork true >/dev/null 2>&1; then
  ISO=(unshare --user --map-root-user --net --pid --fork --kill-child --mount-proc --)
  ISOLATION="unshare (filesystem not restricted)"
elif [ "${{PATCHVAL_CONTAINER:-0}}" = "1" ]; then
  ISOLATION="container"
elif [ "${{PATCHVAL_ALLOW_UNSAFE_REPLAY:-0}}" = "1" ]; then
  ISOLATION="NONE (unsafe override)"
else
  echo "replay.sh: no isolation backend (bwrap/unshare/container) available; refusing to run" >&2
  echo "           the vulnerable binaries on the host. Install bubblewrap or use Docker." >&2
  exit 30
fi
echo "isolation: $ISOLATION"

ERR="$(mktemp)"
run_bin() {{ local BIN="$1"; {invoke}; }}
check() {{ {checks}; }}
graceful() {{ case " $GRACEFUL " in *" $1 "*) return 0;; esac; return 1; }}

base_rep=0; pat_rep=0; pat_clean=0
for i in $(seq 1 "$N"); do
  run_bin "$HERE/bin/base.bin" >/dev/null 2>"$ERR"; rc=$?
  if check; then echo "replay $i (base):    REPRODUCED (rc=$rc)"; base_rep=$((base_rep+1));
  else echo "replay $i (base):    not reproduced (rc=$rc)"; fi
done
if [ -x "$HERE/bin/patched.bin" ]; then
  for i in $(seq 1 "$N"); do
    run_bin "$HERE/bin/patched.bin" >/dev/null 2>"$ERR"; rc=$?
    if check; then echo "replay $i (patched): REPRODUCED (rc=$rc)"; pat_rep=$((pat_rep+1));
    elif graceful "$rc"; then echo "replay $i (patched): clean, graceful exit (rc=$rc)"; pat_clean=$((pat_clean+1));
    else echo "replay $i (patched): not reproduced but NOT a graceful exit (rc=$rc) -> inconclusive"; fi
  done
else
  echo "no patched binary in bundle"
fi
rm -f "$ERR"
echo "base reproduced $base_rep/$N, patched reproduced $pat_rep/$N, patched clean $pat_clean/$N"

verdict=0
{_BASE_CHECK[exp_base]}
{_PATCHED_CHECK[exp_patched]}
if [ "$verdict" -eq 0 ]; then echo "CONFIRMED: {finding_status}"; else echo "NOT CONFIRMED: {finding_status}"; fi
exit "$verdict"
""")
    for s in ("build.sh", "replay.sh"):
        os.chmod(os.path.join(bdir, s), 0o755)
    return {"bundle_dir": bdir, "manifest": os.path.join(bdir, "manifest.json"),
            "replay_input": inp_name}


# --------------------------------------------------------------- suite loop

def _load_suite(path: str) -> dict:
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("version") == SUITE_VERSION:
                return data
        except (OSError, json.JSONDecodeError):
            pass
    return {"version": SUITE_VERSION, "tests": []}


def load_regression_tests(cfg: Config, base_tree_sha: str) -> list[TestCase]:
    """Turn suite entries into security TestCases for this run."""
    if not cfg.regression_suite:
        return []
    suite = _load_suite(cfg.regression_suite)
    sdir = os.path.dirname(cfg.regression_suite)
    out = []
    for e in suite["tests"]:
        inp = os.path.join(sdir, e["input"])
        if not os.path.isfile(inp):
            continue
        drift = e.get("origin", {}).get("base_tree_sha256") != base_tree_sha
        t = TestCase(id=e["id"], input_file=inp, kind="security", is_known_crasher=True,
                     description=f"auto-generated regression test from {e['origin'].get('test')}",
                     regression_origin=dict(e.get("origin", {}), base_drift=drift,
                                            expected_identity=e.get("expected_identity"),
                                            expected_mode=e.get("expected_mode")))
        out.append(t)
    return out


def register(cfg: Config, test: TestCase, input_path: str, identity: tuple,
             crash_summary: dict, base_tree_sha: str, minimized: bool,
             mode: str | None = None) -> dict | None:
    """Append one confirmed input to the persistent suite (dedupe by content)."""
    if not cfg.regression_suite:
        return None
    suite = _load_suite(cfg.regression_suite)
    sdir = os.path.dirname(cfg.regression_suite)
    os.makedirs(os.path.join(sdir, "inputs"), exist_ok=True)
    sha = _sha256(input_path)
    for e in suite["tests"]:
        if e["input_sha256"] == sha:
            return None                                   # already in the suite
    origin_test = test.regression_origin.get("test") if test.regression_origin else test.id
    tid = f"reg_{origin_test}_{sha[:8]}"
    rel = os.path.join("inputs", f"{tid}.bin")
    shutil.copy2(input_path, os.path.join(sdir, rel))
    entry = {
        "id": tid, "input": rel, "input_sha256": sha, "minimized": minimized,
        "expected_identity": list(identity), "expected_mode": mode,
        "expected_error_type": crash_summary.get("error_type"),
        "expected_detection": crash_summary.get("detection"),
        "assert": {"base": "crash with expected identity", "patched": "no crash, graceful exit"},
        "origin": {"config": cfg.name, "test": origin_test, "base_tree_sha256": base_tree_sha,
                   "created_utc": datetime.datetime.now(datetime.timezone.utc)
                   .isoformat(timespec="seconds")},
    }
    suite["tests"].append(entry)
    with open(cfg.regression_suite, "w", encoding="utf-8") as fh:
        json.dump(suite, fh, indent=2)
    return entry


def relocate_suite(suite_path: str | None, registry_dir: str) -> str | None:
    """Map a config's suite file into a writable, persistent registry directory.

    Used when the project tree is read-only (Docker: root fs is read-only, the
    registry lives on a mounted volume). The shipped suite is copied there once
    (seed) and the volume copy is authoritative afterwards.
    """
    if not suite_path:
        return None
    src_dir = os.path.dirname(suite_path)
    target = os.path.basename(os.path.dirname(src_dir)) or "default"
    dst_dir = os.path.join(registry_dir, target)
    dst = os.path.join(dst_dir, os.path.basename(suite_path))
    if not os.path.exists(dst) and os.path.isdir(src_dir):
        os.makedirs(registry_dir, exist_ok=True)
        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
    os.makedirs(dst_dir, exist_ok=True)
    return dst
