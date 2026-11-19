#!/usr/bin/env bash
# Replay finding 'crash_narrow' of target 'csvsum-incomplete' (sanitized build).
# Exit 0 = the base binary reproduced the SAME error class in the SAME function
#          in every replay (the patched binary is replayed too, for contrast).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
N="${1:-3}"
INPUT="$HERE/input.min.bin"
export LD_LIBRARY_PATH="$HERE/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export ASAN_OPTIONS=abort_on_error=1:exitcode=99:print_stacktrace=1:detect_leaks=0:handle_segv=1:symbolize=1:halt_on_error=1:hard_rss_limit_mb=512
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1:abort_on_error=1
ERR="$(mktemp)"
run_bin() { local BIN="$1"; timeout 10 "$BIN"  < "$INPUT"; }
check() { grep -qF -- 'AddressSanitizer: heap-buffer-overflow' "$ERR" && grep -qF -- accumulate "$ERR"; }
ok=0; pat=0
for i in $(seq 1 "$N"); do
  run_bin "$HERE/bin/base.bin" >/dev/null 2>"$ERR"; rc=$?
  if check; then echo "replay $i (base):    REPRODUCED (rc=$rc)"; ok=$((ok+1));
  else echo "replay $i (base):    NOT reproduced (rc=$rc)"; fi
done
if [ -x "$HERE/bin/patched.bin" ]; then
  for i in $(seq 1 "$N"); do
    run_bin "$HERE/bin/patched.bin" >/dev/null 2>"$ERR"; rc=$?
    if check; then echo "replay $i (patched): REPRODUCED (rc=$rc)"; pat=$((pat+1));
    else echo "replay $i (patched): not reproduced (rc=$rc)"; fi
  done
fi
rm -f "$ERR"
echo "base reproduced $ok/$N, patched reproduced $pat/$N"
[ "$ok" -eq "$N" ]
