#!/usr/bin/env bash
#
# run_all.sh -- validate every (target, patch) scenario and check that each
# produces the exit code the brief specifies. Every scenario writes a JSON and
# a text report.
#
#   ./run_all.sh                      reports under a temp dir
#   REPORTS=examples/reports ./run_all.sh   also copy reports there
#   Isolation (bwrap/unshare/container) is mandatory; without it every scenario exits 30.
#   Local development on a machine without a sandbox: EXTRA_ARGS="--allow-no-isolation --no-minimize"
#   (such runs are flagged incomplete and are NOT valid evidence)
#
# The committed regression suites (targets/*/regression/suite.json) are loaded
# and extended by these runs -- that is the regression loop the brief asks for.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
PY="${PYTHON:-python3}"
OUT="${OUT_ROOT:-$(mktemp -d /tmp/patchval_runs.XXXXXX)}"
mkdir -p "$OUT"

SCENARIOS=(
  "vulnstr/config.correct.yaml 0"
  "vulnstr/config.incomplete.yaml 10"
  "vulnstr/config.regression.yaml 20"
  "vulnstr/config.incomplete.file.yaml 10"
  "vulnstr/config.regression.argv.yaml 20"
  "vulnstr/config.correct.argv.yaml 0"
  "csvsum/config.correct.yaml 0"
  "csvsum/config.incomplete.yaml 10"
  "csvsum/config.regression.yaml 20"
  "cjson_minify/config.correct.yaml 0"
  "cjson_minify/config.incomplete.yaml 10"
  "cjson_minify/config.regression.yaml 20"
)

pass=0; fail=0
printf '%-38s %-9s %-7s %s\n' SCENARIO EXPECTED ACTUAL RESULT
printf '%s\n' "----------------------------------------------------------------"
for row in "${SCENARIOS[@]}"; do
  read -r cfg expected <<<"$row"
  name="$(echo "$cfg" | sed 's#/config\.#_#; s#\.yaml$##')"
  w="$OUT/$name"
  # shellcheck disable=SC2086
  "$PY" -m patchval -c "targets/$cfg" --work "$w" --json "$w/report.json" ${EXTRA_ARGS:-} \
        > "$w.report.txt" 2>"$w.stderr"
  actual=$?
  if [ "$actual" = "$expected" ]; then r=OK; pass=$((pass+1)); else r=MISMATCH; fail=$((fail+1)); fi
  printf '%-38s %-9s %-7s %s\n' "$cfg" "$expected" "$actual" "$r"
  if [ -n "${REPORTS:-}" ]; then
    mkdir -p "$REPORTS"
    cp "$w/report.json" "$REPORTS/$name.report.json" 2>/dev/null
    cp "$w.report.txt" "$REPORTS/$name.report.txt"
  fi
done
printf '%s\n' "----------------------------------------------------------------"
echo "PASS=$pass FAIL=$fail   (work dirs and reports under: $OUT)"
exit "$fail"
