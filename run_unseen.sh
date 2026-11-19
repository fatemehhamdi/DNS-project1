#!/usr/bin/env bash
# run_unseen.sh -- validate held-out patch FILES (never referenced by any
# config) by applying each to a copy of the base with --patch, and compare the
# verdict with unseen_patches/expected.tsv.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
PY="${PYTHON:-python3}"
OUT="${OUT_ROOT:-$(mktemp -d /tmp/patchval_unseen.XXXXXX)}"
pass=0; fail=0
printf '%-40s %-36s %-8s %-8s %s\n' CONFIG PATCH EXPECTED ACTUAL RESULT
while read -r cfg patch extra expected; do
  case "$cfg" in ''|\#*) continue;; esac
  name="$(basename "$patch" .diff)"
  w="$OUT/$name-$(basename "$cfg" .yaml)"
  "$PY" -m patchval -c "$cfg" --patch "unseen_patches/$patch" --work "$w" \
      --json "$w/report.json" --no-update-regression ${EXTRA_ARGS:-} -q >/dev/null 2>&1
  actual=$?
  if [ "$actual" = "$expected" ]; then r=OK; pass=$((pass+1)); else r=MISMATCH; fail=$((fail+1)); fi
  printf '%-40s %-36s %-8s %-8s %s\n' "${cfg#targets/}" "$patch" "$expected" "$actual" "$r"
done < unseen_patches/expected.tsv
echo "PASS=$pass FAIL=$fail   (reports under $OUT)"
exit "$fail"
