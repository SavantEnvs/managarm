#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Runs the known-answer suite build.sh produced (mayhem/tests/selftest.cpp): asserted BPF filter
# verdicts / validator decisions and USB descriptor fields, one PASS/FAIL line per check.
RUNNER="$SRC/mayhem/out/test/selftest"
if [ ! -x "$RUNNER" ]; then
  echo "test runner $RUNNER missing — mayhem/build.sh must build it" >&2
  emit_ctrf "managarm-selftest" 0 1 0
  exit 1
fi
out="$("$RUNNER" 2>&1)"; rc=$?
echo "$out"
# extract-ostrace golden tests: decode each mayhem/tests/ostrace/<name>.ostrace and diff stdout
# (the JSON event lines) and stderr (record / loss statistics) against <name>.out / <name>.err.
OSTRACE="$SRC/mayhem/out/test/extract-ostrace"
[ -x "$OSTRACE" ] || { echo "$OSTRACE missing — mayhem/build.sh must build it" >&2; out="$out
FAIL extract-ostrace-missing"; }
tmp="$(mktemp -d)"
for in in "$SRC"/mayhem/tests/ostrace/*.ostrace; do
  n="$(basename "$in" .ostrace)"
  if [ -x "$OSTRACE" ] && (cd "$tmp" && "$OSTRACE" "$in" >"$tmp/$n.out" 2>"$tmp/$n.err") \
     && diff -u "${in%.ostrace}.out" "$tmp/$n.out" && diff -u "${in%.ostrace}.err" "$tmp/$n.err"; then
    out="$out
PASS ostrace_$n"
  else
    out="$out
FAIL ostrace_$n"
  fi
done
rm -rf "$tmp"
echo "$out" | grep '^[A-Z]* ostrace_' || true
passed=$(grep -c '^PASS ' <<<"$out" || true)
failed=$(grep -c '^FAIL ' <<<"$out" || true)
# 19 selftest checks + 2 ostrace goldens; anything missing (runner died / no-op'd) counts as failed.
EXPECTED=21
missing=$(( EXPECTED - passed - failed )); [ "$missing" -gt 0 ] || missing=0
failed=$(( failed + missing ))
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
emit_ctrf "managarm-selftest" "$passed" "$failed" 0
