#!/usr/bin/env bash
#
# mayhem/build.sh — managarm host-side fuzz harnesses.
#
# managarm is a microkernel OS cross-built for itself with meson + its own toolchain; none of that
# runs on a Linux host. The fuzzed parsers are plain C++ (core/lib/bpf, protocols/usb's descriptor
# walker), so they are compiled directly from the upstream sources with the base's clang, against
# the pinned header-only libarch in /opt/toolchains/deps and one host header
# (mayhem/shim/arch/os/dma_pool.hpp) replacing the helix-backed DMA pool header.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${LIBARCH_DIR:=/opt/toolchains/deps/libarch}"
: "${FRIGG_DIR:=/opt/toolchains/deps/frigg}"
: "${BRAGI_DIR:=/opt/toolchains/deps/bragi}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT/obj" "$OUT/test"

STD="-std=gnu++2c"   # upstream: cpp_std=gnu++26
INC=(-I"$SRC/mayhem/shim" -I"$SRC/core/include" -I"$SRC/protocols/usb/include" -I"$LIBARCH_DIR/src/include")

# 1) Project sources, instrumented (ASan+UBSan halting, DWARF 3). The libFuzzer objects also get
#    SanitizerCoverage (-fsanitize=fuzzer-no-link) at COMPILE time — $LIB_FUZZING_ENGINE on the link
#    line alone emits no coverage, so the fuzzer would run blind. The standalone reproducers use a
#    second, coverage-free set of the same objects.
FUZZ_CXXFLAGS="$STD -O1 $SANITIZER_FLAGS $DEBUG_FLAGS"
SANCOV_FLAGS="-fsanitize=fuzzer-no-link"
mkdir -p "$OUT/obj/fuzz" "$OUT/obj/sa"
# shellcheck disable=SC2086
$CXX $FUZZ_CXXFLAGS $SANCOV_FLAGS "${INC[@]}" -c core/lib/bpf/bpf.cpp -o "$OUT/obj/fuzz/bpf.o"
$CXX $FUZZ_CXXFLAGS "${INC[@]}" -c core/lib/bpf/bpf.cpp -o "$OUT/obj/sa/bpf.o"
$CXX $FUZZ_CXXFLAGS -c mayhem/lsan_off.cc -o "$OUT/obj/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj/standalone_main.o"

# 2) Harnesses: libFuzzer binary + run-once standalone reproducer each.
declare -A EXTRA=( [fuzz_bpf_filter]="bpf.o" [fuzz_usb_config]="" )
for h in fuzz_bpf_filter fuzz_usb_config; do
  # shellcheck disable=SC2086
  $CXX $FUZZ_CXXFLAGS $SANCOV_FLAGS "${INC[@]}" -c "mayhem/harnesses/$h.cpp" -o "$OUT/obj/fuzz/$h.o"
  $CXX $FUZZ_CXXFLAGS "${INC[@]}" -c "mayhem/harnesses/$h.cpp" -o "$OUT/obj/sa/$h.o"
  extra_fuzz="" ; extra_sa=""
  [ -z "${EXTRA[$h]}" ] || { extra_fuzz="$OUT/obj/fuzz/${EXTRA[$h]}"; extra_sa="$OUT/obj/sa/${EXTRA[$h]}"; }
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/fuzz/$h.o" $extra_fuzz "$OUT/obj/lsan_off.o" -o "$OUT/$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj/standalone_main.o" "$OUT/obj/sa/$h.o" $extra_sa "$OUT/obj/lsan_off.o" -o "$OUT/$h-standalone"
done

# extract-ostrace (tools/ostrace): a host CLI that decodes ostrace logs. It takes a file path and
# err()s on I/O failure, so it is fuzzed as a file-input AFL target (instrumented with afl-clang-fast,
# ASan+UBSan), not converted to libFuzzer. ostrace.bragi.hpp is generated from the IDL by managarm's
# bragi compiler (pinned in /opt/toolchains/deps/bragi; lark from apt), as upstream's meson does.
mkdir -p "$OUT/gen"
(cd "$BRAGI_DIR/src" && PYTHONPATH="$BRAGI_DIR/src" python3 -m bragi -o "$OUT/gen/ostrace.bragi.hpp" \
    "$SRC/protocols/ostrace/ostrace.bragi" cpp -l stdc++ --protobuf)
OSTRACE_INC=(-I"$OUT/gen" -I"$BRAGI_DIR/src/include" -I"$FRIGG_DIR/src/include")
# shellcheck disable=SC2086
AFL_QUIET=1 afl-clang-fast++ $STD -O1 $SANITIZER_FLAGS $DEBUG_FLAGS "${OSTRACE_INC[@]}" \
    tools/ostrace/extract-ostrace.cpp "$OUT/obj/lsan_off.o" -o "$OUT/extract-ostrace"
# shellcheck disable=SC2086
$CXX $STD -O2 $COVERAGE_FLAGS "${OSTRACE_INC[@]}" tools/ostrace/extract-ostrace.cpp -o "$OUT/test/extract-ostrace"

# 3) Known-answer suite, built with normal flags (no sanitizers) for mayhem/test.sh.
# shellcheck disable=SC2086
$CXX $STD -O2 $COVERAGE_FLAGS "${INC[@]}" mayhem/tests/selftest.cpp core/lib/bpf/bpf.cpp -o "$OUT/test/selftest"

echo "built: $(ls "$OUT")"
