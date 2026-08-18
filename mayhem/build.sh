#!/usr/bin/env bash
#
# pegtl/mayhem/build.sh — build four libFuzzer targets over PEGTL's shipped example grammars,
# plus PEGTL's own ~2900-assertion unit-test suite and a behavioral KAT probe (mayhem/test.sh).
#
# PEGTL is HEADER-ONLY (include/tao/pegtl/**) — there is no library to link. "Building the
# project with sanitizers" happens automatically: each harness #includes the grammar headers
# directly, so tao::pegtl and the example grammar are compiled straight into the (sanitized)
# harness TU. Requires C++20 (CMakeLists.txt: target_compile_features(pegtl INTERFACE cxx_std_20)).
#
# Targets (one Mayhemfile each) — chosen because they are real parsers over adversarial text, not
# toy grammars (docs/netnew-worker-prompt.md repo intel):
#   /mayhem/fuzz_json   — tao::pegtl::json::text        (RFC 8259 JSON)
#   /mayhem/fuzz_uri    — tao::pegtl::uri::URI           (RFC 3986 URI)
#   /mayhem/fuzz_abnf   — tao::pegtl::abnf::rulelist      (RFC 5234/7405 ABNF grammar files)
#   /mayhem/fuzz_lua53  — tao::pegtl::lua53::grammar      (full Lua 5.3 language grammar)
# Each is linked twice: once with $LIB_FUZZING_ENGINE (the fuzz target) and once with
# $STANDALONE_FUZZ_MAIN (a one-shot, non-fuzzer reproducer) -> /mayhem/<name>-standalone.
#
# The oracle (mayhem/test.sh) is TWO layers, because ctest alone is reward-hackable here (see
# mayhem/kat/kat.cpp header for why — the sabotage shim _exit(0)s any binary before it reaches its
# own assertions, and a ctest/exit-code-only judge can't tell that apart from a real silent pass):
#   1) PEGTL's OWN unit suite (src/test/*.cpp, ~275 binaries, ~2900 TAO_PEGTL_TEST_ASSERT calls),
#      built here with the project's NORMAL flags (separate, unsanitized tree) via CMake+ctest.
#   2) /mayhem/kat — a small known-answer probe (mayhem/kat/kat.cpp) that PRINTS parsed JSON/URI
#      field values to stdout; test.sh greps for exact `KAT_...=...` lines, which is what actually
#      detects the sabotage shim (stdout content, not exit code).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS

: "${SRC:=/mayhem}"
cd "$SRC"

STD="-std=c++20"
INC="-I$SRC/include"
HARNESS_DIR="$SRC/mayhem/harnesses"
BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# ── 1) Fuzz targets: header-only, so the grammar + tao::pegtl compile straight into the harness
#       TU with $SANITIZER_FLAGS. Standalone driver compiled once as a C object (C++ would mangle
#       its extern "C" LLVMFuzzerTestOneInput reference otherwise). ──────────────────────────────
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

build_target() {
  local name="$1" src="$2"
  echo "=== building $name ==="
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $STD $INC "$src" $LIB_FUZZING_ENGINE -o "/mayhem/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $STD $INC "$src" "$BUILD/standalone_main.o" -o "/mayhem/$name-standalone"
  echo "built /mayhem/$name (+ standalone)"
}

build_target fuzz_json  "$HARNESS_DIR/fuzz_json.cpp"
build_target fuzz_uri   "$HARNESS_DIR/fuzz_uri.cpp"
build_target fuzz_abnf  "$HARNESS_DIR/fuzz_abnf.cpp"
build_target fuzz_lua53 "$HARNESS_DIR/fuzz_lua53.cpp"

# ── 2) The KAT probe: NORMAL flags (no sanitizer/fuzzer instrumentation — a functional oracle
#       artifact, not a triage target). Ordinary C++ binaries are dynamically linked by default on
#       this toolchain (no cgo-style trick needed, unlike Go); assert it explicitly so a future
#       flag change (e.g. accidental -static) can't silently turn this into a reward-hackable,
#       LD_PRELOAD-immune oracle. ─────────────────────────────────────────────────────────────────
$CXX -std=c++20 -O2 "$INC" "$SRC/mayhem/kat/kat.cpp" -o /mayhem/kat
if ! file /mayhem/kat | grep -q 'dynamically linked'; then
  echo "FATAL: /mayhem/kat is not dynamically linked — the sabotage check could not neuter it," >&2
  echo "       which would make mayhem/test.sh a reward-hackable oracle." >&2
  file /mayhem/kat >&2
  exit 1
fi
echo "built /mayhem/kat (dynamically linked)"

# ── 3) PEGTL's own unit-test suite, NORMAL flags, in a separate/clean tree so mayhem/test.sh only
#       RUNS it (never compiles). All 275 src/test/*.cpp files, one binary each, via CTest. ────────
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -S "$SRC" -B "$SRC/build-tests" \
        -DCMAKE_BUILD_TYPE=Release \
        -DPEGTL_BUILD_TESTS=ON \
        -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake --build "$SRC/build-tests" -j"$MAYHEM_JOBS"
echo "built PEGTL unit-test suite in build-tests/"

echo "build.sh complete:"
ls -la /mayhem/fuzz_json /mayhem/fuzz_uri /mayhem/fuzz_abnf /mayhem/fuzz_lua53 /mayhem/kat 2>&1 || true
