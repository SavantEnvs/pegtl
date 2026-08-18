#!/usr/bin/env bash
#
# pegtl/mayhem/test.sh — RUN (never build) PEGTL's own unit-test suite plus the KAT probe, and
# emit a CTRF summary. exit 0 iff nothing failed.
#
# TWO LAYERS, and the SECOND is the load-bearing one for anti-reward-hacking (SPEC §6.3):
#
#  1) PEGTL's OWN suite (src/test/*.cpp, ~275 binaries, ~2900 TAO_PEGTL_TEST_ASSERT assertions),
#     built by mayhem/build.sh with the project's NORMAL flags, run here via `ctest`. This is a
#     genuine known-answer suite (hand-written grammar/input pairs with expected success/failure
#     asserted per rule) — real coverage of json/uri/abnf/lua53 and the rest of the library.
#
#  2) The KAT probe /mayhem/kat (mayhem/kat/kat.cpp) — REQUIRED in addition to (1), not optional.
#     `ctest` (like `meson test`, proven empirically on a sibling repo — see
#     docs/netnew-worker-prompt.md §4) judges each of its ~275 child processes purely by EXIT CODE.
#     The gate's sabotage shim LD_PRELOADs a constructor that _exit(0)s any non-system binary
#     BEFORE main() runs, so every one of those 275 binaries would still exit 0 under sabotage —
#     ctest would report "100% tests passed" having executed not one TAO_PEGTL_TEST_ASSERT. An
#     exit-code-only judge cannot tell that apart from a real pass, no matter how many genuine
#     assertions the neutered binary contains. So layer (1) ALONE would be reward-hackable.
#
#     /mayhem/kat instead PRINTS parsed field values to stdout (a JSON object's "name" string and
#     recursive value count; a URI's scheme/host/port/userinfo/path/query/fragment) computed via
#     PEGTL's own example builder/action machinery. test.sh below greps for the EXACT expected
#     lines. A neutered /mayhem/kat prints nothing (never reaches main), so every grep fails and
#     FAILED becomes >0 — this is where sabotage is actually caught, via stdout content bash/grep
#     see directly, not via any exit code the shim can fake.
#
# This script only RUNS things; mayhem/build.sh did all the building.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

PASSED=0; FAILED=0; SKIPPED=0

# ── 1) PEGTL's own unit-test suite via ctest (informational — see header for why this alone
#       cannot be the sabotage-detecting oracle). UNCONDITIONAL: a missing build tree is a FAILURE,
#       never a skip — that is exactly how build.sh dropping the suite would go unnoticed. ─────────
BUILD_TESTS="$SRC/build-tests"
if [ ! -d "$BUILD_TESTS" ]; then
  echo "FAIL: $BUILD_TESTS missing — mayhem/build.sh did not build the unit-test suite" >&2
  FAILED=$(( FAILED + 1 ))
else
  echo "=== running: ctest (PEGTL's own suite, $BUILD_TESTS) ==="
  CTEST_LOG="$SRC/mayhem-build/ctest.log"
  mkdir -p "$SRC/mayhem-build"
  if ( cd "$BUILD_TESTS" && ctest --output-on-failure -j"$(nproc)" ) >"$CTEST_LOG" 2>&1; then
    ctest_rc=0
  else
    ctest_rc=$?
  fi
  tail -40 "$CTEST_LOG" || true

  # Parse ctest's own summary line: "NN% tests passed, F tests failed out of T"
  summary="$(grep -E '^[0-9]+% tests passed, [0-9]+ tests? failed out of [0-9]+' "$CTEST_LOG" || true)"
  if [ -z "$summary" ]; then
    echo "FAIL: could not parse a ctest summary line — the suite did not run" >&2
    FAILED=$(( FAILED + 1 ))
  else
    ct_failed="$(printf '%s\n' "$summary" | sed -E 's/^[0-9]+% tests passed, ([0-9]+) tests? failed out of ([0-9]+)$/\1/')"
    ct_total="$(printf '%s\n' "$summary" | sed -E 's/^[0-9]+% tests passed, ([0-9]+) tests? failed out of ([0-9]+)$/\2/')"
    ct_passed=$(( ct_total - ct_failed ))
    echo "ctest: $ct_passed passed, $ct_failed failed, $ct_total total"
    PASSED=$(( PASSED + ct_passed ))
    FAILED=$(( FAILED + ct_failed ))
  fi
fi

# ── 2) The KAT probe (sabotage-DETECTING; see header). UNCONDITIONAL by design: a missing binary
#       is a FAILURE, never a skip — a `[ -x ... ]` guard here is exactly how this oracle would
#       silently degrade back to the reward-hackable ctest-only case. ───────────────────────────────
echo "=== KAT probe: /mayhem/kat (dynamically linked; asserts printed VALUES) ==="
if [ ! -x /mayhem/kat ]; then
  echo "FAIL: /mayhem/kat missing or not executable" >&2
  FAILED=$(( FAILED + 1 ))
  KAT_OUT=""
else
  KAT_OUT="$(/mayhem/kat 2>&1)"; kat_rc=$?
  echo "$KAT_OUT"
  if [ "$kat_rc" -ne 0 ]; then
    echo "note: /mayhem/kat exited $kat_rc (checked below via printed VALUES, not this exit code)"
  fi
fi

# kat_expect <label> <exact-line>
kat_expect() {
  local label="$1" line="$2"
  if printf '%s\n' "$KAT_OUT" | grep -qxF "$line"; then
    echo "KAT PASS: $label"
    PASSED=$(( PASSED + 1 ))
  else
    echo "KAT FAIL: $label — expected exact line: $line" >&2
    FAILED=$(( FAILED + 1 ))
  fi
}

# Expected values — fixed inputs baked into mayhem/kat/kat.cpp:
#   JSON: {"name":"pegtl","numbers":[1,2,3],"nested":{"ok":true}}  -> 8 values, name "pegtl"
#   URI:  https://user:pass@example.org:8080/a/b?x=1&y=2#frag
kat_expect "json parses"               'KAT_JSON_OK=1'
kat_expect "json value count"          'KAT_JSON_COUNT=8'
kat_expect "json string field"         'KAT_JSON_NAME=pegtl'
kat_expect "uri scheme"                'KAT_URI_SCHEME=https'
kat_expect "uri host"                  'KAT_URI_HOST=example.org'
kat_expect "uri port"                  'KAT_URI_PORT=8080'
kat_expect "uri userinfo"              'KAT_URI_USERINFO=user:pass'
kat_expect "uri path"                  'KAT_URI_PATH=/a/b'
kat_expect "uri query"                 'KAT_URI_QUERY=x=1&y=2'
kat_expect "uri fragment"              'KAT_URI_FRAGMENT=frag'

emit_ctrf "pegtl-ctest+kat" "$PASSED" "$FAILED" "$SKIPPED"
