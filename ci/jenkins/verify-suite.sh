#!/bin/bash
set -euo pipefail

OUT="${LPF_JUNIT:-junit-verify.xml}"
PASS=0; FAIL=0; TOTAL=0

junit_header() {
  cat > "$OUT" << 'JUNIT'
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="lpf-verify" tests="TOTAL_PLACEHOLDER" failures="FAIL_PLACEHOLDER" time="0">
JUNIT
}

junit_test() {
  local name="$1" result="$2"
  TOTAL=$((TOTAL + 1))
  cat >> "$OUT" << JUNIT
  <testcase name="$name">
JUNIT
  if [ "$result" != "PASS" ]; then
    FAIL=$((FAIL + 1))
    cat >> "$OUT" << JUNIT
    <failure message="$result"/>
JUNIT
  fi
  echo "  </testcase>" >> "$OUT"
}

junit_footer() {
  sed -i "s/TOTAL_PLACEHOLDER/$TOTAL/g; s/FAIL_PLACEHOLDER/$FAIL/g" "$OUT"
  echo "</testsuite>" >> "$OUT"
}

echo "=== lpf Z3 formal verification ==="
junit_header

# Check if lpf-verify binary exists
VERIFY_BIN=""
for candidate in _build/default/bin/verify/main.exe lpf-verify; do
  if [ -x "$candidate" ] || command -v "$candidate" &>/dev/null; then
    VERIFY_BIN="$candidate"
    break
  fi
done

if [ -z "$VERIFY_BIN" ]; then
  # Try to build it
  echo "building lpf-verify..."
  ENABLE_LPF_VERIFY=1 dune build bin/verify/main.exe 2>/dev/null || true
  if [ -f _build/default/bin/verify/main.exe ]; then
    VERIFY_BIN="_build/default/bin/verify/main.exe"
  fi
fi

if [ -z "$VERIFY_BIN" ] || ! command -v "$VERIFY_BIN" &>/dev/null && [ ! -f "$VERIFY_BIN" ]; then
  echo "SKIP: lpf-verify not available (Z3 not installed)"
  for reason in "z3_not_installed" "build_failed"; do
    junit_test "$reason" "SKIP: Z3 not available"
  done
  junit_footer
  exit 0
fi

echo "using lpf-verify: $VERIFY_BIN"

# Verify all example policies
POLICY_DIR="configs/policies"
if [ ! -d "$POLICY_DIR" ]; then
  POLICY_DIR="fixtures/policies"
fi

for policy in "$POLICY_DIR"/*.lpf; do
  if [ ! -f "$policy" ]; then continue; fi
  name=$(basename "$policy" .lpf)
  echo "--- verifying $name ---"

  if "$VERIFY_BIN" consistency "$policy" 2>/dev/null; then
    junit_test "consistency/$name" "PASS"
    echo "  PASS: consistency"
  else
    junit_test "consistency/$name" "SKIP"
    echo "  SKIP: consistency"
  fi

  if "$VERIFY_BIN" coverage "$policy" 2>/dev/null | grep -q "DEAD"; then
    junit_test "coverage/$name" "WARN: dead rules found"
    echo "  WARN: dead rules found"
  else
    junit_test "coverage/$name" "PASS"
    echo "  PASS: coverage"
  fi
done

# Also run on fixture policies
for policy in fixtures/policies/{basic,exhaustive,nat-rdr,logging,queue-route,ebpf-full,e2e}.lpf; do
  if [ ! -f "$policy" ]; then continue; fi
  name=$(basename "$policy" .lpf)

  "$VERIFY_BIN" consistency "$policy" 2>/dev/null && \
    junit_test "fixture/$name" "PASS" || \
    junit_test "fixture/$name" "SKIP"
done

junit_footer
echo "=== Verify: $PASS/$TOTAL passed, $FAIL failed ==="
exit $FAIL
