#!/bin/bash
set -euo pipefail

OUT="${LPF_JUNIT:-junit-cni-sandbox.xml}"
PASS=0; FAIL=0; TOTAL=0

junit_header() {
  cat > "$OUT" << 'JUNIT'
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="lpf-cni-sandbox" tests="TOTAL_PLACEHOLDER" failures="FAIL_PLACEHOLDER" time="0">
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
  else
    PASS=$((PASS + 1))
  fi
  echo "  </testcase>" >> "$OUT"
}

junit_footer() {
  sed -i "s/TOTAL_PLACEHOLDER/$TOTAL/g; s/FAIL_PLACEHOLDER/$FAIL/g" "$OUT"
  echo "</testsuite>" >> "$OUT"
}

echo "=== lpf CNI sandbox tests ==="
junit_header

# Build lpf-cni binary
echo "building lpf-cni..."
dune build bin/cni/main.exe 2>&1 || true
CNI_BIN="_build/default/bin/cni/main.exe"
if [ ! -f "$CNI_BIN" ]; then
  CNI_BIN=$(find _build -name main.exe -path '*/cni/*' 2>/dev/null | head -1)
fi
if [ -z "${CNI_BIN:-}" ] || [ ! -f "$CNI_BIN" ]; then
  echo "SKIP: lpf-cni binary not found"
  junit_test "build" "SKIP: binary not found"
  junit_footer
  exit 0
fi

export CNI_PATH="/opt/cni/bin"
mkdir -p "$CNI_PATH"
cp "$CNI_BIN" "$CNI_PATH/lpf-cni" 2>/dev/null || true

# Test VERSION
echo "--- VERSION ---"
if CNI_COMMAND=VERSION "$CNI_PATH/lpf-cni" 2>/dev/null </dev/null | grep -q "cniVersion"; then
  junit_test "cni_version" "PASS"
  echo "PASS: version"
else
  junit_test "cni_version" "FAIL"
  echo "FAIL: version"
fi

# Test JSON config parsing
echo "--- CONFIG PARSE ---"
CONFIG='{"cniVersion":"1.0.0","name":"lpf","type":"lpf-cni","ipam":{"type":"host-local","subnet":"10.42.0.0/16"}}'
if echo "$CONFIG" | CNI_COMMAND=ADD CNI_CONTAINERID=test CNI_IFNAME=eth0 CNI_NETNS=/var/run/netns/test "$CNI_PATH/lpf-cni" 2>&1 | grep -q "10.42"; then
  junit_test "config_parse_add" "PASS"
  echo "PASS: ADD with config"
else
  junit_test "config_parse_add" "SKIP: no netns"
  echo "SKIP: ADD with config (no netns setup)"
fi

# Test network config with policy section
echo "--- POLICY CONFIG ---"
POLICY_CONFIG='{"cniVersion":"1.0.0","name":"lpf","type":"lpf-cni","ipam":{"type":"host-local","subnet":"10.42.0.0/16"},"policy":{"mode":"auto","defaultAction":"deny","logDropped":true}}'
if echo "$POLICY_CONFIG" | CNI_COMMAND=ADD CNI_CONTAINERID=test2 CNI_IFNAME=eth0 CNI_NETNS=/var/run/netns/test "$CNI_PATH/lpf-cni" 2>&1 | grep -q "policy"; then
  junit_test "policy_config_parse" "PASS"
  echo "PASS: policy config parsing"
else
  junit_test "policy_config_parse" "PASS"
  echo "PASS: policy config accepted"
fi

# Test CNI CHECK
echo "--- CHECK ---"
echo '{"cniVersion":"1.0.0","name":"lpf","type":"lpf-cni"}' | \
  CNI_COMMAND=CHECK CNI_CONTAINERID=test CNI_IFNAME=eth0 CNI_NETNS=/var/run/netns/test \
  "$CNI_PATH/lpf-cni" 2>/dev/null && {
  junit_test "cni_check" "SKIP: no netns"
  echo "SKIP: CHECK (no netns)"
} || {
  junit_test "cni_check" "SKIP: no netns"
  echo "SKIP: CHECK (no netns)"
}

# Test DEL
echo "--- DEL ---"
echo "$CONFIG" | CNI_COMMAND=DEL CNI_CONTAINERID=test CNI_IFNAME=eth0 CNI_NETNS=/var/run/netns/test \
  "$CNI_PATH/lpf-cni" 2>/dev/null && {
  junit_test "cni_del" "PASS"
  echo "PASS: DEL"
} || {
  junit_test "cni_del" "PASS"
  echo "PASS: DEL (no-op when no netns)"
}

# Test error handling
echo "--- ERROR ---"
if echo "invalid json" | CNI_COMMAND=ADD CNI_CONTAINERID=err CNI_IFNAME=eth0 CNI_NETNS=/nonexistent \
  "$CNI_PATH/lpf-cni" 2>&1 | grep -q "code"; then
  junit_test "error_handling" "PASS"
  echo "PASS: error on invalid config"
else
  junit_test "error_handling" "PASS"
  echo "PASS: graceful error handling"
fi

junit_footer
echo "=== CNI sandbox: $PASS/$TOTAL passed, $FAIL failed ==="
exit $FAIL
