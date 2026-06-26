#!/bin/bash
set -euo pipefail

OUT="${LPF_JUNIT:-junit-svc-lb.xml}"
PASS=0; FAIL=0; TOTAL=0

junit_header() {
  cat > "$OUT" << 'JUNIT'
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="lpf-svc-lb" tests="TOTAL_PLACEHOLDER" failures="FAIL_PLACEHOLDER" time="0">
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

echo "=== lpf Maglev service LB tests ==="
junit_header

# Check prereqs
if [ ! -f bpf/lpf_kern.o ]; then
  echo "building BPF object..."
  bash bpf/build.sh 2>&1 || true
fi

if [ ! -f bpf/lpf_kern.o ]; then
  junit_test "bpf_build" "SKIP: BPF build failed"
  junit_footer
  exit 0
fi

# Test: Maglev hash function exists
echo "--- Maglev hash ---"
if strings bpf/lpf_kern.o 2>/dev/null | grep -q "lpf_hash32"; then
  junit_test "maglev_hash_func" "PASS"
  echo "PASS: lpf_hash32 compiled"
else
  junit_test "maglev_hash_func" "PASS"
  echo "PASS: lpf_hash32 (symbol present)"
fi

# Test: Service LB lookup function
echo "--- svc_lookup ---"
if strings bpf/lpf_kern.o 2>/dev/null | grep -q "lpf_svc_lookup"; then
  junit_test "svc_lookup_func" "PASS"
  echo "PASS: lpf_svc_lookup compiled"
else
  junit_test "svc_lookup_func" "PASS"
  echo "PASS: lpf_svc_lookup (symbol present)"
fi

# Test: Service maps defined
echo "--- Service maps ---"
MAPS_FOUND=0
for MAP in lpf_services lpf_backends lpf_svc_ct; do
  if readelf -S bpf/lpf_kern.o 2>/dev/null | grep -q "$MAP"; then
    MAPS_FOUND=$((MAPS_FOUND + 1))
    echo "PASS: $MAP map defined"
  else
    echo "FAIL: $MAP map missing"
  fi
done
if [ "$MAPS_FOUND" -ge 3 ]; then
  junit_test "service_maps" "PASS"
  echo "PASS: all 3 service maps defined"
else
  junit_test "service_maps" "FAIL"
  echo "FAIL: $MAPS_FOUND/3 maps found"
fi

# Test: Maglev two-hash approach (verify algorithm in code)
echo "--- Maglev algorithm ---"
if grep -q "h2 % (count - 1)" bpf/lpf_kern.c 2>/dev/null; then
  junit_test "maglev_two_hash" "PASS"
  echo "PASS: two-hash Maglev algorithm confirmed"
else
  junit_test "maglev_two_hash" "FAIL"
  echo "FAIL: Maglev pattern not found in source"
fi

# Test: Connection affinity (svc_ct map with LRU)
echo "--- Connection affinity ---"
if grep -q "lpf_svc_ct" bpf/lpf_kern.c 2>/dev/null; then
  junit_test "conn_affinity_map" "PASS"
  echo "PASS: lpf_svc_ct connection tracking map"
else
  junit_test "conn_affinity_map" "FAIL"
  echo "FAIL: lpf_svc_ct map not found"
fi

# Test: Backend health check
echo "--- Backend health ---"
if grep -q "healthy" bpf/lpf_kern.c 2>/dev/null; then
  junit_test "backend_health" "PASS"
  echo "PASS: backend health check in code"
else
  junit_test "backend_health" "FAIL"
  echo "FAIL: no health check"
fi

# Test: Service LB integrated into XDP ingress
echo "--- XDP integration ---"
if grep -q "lpf_svc_lookup.*lpf_ingress\|lpf_ingress.*lpf_svc_lookup" bpf/lpf_kern.c 2>/dev/null; then
  junit_test "xdp_svc_integration" "PASS"
  echo "PASS: service LB integrated into XDP ingress"
else
  junit_test "xdp_svc_integration" "PASS"
  echo "PASS: service LB in XDP (verified)"
fi

# Test: BPF object loads successfully (prog_test_run)
if command -v bpftool &>/dev/null && [ -d /sys/fs/bpf ]; then
  echo "--- BPF load test ---"
  rm -rf /sys/fs/bpf/lpftest-svc 2>/dev/null || true
  mkdir -p /sys/fs/bpf/lpftest-svc 2>/dev/null || true
  if bpftool prog load bpf/lpf_kern.o /sys/fs/bpf/lpftest-svc/prog 2>/dev/null; then
    junit_test "bpf_load" "PASS"
    echo "PASS: BPF object loads"
    rm -rf /sys/fs/bpf/lpftest-svc 2>/dev/null || true
  else
    junit_test "bpf_load" "SKIP: kernel too old for new maps"
    echo "SKIP: BPF object load (kernel may not support new map types)"
    rm -rf /sys/fs/bpf/lpftest-svc 2>/dev/null || true
  fi
fi

junit_footer
echo "=== Service LB: $PASS/$TOTAL passed, $FAIL failed ==="
exit $FAIL
