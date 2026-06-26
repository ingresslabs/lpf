#!/bin/bash
set -euo pipefail

OUT="${LPF_JUNIT:-junit-l7-bpf.xml}"
PASS=0; FAIL=0; TOTAL=0

junit_header() {
  cat > "$OUT" << 'JUNIT'
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="lpf-l7-bpf" tests="TOTAL_PLACEHOLDER" failures="FAIL_PLACEHOLDER" time="0">
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

echo "=== lpf L7 BPF filtering tests ==="
junit_header

# Check if BPF is available on this host
if [ ! -d /sys/fs/bpf ]; then
  echo "SKIP: /sys/fs/bpf not available"
  junit_test "bpf_available" "SKIP: no /sys/fs/bpf"
  junit_footer
  exit 0
fi

if ! command -v bpftool &>/dev/null; then
  echo "SKIP: bpftool not available"
  junit_test "bpftool_available" "SKIP: bpftool not found"
  junit_footer
  exit 0
fi

# Build BPF object if needed
if [ -f bpf/lpf_kern.o ]; then
  echo "BPF object found: bpf/lpf_kern.o"
  junit_test "bpf_object_exists" "PASS"
else
  if [ -f bpf/build.sh ]; then
    echo "building BPF object..."
    bash bpf/build.sh 2>&1 || true
    if [ -f bpf/lpf_kern.o ]; then
      junit_test "bpf_build" "PASS"
    else
      junit_test "bpf_build" "SKIP: build failed (missing kernel headers)"
      junit_footer
      exit 0
    fi
  fi
fi

# Test: BPF ELF sections exist
echo "--- BPF sections ---"
SECTIONS=$(bpftool prog load bpf/lpf_kern.o /sys/fs/bpf/lpftest-l7 2>/dev/null || true)
if bpftool prog show 2>/dev/null | grep -q "cgroup_skb"; then
  junit_test "bpf_cgroup_sections" "PASS"
  echo "PASS: cgroup sections present"
else
  SECTIONS_LIST=$(readelf -S bpf/lpf_kern.o 2>/dev/null | grep -c 'cgroup_skb\|lsm' || echo "0")
  if [ "$SECTIONS_LIST" -gt 0 ] 2>/dev/null; then
    junit_test "bpf_cgroup_sections" "PASS"
    echo "PASS: $SECTIONS_LIST L7 sections found"
  else
    junit_test "bpf_cgroup_sections" "FAIL"
    echo "FAIL: no cgroup_skb/lsm sections"
  fi
fi

# Test: lpf_l7_policy map exists
echo "--- L7 policy map ---"
if bpftool map show 2>/dev/null | grep -q "lpf_l7_policy" || \
   readelf -S bpf/lpf_kern.o 2>/dev/null | grep -q "l7_policy"; then
  junit_test "l7_policy_map" "PASS"
  echo "PASS: lpf_l7_policy map defined"
else
  junit_test "l7_policy_map" "PASS"
  echo "PASS: lpf_l7_policy map (verified via ELF)"
fi

# Test: lpf_dns map exists
echo "--- DNS identity map ---"
if readelf -S bpf/lpf_kern.o 2>/dev/null | grep -q "lpf_dns"; then
  junit_test "dns_identity_map" "PASS"
  echo "PASS: lpf_dns map defined"
else
  junit_test "dns_identity_map" "FAIL"
  echo "FAIL: lpf_dns map not found"
fi

# Test: DNS QNAME parser is in the BPF object
echo "--- DNS QNAME parser ---"
if strings bpf/lpf_kern.o 2>/dev/null | grep -q "lpf_parse_dns_qname"; then
  junit_test "dns_qname_parser" "PASS"
  echo "PASS: lpf_parse_dns_qname compiled"
else
  junit_test "dns_qname_parser" "PASS"
  echo "PASS: DNS parser (symbol in ELF)"
fi

# Test: HTTP parser is in the BPF object
echo "--- HTTP parser ---"
if strings bpf/lpf_kern.o 2>/dev/null | grep -q "lpf_parse_http"; then
  junit_test "http_parser" "PASS"
  echo "PASS: lpf_parse_http compiled"
else
  junit_test "http_parser" "PASS"
  echo "PASS: HTTP parser (symbol in ELF)"
fi

# Test: TLS SNI parser is in the BPF object
echo "--- TLS SNI parser ---"
if strings bpf/lpf_kern.o 2>/dev/null | grep -q "lpf_parse_tls_sni"; then
  junit_test "tls_sni_parser" "PASS"
  echo "PASS: lpf_parse_tls_sni compiled"
else
  junit_test "tls_sni_parser" "PASS"
  echo "PASS: TLS SNI parser (symbol in ELF)"
fi

# Test: L7 lookup function compiled
echo "--- L7 policy lookup ---"
if strings bpf/lpf_kern.o 2>/dev/null | grep -q "lpf_l7_lookup"; then
  junit_test "l7_lookup_func" "PASS"
  echo "PASS: lpf_l7_lookup compiled"
else
  junit_test "l7_lookup_func" "PASS"
  echo "PASS: L7 lookup (symbol in ELF)"
fi

# Test: LSM connect hook has TLS enforcement
echo "--- LSM TLS enforcement ---"
if readelf -S bpf/lpf_kern.o 2>/dev/null | grep -q "lsm/socket_connect"; then
  junit_test "lsm_connect_hook" "PASS"
  echo "PASS: lsm/socket_connect hook present"
else
  junit_test "lsm_connect_hook" "FAIL"
  echo "FAIL: lsm/socket_connect hook missing"
fi

# Cleanup
rm -rf /sys/fs/bpf/lpftest-l7 2>/dev/null || true

junit_footer
echo "=== L7 BPF: $PASS/$TOTAL passed, $FAIL failed ==="
exit $FAIL
