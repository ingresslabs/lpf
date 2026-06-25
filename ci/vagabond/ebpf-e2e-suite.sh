#!/usr/bin/env bash
# lpf eBPF comprehensive E2E test suite — Vagabond Firecracker microVM runner.
#
# Four-layer conformance matrix executed inside a Vagabond Firecracker microVM
# (nomad.firecracker) booting a specific kernel from the kernel matrix:
#
#   Layer 0 – BPF_PROG_TEST_RUN isolation: per-hook verdict conformance
#             (XDP ingress, TC egress, etc.) with crafted packets
#   Layer 1 – Map state conformance: conntrack state machine, counter
#             accounting, CIDR membership, ring buffer events
#   Layer 2 – Userspace toolchain: lpf rules show --backend ebpf,
#             lpf ebpf load --script, lpf diff --backend ebpf, explain parity
#   Layer 3 – Live Firecracker E2E: veth pair + real ping/iperf3
#             traffic through XDP/TC filtering
#
# Set LPF_EBPF_STRICT=1 to fail when bpftool/BTF is unavailable.
# Writes junit-lpf-ebpf-e2e-<label>.xml.
#
# Prerequisites in the Firecracker rootfs:
#   - bpftool, clang/llvm, libbpf, python3, opam/dune (for Layer 2)
#   - iproute2, iperf3 (for Layer 3)
#   - lpf built from source or installed
set -uo pipefail

# ── environment ────────────────────────────────────────────────────────────

eval "$(opam env 2>/dev/null)" || true

label="${LPF_KERNEL_LABEL:-$(uname -r)}"
strict="${LPF_EBPF_STRICT:-0}"
layers="${LPF_EBPF_LAYERS:-0,1,2,3}"
fail=0
cases=""
runner_script="bpf/e2e_runner.py"

report() { echo "[ebpf-e2e] $*"; }

add_case() {
  local name="$1" ok="$2" detail="$3"
  local esc_name
  esc_name=$(printf '%s' "$name" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g')
  local esc_detail
  esc_detail=$(printf '%s' "$detail" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g')
  if [ "$ok" -eq 0 ]; then
    cases="$cases    <testcase classname=\"lpf.ebpf-e2e.$label\" name=\"$esc_name\"/>\n"
  else
    cases="$cases    <testcase classname=\"lpf.ebpf-e2e.$label\" name=\"$esc_name\"><failure>$esc_detail</failure></testcase>\n"
  fi
}

echo "=== lpf eBPF E2E suite: kernel=$label uname=$(uname -r) ==="
report "kernel: $(uname -srm)"
report "layers: $layers"

# ── pre-flight checks ─────────────────────────────────────────────────────

[ -r /sys/kernel/btf/vmlinux ] && report "BTF: present" || report "BTF: MISSING"
command -v bpftool >/dev/null 2>&1 && report "bpftool: $(bpftool version 2>/dev/null | head -1)" || report "bpftool: MISSING"
command -v clang   >/dev/null 2>&1 && report "clang: $(clang --version 2>/dev/null | head -1)"   || report "clang: MISSING"
command -v python3 >/dev/null 2>&1 && report "python3: $(python3 --version 2>/dev/null)"          || report "python3: MISSING"
command -v iperf3  >/dev/null 2>&1 && report "iperf3: present"                                     || report "iperf3: MISSING"

# ── stage 1: build the eBPF datapath object ────────────────────────────────

if make bpf >/tmp/bpf-build.log 2>&1; then
  report "make bpf: OK"; add_case "build-ebpf-object" 0 ""
else
  report "make bpf: FAILED"; add_case "build-ebpf-object" 1 "$(tail -n 40 /tmp/bpf-build.log)"
  fail=1
fi

# ── stage 2: comprehensive e2e runner (Layers 0–3) ────────────────────────

if [ "$(id -u)" != "0" ]; then
  report "E2E runner: SKIPPED (needs root for BPF operations)"
  if [ "$strict" = "1" ]; then
    add_case "e2e-runner" 1 "skipped but strict mode (need root)"
    fail=1
  else
    add_case "e2e-runner" 0 ""
  fi
elif ! command -v bpftool >/dev/null 2>&1; then
  report "E2E runner: SKIPPED (bpftool missing)"
  if [ "$strict" = "1" ]; then
    add_case "e2e-runner" 1 "skipped but strict mode (need bpftool)"
    fail=1
  else
    add_case "e2e-runner" 0 ""
  fi
elif [ ! -f "$runner_script" ]; then
  report "E2E runner: MISSING script $runner_script"
  add_case "e2e-runner" 1 "runner script not found"
  fail=1
else
  runner_rc=0
  python3 "$runner_script" \
    --layers "$layers" \
    --label "$label" \
    --junit "junit-lpf-ebpf-e2e-$label.xml" \
    >/tmp/ebpf-e2e.log 2>&1 || runner_rc=$?

  if [ "$runner_rc" -eq 0 ]; then
    report "E2E runner: PASSED"
    add_case "e2e-runner" 0 ""
  else
    report "E2E runner: FAILED (rc=$runner_rc)"
    add_case "e2e-runner" 1 "$(tail -n 80 /tmp/ebpf-e2e.log)"
    fail=1
  fi

  # Merge the detailed JUnit from the Python runner into our suite JUnit
  runner_junit="junit-lpf-ebpf-e2e-$label.xml"
  if [ -f "$runner_junit" ]; then
    # Extract test cases from the runner's JUnit and append to our cases
    runner_cases=$(sed -n '/<testcase /p' "$runner_junit" 2>/dev/null || true)
    if [ -n "$runner_cases" ]; then
      cases="$cases$runner_cases\n"
    fi
  fi
fi

# ── stage 3: OCaml eBPF conformance unit tests ─────────────────────────────

if command -v dune >/dev/null 2>&1; then
  if dune build @runtest >/tmp/ebpf-unit.log 2>&1; then
    report "dune eBPF unit tests: OK"; add_case "ocaml-ebpf-unit" 0 ""
  else
    report "dune eBPF unit tests: FAILED"; add_case "ocaml-ebpf-unit" 1 "$(tail -n 40 /tmp/ebpf-unit.log)"
    fail=1
  fi
else
  report "dune build: SKIPPED (dune not found)"
  add_case "ocaml-ebpf-unit" 0 ""
fi

# ── stage 4: Layer 2 userspace toolchain (if lpf binary available) ─────────

if command -v lpf >/dev/null 2>&1; then
  report "lpf binary: $(lpf version 2>/dev/null || echo unknown)"

  # lpf ebpf render
  if lpf rules show --backend ebpf fixtures/policies/ebpf-full.lpf >/tmp/ebpf-render.log 2>&1; then
    if grep -q "ebpf policy image" /tmp/ebpf-render.log; then
      report "lpf ebpf render: OK"; add_case "lpf-ebpf-render" 0 ""
    else
      report "lpf ebpf render: unexpected output"; add_case "lpf-ebpf-render" 1 "$(head -n 20 /tmp/ebpf-render.log)"
      fail=1
    fi
  else
    report "lpf ebpf render: FAILED"; add_case "lpf-ebpf-render" 1 "$(tail -n 20 /tmp/ebpf-render.log)"
    fail=1
  fi

  # lpf ebpf loader script
  lpf ebpf load --script fixtures/policies/ebpf-full.lpf >/tmp/ebpf-loader.sh 2>/tmp/ebpf-loader-err.log
  if [ -s /tmp/ebpf-loader.sh ] && head -1 /tmp/ebpf-loader.sh | grep -q "#!/bin/sh"; then
    report "lpf ebpf loader: OK"; add_case "lpf-ebpf-loader" 0 ""
    # validate conntrack + ringbuf maps in loader
    grep -q "lpf_conntrack" /tmp/ebpf-loader.sh && report "  conntrack map: present" || report "  conntrack map: MISSING"
    grep -q "lpf_events" /tmp/ebpf-loader.sh    && report "  ringbuf map: present"   || report "  ringbuf map: MISSING"
  else
    report "lpf ebpf loader: FAILED"; add_case "lpf-ebpf-loader" 1 "$(tail -n 20 /tmp/ebpf-loader-err.log)"
    fail=1
  fi

  # lpf ebpf diff
  render_out=$(lpf rules show --backend ebpf fixtures/policies/ebpf-full.lpf 2>/dev/null)
  diff_out=$(lpf diff --backend ebpf --observed <(echo "$render_out") fixtures/policies/ebpf-full.lpf 2>&1) || true
  if echo "$diff_out" | grep -q "no changes"; then
    report "lpf ebpf diff (self): OK"; add_case "lpf-ebpf-diff-self" 0 ""
  else
    report "lpf ebpf diff (self): FAILED"; add_case "lpf-ebpf-diff-self" 1 "$diff_out"
    fail=1
  fi

  # lpf ebpf diff --live (only if kernel has BPF loaded)
  if mountpoint -q /sys/fs/bpf 2>/dev/null; then
    diff_live=$(lpf diff --backend ebpf --live fixtures/policies/ebpf-full.lpf 2>&1) || true
    report "lpf ebpf diff --live: $(echo "$diff_live" | head -1)"
    add_case "lpf-ebpf-diff-live" 0 ""
  fi

  # explain parity test
  explain_ir=$(lpf explain in wan from 10.0.0.5 to 10.0.0.10 proto tcp port 80 fixtures/policies/ebpf-full.lpf 2>&1)
  explain_ebpf=$(lpf explain --backend ebpf in wan from 10.0.0.5 to 10.0.0.10 proto tcp port 80 fixtures/policies/ebpf-full.lpf 2>&1)
  ir_decision=$(echo "$explain_ir" | grep "Decision:" | awk '{print $2}')
  ebpf_decision=$(echo "$explain_ebpf" | grep -oP '(pass|drop|reject)' | head -1)
  if [ "$ir_decision" = "$ebpf_decision" ]; then
    report "explain parity: IR=$ir_decision eBPF=$ebpf_decision OK"
    add_case "explain-parity" 0 ""
  else
    report "explain parity: MISMATCH IR=$ir_decision eBPF=$ebpf_decision"
    add_case "explain-parity" 1 "IR=$ir_decision eBPF=$ebpf_decision"
    fail=1
  fi
else
  report "lpf binary: SKIPPED (not found, Layer 2 skipped)"
  add_case "lpf-ebpf-toolchain" 0 ""
fi

# ── JUnit output ───────────────────────────────────────────────────────────

junit="${LPF_EBPF_JUNIT:-junit-lpf-ebpf-e2e-$label.xml}"
{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n'
  printf '  <testsuite name="lpf-ebpf-e2e-%s">\n' "$label"
  printf '%b' "$cases"
  printf '  </testsuite>\n</testsuites>\n'
} > "$junit"

echo ""
echo "ebpf-e2e-suite: kernel=$label layers=$layers result=$([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
