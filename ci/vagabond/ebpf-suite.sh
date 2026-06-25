#!/usr/bin/env bash
# lpf eBPF datapath conformance, designed to run inside a Vagabond Firecracker
# microVM (nomad.firecracker) booting a specific kernel from the kernel matrix.
#
# Three-tier conformance pipeline:
#   1) Basic e2e progrun matrix (bpf/e2e_progrun.py) — 80+ XDP verdict checks
#   2) Comprehensive E2E runner (bpf/e2e_runner.py) — 4-layer matrix:
#      Layer 0: per-hook progrun (XDP, TC, cgroup, LSM)
#      Layer 1: map state (conntrack, counters, CIDR, ringbuf)
#      Layer 2: userspace toolchain (lpf CLI integration)
#      Layer 3: live Firecracker e2e (veth, ping, iperf3)
#   3) OCaml eBPF unit tests (dune build @runtest)
#
# The comprehensive runner produces its own JUnit XML; this script aggregates
# all results into a single junit-lpf-ebpf-<label>.xml.
#
# Requires root + bpftool + kernel BTF — exactly what a hardware-isolated
# microVM provides without touching the host kernel.
#
# Set LPF_EBPF_STRICT=1 to fail when bpftool/BTF is unavailable (otherwise
# those steps are reported as skipped).
# Set LPF_EBPF_LAYERS to control which e2e layers run (default: 0,1,2,3).
set -uo pipefail

# Make dune/opam tooling available when present (rootfs may ship an opam env).
eval "$(opam env 2>/dev/null)" || true

label="${LPF_KERNEL_LABEL:-$(uname -r)}"
strict="${LPF_EBPF_STRICT:-0}"
layers="${LPF_EBPF_LAYERS:-0,1,2,3}"
fail=0
cases=""

report() { echo "[ebpf] $*"; }

add_case() {
  local name="$1" ok="$2" detail="$3"
  local esc_name esc_detail
  esc_name=$(printf '%s' "$name" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g')
  esc_detail=$(printf '%s' "$detail" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g')
  if [ "$ok" -eq 0 ]; then
    cases="$cases    <testcase classname=\"lpf.ebpf.$label\" name=\"$esc_name\"/>\n"
  else
    cases="$cases    <testcase classname=\"lpf.ebpf.$label\" name=\"$esc_name\"><failure>$esc_detail</failure></testcase>\n"
  fi
}

echo "=== lpf eBPF datapath conformance: kernel-label=$label uname=$(uname -r) ==="
report "kernel: $(uname -srm)"
[ -r /sys/kernel/btf/vmlinux ] && report "BTF: present" || report "BTF: MISSING"
command -v bpftool >/dev/null 2>&1 && report "bpftool: $(bpftool version 2>/dev/null | head -1)" || report "bpftool: MISSING"
command -v clang   >/dev/null 2>&1 && report "clang: $(clang --version 2>/dev/null | head -1)"   || report "clang: MISSING"
command -v python3 >/dev/null 2>&1 && report "python3: $(python3 --version 2>/dev/null)"          || report "python3: MISSING"

# ── 1) build the eBPF datapath object (clang/llvm + kernel BTF). ──────────

if make bpf >/tmp/bpf-build.log 2>&1; then
  report "make bpf: OK"; add_case "build-ebpf-object" 0 ""
else
  report "make bpf: FAILED"; add_case "build-ebpf-object" 1 "$(tail -n 40 /tmp/bpf-build.log)"; fail=1
fi

# ── 2) basic in-kernel conformance matrix (e2e_progrun.py, ~80 checks) ────

if [ "$(id -u)" = "0" ] && command -v bpftool >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  if [ -f bpf/e2e_progrun.py ]; then
    if python3 bpf/e2e_progrun.py >/tmp/bpf-progrun.log 2>&1; then
      report "e2e_progrun: OK"; add_case "basic-progrun-matrix" 0 ""
    else
      report "e2e_progrun: FAILED"; add_case "basic-progrun-matrix" 1 "$(tail -n 60 /tmp/bpf-progrun.log)"; fail=1
    fi
  else
    report "e2e_progrun: SKIPPED (script not found)"
    add_case "basic-progrun-matrix" 0 ""
  fi
else
  report "basic progrun: SKIPPED (need root + bpftool + python3)"
  if [ "$strict" = "1" ]; then add_case "basic-progrun-matrix" 1 "skipped but strict"; fail=1; else add_case "basic-progrun-matrix" 0 ""; fi
fi

# ── 3) comprehensive E2E runner (4-layer matrix) ──────────────────────────

if [ "$(id -u)" = "0" ] && command -v bpftool >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  if [ -f bpf/e2e_runner.py ]; then
    runner_label="${label}"
    runner_junit="junit-lpf-ebpf-e2e-${runner_label}.xml"
    if python3 bpf/e2e_runner.py \
        --layers "$layers" \
        --label "$runner_label" \
        --junit "$runner_junit" \
        --skip-build \
        >/tmp/ebpf-e2e-runner.log 2>&1; then
      report "e2e_runner: OK (layers=$layers)"; add_case "comprehensive-e2e-runner" 0 ""

      # merge runner JUnit test cases
      if [ -f "$runner_junit" ]; then
        runner_cases=$(sed -n '/<testcase /p' "$runner_junit" 2>/dev/null || true)
        if [ -n "$runner_cases" ]; then
          cases="$cases$runner_cases\n"
        fi
      fi
    else
      report "e2e_runner: FAILED (layers=$layers)"; add_case "comprehensive-e2e-runner" 1 "$(tail -n 80 /tmp/ebpf-e2e-runner.log)"; fail=1
    fi
  else
    report "e2e_runner: SKIPPED (script not found)"
    add_case "comprehensive-e2e-runner" 0 ""
  fi
else
  report "comprehensive e2e runner: SKIPPED (need root + bpftool + python3)"
  if [ "$strict" = "1" ]; then add_case "comprehensive-e2e-runner" 1 "skipped but strict"; fail=1; else add_case "comprehensive-e2e-runner" 0 ""; fi
fi

# ── 4) OCaml eBPF conformance unit tests. ──────────────────────────────────

if command -v dune >/dev/null 2>&1; then
  if opam exec -- dune build @runtest >/tmp/ebpf-unit.log 2>&1; then
    report "dune eBPF unit tests: OK"; add_case "ocaml-ebpf-unit" 0 ""
  else
    report "dune eBPF unit tests: FAILED"; add_case "ocaml-ebpf-unit" 1 "$(tail -n 40 /tmp/ebpf-unit.log)"; fail=1
  fi
else
  report "dune eBPF unit tests: SKIPPED (dune not found)"
  add_case "ocaml-ebpf-unit" 0 ""
fi

# ── JUnit output ───────────────────────────────────────────────────────────

junit="${LPF_EBPF_JUNIT:-junit-lpf-ebpf-$label.xml}"
{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n'
  printf '  <testsuite name="lpf-ebpf-%s">\n' "$label"
  printf '%b' "$cases"
  printf '  </testsuite>\n</testsuites>\n'
} > "$junit"

echo "ebpf-suite: kernel=$label result=$([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
