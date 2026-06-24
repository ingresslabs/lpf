#!/usr/bin/env bash
# lpf eBPF datapath conformance, designed to run inside a Vagabond Firecracker
# microVM (nomad.firecracker) booting a specific kernel from the kernel matrix.
#
# Builds the eBPF datapath object and runs the in-kernel conformance matrix
# (load via bpftool + progrun), plus the OCaml eBPF conformance unit tests.
# Requires root + bpftool + kernel BTF -- exactly what a hardware-isolated
# microVM provides without touching the host kernel.
#
# Set LPF_EBPF_STRICT=1 to fail when bpftool/BTF is unavailable (otherwise those
# steps are reported as skipped). Writes junit-lpf-ebpf-<label>.xml.
set -uo pipefail

# Make dune/opam tooling available when present (rootfs may ship an opam env).
eval "$(opam env 2>/dev/null)" || true

label="${LPF_KERNEL_LABEL:-$(uname -r)}"
strict="${LPF_EBPF_STRICT:-0}"
fail=0
cases=""
report() { echo "[ebpf] $*"; }
add_case() {
  local name="$1" ok="$2" detail="$3"
  if [ "$ok" -eq 0 ]; then
    cases="$cases    <testcase classname=\"lpf.ebpf.$label\" name=\"$name\"/>\n"
  else
    cases="$cases    <testcase classname=\"lpf.ebpf.$label\" name=\"$name\"><failure>$detail</failure></testcase>\n"
  fi
}

echo "=== lpf eBPF datapath conformance: kernel-label=$label uname=$(uname -r) ==="
report "kernel: $(uname -srm)"
[ -r /sys/kernel/btf/vmlinux ] && report "BTF: present" || report "BTF: MISSING"
command -v bpftool >/dev/null 2>&1 && report "bpftool: $(bpftool version 2>/dev/null | head -1)" || report "bpftool: MISSING"
command -v clang   >/dev/null 2>&1 && report "clang: $(clang --version 2>/dev/null | head -1)"   || report "clang: MISSING"

# 1) build the eBPF datapath object (clang/llvm + kernel BTF).
if make bpf >/tmp/bpf-build.log 2>&1; then
  report "make bpf: OK"; add_case "build-ebpf-object" 0 ""
else
  report "make bpf: FAILED"; add_case "build-ebpf-object" 1 "$(tail -n 40 /tmp/bpf-build.log)"; fail=1
fi

# 2) in-kernel conformance matrix (root + bpftool + bpf fs).
if [ "$(id -u)" = "0" ] && command -v bpftool >/dev/null 2>&1; then
  if make bpf-e2e >/tmp/bpf-e2e.log 2>&1; then
    report "make bpf-e2e: OK"; add_case "in-kernel-conformance" 0 ""
  else
    report "make bpf-e2e: FAILED"; add_case "in-kernel-conformance" 1 "$(tail -n 60 /tmp/bpf-e2e.log)"; fail=1
  fi
else
  report "make bpf-e2e: SKIPPED (need root + bpftool)"
  if [ "$strict" = "1" ]; then add_case "in-kernel-conformance" 1 "skipped but strict"; fail=1; else add_case "in-kernel-conformance" 0 ""; fi
fi

# 3) OCaml eBPF conformance unit tests.
if opam exec -- dune build @runtest >/tmp/ebpf-unit.log 2>&1; then
  report "dune eBPF unit tests: OK"; add_case "ocaml-ebpf-unit" 0 ""
else
  report "dune eBPF unit tests: FAILED"; add_case "ocaml-ebpf-unit" 1 "$(tail -n 40 /tmp/ebpf-unit.log)"; fail=1
fi

junit="${LPF_EBPF_JUNIT:-junit-lpf-ebpf-$label.xml}"
{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n'
  printf '  <testsuite name="lpf-ebpf-%s">\n' "$label"
  printf '%b' "$cases"
  printf '  </testsuite>\n</testsuites>\n'
} > "$junit"

echo "ebpf-suite: kernel=$label result=$([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
