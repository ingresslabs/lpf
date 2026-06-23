#!/bin/sh
# Compile the lpf CO-RE BPF object against the running kernel's BTF.
# Requires: clang, llvm-strip, bpftool, and /sys/kernel/btf/vmlinux.
set -e

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
btf=${LPF_BTF:-/sys/kernel/btf/vmlinux}
arch=$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

if [ ! -f "$dir/vmlinux.h" ]; then
  echo "generating vmlinux.h from $btf"
  bpftool btf dump file "$btf" format c >"$dir/vmlinux.h"
fi

clang -O2 -g -Wall -Wno-missing-declarations -target bpf "-D__TARGET_ARCH_$arch" \
  -c "$dir/lpf_kern.c" -o "$dir/lpf_kern.o"
llvm-strip -g "$dir/lpf_kern.o" 2>/dev/null || true
echo "built $dir/lpf_kern.o"
