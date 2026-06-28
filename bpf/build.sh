#!/bin/sh
# Compile the lpf CO-RE BPF object against the running kernel's BTF.
#
# Produces lpf_kern.o containing all hook programs:
#   XDP ingress (lpf_ingress), TC egress (lpf_egress),
#   cgroup_skb ingress/egress (lpf_cgroup_ingress/egress),
#   LSM socket_connect (lpf_lsm_connect), LSM socket_bind (lpf_lsm_bind).
#
# Requires: clang, llvm-objdump, llvm-strip, bpftool, libbpf headers, and
# /sys/kernel/btf/vmlinux unless bpf/vmlinux.h has already been generated.
# Set LPF_BPF_TARGET to override the BPF target (default: native arch).
set -e

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
btf=${LPF_BTF:-/sys/kernel/btf/vmlinux}
arch=$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
target_arch="${LPF_BPF_TARGET:-$arch}"
clang=${CLANG:-clang}
llvm_objdump=${LLVM_OBJDUMP:-llvm-objdump}
llvm_strip=${LLVM_STRIP:-llvm-strip}
bpftool=${BPFTOOL:-bpftool}
libbpf_include=${LIBBPF_INCLUDE:-}
no_btf=${LPF_NO_BTF:-0}
cni_only=${LPF_BPF_CNI_ONLY:-0}

need_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool: $1" >&2
    exit 127
  fi
}

need_tool "$clang"
need_tool "$llvm_objdump"
need_tool "$llvm_strip"

if [ -n "$libbpf_include" ]; then
  include_flags="-I$libbpf_include"
elif [ -d /usr/include/bpf ]; then
  include_flags=
elif [ -d /usr/local/include/bpf ]; then
  include_flags="-I/usr/local/include"
elif command -v brew >/dev/null 2>&1 && [ -d "$(brew --prefix libbpf 2>/dev/null)/include/bpf" ]; then
  include_flags="-I$(brew --prefix libbpf)/include"
else
  echo "missing libbpf headers: cannot find bpf/bpf_helpers.h" >&2
  echo "install libbpf-dev on Debian/Ubuntu, or set LIBBPF_INCLUDE to the directory containing bpf/" >&2
  exit 1
fi

btf_flags=
extra_cflags=${LPF_EXTRA_CFLAGS:-}
if [ "$no_btf" = "1" ]; then
  btf_flags="-DLPF_NO_VMLINUX_H"
  case "$(uname -m)" in
    x86_64) uapi_arch_include=/usr/include/x86_64-linux-gnu ;;
    aarch64) uapi_arch_include=/usr/include/aarch64-linux-gnu ;;
    *) uapi_arch_include= ;;
  esac
  if [ -n "$uapi_arch_include" ] && [ -d "$uapi_arch_include" ]; then
    btf_flags="$btf_flags -I$uapi_arch_include"
  fi
elif [ ! -s "$dir/vmlinux.h" ]; then
  need_tool "$bpftool"
  if [ ! -r "$btf" ]; then
    echo "missing kernel BTF: $btf" >&2
    echo "set LPF_BTF to a readable vmlinux BTF file, or provide non-empty $dir/vmlinux.h" >&2
    exit 1
  fi
  echo "generating vmlinux.h from $btf"
  "$bpftool" btf dump file "$btf" format c >"$dir/vmlinux.h"
fi

if [ "$cni_only" = "1" ]; then
  extra_cflags="$extra_cflags -DLPF_BPF_CNI_ONLY"
fi

"$clang" -O2 -g -Wall \
  -fno-builtin \
  -fno-builtin-memcpy \
  -fno-builtin-memset \
  -Wno-missing-declarations \
  -Wno-compare-distinct-pointer-types \
  -target bpf \
  "-D__TARGET_ARCH_$target_arch" \
  $extra_cflags \
  $btf_flags \
  $include_flags \
  -c "$dir/lpf_kern.c" -o "$dir/lpf_kern.o"

# Verify all expected sections are present
echo "program sections:"
if [ "$cni_only" = "1" ]; then
  expected_sections="cgroup_skb/ingress cgroup_skb/egress lsm/socket_connect lsm/socket_bind"
else
  expected_sections="xdp tc cgroup_skb/ingress cgroup_skb/egress lsm/socket_connect lsm/socket_bind"
fi
for sec in $expected_sections; do
  if "$llvm_objdump" -h "$dir/lpf_kern.o" 2>/dev/null | grep -qF "$sec"; then
    echo "  $sec: present"
  else
    echo "  $sec: MISSING"
  fi
done

"$llvm_strip" -g "$dir/lpf_kern.o" 2>/dev/null || true
echo "built $dir/lpf_kern.o"
