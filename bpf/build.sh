#!/bin/sh
# Compile the lpf CO-RE BPF object against the running kernel's BTF.
#
# Produces lpf_kern.o containing all hook programs:
#   XDP ingress (lpf_ingress), TC egress (lpf_egress),
#   cgroup_skb ingress/egress (lpf_cgroup_ingress/egress),
#   LSM socket_connect (lpf_lsm_connect), LSM socket_bind (lpf_lsm_bind).
#
# Requires: clang, llvm-strip, bpftool, and /sys/kernel/btf/vmlinux.
# Set LPF_BPF_TARGET to override the BPF target (default: native arch).
set -e

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
btf=${LPF_BTF:-/sys/kernel/btf/vmlinux}
arch=$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
target_arch="${LPF_BPF_TARGET:-$arch}"
cni_only="${LPF_BPF_CNI_ONLY:-0}"

if [ ! -f "$dir/vmlinux.h" ]; then
  echo "generating vmlinux.h from $btf"
  bpftool btf dump file "$btf" format c >"$dir/vmlinux.h"
fi

extra_cflags=
if ! grep -Eq 'typedef .*__u(8|16|32|64);' "$dir/vmlinux.h"; then
  multiarch=$(cc -dumpmachine 2>/dev/null || true)
  if [ -n "$multiarch" ] && [ -d "/usr/include/$multiarch" ]; then
    extra_cflags="$extra_cflags -I/usr/include/$multiarch"
  fi
  extra_cflags="$extra_cflags -include linux/types.h"
fi
if [ "$cni_only" = "1" ]; then
  extra_cflags="$extra_cflags -DLPF_BPF_CNI_ONLY"
fi

clang -O2 -g -Wall \
  -Wno-missing-declarations \
  -Wno-compare-distinct-pointer-types \
  -fno-builtin \
  -fno-builtin-memcpy \
  -fno-builtin-memset \
  -target bpf \
  "-D__TARGET_ARCH_$target_arch" \
  ${LPF_EXTRA_CFLAGS:-} \
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
  if llvm-objdump -h "$dir/lpf_kern.o" 2>/dev/null | grep -qF "$sec"; then
    echo "  $sec: present"
  else
    echo "  $sec: MISSING"
  fi
done

llvm-strip -g "$dir/lpf_kern.o" 2>/dev/null || true
echo "built $dir/lpf_kern.o"
