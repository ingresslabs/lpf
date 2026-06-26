#!/bin/bash
# lpf Firecracker init — minimal init for Firecracker microVMs.
# Mounts virtual filesystems, starts sshd, and drops into a shell
# (or runs the Vagabond command if provided via kernel cmdline).
set -euo pipefail

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

mkdir -p /dev/pts
mount -t devpts devpts /dev/pts

# Bring up loopback
ip link set lo up

# Start sshd if available
if command -v sshd >/dev/null 2>&1; then
  sshd
fi

# Read the Vagabond command from the kernel cmdline if present
vagabond_cmd=$(grep -o 'vagabond_cmd=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2- | sed 's/%20/ /g' || true)

if [ -n "${vagabond_cmd:-}" ]; then
  echo "[lpf-rootfs] running Vagabond command: $vagabond_cmd"
  eval "$vagabond_cmd"
  echo "[lpf-rootfs] command finished, shutting down"
  poweroff -f
else
  echo "[lpf-rootfs] no command supplied, dropping to shell"
  exec /bin/bash
fi
