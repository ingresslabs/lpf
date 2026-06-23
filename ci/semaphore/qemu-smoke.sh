#!/usr/bin/env bash
set -euo pipefail

log_path="${1:-reports/qemu-smoke.log}"
timeout_seconds="${LPF_QEMU_TIMEOUT:-60}"
memory="${LPF_QEMU_MEMORY:-256M}"
qemu_bin="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
accel_mode="${LPF_QEMU_ACCEL:-tcg}"

mkdir -p "$(dirname "$log_path")"

if ! command -v "$qemu_bin" >/dev/null 2>&1; then
  echo "qemu-system-x86_64 not found" >&2
  exit 1
fi

kernel="${LPF_QEMU_KERNEL:-}"
if [ -z "$kernel" ]; then
  kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -1)"
fi
if [ -z "$kernel" ] || [ ! -r "$kernel" ]; then
  echo "no readable kernel image found under /boot" >&2
  exit 1
fi

if [ "$accel_mode" = "kvm" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  accel_args=(-machine accel=kvm:tcg -cpu host)
  expected_accel="KVM"
else
  accel_args=(-machine accel=tcg -cpu max)
  expected_accel="TCG"
fi

set +e
timeout --foreground -k 5 "$timeout_seconds" "$qemu_bin" \
  "${accel_args[@]}" \
  -m "$memory" \
  -smp 1 \
  -nographic \
  -no-reboot \
  -kernel "$kernel" \
  -append "console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 panic=1" \
  </dev/null >"$log_path" 2>&1
status=$?
set -e

if [ "$status" -ne 0 ] && [ "$status" -ne 124 ] && [ "$status" -ne 137 ] && [ "$status" -ne 143 ]; then
  sed -n '1,160p' "$log_path" >&2
  exit "$status"
fi

if ! grep -Eq 'Linux version|Kernel panic|VFS:|Run /init' "$log_path"; then
  echo "qemu produced no recognizable kernel boot output (accel=$expected_accel, status=$status)" >&2
  sed -n '1,160p' "$log_path" >&2
  exit 1
fi
grep -q 'DMI: QEMU' "$log_path"

printf 'qemu boot smoke passed with %s using %s\n' "$expected_accel" "$kernel"
