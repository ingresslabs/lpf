#!/bin/bash
set -euo pipefail

PASS=0
FAIL=0
TOTAL=0

run_test() {
  local name="$1"
  local policy="$2"
  local src_cidr="$3"
  local dst_addr="$4"
  local dst_port="$5"
  local expect="$6"
  TOTAL=$((TOTAL + 1))
  echo "TEST [$TOTAL]: $name"

  local test_container="lpf-cni-test-$$-$TOTAL"
  local host_if="lpfh$(printf '%08x' "$TOTAL")"
  local container_if="eth0"

  cleanup() {
    ip link delete "$host_if" 2>/dev/null || true
    docker rm -f "$test_container" 2>/dev/null || true
  }
  trap cleanup EXIT

  docker run -d --name "$test_container" \
    --privileged \
    --cap-add BPF --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    -v /sys/fs/bpf:/sys/fs/bpf \
    alpine:latest sleep 3600 > /dev/null

  local pid
  pid=$(docker inspect -f '{{.State.Pid}}' "$test_container")

  ip link add "$host_if" type veth peer name "$container_if"
  ip link set "$container_if" netns "$pid"
  nsenter -t "$pid" -n ip addr add "$src_cidr" dev "$container_if"
  nsenter -t "$pid" -n ip link set "$container_if" up
  nsenter -t "$pid" -n ip link set lo up
  ip link set "$host_if" up

  ip addr add "${dst_addr}/24" dev "$host_if" 2>/dev/null || true

  local container_ip
  container_ip=$(echo "$src_cidr" | cut -d/ -f1)

  sleep 1

  local result="PASS"
  if [ "$expect" = "PASS" ]; then
    if ! docker exec "$test_container" timeout 3 nc -zv "$dst_addr" "$dst_port" 2>/dev/null; then
      result="FAIL"
    fi
  elif [ "$expect" = "DROP" ]; then
    if docker exec "$test_container" timeout 3 nc -zv "$dst_addr" "$dst_port" 2>/dev/null; then
      result="FAIL"
    fi
  fi

  cleanup
  trap - EXIT

  if [ "$result" = "PASS" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: $name"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $name (expected $expect)"
  fi
}

echo "=== lpf CNI sandbox tests ==="

run_test "allow: icmp ping" \
  "pass in on eth0 proto icmp from any to any" \
  "10.42.0.2/32" "10.42.0.1" "0" "PASS"

run_test "allow: tcp port 80" \
  "pass in on eth0 proto tcp from any to any port 80" \
  "10.42.1.2/32" "10.42.1.1" "80" "PASS"

echo ""
echo "=== $PASS/$TOTAL passed, $FAIL failed ==="
exit $FAIL
