#!/bin/bash
set -euo pipefail

echo "=== lpf k3s CNI E2E ==="

CLUSTER_NAME="lpf-cni-e2e-$$"
trap 'k3d cluster delete "$CLUSTER_NAME" 2>/dev/null || true' EXIT

k3d cluster create "$CLUSTER_NAME" \
  --k3s-arg "--flannel-backend=none@server:0" \
  --k3s-arg "--disable-network-policy@server:0" \
  --wait

kubectl wait --for=condition=ready node --all --timeout=120s

kubectl create ns tenant-a
kubectl create ns tenant-b

kubectl run web --image=nginx:alpine --port=80 -n tenant-a
kubectl run db --image=postgres:16-alpine --port=5432 -n tenant-a
kubectl run attacker --image=alpine/curl -n tenant-b -- sleep 3600

kubectl wait --for=condition=ready pod -n tenant-a --all --timeout=120s
kubectl wait --for=condition=ready pod -n tenant-b --all --timeout=120s

WEB_IP=$(kubectl get pod web -n tenant-a -o jsonpath='{.status.podIP}')
DB_IP=$(kubectl get pod db -n tenant-a -o jsonpath='{.status.podIP}')
ATTACKER=$(kubectl get pod attacker -n tenant-b -o jsonpath='{.metadata.name}')

echo "Web IP: $WEB_IP"
echo "DB IP: $DB_IP"

PASS=0
FAIL=0

check_pass() {
  local desc="$1" cmd="$2"
  if eval "$cmd"; then
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc"
    FAIL=$((FAIL + 1))
  fi
}

check_block() {
  local desc="$1" cmd="$2"
  if eval "$cmd"; then
    echo "FAIL: $desc (expected block, got pass)"
    FAIL=$((FAIL + 1))
  else
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  fi
}

check_pass "web reachable from attacker" \
  "kubectl exec $ATTACKER -n tenant-b -- timeout 5 wget -q -O- http://${WEB_IP}"

check_pass "db reachable from web" \
  "kubectl exec web -n tenant-a -- timeout 3 nc -zv $DB_IP 5432"

check_block "db blocked from attacker" \
  "kubectl exec $ATTACKER -n tenant-b -- timeout 3 nc -zv $DB_IP 5432"

echo ""
echo "=== k3s E2E: $PASS passed, $FAIL failed ==="
exit $FAIL
