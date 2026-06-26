#!/bin/bash
set -euo pipefail

echo "=== lpf kind multi-node CNI E2E ==="

CLUSTER_NAME="lpf-cni-kind-$$"
trap 'kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true' EXIT

kind create cluster --name "$CLUSTER_NAME" --config ci/cni/kind-config.yaml --wait 5m

kubectl wait --for=condition=ready node --all --timeout=120s

echo "Installing lpf CNI..."
kubectl apply -f packaging/k8s/lpf-cni.yaml

kubectl wait --for=condition=ready pod -n kube-system -l app=lpf-cni --timeout=120s

PASS=0
FAIL=0

echo "Deploying test workloads..."
kubectl create ns tenant-a
kubectl create ns tenant-b

kubectl run web --image=nginx:alpine --port=80 -n tenant-a
kubectl run db --image=postgres:16-alpine --port=5432 -n tenant-a

kubectl wait --for=condition=ready pod -n tenant-a --all --timeout=120s

NODES=$(kubectl get nodes -o name | wc -l | tr -d ' ')
echo "Cluster nodes: $NODES"

WEB_NODE=$(kubectl get pod web -n tenant-a -o jsonpath='{.spec.nodeName}')
DB_NODE=$(kubectl get pod db -n tenant-a -o jsonpath='{.spec.nodeName}')
echo "web on: $WEB_NODE, db on: $DB_NODE"

if [ "$WEB_NODE" != "$DB_NODE" ]; then
  echo "PASS: web and db on different nodes (cross-node traffic)"
  PASS=$((PASS + 1))
else
  echo "INFO: web and db on same node"
fi

WEB_IP=$(kubectl get pod web -n tenant-a -o jsonpath='{.status.podIP}')
DB_IP=$(kubectl get pod db -n tenant-a -o jsonpath='{.status.podIP}')

if kubectl exec web -n tenant-a -- timeout 3 nc -zv "$DB_IP" 5432; then
  echo "PASS: cross-node web->db:5432"
  PASS=$((PASS + 1))
else
  echo "FAIL: cross-node web->db:5432"
  FAIL=$((FAIL + 1))
fi

kubectl get pods -n kube-system -l app=lpf-cni -o wide
kubectl logs -n kube-system -l app=lpf-cni --tail=20 || true

echo ""
echo "=== kind E2E: $PASS passed, $FAIL failed ==="
exit $FAIL
