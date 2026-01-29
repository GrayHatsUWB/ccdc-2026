#!/usr/bin/env bash

set -euo pipefail

echo "=== Checking for kubectl ==="
if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl not found on this system."
    exit 1
fi
echo "kubectl found: $(command -v kubectl)"
echo

echo "=== Checking cluster connectivity ==="
if ! kubectl version --short >/dev/null 2>&1; then
    echo "kubectl exists but cannot reach any cluster."
    exit 2
fi
kubectl version --short
echo

echo "=== Current Context ==="
kubectl config current-context || true
echo

echo "=== All Contexts ==="
kubectl config get-contexts || true
echo

echo "=== Cluster Info ==="
kubectl cluster-info || true
echo

echo "=== Nodes ==="
kubectl get nodes -o wide || true
echo

echo "=== Namespaces ==="
kubectl get ns || true
echo

echo "=== API Resources ==="
kubectl api-resources || true
echo

echo "=== API Versions ==="
kubectl api-versions || true
echo

echo "=== Pods (all namespaces) ==="
kubectl get pods -A -o wide || true
echo

echo "=== Deployments (all namespaces) ==="
kubectl get deploy -A -o wide || true
echo

echo "=== StatefulSets (all namespaces) ==="
kubectl get statefulset -A -o wide || true
echo

echo "=== DaemonSets (all namespaces) ==="
kubectl get daemonset -A -o wide || true
echo

echo "=== Services (all namespaces) ==="
kubectl get svc -A -o wide || true
echo

echo "=== Ingresses (all namespaces) ==="
kubectl get ingress -A || true
echo

echo "=== Events (cluster-wide) ==="
kubectl get events -A --sort-by=.metadata.creationTimestamp || true
echo

echo "=== Storage Classes ==="
kubectl get storageclass || true
echo

echo "=== Persistent Volumes ==="
kubectl get pv || true
echo

echo "=== Persistent Volume Claims (all namespaces) ==="
kubectl get pvc -A || true
echo

echo "=== Cluster Roles ==="
kubectl get clusterroles || true
echo

echo "=== Cluster Role Bindings ==="
kubectl get clusterrolebindings || true
echo

echo "=== Summary ==="
echo "Cluster report complete."
