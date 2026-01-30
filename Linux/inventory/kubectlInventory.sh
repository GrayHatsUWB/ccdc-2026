#!/usr/bin/env bash

set -euo pipefail

divider() {
    echo "------------------------------------------------------------"
}

section() {
    divider
    echo "### $1"
    divider
}

echo
section "Checking kubectl availability"

if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl is NOT installed on this system."
    exit 1
fi

echo "kubectl binary: $(command -v kubectl)"
echo "kubectl client version:"
kubectl version --client || true
echo

section "Checking cluster connectivity"

if kubectl version >/dev/null 2>&1; then
    echo "Cluster is reachable."
else
    echo "kubectl exists but cannot reach any cluster."
fi
echo

section "Kubeconfig Information"
kubectl config view || true
echo

section "Current Context"
kubectl config current-context || true
echo

section "All Contexts"
kubectl config get-contexts || true
echo

section "Cluster Info"
kubectl cluster-info || true
echo

section "Nodes"
kubectl get nodes -o wide || true
echo

section "Namespaces"
kubectl get ns || true
echo

section "Pods (all namespaces)"
kubectl get pods -A -o wide || true
echo

section "Deployments (all namespaces)"
kubectl get deploy -A -o wide || true
echo

section "StatefulSets (all namespaces)"
kubectl get statefulset -A -o wide || true
echo

section "DaemonSets (all namespaces)"
kubectl get daemonset -A -o wide || true
echo

section "ReplicaSets (all namespaces)"
kubectl get rs -A -o wide || true
echo

section "Jobs (all namespaces)"
kubectl get jobs -A || true
echo

section "CronJobs (all namespaces)"
kubectl get cronjobs -A || true
echo

section "Services (all namespaces)"
kubectl get svc -A -o wide || true
echo

section "Ingresses (all namespaces)"
kubectl get ingress -A || true
echo

section "Events (cluster-wide)"
kubectl get events -A --sort-by=.metadata.creationTimestamp || true
echo

section "Storage Classes"
kubectl get storageclass || true
echo

section "Persistent Volumes"
kubectl get pv || true
echo

section "Persistent Volume Claims (all namespaces)"
kubectl get pvc -A || true
echo

section "Summary"
echo "Cluster diagnostic report complete."
divider
