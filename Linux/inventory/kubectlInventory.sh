#!/usr/bin/env bash

set -euo pipefail

# --- Colors ---
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m' 

header() {
    echo -e "\n${BLUE}================================================================================${NC}"
    echo -e "${BLUE}   $1 ${NC}"
    echo -e "${BLUE}================================================================================${NC}"
}

section() {
    echo -e "\n${CYAN}>>> $1${NC}"
}

# --- [ENVIRONMENT DETECTION] ---
export KUBECONFIG=${KUBECONFIG:-""}
PATHS=("$HOME/.kube/config" "/etc/rancher/k3s/k3s.yaml" "/etc/kubernetes/admin.conf")
for path in "${PATHS[@]}"; do
    if [[ -z "$KUBECONFIG" && -f "$path" && -r "$path" ]]; then
        export KUBECONFIG="$path"
        break
    fi
done

if ! command -v kubectl >/dev/null 2>&1; then
    echo -e "${RED}[!] Error: kubectl binary not found. This script requires kubectl to audit the system.${NC}"
    exit 1
fi

header "1. CLUSTER TOPOLOGY & NODE DEEP-DIVE"
echo -e "${GREEN}[+] API Server Endpoint:${NC} $(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo 'Unknown')"

section "Node Hardware & Runtime"
echo -e "${YELLOW}$(printf "%-22s %-12s %-15s %-20s %-15s" "NAME" "STATUS" "INTERNAL-IP" "OS-IMAGE" "KERNEL")${NC}"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[-1].type}{"\t"}{.status.addresses[?(@.type=="InternalIP")].address}{"\t"}{.status.nodeInfo.osImage}{"\t"}{.status.nodeInfo.kernelVersion}{"\n"}{end}' | \
awk -F'\t' '{printf "%-22s %-12s %-15s %-20s %-15s\n", $1, $2, $3, $4, $5}'

section "Node Roles & Software"
kubectl get nodes -o custom-columns="NAME:.metadata.name,ROLE:.metadata.labels.kubernetes\.io/role,RUNTIME:.status.nodeInfo.containerRuntimeVersion,LABELS:.metadata.labels" --no-headers | \
awk '{printf "  %-22s | Role: %-10s | Runtime: %-15s | Labels: %.50s\n", $1, $2, $3, $4}'

header "2. NAMESPACES & LOGICAL LAYOUT"
echo -e "${YELLOW}$(printf "%-22s %-10s %-25s %-30s" "NAMESPACE" "STATUS" "CREATED-AT" "LABELS")${NC}"
kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.creationTimestamp}{"\t"}{.metadata.labels}{"\n"}{end}' | \
awk -F'\t' '{printf "%-22s %-10s %-25s %.50s\n", $1, $2, $3, $4}'

header "3. GLOBAL POD INVENTORY & NETWORK MAP"
section "Pod Connectivity & Physical Host Mapping"
echo -e "${YELLOW}$(printf "%-18s %-35s %-15s %-15s %-10s" "NAMESPACE" "POD-NAME" "POD-IP" "NODE-IP" "STATUS")${NC}"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.podIP}{"\t"}{.status.hostIP}{"\t"}{.status.phase}{"\n"}{end}' | \
awk -F'\t' '{printf "%-18s %-35s %-15s %-15s %-10s\n", $1, $2, $3, $4, $5}'

section "Pod Ownership & Resource Labels"
kubectl get pods -A -o custom-columns="NS:.metadata.namespace,NAME:.metadata.name,OWNER:.metadata.ownerReferences[0].name,LABELS:.metadata.labels" --no-headers | \
awk '{printf "  %-15s %-35s | Owner: %-15s | Labels: %.70s\n", $1, $2, $3, $4}'

# --- UNIVERSAL DIAGNOSTIC ENGINE ---
section "Pod Health & Universal Error Analytics"
ERROR_PODS=$(kubectl get pods -A --no-headers | grep -vE "Running|Completed" | awk '{print $1"/"$2}' || true)
if [ ! -z "$ERROR_PODS" ]; then
    echo -e "${RED}[!] CRITICAL POD ISSUES DETECTED:${NC}"
    printf "${YELLOW}  %-45s %-20s %-50s${NC}\n" "POD (NS/NAME)" "REASON" "MESSAGE"
    for p in $ERROR_PODS; do
        NS=$(echo $p | cut -d'/' -f1); NAME=$(echo $p | cut -d'/' -f2)
        # Check all possible error states: Waiting, Terminated, or Scheduler-level Pending
        DIAG=$(kubectl get pod "$NAME" -n "$NS" -o jsonpath='{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{.state.waiting.message}{.state.terminated.reason}{" "}{.state.terminated.message}{"\n"}{end}' | head -n 1)
        if [ -z "$(echo "$DIAG" | tr -d ' ')" ]; then
            REASON="Scheduling"
            MESSAGE=$(kubectl get pod "$NAME" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="PodScheduled")].message}')
        else
            REASON=$(echo "$DIAG" | awk '{print $1}')
            MESSAGE=$(echo "$DIAG" | cut -d' ' -f2-)
        fi
        printf "  %-45s %-20s %.70s\n" "$p" "${REASON:-Unknown}" "${MESSAGE:-'No container message (check events)'}"
    done
else
    echo -e "${GREEN}[OK] All pods are healthy (Running/Completed).${NC}"
fi

header "4. EXTERNAL EXPOSURE & SERVICES"
section "L4 Services (LoadBalancers & Gateways)"
echo -e "${YELLOW}$(printf "%-18s %-25s %-12s %-15s %-20s" "NAMESPACE" "SERVICE" "TYPE" "EXTERNAL-IP" "PORT(S)")${NC}"
kubectl get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.type}{"\t"}{.status.loadBalancer.ingress[*].ip}{"\t"}{.spec.ports[*].port}{"\n"}{end}' | \
grep -v "ClusterIP" | awk -F'\t' '{printf "%-18s %-25s %-12s %-15s %-20s\n", $1, $2, $3, $4, $5}'

section "L7 Ingress Routes"
kubectl get ingress -A -o custom-columns="NS:.metadata.namespace,NAME:.metadata.name,HOSTS:.spec.rules[*].host,CLASS:.spec.ingressClassName,ANNOTATIONS:.metadata.annotations" --no-headers | \
awk '{printf "  %-15s %-25s | Hosts: %-25s | Class: %-10s | Annotations: %.30s\n", $1, $2, $3, $4, $5}'

header "5. SECURITY AUDIT & STORAGE"
section "Security Risks"
echo -e "${CYAN}Privileged Pods (Potential Host Escape):${NC}"
kubectl get pods -A -o jsonpath='{range .items[?(@.spec.containers[*].securityContext.privileged==true)]}  [DANGER] {.metadata.namespace}/{.metadata.name}{"\n"}{end}' || echo "  [OK] None found."

echo -e "\n${CYAN}HostPath Volumes (Direct Disk Access):${NC}"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.volumes[*].hostPath.path}{"\n"}{end}' | grep -vE "^.*/\t$" | awk '{printf "  [!] HostLeak: %-40s Path: %s\n", $1, $2}' || echo "  [OK] No HostPath volumes."

echo -e "\n${CYAN}Cluster-Admin RBAC (God Mode):${NC}"
kubectl get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{"\t"}{.subjects[*].name}{"\n"}{end}' | awk '{printf "  - Binding: %-30s | User: %s\n", $1, $2}'

section "Persistent Storage Inventory"
echo -e "${YELLOW}$(printf "%-35s %-10s %-10s %-15s %-20s" "PV-NAME" "SIZE" "STATUS" "RECLAIM" "STORAGECLASS")${NC}"
kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.capacity.storage}{"\t"}{.status.phase}{"\t"}{.spec.persistentVolumeReclaimPolicy}{"\t"}{.spec.storageClassName}{"\n"}{end}' | \
awk -F'\t' '{printf "%-35s %-10s %-10s %-15s %-20s\n", $1, $2, $3, $4, $5}'

header "AUDIT SUMMARY"
printf "  Nodes: %-5s | Pods: %-5s | Namespaces: %-5s | PersistentVolumes: %s\n" \
    "$(kubectl get nodes --no-headers | wc -l)" \
    "$(kubectl get pods -A --no-headers | wc -l)" \
    "$(kubectl get ns --no-headers | wc -l)" \
    "$(kubectl get pv --no-headers 2>/dev/null | wc -l || echo 0)"
