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

header "1. CLUSTER TOPOLOGY & NODES"
echo -e "${GREEN}[+] API Server:${NC} $(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo 'Unknown')"

section "Node Hardware & Runtime"
echo -e "${YELLOW}$(printf "%-22s %-12s %-15s %-20s %-15s" "NAME" "STATUS" "INTERNAL-IP" "OS-IMAGE" "KERNEL")${NC}"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[-1].type}{"\t"}{.status.addresses[?(@.type=="InternalIP")].address}{"\t"}{.status.nodeInfo.osImage}{"\t"}{.status.nodeInfo.kernelVersion}{"\n"}{end}' | \
awk -F'\t' '{printf "%-22s %-12s %-15s %-20s %-15s\n", $1, $2, $3, $4, $5}'

section "Node Pressure & Resource Warnings"
# Detects DiskPressure, MemoryPressure, or PIDPressure
NODE_ERRS=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[?(@.status=="True")]}{.type}{" "}{end}{"\n"}{end}' | grep -v "Ready" || true)
if [ ! -z "$NODE_ERRS" ]; then
    echo -e "${RED}[!] CRITICAL: Node Resource Pressure Detected:${NC}"
    echo "$NODE_ERRS" | awk '{printf "  - Node: %-22s Condition: %s\n", $1, $2}'
else
    echo -e "${GREEN}[OK] No Node pressure flags detected.${NC}"
fi

header "2. POD & NETWORK INVENTORY"
section "Pod-to-Node Mapping"
echo -e "${YELLOW}$(printf "%-18s %-35s %-15s %-15s %-10s" "NAMESPACE" "POD-NAME" "POD-IP" "NODE-IP" "STATUS")${NC}"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.podIP}{"\t"}{.status.hostIP}{"\t"}{.status.phase}{"\n"}{end}' | \
awk -F'\t' '{printf "%-18s %-35s %-15s %-15s %-10s\n", $1, $2, $3, $4, $5}'

# --- UNIVERSAL DIAGNOSTIC ENGINE ---
section "Pod Health & Error Analytics"
ERROR_PODS=$(kubectl get pods -A --no-headers | grep -vE "Running|Completed" | awk '{print $1"/"$2}' || true)
if [ ! -z "$ERROR_PODS" ]; then
    printf "${YELLOW}  %-45s %-20s %-50s${NC}\n" "POD (NS/NAME)" "REASON" "MESSAGE"
    for p in $ERROR_PODS; do
        NS=$(echo $p | cut -d'/' -f1); NAME=$(echo $p | cut -d'/' -f2)
        DIAG=$(kubectl get pod "$NAME" -n "$NS" -o jsonpath='{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{.state.waiting.message}{.state.terminated.reason}{" "}{.state.terminated.message}{"\n"}{end}' | head -n 1)
        if [ -z "$(echo "$DIAG" | tr -d ' ')" ]; then
            REASON="Scheduling"
            MESSAGE=$(kubectl get pod "$NAME" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="PodScheduled")].message}')
        else
            REASON=$(echo "$DIAG" | awk '{print $1}'); MESSAGE=$(echo "$DIAG" | cut -d' ' -f2-)
        fi
        printf "  %-45s %-20s %.70s\n" "$p" "${REASON:-Unknown}" "${MESSAGE:-'No container message'}"
    done
fi

header "3. INGRESS & EXTERNAL EXPOSURE"
section "L4 Services & Endpoints (Network Entry)"
echo -e "${YELLOW}$(printf "%-15s %-25s %-12s %-15s %-20s" "NAMESPACE" "SERVICE" "TYPE" "EXTERNAL-IP" "TARGET-POD-IPS")${NC}"
kubectl get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.type}{"\t"}{.status.loadBalancer.ingress[*].ip}{"\t"}{.spec.clusterIP}{"\n"}{end}' | \
while read -r line; do
    NS=$(echo "$line" | awk '{print $1}'); NAME=$(echo "$line" | awk '{print $2}')
    ENDPOINTS=$(kubectl get endpoints "$NAME" -n "$NS" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || echo "None")
    echo "$line $ENDPOINTS" | awk '{printf "%-15s %-25s %-12s %-15s %-20s\n", $1, $2, $3, $4, $5}'
done

section "L7 Ingress Routes (Virtual Hosts)"
kubectl get ingress -A -o custom-columns="NS:.metadata.namespace,NAME:.metadata.name,HOSTS:.spec.rules[*].host,CLASS:.spec.ingressClassName" --no-headers | \
awk '{printf "  %-15s %-25s | Hosts: %-25s | Class: %-10s\n", $1, $2, $3, $4}'

header "4. SECURITY & VULNERABILITY AUDIT"
section "Container Image Registry Audit"
echo -e "${YELLOW}$(printf "%-18s %-35s %-40s" "NAMESPACE" "POD-NAME" "IMAGE-SOURCE")${NC}"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | \
awk -F'\t' '{printf "%-18s %-35s %.60s\n", $1, $2, $3}'

section "Security Risks & RBAC"
echo -e "${CYAN}Privileged Pods:${NC}"
kubectl get pods -A -o jsonpath='{range .items[?(@.spec.containers[*].securityContext.privileged==true)]}  [DANGER] {.metadata.namespace}/{.metadata.name}{"\n"}{end}' || echo "  [OK] None."

echo -e "\n${CYAN}HostPath Leaks:${NC}"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.volumes[*].hostPath.path}{"\n"}{end}' | grep -vE "^.*/\t$" | awk '{printf "  [!] HostAccess: %-30s Path: %s\n", $1, $2}' || echo "  [OK] None."

header "5. STORAGE & BACKEND INVENTORY"
section "Persistent Volume Claims (App to Disk Mapping)"
echo -e "${YELLOW}$(printf "%-15s %-30s %-10s %-15s %-20s" "NAMESPACE" "PVC-NAME" "STATUS" "VOLUME" "STORAGE-CLASS")${NC}"
kubectl get pvc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.spec.volumeName}{"\t"}{.spec.storageClassName}{"\n"}{end}' | \
awk -F'\t' '{printf "%-15s %-30s %-10s %-15s %-20s\n", $1, $2, $3, $4, $5}'

section "Physical Volume Backend"
echo -e "${YELLOW}$(printf "%-35s %-10s %-15s %-15s" "PV-NAME" "SIZE" "RECLAIM" "STATUS")${NC}"
kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.capacity.storage}{"\t"}{.spec.persistentVolumeReclaimPolicy}{"\t"}{.status.phase}{"\n"}{end}' | \
awk -F'\t' '{printf "%-35s %-10s %-15s %-15s\n", $1, $2, $3, $4}'

header "6. CLUSTER EVENTS & SYSTEM WARNINGS"
section "Last 15 Minutes: Error/Warning Log"
# Captures system-level events (Mount failures, OOM kills, Node lost)
kubectl get events -A --field-selector type=Warning --no-headers 2>/dev/null | \
awk '{printf "  - [%-15s] %-15s | %s\n", $1, $4, substr($0, index($0,$7))}' | tail -n 15 || echo "  No recent system warnings."

header "AUDIT SUMMARY"
printf "  Nodes: %s | Pods: %s | External IPs: %s | Storage: %s\n" \
    "$(kubectl get nodes --no-headers | wc -l)" \
    "$(kubectl get pods -A --no-headers | wc -l)" \
    "$(kubectl get svc -A --no-headers | grep -v "none" | wc -l)" \
    "$(kubectl get pv --no-headers 2>/dev/null | wc -l || echo 0)"
