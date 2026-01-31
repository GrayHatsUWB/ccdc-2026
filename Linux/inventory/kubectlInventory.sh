#!/usr/bin/env bash

set -euo pipefail

# --- Colors & Formatting ---
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
PATHS=("$HOME/.kube/config" "/etc/rancher/k3s/k3s.yaml" "/etc/kubernetes/admin.conf")
for path in "${PATHS[@]}"; do
    if [[ -f "$path" && -r "$path" ]]; then
        export KUBECONFIG="$path"
        break
    fi
done

if ! command -v kubectl >/dev/null 2>&1; then
    echo -e "${RED}[!] Error: kubectl binary not found.${NC}"
    exit 1
fi

header "1. CLUSTER TOPOLOGY & NETWORKING"

# 1.1 Cluster Level IP Info
SERVER_URL=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo "Unknown")
echo -e "${GREEN}[+] API Server Endpoint:${NC} $SERVER_URL"

# 1.2 Node Deep-Dive (Names, IPs, OS, Kernel)
section "Node Inventory & IP Mapping"
kubectl get nodes -o custom-columns="NAME:.metadata.name,INTERNAL-IP:.status.addresses[?(@.type=='InternalIP')].address,EXTERNAL-IP:.status.addresses[?(@.type=='ExternalIP')].address,STATUS:.status.conditions[-1].type,RUNTIME:.status.nodeInfo.containerRuntimeVersion,KERNEL:.status.nodeInfo.kernelVersion,OS:.status.nodeInfo.osImage"

# 1.3 Pod Subnets (CIDRs)
section "Cluster Network Ranges (CIDRs)"
kubectl get nodes -o custom-columns="NODE:.metadata.name,POD-CIDR:.spec.podCIDR" || echo "  [i] Pod CIDRs not explicitly defined in node spec (standard for some CNIs)."

header "2. NAMESPACE & POD INVENTORY"

# 2.1 Namespace Details
section "Namespace Registry & Security Profile"
kubectl get ns -o custom-columns="NAME:.metadata.name,STATUS:.status.phase,AGE:.metadata.creationTimestamp"

# 2.2 Pod Deep-Dive (The "Where is everything?" section)
section "Global Pod & IP Inventory (All Namespaces)"
kubectl get pods -A -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName,STATUS:.status.phase"

header "3. SECURITY & VULNERABILITY AUDIT"

# 3.1 Privileged Pods
section "Container Privilege Audit"
PRIV=$(kubectl get pods -A -o jsonpath='{range .items[?(@.spec.containers[*].securityContext.privileged==true)]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}')
if [ ! -z "$PRIV" ]; then
    echo -e "${RED}[!] DANGER: Privileged Pods detected (Host Access):${NC}"
    echo "$PRIV" | awk '{printf "  - Namespace: %-15s Pod: %s\n", $1, $2}'
else
    echo -e "${GREEN}[OK] No privileged pods detected.${NC}"
fi

# 3.2 RBAC Audit
section "Identity & Access (Cluster-Admins)"
echo -e "Users/Groups with 'God Mode' (cluster-admin):"
kubectl get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{"\t"}{.subjects[*].name}{"\n"}{end}' | sed 's/^/  - /'

# 3.3 Host Leakage
section "Host Network/PID Leakage"
LEAKS=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.hostNetwork}{"\t"}{.spec.hostPID}{"\n"}{end}' | grep "true" || true)
if [ ! -z "$LEAKS" ]; then
    echo -e "${YELLOW}[!] WARNING: Pods sharing Host Network or PID Namespace:${NC}"
    echo -e "NAMESPACE\tPOD\tHOST_NET\tHOST_PID"
    echo "$LEAKS" | sed 's/^/  - /'
else
    echo -e "${GREEN}[OK] No host-leakage pods detected.${NC}"
fi

header "4. INGRESS & EXTERNAL EXPOSURE"

section "Services (LoadBalancers & NodePorts)"
kubectl get svc -A -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[*].ip,PORT(S):.spec.ports[*].port" | grep -v "ClusterIP" || echo "  No external-facing services found."

section "Ingress Routes (L7 Layer)"
kubectl get ingress -A -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,CLASS:.spec.ingressClassName,HOSTS:.spec.rules[*].host,ADDRESS:.status.loadBalancer.ingress[*].ip"

header "5. STORAGE & BACKEND"
section "Persistent Volumes & Storage Classes"
kubectl get sc
echo ""
kubectl get pv -o custom-columns="NAME:.metadata.name,CAPACITY:.spec.capacity.storage,ACCESS-MODES:.spec.accessModes,RECLAIM:.spec.persistentVolumeReclaimPolicy,STATUS:.status.phase,CLAIM:.spec.claimRef.name"

header "AUDIT SUMMARY"
echo -e "${CYAN}Report Complete.${NC}"
echo -e "Total Nodes:      $(kubectl get nodes --no-headers | wc -l)"
echo -e "Total Namespaces: $(kubectl get ns --no-headers | wc -l)"
echo -e "Total Pods:       $(kubectl get pods -A --no-headers | wc -l)"
echo -e "--------------------------------------------------------------------------------"
