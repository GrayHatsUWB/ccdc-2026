#!/bin/sh

# Use /bin/sh for maximum compatibility across Alpine (dash/ash) and others
set -eu

# --- Helper Functions ---
header() {
    echo ""
    echo "================================================================================"
    echo "    $1"
    echo "================================================================================"
}

section() {
    echo ""
    echo ">>> $1"
}

# --- Environment Detection ---
export KUBECONFIG=${KUBECONFIG:-""}
PATHS="$HOME/.kube/config:/etc/rancher/k3s/k3s.yaml:/etc/kubernetes/admin.conf"

if [ -z "$KUBECONFIG" ]; then
    OLD_IFS=$IFS
    IFS=":"
    for path in $PATHS; do
        if [ -f "$path" ] && [ -r "$path" ]; then
            export KUBECONFIG="$path"
            break
        fi
    done
    IFS=$OLD_IFS
fi

header "1. CLUSTER TOPOLOGY & NODES"
echo "[+] API Server: $(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo 'Unknown')"

section "Node Hardware & Runtime"
printf "%-22s %-12s %-15s %-20s %-15s\n" "NAME" "STATUS" "INTERNAL-IP" "OS-IMAGE" "KERNEL"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[-1].type}{"\t"}{.status.addresses[?(@.type=="InternalIP")].address}{"\t"}{.status.nodeInfo.osImage}{"\t"}{.status.nodeInfo.kernelVersion}{"\n"}{end}' | \
awk -F'\t' '{printf "%-22s %-12s %-15s %-20s %-15s\n", $1, $2, $3, $4, $5}'

section "Node Pressure & Resource Warnings"
NODE_ERRS=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[?(@.status=="True")]}{.type}{" "}{end}{"\n"}{end}' | grep -v "Ready" || true)
if [ -n "$NODE_ERRS" ]; then
    echo "[!] CRITICAL: Node Resource Pressure Detected:"
    echo "$NODE_ERRS" | awk '{printf "  - Node: %-22s Condition: %s\n", $1, $2}'
else
    echo "[OK] No Node pressure flags detected."
fi

header "2. POD & NETWORK INVENTORY"
section "Pod-to-Node Mapping"
printf "%-18s %-35s %-15s %-15s %-10s\n" "NAMESPACE" "POD-NAME" "POD-IP" "NODE-IP" "STATUS"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.podIP}{"\t"}{.status.hostIP}{"\t"}{.status.phase}{"\n"}{end}' | \
awk -F'\t' '{printf "%-18s %-35s %-15s %-15s %-10s\n", $1, $2, $3, $4, $5}'

section "Pod Health & Error Analytics"
ERROR_PODS=$(kubectl get pods -A --no-headers | grep -vE "Running|Completed" | awk '{print $1"/"$2}' || true)
if [ -n "$ERROR_PODS" ]; then
    printf "  %-45s %-20s %-50s\n" "POD (NS/NAME)" "REASON" "MESSAGE"
    for p in $ERROR_PODS; do
        NS=$(echo "$p" | cut -d'/' -f1)
        NAME=$(echo "$p" | cut -d'/' -f2)
        DIAG=$(kubectl get pod "$NAME" -n "$NS" -o jsonpath='{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{.state.waiting.message}{.state.terminated.reason}{" "}{.state.terminated.message}{"\n"}{end}' | head -n 1)
        if [ -z "$(echo "$DIAG" | tr -d ' ')" ]; then
            REASON="Scheduling"
            MESSAGE=$(kubectl get pod "$NAME" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="PodScheduled")].message}')
        else
            REASON=$(echo "$DIAG" | awk '{print $1}')
            MESSAGE=$(echo "$DIAG" | cut -d' ' -f2-)
        fi
        printf "  %-45s %-20s %.70s\n" "$p" "${REASON:-Unknown}" "${MESSAGE:-'No container message'}"
    done
fi

header "3. INGRESS & EXTERNAL EXPOSURE"
section "L4 Services & Endpoints"
printf "%-15s %-25s %-12s %-15s %-20s\n" "NAMESPACE" "SERVICE" "TYPE" "EXTERNAL-IP" "TARGET-POD-IPS"
kubectl get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.type}{"\t"}{.status.loadBalancer.ingress[*].ip}{"\t"}{.spec.clusterIP}{"\n"}{end}' | \
while read -r line; do
    [ -z "$line" ] && continue
    NS=$(echo "$line" | awk '{print $1}')
    NAME=$(echo "$line" | awk '{print $2}')
    ENDPOINTS=$(kubectl get endpoints "$NAME" -n "$NS" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || echo "None")
    echo "$line $ENDPOINTS" | awk '{printf "%-15s %-25s %-12s %-15s %-20s\n", $1, $2, $3, $4, $5}'
done

header "4. SECURITY & VULNERABILITY AUDIT"
section "Container Image Registry Audit"
printf "%-18s %-35s %-40s\n" "NAMESPACE" "POD-NAME" "IMAGE-SOURCE"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | \
awk -F'\t' '{printf "%-18s %-35s %.60s\n", $1, $2, $3}'

section "Security Risks"
echo "Privileged Pods:"
kubectl get pods -A -o jsonpath='{range .items[?(@.spec.containers[*].securityContext.privileged==true)]}  [DANGER] {.metadata.namespace}/{.metadata.name}{"\n"}{end}' || echo "  [OK] None."

header "5. STORAGE INVENTORY"
section "PVC to PV Mapping"
printf "%-15s %-30s %-10s %-15s %-20s\n" "NAMESPACE" "PVC-NAME" "STATUS" "VOLUME" "STORAGE-CLASS"
kubectl get pvc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.spec.volumeName}{"\t"}{.spec.storageClassName}{"\n"}{end}' | \
awk -F'\t' '{printf "%-15s %-30s %-10s %-15s %-20s\n", $1, $2, $3, $4, $5}'

header "6. SYSTEM WARNINGS (Last 15m)"
kubectl get events -A --field-selector type=Warning --no-headers 2>/dev/null | \
awk '{printf "  - [%s] %s | %s\n", $1, $4, $0}' | tail -n 15 || echo "  No recent system warnings."

header "AUDIT SUMMARY"
printf "  Nodes: %s | Pods: %s | Services: %s | Volumes: %s\n" \
    "$(kubectl get nodes --no-headers | wc -l)" \
    "$(kubectl get pods -A --no-headers | wc -l)" \
    "$(kubectl get svc -A --no-headers | wc -l)" \
    "$(kubectl get pv --no-headers 2>/dev/null | wc -l || echo 0)"
