#!/bin/bash
# Usage: ./rotate.sh <namespace> <secret-name> <key> <new-value>
# used for rotating Kubernetes secrets and restarting deployments that depend on them with zero downtime.
NAMESPACE=$1
SECRET_NAME=$2
KEY=$3
NEW_VALUE=$4

if [[ -z "$NEW_VALUE" ]]; then
  echo "Usage: $0 <namespace> <secret-name> <key> <new-value>"
  exit 1
fi

echo "--- 1. Updating Secret: $SECRET_NAME in $NAMESPACE ---"
# Update the secret using a dry-run to generate YAML, then apply it
kubectl create secret generic "$SECRET_NAME" \
  --from-literal="$KEY=$NEW_VALUE" \
  --dry-run=client -o yaml | kubectl apply -n "$NAMESPACE" -f -

echo "--- 2. Identifying impacted Deployments ---"
# Find all deployments that use this secret (as env or volume)
DEPS=$(kubectl get deployments -n "$NAMESPACE" -o json | \
  jq -r '.items[] | select(.spec.template.spec.containers[].env[].valueFrom.secretKeyRef.name == "'$SECRET_NAME'" or .spec.template.spec.volumes[].secret.secretName == "'$SECRET_NAME'") | .metadata.name')

if [[ -z "$DEPS" ]]; then
  echo "No deployments found using $SECRET_NAME. Manual restart may be required."
else
  for DEP in $DEPS; do
    echo "Rolling out restart for Deployment: $DEP..."
    # Triggers a rolling update (one pod at a time) to ensure no downtime
    kubectl rollout restart deployment/"$DEP" -n "$NAMESPACE"
    kubectl rollout status deployment/"$DEP" -n "$NAMESPACE"
  done
fi

echo "Rotation Complete."
