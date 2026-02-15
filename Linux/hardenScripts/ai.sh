#!/bin/sh

# Harden host by disabling unprivileged user namespaces.
# - Skips running inside containers to avoid changing container environments.
# - Requires root to modify sysctl values; changes are immediate but not persistent
#   across reboots (persist via /etc/sysctl.conf or a file in /etc/sysctl.d/).

# If common container tooling or Minikube is present, assume we're in or managing
# containers and skip making kernel/sysctl changes.
if command -v docker >/dev/null || command -v kubectl >/dev/null || command -v podman >/dev/null || command -v minikube >/dev/null; then
    echo "Container detected, skipping"
    exit 1
fi

# Disable unprivileged user namespace clone support if the kernel exposes this
# sysctl. This reduces attack surface but can break unprivileged user namespaces.
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    sysctl -w kernel.unprivileged_userns_clone=0
fi

# Limit the maximum number of user namespaces for non-root users if available.
if [ -f /proc/sys/user/max_user_namespaces ]; then
    sysctl -w user.max_user_namespaces=0
fi