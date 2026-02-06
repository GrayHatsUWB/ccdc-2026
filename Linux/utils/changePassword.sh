#!/usr/bin/env bash

USER="$1"

if [[ -z "$USER" ]]; then
  echo "Usage: $0 <username>"
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "This script must be run with sudo."
  exit 1
fi

if ! id "$USER" >/dev/null 2>&1; then
  echo "User '$USER' does not exist."
  exit 0
fi

if ! getent passwd "$USER" >/dev/null 2>&1; then
  echo "User '$USER' not found in passwd database."
  exit 0
fi

SHELL_FIELD=$(getent passwd "$USER" | awk -F: '{print $7}')
if [[ "${SHELL_FIELD#*"sh"}" == "$SHELL_FIELD" ]]; then
  exit 0
fi

NEWPASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "20")
echo "$USER,$NEWPASS"

if command -v chpasswd >/dev/null 2>&1; then
    echo "$USER:$NEWPASS" | chpasswd
else
  printf "%s\n%s\n" "$NEWPASS" "$NEWPASS" | passwd "$USER"
fi
