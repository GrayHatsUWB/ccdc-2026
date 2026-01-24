#!/bin/bash
# List all users with root or sudo privileges across distros

echo "=== Root-level accounts (UID 0) ==="
awk -F: '($3 == 0) {print $1}' /etc/passwd

echo
echo "=== Groups with sudo privileges (from /etc/sudoers) ==="
groups=$(grep -E '^[[:space:]]*%[a-zA-Z0-9_-]+' /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
         | awk '{print $1}' | tr -d '%')

# Always include sudo and wheel groups if they exist
for g in sudo wheel; do
  if getent group "$g" > /dev/null; then
    groups="$groups $g"
  fi
done

groups=$(echo "$groups" | tr ' ' '\n' | sort -u)

if [ -z "$groups" ]; then
  echo "No sudo groups found."
else
  for grp in $groups; do
    echo "Group: $grp"
    members=$(getent group "$grp" | awk -F: '{print $4}')
    if [ -n "$members" ]; then
      echo "  Members: $members"
    else
      echo "  (no members)"
    fi
  done
fi

echo
echo "=== Users explicitly listed in sudoers ==="
grep -E '^[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]+ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
  | awk '{print $1}' | sort -u

echo
echo "=== Consolidated list of sudo-capable users ==="
{
  awk -F: '($3 == 0) {print $1}' /etc/passwd
  for grp in $groups; do
    getent group "$grp" | awk -F: '{print $4}' | tr ',' '\n'
  done
  grep -E '^[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]+ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
    | awk '{print $1}'
} | sort -u
