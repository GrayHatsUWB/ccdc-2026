#!/bin/bash

USER="$1"

if [[ -z "$USER" ]]; then
  echo "Usage: $0 <username>"
  exit 1
fi

if id "$USER" >/dev/null 2>&1; then
  echo "User '$USER' already exists."
  exit 1
fi

PASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "20")

# Create the user with a home directory
sudo useradd -m -s /bin/bash "$USER"

# Set the user's password
echo "$USER:$PASS" | sudo chpasswd

# Detect sudo group
if getent group sudo > /dev/null; then
  sudo usermod -aG sudo "$USER"
elif getent group wheel > /dev/null; then
  sudo usermod -aG wheel "$USER"
else
  echo "No sudo/wheel group found. Please configure /etc/sudoers manually."
  exit 0
fi

echo "$USER,$PASS"
