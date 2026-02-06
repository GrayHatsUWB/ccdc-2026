#!/usr/bin/env bash

HOSTNAME=$(hostname || cat /etc/hostname)
echo -e "HOST: $HOSTNAME"
echo "------------------"

while IFS=: read -r username _ uid _ _ _ shell; do
  sh "$(dirname "$0")/changePassword.sh" "$username"
done < /etc/passwd
