#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root."
  exit 1
fi

echo "Enter user credentials. Type 'done' as username to finish."

while true; do
  read -p "Username: " username

  if [[ "$username" == "done" ]]; then
    break
  fi

  # hide password input
  read -s -p "Password: " password
  echo

  if id "$username" &>/dev/null; then
    echo "$username:$password" | chpasswd
    echo "Password updated for $username"
  else
    echo "Skipping $username (user does not exist)"
  fi

  echo
done

echo "Done."
