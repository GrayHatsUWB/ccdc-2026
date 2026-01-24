#!/bin/bash

TARGET_PATH=$1

if [ -z "$TARGET_PATH" ]; then
  echo "Error: You must provide a file or directory path."
  echo "Usage: $0 /path/to/file_or_directory"
  exit 1
fi


if command -v realpath >/dev/null 2>&1; then
  ABS_PATH=$(realpath -m -- "$TARGET_PATH")
elif command -v readlink >/dev/null 2>&1 && readlink -f "$TARGET_PATH" >/dev/null 2>&1; then
  ABS_PATH=$(readlink -f -- "$TARGET_PATH")
else
  # Pure bash fallback
  if [ -d "$TARGET_PATH" ]; then
    ABS_PATH=$(cd -P -- "$TARGET_PATH" && pwd -P)
  else
    ABS_PATH=$(cd -P -- "$(dirname -- "$TARGET_PATH")" && printf '%s/%s\n' "$(pwd -P)" "$(basename -- "$TARGET_PATH")")
  fi
fi

TARGET_PATH="$ABS_PATH"
CONFIG_FILE="/var/ossec/etc/ossec.conf"

awk -v path="$TARGET_PATH" '
  BEGIN {
    block = "<syscheck>\n  <directories realtime=\"yes\">" path "</directories>\n</syscheck>"
    done = 0
  }
  {
    if (!done && /<\/ossec_config>/) {
      print block
      done = 1
    }
    print
  }
' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
