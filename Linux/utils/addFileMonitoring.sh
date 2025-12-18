#!/bin/bash

TARGET_PATH=$1

if [ -z "$TARGET_PATH" ]; then
  echo "Error: You must provide a file or directory path."
  echo "Usage: $0 /path/to/file_or_directory"
  exit 1
fi

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
