#!/bin/bash

#ALLOWED_RANGE="192.168.1.0/24"
#TIME=30
WAITTIME="10"

# Logs the JSON input received from Wazuh Active Response

LOG_FILE="/var/log/Block_SSH"
BLOCKED_LOG_FILE="/var/log/Block_SSH-blocked"
echo "Invoked at $(date)" >> "$LOG_FILE"

# Read all input from STDIN
PAYLOAD=$(timeout 1 cat)

echo "payload:$PAYLOAD" >> "$LOG_FILE"
# Append to log file with timestamp
#echo "$(date '+%Y/%m/%d %H:%M:%S') simple-ar: $input" >> "$LOG_FILE"

SRCIP=$(echo "$PAYLOAD" | jq -r '.parameters.alert.data.srcip')

echo "Source IP: $SRCIP" >> "$LOG_FILE"

sleep "$WAITTIME"

#Hard coded test
#SRCIP="192.168.1.45"

while IFS= read -r pts; do
    line=$(ps aux | grep ssh | grep -w "$pts")
    line=$(echo "$line" | awk '{print $2}')
    echo "PID $line"
    kill "$line"
    #add blocked action to log
    echo "$(date '+%Y/%m/%d %H:%M:%S') | $SRCIP" >> "$BLOCKED_LOG_FILE"
done < <(who | grep -w "$SRCIP" | awk '{print $3}' | grep '^pts/')



echo '{"version":1,"origin":{"name":"block-ssh","module":"active-response"},"command":"delete"}'
exit 0
