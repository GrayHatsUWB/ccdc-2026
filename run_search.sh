#!/bin/bash
COUNTER_FILE="/tmp/.search_counter"
if [ ! -f "$COUNTER_FILE" ]; then
    echo 0 > "$COUNTER_FILE"
fi
COUNT=$(cat "$COUNTER_FILE")
COUNT=$((COUNT + 1))
echo $COUNT > "$COUNTER_FILE"
python3 /home/debian/LSMS/start_search.py --monitoring > "/tmp/.search_${COUNT}.log" 2>&1
