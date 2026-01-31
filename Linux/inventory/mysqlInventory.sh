#!/bin/bash

# --- Configuration & Arguments ---
# Usage: ./script.sh <user> <password> <host> <port>
USER=${1:-"root"}
PASS=${2:-""}
HOST=${3:-"127.0.0.1"}
PORT=${4:-"3306"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="mysql_audit_${HOST}_${TIMESTAMP}.log"

# Function to log and print simultaneously
log_echo() {
    echo -e "$1" | tee -a "$LOGFILE"
}

if [ -z "$PASS" ]; then
    read -sp "[?] Enter password for '$USER' on $HOST: " PASS
    echo ""
fi

# Base command with connection timeout
MYSQL_CMD="mysql -u$USER -p$PASS -h $HOST -P $PORT --connect-timeout=5 --skip-column-names -B -e"

log_echo "====================================================="
log_echo "   MYSQL/MARIADB SECURITY AUDIT: $HOST"
log_echo "   Report: $LOGFILE"
log_echo "====================================================="

# 0. NETWORK CONNECTIVITY CHECK (Bash Native)
log_echo "[0] TESTING NETWORK PATH"
log_echo "-----------------------------------------------------"
# This uses Bash's built-in /dev/tcp pseudo-device
if timeout 3 bash -c "echo > /dev/tcp/$HOST/$PORT" 2>/dev/null; then
    log_echo "  [OK] TCP Port $PORT on $HOST is OPEN."
else
    log_echo "  [!] ERROR: Cannot reach $HOST on port $PORT. Check firewalls."
    exit 1
fi

# 1. ANONYMOUS ACCESS CHECK
log_echo -e "\n[1] ANONYMOUS LOGIN TEST"
log_echo "-----------------------------------------------------"
if mysql -u "" -h "$HOST" -P "$PORT" --connect-timeout=3 -e "status" >/dev/null 2>&1; then
    log_echo "  [!!!] DANGER: Server at $HOST allows ANONYMOUS login."
else
    log_echo "  [OK] Anonymous login disabled."
fi

# 2. SQL AUTHENTICATION CHECK
if ! $MYSQL_CMD "status" >/dev/null 2>&1; then
    log_echo -e "\n[!] Error: SQL Authentication failed for '$USER'@'$HOST'."
    exit 1
fi

# 3. USER & ROLE AUDIT
log_echo -e "\n[2] USER ACCOUNTS & AUTHENTICATION PLUGINS"
log_echo "-----------------------------------------------------"
printf "  %-25s | %-15s | %-15s\n" "User@Host" "Plugin" "Password Set" | tee -a "$LOGFILE"
$MYSQL_CMD "SELECT User, Host, plugin, IF(authentication_string='' OR Password='', 'NO', 'YES') FROM mysql.user;" | \
while read -r U H P S; do
    printf "  %-25s | %-15s | %-15s\n" "$U@$H" "$P" "$S" | tee -a "$LOGFILE"
done

log_echo -e "\n[3] ROLE MAPPINGS"
log_echo "-----------------------------------------------------"
ROLES=$($MYSQL_CMD "SELECT User, Host, Role FROM mysql.roles_mapping;" 2>/dev/null || echo "")
if [ -z "$ROLES" ]; then
    log_echo "  No specific roles mapped."
else
    log_echo "$ROLES" | awk '{print "  - User "$1"@"$2" has role: "$3}'
fi

# 4. PERMISSIONS DEEP DIVE
log_echo -e "\n[4] DETAILED USER PRIVILEGES (GRANTS)"
log_echo "-----------------------------------------------------"
USERS_LIST=$($MYSQL_CMD "SELECT User, Host FROM mysql.user;")
while read -r U H; do
    log_echo "  GRANT for '$U'@'$H':"
    $MYSQL_CMD "SHOW GRANTS FOR '$U'@'$H';" 2>/dev/null | sed 's/^/    |-- /' | tee -a "$LOGFILE" || log_echo "    |-- [!] Could not retrieve."
    echo "" | tee -a "$LOGFILE"
done <<< "$USERS_LIST"

# 5. INVENTORY
log_echo -e "\n[5] DATABASE & TABLE INVENTORY"
log_echo "-----------------------------------------------------"
DBS=$($MYSQL_CMD "SHOW DATABASES;" | grep -Ev "(information_schema|performance_schema|sys|mysql)")

for DB in $DBS; do
    DB_SIZE=$($MYSQL_CMD "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) FROM information_schema.TABLES WHERE table_schema='$DB';")
    log_echo "DATABASE: $DB (Size: ${DB_SIZE:-0} MB)"
    
    $MYSQL_CMD "SELECT table_name, engine, table_rows, create_time 
                FROM information_schema.tables 
                WHERE table_schema='$DB';" | \
    while read -r TNAME TENG TROWS TDATE; do
        printf "  |-- %-25s | %-10s | Rows: %-8s | Created: %s\n" "$TNAME" "$TENG" "$TROWS" "$TDATE" | tee -a "$LOGFILE"
    done
    echo "" | tee -a "$LOGFILE"
done

# 6. SECURITY VARS
log_echo -e "\n[6] CRITICAL SECURITY VARIABLES"
log_echo "-----------------------------------------------------"
printf "  %-25s | %-10s\n" "Variable Name" "Value" | tee -a "$LOGFILE"
$MYSQL_CMD "SHOW VARIABLES WHERE Variable_name IN ('local_infile', 'skip_networking', 'have_ssl', 'version');" | \
while read -r V VAL; do
    printf "  %-25s | %-10s\n" "$V" "$VAL" | tee -a "$LOGFILE"
done

log_echo -e "\n--- Audit Finished for $HOST ---"
