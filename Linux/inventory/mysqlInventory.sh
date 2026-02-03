#!/bin/sh
set -eu

# --- Configuration ---
# Usage: ./script.sh <user> <host> <port>
USER=${1:-"root"}
HOST=${2:-"127.0.0.1"}
PORT=${3:-"3306"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="mysql_audit_${HOST}.log"

log_echo() {
    echo "$1" | tee -a "$LOGFILE"
}

# Always prompt for password once at the start
printf "[?] Enter password for '%s' on %s: " "$USER" "$HOST"
stty -echo
read -r PASS
stty echo
echo ""

# Base command - Notice the -p (no space) followed by the variable
# Using -N to remove headers and -s for silent/clean output
MYSQL_CMD="mysql -u$USER -p$PASS -h$HOST -P$PORT -s -N --connect-timeout=5"

header() {
    log_echo "-----------------------------------------------------"
    log_echo " $1"
    log_echo "-----------------------------------------------------"
}

header "MYSQL AUDIT: $HOST (User: $USER)"

# 1. ANONYMOUS CHECK
section() { echo "\n>>> $1"; }

section "ANONYMOUS LOGIN TEST"
if mysql -u "" -h "$HOST" -P "$PORT" --connect-timeout=3 -e "status" >/dev/null 2>&1; then
    log_echo " [!!!] DANGER: Anonymous login ENABLED."
else
    log_echo " [OK] Anonymous login disabled."
fi

# 2. VALIDATE CREDENTIALS
if ! $MYSQL_CMD -e "status" >/dev/null 2>&1; then
    log_echo " [!] Error: Authentication failed for '$USER'. exiting."
    exit 1
fi

# 3. USER AUDIT
section "USER ACCOUNTS"
printf "%-25s | %-15s | %-10s\n" "User@Host" "Plugin" "Has Pass"
# Redirecting to a temporary file prevents the 'while' loop from hanging
$MYSQL_CMD -e "SELECT User, Host, plugin, IF(authentication_string='' OR Password='', 'NO', 'YES') FROM mysql.user;" > .users.tmp
while read -r U H P S; do
    printf "%-25s | %-15s | %-10s\n" "$U@$H" "$P" "$S" | tee -a "$LOGFILE"
done < .users.tmp

# 4. DATABASE INVENTORY
section "DATABASE INVENTORY"
DBS=$($MYSQL_CMD -e "SHOW DATABASES;" | grep -Ev "(information_schema|performance_schema|sys|mysql)")

for DB in $DBS; do
    SIZE=$($MYSQL_CMD -e "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) FROM information_schema.TABLES WHERE table_schema='$DB';")
    log_echo "DB: $DB (${SIZE:-0} MB)"
    
    $MYSQL_CMD -e "SELECT table_name, engine, table_rows FROM information_schema.tables WHERE table_schema='$DB' LIMIT 5;" > .tabs.tmp
    while read -r TNAME TENG TROWS; do
        printf "  |-- %-20s | %-10s | %s rows\n" "$TNAME" "$TENG" "$TROWS" | tee -a "$LOGFILE"
    done < .tabs.tmp
done

# Cleanup
rm -f .users.tmp .tabs.tmp

log_echo "\n--- Audit Complete ---"
