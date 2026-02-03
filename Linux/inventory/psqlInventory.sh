#!/bin/sh
set -u

# --- 1. Inputs ---
TARGET_USER="${1:-postgres}"
TARGET_HOST="${2:-127.0.0.1}"
TARGET_PORT="${3:-5432}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="pg_audit_${TARGET_HOST}.log"

log_echo() {
    echo "$1" | tee -a "$LOGFILE"
}

# --- 2. Secure Password ---
if [ -z "${PGPASSWORD:-}" ]; then
    printf "[?] Enter password for '%s' on %s: " "$TARGET_USER" "$TARGET_HOST"
    stty -echo
    read -r PASS
    stty echo
    echo ""
    export PGPASSWORD="$PASS"
fi

# Standardized PSQL command
PSQL_BASE="psql -h $TARGET_HOST -p $TARGET_PORT -U $TARGET_USER -t -A -q"

log_echo "====================================================="
log_echo "   SECURE POSTGRESQL AUDIT: $TARGET_HOST"
log_echo "====================================================="

# Validate Connection
if ! $PSQL_BASE -d postgres -c "SELECT 1" >/dev/null 2>&1; then
    log_echo "  [!] Error: Authentication failed."
    exit 1
fi

# --- 3. User Audit ---
log_echo "\n[1] USER ACCOUNTS"
log_echo "-----------------------------------------------------"
$PSQL_BASE -d postgres -c "SELECT rolname, 
       CASE WHEN rolsuper THEN 'YES' ELSE 'NO' END, 
       CASE WHEN rolpassword IS NULL THEN 'YES' ELSE 'NO' END, 
       CASE WHEN rolcanlogin THEN 'YES' ELSE 'NO' END
       FROM pg_roles ORDER BY rolcanlogin DESC;" > .users.tmp

while IFS='|' read -r RNAME RSUP RNOP RLOG; do
    printf "%-25s | Super: %-3s | NoPass: %-3s | Login: %s\n" "$RNAME" "$RSUP" "$RNOP" "$RLOG" | tee -a "$LOGFILE"
done < .users.tmp

# --- 4. Data Access Matrix (SAFE PARAMETERIZATION) ---
log_echo "\n[2] DATA ACCESS PERMISSIONS"
log_echo "-----------------------------------------------------"
$PSQL_BASE -d postgres -c "SELECT datname FROM pg_database WHERE datistemplate = false;" > .dbs.tmp

while read -r DNAME; do
    # We export the DB name to the environment. 
    # Inside the SQL, we use 'current_database()' or 'getenv' equivalents.
    export CURRENT_AUDIT_DB="$DNAME"
    
    # We use -d "$DNAME" to connect directly to the target. 
    # This is the safest way to ensure context isolation.
    $PSQL_BASE -d "$DNAME" -c "
    SELECT current_database(), r.rolname,
       CASE WHEN has_database_privilege(r.rolname, current_database(), 'CONNECT') THEN 'YES' ELSE 'NO' END,
       CASE WHEN EXISTS (SELECT 1 FROM information_schema.table_privileges 
            WHERE grantee = r.rolname AND privilege_type = 'SELECT') 
            OR r.rolsuper THEN 'YES' ELSE 'NO' END,
       CASE WHEN EXISTS (SELECT 1 FROM information_schema.table_privileges 
            WHERE grantee = r.rolname AND privilege_type IN ('INSERT','UPDATE','DELETE')) 
            OR r.rolsuper THEN 'YES' ELSE 'NO' END
    FROM pg_roles r WHERE r.rolcanlogin = true;" > .access.tmp

    while IFS='|' read -r DB UNAME UCONN UREAD UWRITE; do
        if [ "$UCONN" = "YES" ] || [ "$UREAD" = "YES" ]; then
            printf "DB: %-15s | User: %-15s | Conn: %-3s | Read: %-3s | Write: %s\n" \
            "$DB" "$UNAME" "$UCONN" "$UREAD" "$UWRITE" | tee -a "$LOGFILE"
        fi
    done < .access.tmp
done < .dbs.tmp

# --- 5. Database Inventory ---
log_echo "\n[3] INVENTORY"
log_echo "-----------------------------------------------------"
while read -r DNAME; do
    DSIZE=$($PSQL_BASE -d postgres -c "SELECT pg_size_pretty(pg_database_size('$DNAME'));")
    log_echo "DATABASE: $DNAME (Size: $DSIZE)"
    
    $PSQL_BASE -d "$DNAME" -c "
     SELECT c.relname, n.nspname, pg_size_pretty(pg_total_relation_size(c.oid))
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace 
     WHERE c.relkind = 'r' AND n.nspname = 'public' LIMIT 5;" > .tabs.tmp
    
    while IFS='|' read -r TNAME TNS TSIZE; do
        printf "  |-- %-30s | Size: %s\n" "$TNAME" "$TSIZE" | tee -a "$LOGFILE"
    done < .tabs.tmp
done < .dbs.tmp

# Cleanup
rm -f .users.tmp .dbs.tmp .access.tmp .tabs.tmp
unset PGPASSWORD CURRENT_AUDIT_DB

log_echo "\n--- Audit Finished ---"
