#!/bin/bash

# --- Configuration ---
USER=${1:-"root"}
PASS=${2:-""}

if [ -z "$PASS" ]; then
    read -sp "[?] Enter password for '$USER': " PASS
    echo ""
fi

# Base MySQL command
MYSQL_CMD="mysql -u$USER -p$PASS -h 127.0.0.1 --skip-column-names -B -e"

# Test Connection
if ! $MYSQL_CMD "status" >/dev/null 2>&1; then
    echo "[!] Error: Connection failed. Check credentials."
    exit 1
fi

echo "====================================================="
echo "   MYSQL/MARIADB FULL SECURITY & INVENTORY AUDIT     "
echo "   Generated on: $(date)"
echo "====================================================="

# 1. ANONYMOUS ACCESS CHECK
echo -e "\n[1] ANONYMOUS LOGIN TEST"
echo "-----------------------------------------------------"
if mysql -u "" -h 127.0.0.1 -e "status" >/dev/null 2>&1; then
    echo "  [!!!] DANGER: Anonymous login is ENABLED at the server level."
else
    echo "  [OK] Anonymous login (no username) is disabled."
fi

# 2. USER AUTHENTICATION & ROLES
echo -e "\n[2] USER ACCOUNTS & AUTHENTICATION PLUGINS"
echo "-----------------------------------------------------"
printf "  %-20s | %-15s | %-15s\n" "User@Host" "Plugin" "Password Set"
$MYSQL_CMD "SELECT User, Host, plugin, IF(authentication_string='' OR Password='', 'NO', 'YES') FROM mysql.user;" | \
while read U H P S; do
    printf "  %-20s | %-15s | %-15s\n" "$U@$H" "$P" "$S"
done

echo -e "\n[3] ROLE MAPPINGS (RBAC)"
echo "-----------------------------------------------------"
ROLES=$($MYSQL_CMD "SELECT User, Host, Role FROM mysql.roles_mapping;" 2>/dev/null)
if [ -z "$ROLES" ]; then
    echo "  No specific roles mapped."
else
    echo "$ROLES" | awk '{print "  - User "$1"@"$2" has role: "$3}'
fi

# 3. PERMISSIONS DEEP DIVE (The "Who can do what" section)
echo -e "\n[4] DETAILED USER PRIVILEGES (GRANTS)"
echo "-----------------------------------------------------"
USERS_LIST=$($MYSQL_CMD "SELECT User, Host FROM mysql.user;")
while read -r U H; do
    echo "  GRANT for '$U'@'$H':"
    $MYSQL_CMD "SHOW GRANTS FOR '$U'@'$H';" | sed 's/^/    |-- /'
    echo ""
done <<< "$USERS_LIST"

# 4. DATABASE & TABLE INVENTORY
echo -e "\n[5] DATABASE & TABLE INVENTORY"
echo "-----------------------------------------------------"
DBS=$($MYSQL_CMD "SHOW DATABASES;" | grep -Ev "(information_schema|performance_schema|sys|mysql)")

for DB in $DBS; do
    # Get database size
    DB_SIZE=$($MYSQL_CMD "SELECT SUM(data_length + index_length) / 1024 / 1024 FROM information_schema.TABLES WHERE table_schema='$DB';")
    echo "DATABASE: $DB (Size: ${DB_SIZE:-0} MB)"
    
    # Tables in this DB
    $MYSQL_CMD "SELECT table_name, engine, table_rows, create_time 
                FROM information_schema.tables 
                WHERE table_schema='$DB';" | \
    while read TNAME TENG TROWS TDATE; do
        printf "  |-- %-25s | %-10s | Rows: %-8s | Created: %s\n" "$TNAME" "$TENG" "$TROWS" "$TDATE"
    done
    echo ""
done

# 5. GLOBAL VARIABLES SECURITY CHECK
echo -e "\n[6] CRITICAL SECURITY VARIABLES"
echo "-----------------------------------------------------"
printf "  %-25s | %-10s\n" "Variable Name" "Value"
$MYSQL_CMD "SHOW VARIABLES WHERE Variable_name IN ('local_infile', 'skip_networking', 'have_ssl', 'version');" | \
while read V VAL; do
    printf "  %-25s | %-10s\n" "$V" "$VAL"
done

echo -e "\n--- Audit Finished ---"
