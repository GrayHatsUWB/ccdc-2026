#!/bin/bash

echo "#############################################"
echo "# LINUX ENUM BASELINE"
echo "# Host: $(hostname)"
echo "# Date: $(date -u)"
echo "#############################################"

echo -e "\n===== /etc PASSWD ====="
cat /etc/passwd

echo -e "\n===== /etc SHADOW ====="
cat /etc/shadow

echo -e "\n===== GROUPS ====="
cat /etc/group

echo -e "\n===== SUDOERS ====="
cat /etc/sudoers 2>/dev/null
ls -l /etc/sudoers.d 2>/dev/null
for f in /etc/sudoers.d/*; do
    echo "--- $f ---"
    cat "$f" 2>/dev/null
done

echo -e "\n===== SSH CONFIG ====="
cat /etc/ssh/sshd_config 2>/dev/null

echo -e "\n===== AUTHORIZED KEYS ====="
find /home /root -name authorized_keys -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null

echo -e "\n===== CRONTAB SYSTEM ====="
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.* 2>/dev/null

echo -e "\n===== CRONTAB USERS ====="
for u in $(cut -f1 -d: /etc/passwd); do
    echo "--- USER: $u ---"
    crontab -u $u -l 2>/dev/null
done

echo -e "\n===== AT JOBS ====="
atq 2>/dev/null

echo -e "\n===== SYSTEMD SERVICES (if present) ====="
which systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service

echo -e "\n===== INIT.D ====="
ls -la /etc/init.d 2>/dev/null

echo -e "\n===== RC LOCAL ====="
cat /etc/rc.local 2>/dev/null

echo -e "\n===== LD_PRELOAD ====="
cat /etc/ld.so.preload 2>/dev/null

echo -e "\n===== PAM ====="
ls -la /etc/pam.d 2>/dev/null
for f in /etc/pam.d/*; do
    echo "--- $f ---"
    cat "$f" 2>/dev/null
done

echo -e "\n===== LISTENING PORTS ====="
ss -tulpn

echo -e "\n===== LOADED KERNEL MODULES ====="
lsmod

echo -e "\n===== SUID BINARIES ====="
find / -xdev -perm -4000 -type f 2>/dev/null | sort

echo -e "\n===== WORLD WRITABLE FILES ====="
find / -xdev -type f -perm -0002 2>/dev/null | sort

echo -e "\n===== RECENT FILES (24h) ====="
find / -xdev -type f -mtime -1 2>/dev/null | sort

echo -e "\n===== /TMP CONTENTS ====="
ls -a /tmp

echo -e "\n===== /DEV/SHM CONTENTS ====="
ls -la /dev/shm

echo -e "\n===== /USR/LOCAL/BIN ====="
ls -la /usr/local/bin

echo -e "\n===== WEB ROOT (if exists) ====="
ls -laR /var/www 2>/dev/null

echo -e "\n===== PROCESS LIST ====="
ps auxf

echo -e "\n===== DONE ====="
