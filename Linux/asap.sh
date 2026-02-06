sh "$(dirname "$0")/utils/changePassword.sh" "root"
sudo passwd -l root > /dev/null

USER=graypcf
PASS="$PASS" sh "$(dirname "$0")/utils/createSudoUser.sh" "$USER" 2>&1

sh "$(dirname "$0")/hardenScripts/ssh.sh"
sh "$(dirname "$0")/hardenScripts/key_perms.sh"
sh "$(dirname "$0")/utils/LSMS_Setup.sh"
sh "$(dirname "$0")/utils/LSMS_monitor.sh"
sh "$(dirname "$0")/inventory/inventory.sh"

echo "Paste inventory to Discord"
