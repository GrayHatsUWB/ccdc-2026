**Linux Directory — README**

Description:
- This directory contains Linux-oriented scripts and supporting files used for enumeration, hardening, SELinux policy artifacts, Kubernetes helpers, Wazuh integration, and assorted utilities used in the CCDC lab.

How to use these scripts:
- Most files are POSIX shell scripts. Make them executable and run with a shell. Use `sudo` when commands require root privileges.

Quick run examples:
```bash
# make executable (if needed)
chmod +x Linux/asap.sh
./Linux/asap.sh

# or run via bash explicitly
bash Linux/inventory/bad.sh
```

Inventory scripts (enumeration & auditing):
- Files: [Linux/inventory](Linux/inventory) — examples include [Linux/inventory/inventory.sh](Linux/inventory/inventory.sh), [Linux/inventory/bad.sh](Linux/inventory/bad.sh), [Linux/inventory/kubectlInventory.sh](Linux/inventory/kubectlInventory.sh), [Linux/inventory/mysqlInventory.sh](Linux/inventory/mysqlInventory.sh), [Linux/inventory/psqlInventory.sh](Linux/inventory/psqlInventory.sh), and others.
- Purpose: gather system info, service lists, SUID/permissions, package lists, and quick compromise indicators.
- Run: `bash Linux/inventory/<script>.sh` or make executable and run `./Linux/inventory/<script>.sh`.

Harden scripts:
- Files: [Linux/hardenScripts](Linux/hardenScripts) — includes `ai.sh`, `firstrun.sh`, `key_perms.sh`, `php.sh`, `ssh.sh`.
- Purpose: apply configuration hardening steps (file perms, SSH config, PHP hardening, first-run tasks).
- Run: inspect before running; these change system configuration. Example:
```bash
bash Linux/hardenScripts/firstrun.sh
```

Kubernetes helper(s):
- File: [Linux/kubernetes/rotate_creds.sh](Linux/kubernetes/rotate_creds.sh) — rotates or refreshes cluster credentials; run with appropriate kubeconfig context.

SELinux artifacts:
- Folder: [Linux/SELINUX](Linux/SELINUX) — contains `.te` policy source files and `file_contexts`.
- Purpose: SELinux policy source and filecontext additions; to build/install a policy use standard tools. Example flow:
```bash
checkmodule -M -m -o mypol.mod mypol.te
semodule_package -o mypol.pp -m mypol.mod
sudo semodule -i mypol.pp
```

Services, utils, and Wazuh:
- [Linux/services](Linux/services) and [Linux/utils](Linux/utils) contain helper scripts and small utilities used by orchestration/playbooks.
- [Linux/Wazuh](Linux/Wazuh) contains Wazuh agent/manager helpers and configs used by playbooks in this repo.

Safety & notes:
- Always read a script before executing, especially anything in `hardenScripts` or `inventory` that enumerates credentials or modifies the system.
- Prefer running these scripts inside a disposable VM or test environment.
- Many scripts assume common Linux utilities are installed (`bash`, `awk`, `sed`, `grep`, `curl`, `kubectl`, `checkmodule`, `semodule_package`, etc.).

If you want, I can:
- Add brief per-file usage examples for every script in `Linux/inventory` and `Linux/hardenScripts`.
- Run a quick scan to auto-generate usage examples from shebangs and top comments.

Detailed script index (by path):

- `Linux/asap.sh`: orchestration entrypoint that runs initial hardening and inventory tasks.
	- Purpose: bootstrap task that calls `hardenScripts` and inventory checks.
	- Privileges: must be run as root/sudo.
	- Example: `sudo bash Linux/asap.sh`

- `Linux/hardenScripts/firstrun.sh`:
	- Purpose: initial package installs and baseline hardening for many distros (Debian/RHEL/Alpine).
	- Privileges: root required.
	- Example: `sudo bash Linux/hardenScripts/firstrun.sh`
	- Notes: Installs packages, backups PAM, modifies php.ini values and restarts web services.

- `Linux/hardenScripts/ssh.sh`:
	- Purpose: apply recommended SSH config changes (create /etc/ssh/sshd_config.d entries, disable pubkey auth, lock root login).
	- Privileges: root required.
	- Example: `sudo bash Linux/hardenScripts/ssh.sh`
	- Notes: Restarts sshd; inspect `/etc/ssh/sshd_config.d/dominion_ssh.conf` after run.

- `Linux/hardenScripts/key_perms.sh`:
	- Purpose: tighten permissions on `id_*` SSH private keys for root and local human users.
	- Privileges: root required.
	- Example: `sudo bash Linux/hardenScripts/key_perms.sh`

- `Linux/hardenScripts/php.sh`:
	- Purpose: append conservative PHP config settings to discovered `php.ini` files and restart web/PHP services.
	- Privileges: root required.
	- Example: `sudo bash Linux/hardenScripts/php.sh`
	- Notes: Adds multiple directives (e.g., `display_errors = off`, `allow_url_fopen = off`) — review changes before running on production.

- `Linux/hardenScripts/ai.sh`:
	- Purpose: kernel hardening steps to disable unprivileged user namespaces if not in a container.
	- Privileges: root required to call `sysctl`.
	- Example: `sudo bash Linux/hardenScripts/ai.sh`

- `Linux/utils/checkForDep.sh`:
	- Purpose: check if a named binary is installed and attempt to install it via the host package manager.
	- Privileges: may require sudo to install.
	- Example: `bash Linux/utils/checkForDep.sh jq`

- `Linux/utils/LSMS_Setup.sh` and `Linux/utils/LSMS_monitor.sh`:
	- Purpose: helpers to install and run the LSMS search/monitoring tool (external repo referenced).
	- Privileges: depends on what LSMS needs (likely root for setup).
	- Example: `bash Linux/utils/LSMS_Setup.sh`

- `Linux/utils/run_search.sh`:
	- Purpose: simple wrapper to start LSMS search invocation and rotate a local counter (creates /tmp/.search_*.log).
	- Example: `bash Linux/utils/run_search.sh`

- `Linux/utils/credsChanger.sh`:
	- Purpose: interactive password reset tool (prompts username/password pairs and runs `chpasswd`).
	- Privileges: must be root.
	- Example: `sudo bash Linux/utils/credsChanger.sh`

- `Linux/utils/changePassword.sh`:
	- Purpose: change or generate a password for a single user (prints username and generated password).
	- Privileges: root required.
	- Example: `sudo bash Linux/utils/changePassword.sh someuser`

- `Linux/utils/changeAllPasswords.sh`:
	- Purpose: iterate over `/etc/passwd` and call `changePassword.sh` for each user (bulk password rotation).
	- Privileges: root required.
	- Example: `sudo bash Linux/utils/changeAllPasswords.sh`
	- Notes: destructive — only run in disposable/test environments.

- `Linux/utils/createSudoUser.sh`:
	- Purpose: create a user, set a random password, and add to the `sudo` or `wheel` group if present.
	- Privileges: must be run with sudo.
	- Example: `sudo bash Linux/utils/createSudoUser.sh newuser`

- `Linux/utils/backup.sh`:
	- Purpose: compress a file/dir (if needed) and upload to `https://0x0.st`, returning a public link.
	- Example: `bash Linux/utils/backup.sh /etc/ssh/sshd_config`
	- Notes: uploads potentially sensitive data to a public paste service — use carefully.

- `Linux/utils/addFileMonitoring.sh`:
	- Purpose: insert a `<syscheck>` entry into Wazuh `ossec.conf` to add realtime monitoring for a file/path.
	- Privileges: root required (writes to `/var/ossec/etc/ossec.conf`).
	- Example: `sudo bash Linux/utils/addFileMonitoring.sh /etc/passwd`

- `Linux/services/Nginx/init.sh`:
	- Purpose: init script for `nginx` providing start/stop/restart/reload operations (SysV-style).
	- Privileges: root required to manage service.
	- Example: `sudo /etc/init.d/nginx start`

- `Linux/services/flawless-hedgehog-apache.sh`:
	- Purpose: interactive Apache hardening helper (adds headers, disables directory listing, etc.).
	- Privileges: root required.
	- Example: `sudo bash Linux/services/flawless-hedgehog-apache.sh /etc/apache2/apache2.conf`
	- Notes: interactive; creates a backup of target config before changes.

- `Linux/Wazuh/installWazuhAgent.sh`:
	- Purpose: download and install Wazuh agent package (DEB or RPM) and update `ossec.conf` manager IP.
	- Privileges: root required.
	- Example: `sudo bash Linux/Wazuh/installWazuhAgent.sh wazuh-manager.example.local`

- `Linux/Wazuh/initCustomWazuhAgentConfigs.sh` and `Linux/Wazuh/initCustomWazuhManagerConfigs.sh`:
	- Purpose: insert local active-response rules and commands into `/var/ossec/etc/ossec.conf` and enable logging/JSON options.
	- Privileges: root (writes to Wazuh config files).
	- Example: `sudo bash Linux/Wazuh/initCustomWazuhAgentConfigs.sh`

- `Linux/Wazuh/Active Response/block-ssh.sh`:
	- Purpose: an active-response script triggered by Wazuh alerts; logs payload, attempts to kill ssh sessions from the source IP and returns a delete command for the active-response protocol.
	- Privileges: executed by Wazuh active-response (local) — will need appropriate permissions to kill processes.

- `Linux/kubernetes/rotate_creds.sh`:
	- Purpose: rotate a Kubernetes secret key value and rollout restart affected deployments with zero-downtime.
	- Privileges: requires `kubectl` permissions for the target namespace.
	- Usage: `bash Linux/kubernetes/rotate_creds.sh myns mysecret mykey newvalue`

- Inventory and enumeration scripts (paths under `Linux/inventory`):
	- `kubectlInventory.sh`: Kubernetes cluster & pod inventory, checks node health, services, pod errors; requires `kubectl` configured access. Run: `bash Linux/inventory/kubectlInventory.sh`.
	- `mysqlInventory.sh`: MySQL/MariaDB audit script (connects to DB, enumerates users, grants, DB sizes). Usage: `bash Linux/inventory/mysqlInventory.sh <user> <pass> <host> <port>`.
	- `psqlInventory.sh`: PostgreSQL audit script; prompts for password if none set, enumerates roles and DB permissions. Usage: `bash Linux/inventory/psqlInventory.sh postgres 127.0.0.1 5432`.
	- `inventory.sh`: host inventory (network, services, containers, mounts, users) — run as root for full output. `sudo bash Linux/inventory/inventory.sh`.
	- `bad.sh`: collection of potentially risky/interesting items — run as `bash Linux/inventory/bad.sh`.
	- `docker1.sh`: searches host and container filesystem for Docker-related config files; requires `docker` CLI to inspect containers. `bash Linux/inventory/docker1.sh`.
	- `baseq.sh`: small script to print hostname and OS summary. `bash Linux/inventory/baseq.sh`.
	- `getsuidexe.sh`: find SUID/SGID binaries (uses `find -perm /7000`). `sudo bash Linux/inventory/getsuidexe.sh`.
	- `findSudoUsers.sh`: list users with sudo/wheel privileges and parse sudoers. `bash Linux/inventory/findSudoUsers.sh`.
	- `filelist.sh`: find tarballs, world-writable files, SUID/GID files, and ACLs across the system. `sudo bash Linux/inventory/filelist.sh`.
	- `packageinstall.sh`: extract package install history (APT-focused). `bash Linux/inventory/packageinstall.sh`.
	- `svc_enum.sh`: service-specific enumeration helper (SSH/FTP/NGINX/APACHE/SMB) — pass service name: `bash Linux/inventory/svc_enum.sh NGINX`.
	- `web.sh`: web-related inventory (notable files or checks); `bash Linux/inventory/web.sh`.

Safety reminders and recommended order:
- Read scripts before running them. Many inventory scripts are read-only, but hardening scripts and Wazuh installers modify system configuration.
- For non-destructive auditing, run inventory scripts first (no root where possible), then run monitoring/agent installs in controlled environments.

Want me to commit these per-file entries into `Linux/README.md` as structured anchor links (so you can jump to each script) or generate individual README files per subdirectory (`inventory/README.md`, `hardenScripts/README.md`)?
