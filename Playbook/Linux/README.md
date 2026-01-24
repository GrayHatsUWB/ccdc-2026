## Phase 1: Enumeration
Run `Linux/asap.sh` and immediately send the output in Discord.

## Phase 2: Service Hardening Discovery
Track down and harden each service.
- Inventory running services and listening ports.
- Locate service configs and note auth methods/credentials.
- Check vendor docs or team notes for required settings.
- Record hardening steps needed per service (web, DB, SSH, mail, etc.).

## Phase 3: Backup
Find service config files and back them up using `Linux/utils/backup.sh`.
- Target service configs (usually under `/etc`, `/opt`, or app-specific dirs).
- Run `Linux/utils/backup.sh <file_or_folder>` for each config or directory.
