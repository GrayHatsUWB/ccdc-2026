# Securing Windows (CCDC Protocol)

## Phase 1: Enumeration


## Phase 2: User & Account Hardening

> [!CAUTION]
> This script will NOT change the passwords of service accounts. You will NEED to change them yourself, AFTER ensuring you have found all places where the password will need to be updated. DO NOT FORGET TO CHANGE THEM.

- **Step 3: Password Resets**
  - **Domain Controller:** Run `Change-Domain-User-Passwords.ps1`.
    - Only run this if you are on the DC, it will not be useful if you are on a workstation.
  - **Member Server/Workstation:** Change local Administrator password immediately.
  - **KRBTGT:** Run [this script](https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1) to reset the `krbtgt` user password which will invalidate Golden Tickets.
    - If you suspect that your machine is being accessed via Golden Tickets, run the script again.
  - **Machine Account:** Run `Reset-ComputerMachinePassword` on your machine.
    - Since all machines are cloned from the same source, this will prevent you from being breached due to another team's carelessness.
- **Step 4: Account Cleanup**
  - Disable Guest account:
    - `net user Guest /active:no`
  - Audit user list for unauthorized accounts and delete them.
  - **Control Panel:** Enable Always Notify for account changes
    - `Control Panel\User Accounts\User Accounts` -> `User Account Control Settings` -> `Always Notify`
  - **Group Policy:** Disable "Store passwords using reversible encryption".
    - `Computer Configuration` -> `Windows Settings` -> `Security Settings` -> `Account Policies` -> `Password Policy` -> `Store password using reversible encryption` -> `Disabled`

## Phase 3: Attack Surface Reduction

- **Step 5: Patch Known Exploits**
  - **Zerologon:** Run `Auto-Patch-Zerologon-V2.ps1`.
  - **SMBv1:** Disable immediately (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`).
  - **Mimikatz Protections:**
    - Disable WDigest credentials in Registry (`UseLogonCredential` = 0).
    - Add `LSA Protection` registry key.
  - **RDP Hardening:**
    - Disable "Shutdown without logon".
    - Disable Remote Assistance.
    - Ensure NLA (Network Level Authentication) is enabled.
  - **Accessibility Features:** Check `sethc.exe`, `utilman.exe` in `System32` for modifications (Sticky Keys backdoor).

## Phase 4: Defensive Tooling

**Goal:** Enable visibility and active protection.

- [ ] **Step 6: Enable Windows Defender / Antivirus**
  - Ensure Real-time protection is ON via Group Policy.
  - _Optional:_ Install Malwarebytes (Only if compatible with scoring engine/services).
- [ ] **Step 7: Windows Updates**
  - Start downloads immediately (resource permitting). Prioritize Security Updates.

## Phase 5: Persistence Hunting

**Goal:** Find and remove backdoors.

- [ ] **Step 8: Install SysInternals & Aurora**
  - **Sysmon:** Install with a solid config (e.g., SwiftOnSecurity).
  - **Autoruns:** Check for malicious startup items.
  - **ProcMon:** Monitor for strange process behavior.
- [ ] **Step 9: Persistence Checks**
  - **Task Scheduler:** Look for repeating tasks or tasks running as SYSTEM.
  - **Startup Folders:** Check `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`.
  - **Registry Run Keys:** Check `HKLM\...\Run` and `HKLM\...\RunOnce`.
  - **WMI Subscriptions:** Run PowerShell commands to check `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding`.

## Phase 6: Automation & Maintenance

- [ ] **Step 10: Scheduled Tasks (Blue Team)**
  - Create tasks to periodically re-enable Firewall and Defender.
  - Create tasks to reset machine passwords periodically.
