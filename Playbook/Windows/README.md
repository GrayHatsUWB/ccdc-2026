# Securing Windows (CCDC Protocol)

## Phase 1: Enumeration

- **Step 1: Enumerate Machine**
  - **Network Scan:** Run `nmap -T4 -sV -sC <IP address>` from a Linux host to see what services are running and what ports are open.
    - Installing and running nmap from a Windows machine can be a pain, so just do it from Linux
      > [!TIP]
      > Move to step 2 while this runs, as it can take a while. Don't forget to look at the results!

- **Step 2: Local Audit**
  - **CMD:** Run `netstat -abno` (as Admin) to see Ports mapped to Process Names.
  - **PowerShell:** Run this one-liner to see listening ports and their processes:

    - ```powershell
      Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object LocalPort, @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
      ```

## Phase 2: User & Account Hardening

- **Step 3: Password Resets**
  - **Domain Controller:** Run `Change-Domain-User-Passwords.ps1`.
    - Only run this if you are on the DC, it will not be useful if you are on a workstation.
      > [!CAUTION]
      > This script will NOT change the passwords of service accounts (`svc_xxx`). You will NEED to change them yourself, AFTER ensuring you have found all places where the password will need to be updated. DO NOT FORGET TO CHANGE THEM.
  - **Member Server/Workstation:** Change local Administrator password immediately.
    - `net user Administrator *`
  - **KRBTGT:** Run [this script](https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1) to reset the `krbtgt` user password which will invalidate Golden Tickets.
    - If you suspect that your machine is being accessed via Golden Tickets, run the script again.
  - **Machine Account:** Run `Reset-ComputerMachinePassword` on your machine.
    - Since all machines are cloned from the same source, this will prevent you from being breached due to another team's carelessness.
- **Step 4: Account Cleanup**
  - Run the [Account-Cleanup.ps1](../../Windows/Account-Cleanup.ps1) script

  > [!WARNING]
  > If the script fails, make sure to do these steps manually, as specified below. If the script does not fail, these steps are not necessary.

  - Disable Guest account:
    - `net user Guest /active:no`
  - Audit user list for unauthorized accounts and delete them.
  - **Control Panel:** Enable Always Notify for account changes
    - `Control Panel\User Accounts\User Accounts` -> `User Account Control Settings` -> `Always Notify`
  - **Group Policy:** Disable "Store passwords using reversible encryption".
    - `Computer Configuration` -> `Windows Settings` -> `Security Settings` -> `Account Policies` -> `Password Policy` -> `Store password using reversible encryption` -> `Disabled`

## Phase 3: Attack Surface Reduction

- **Step 5: Patch Known Exploits**
  - Run the [Auto-Patch-Exploits.ps1](../../Windows/Auto-Patch-Exploits.ps1) script
    > [!INFO]
    > This scritp will attempt to install security packages as part of the process, and will require a system reboot if any packages are installed. Restart as soon as possible to ensure the security patches are applied.

  > [!WARNING]
  > If the script fails, make sure to do these steps manually, as specified below. If the script does not fail, these steps are not necessary.
  - **Zerologon:** Run `Auto-Patch-Zerologon-V2.ps1`.
  - **SMBv1:** Check if any services are actively using an SMB share on this machine, before disabling. Make sure to inform other members before disabling SMBv1 so their services don't go down without warning.
    - `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
    - If your machine is running Windows 7, Windows Server 2008, or Windows Vista, run this command:

      ```powershell
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
      ```

      > [!IMPORTANT]
      > You must restart after running this powershell command.

  - **SMBv3:** If services are using SMBv1, run this command to enable SMBv3 (Uses SMBv2 stack), which is more secure. If nothing depends on SMB, there is no need to enable SMBv3.
    - `Set-SmbServerConfiguration -EnableSMB2Protocol $true`
    - If your machine is running Windows 7, Windows Server 2008, or Windows Vista, run this command:

      ```powershell
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 -Force
      ```

       > [!IMPORTANT]
      > You must restart after running this powershell command.

  - **Mimikatz Protections:**
    - Disable WDigest credentials in Registry (`UseLogonCredential` = 0).
    - Add `LSA Protection` registry key.

  > [!INFO]
  > These steps below are not included in the above script, do them manually

  - **RDP Hardening:**
    - Disable "Shutdown without logon".
    - Disable Remote Assistance.
  - **Accessibility Features:** Check `sethc.exe`, `utilman.exe` in `C:\Windows\System32` modifications (Sticky Keys backdoor).

## Phase 4: Defensive Tooling

- **Step 6: Enable Windows Defender / Antivirus**
  - Ensure Real-time protection is ON via Group Policy.
    - `Computer Configuration` -> `Administrative Templates` -> `Windows Components` -> `Microsoft Defender Antivirus` -> `Real-time Protection` -> `Turn off real-time protection` -> `Enabled`
  - _Optional:_ Consider installing Malwarebytes (if time allows).
    - Malwarebytes can lock registry key edits, and alert you if any changes are attempted
- **Step 7: Windows Updates**
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
