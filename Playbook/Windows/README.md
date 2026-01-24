# Securing Windows (CCDC Protocol)

## Phase 1: Enumeration

> [!TIP]
> Move to step 2 while step 1 runs, as it can take a while. Don't forget to look at the results!

- **Step 1: Enumerate Machine**
  - **Network Scan:** Run `nmap -T4 -sV -sC <IP address>` from a Linux host to see what services are running and what ports are open.
    - Installing and running nmap from a Windows machine can be a pain, so just do it from Linux

- **Step 2: Local Audit**
  - **CMD:** Run `netstat -abno` (as Admin) to see Ports mapped to Process Names.
  - **PowerShell:** Run this one-liner to see listening ports and their processes:

    - ```powershell
      Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object LocalPort, @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
      ```

## Phase 2: User & Account Hardening

> [!CAUTION]
> The [Change-Domain-User-Passwords.ps1](../../Change-Domain-User-Passwords.ps1) script will NOT change the passwords of service accounts (`svc_xxx`). You will NEED to change them yourself, AFTER ensuring you have found all places where the password will need to be updated.
>
> **DO NOT FORGET TO CHANGE THE SERVICE ACCOUNT PASSWORDS!.**

- **Step 3: Password Resets**
  - **Domain Controller:** Run the [Change-Domain-User-Passwords.ps1](../../Change-Domain-User-Passwords.ps1) script.
    - Only run this if you are on the DC, it will not be useful if you are on a workstation.
  - **Member Server/Workstation:** Change local Administrator password immediately.
    - `net user Administrator *`
  - **KRBTGT:** Run [Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1](https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1) to reset the `krbtgt` user password which will invalidate Golden Tickets.
    - If you suspect that your machine is being accessed via Golden Tickets, run the script again.
  - **Machine Account:** Run `Reset-ComputerMachinePassword` on your machine.
    - Since all machines are cloned from the same source, this will prevent you from being breached due to another team's carelessness.

- **Step 4a: Run [Account-Cleanup.ps1](../../Windows/Account-Cleanup.ps1)**

> [!WARNING]
> If the script fails, make sure to do the steps manually, as specified below. If the script does not fail, skip step 4b.

- **Step 4b: Manual Account Cleanup**
  - Disable Guest account:
    - `net user Guest /active:no`
  - Audit the user list for unauthorized accounts and delete them.
  - **Control Panel:** Enable Always Notify for account changes
    - Navigate to `Control Panel\User Accounts\User Accounts` -> `User Account Control Settings` -> `Always Notify`
    - Or run:

      ```powershell
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
      ```

  - **Group Policy:** Disable "Store passwords using reversible encryption".
    - `Computer Configuration` -> `Windows Settings` -> `Security Settings` -> `Account Policies` -> `Password Policy` -> `Store password using reversible encryption` -> `Disabled`

## Phase 3: Attack Surface Reduction

> [!NOTE]
> The [Auto-Patch-Exploits.ps1](../../Windows/Auto-Patch-Exploits.ps1) script will attempt to install security packages as part of the process, and will require a system reboot if any packages are installed. Restart as soon as possible to ensure the security patches are applied.

- **Step 5a: Run [Auto-Patch-Exploits.ps1](../../Windows/Auto-Patch-Exploits.ps1)**

> [!WARNING]
> If the script fails, make sure to do the steps manually, as specified below. If the script does not fail, skip step 5b.

- **Step 5b: Manually Patch Known Exploits**
  - **Zerologon:** Run `Auto-Patch-Zerologon-V2.ps1`.
  - **SMBv1:** Check if any services are actively using an SMB share on this machine, before disabling. Make sure to inform other members before disabling SMBv1 so their services don't go down without warning.
    - `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
    - If your machine is running Windows 7, Windows Server 2008, or Windows Vista, run this command:

      ```powershell
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
       ```

  - **SMBv3:** If services are using SMBv1, run this command to enable SMBv3 (Uses SMBv2 stack), which is more secure. If nothing depends on SMB, there is no need to enable SMBv3.
    - `Set-SmbServerConfiguration -EnableSMB2Protocol $true`
    - If your machine is running Windows 7, Windows Server 2008, or Windows Vista, run this command:

      ```powershell
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 -Force
      ```

  - **Mimikatz Protections:**
    - Disable WDigest credentials in Registry

      ```powershell
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType DWORD -Force
      ```

    - Add `LSA Protection` registry key.

      ```powershell
      New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force
      ```

> [!WARNING]
> You **MUST** restart after having run any of the commands above for them to apply.

> [!NOTE]
> These steps below are not included in the above script, you must do them manually

- **Step 5c: Final Manual Checks**

  - **RDP Hardening:**
    - Disable "Shutdown without logon".
    - Disable Remote Assistance.
  - **Accessibility Features:** Check `sethc.exe`, `utilman.exe` in `C:\Windows\System32` (Sticky Keys backdoor).

## Phase 4: Defensive Tooling

- **Step 6: Enable Windows Defender / Antivirus**
  - Ensure Real-time protection is ON via Group Policy.
    - `Computer Configuration` -> `Administrative Templates` -> `Windows Components` -> `Microsoft Defender Antivirus` -> `Real-time Protection` -> `Turn off real-time protection` -> `Enabled`
  - _Optional:_ Consider installing Malwarebytes (if time allows).
    - Malwarebytes can lock registry key edits, and alert you if any changes are attempted

- **Step 7: Enable Auditing:** Run the [Audit-Policy.ps1](../../Windows/Audit-Policy.ps1) script
  - This will allow you to get more info in your Windows Logs.

- **Step 8: Windows Updates**
  - Install any updates that are pending to ensure anything else that was missed is patched out. This may take a while, and consume a lot of resources

## Phase 5: Persistence Hunting

- **Step 9: Install SysInternals**
  - **Sysmon:** Install with a solid config (e.g., SwiftOnSecurity).
  - **Autoruns:** Check for malicious startup items.
  - **ProcMon:** Monitor for strange process behavior.
- **Step 10: Persistence Checks**
  - **Task Scheduler:** Look for repeating tasks or tasks running as SYSTEM.
  - **Startup Folders:** Check for programs in:
    - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
    - `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp`
  - **Registry Run Keys:** Check these registry keys for anything strange:
    - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
    - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
    - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
    - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - **Missing Security Descriptors:** Check for tasks with missing SDs here:
    - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
  - **WMI Subscriptions:** Run these PowerShell commands to check for suspicious entries:

    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __EventFilter
    ```

    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer
    ```

    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
    ```

## Phase 6: Automation & Maintenance

- **Step 11: Scheduled Tasks**
  - Create tasks to periodically re-enable Defender and to Reset the machine password.
  - Create tasks to reset machine passwords periodically, or just remeber to reset them yourself.

## Phase 7: Things I have no documention for yet

- **Step 12: Harden IIS**
  - Setup minimal pool privileges, disable directory browsing, and disable anonymous authentication

- **Step 13: Disable network shares**
  - Disable any network shares that should not be enabled.

- Consider looking at [this](https://github.com/BYU-CCDC/public-ccdc-resources/blob/main/windows/hardening/ww-hardening.ps1) script/repo for solutions. I have no idea if its good.
