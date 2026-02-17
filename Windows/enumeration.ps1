# ===============================
# baseline_enum.ps1 (baseline-style)
# Logs to a folder where the script is located.
# PowerShell 5.1+ recommended.
# ===============================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ---------- Output folder (same directory as script) ----------
$ScriptBase = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LogsRoot = Join-Path $ScriptBase "Logs"
if (-not (Test-Path $LogsRoot)) { New-Item -ItemType Directory -Path $LogsRoot | Out-Null }

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = Join-Path $LogsRoot "baseline_$TimeStamp"
New-Item -ItemType Directory -Path $OutDir | Out-Null

# Optional: capture everything printed to console too
Start-Transcript -Path (Join-Path $OutDir "master_transcript.txt") -Append | Out-Null

function Write-Section {
    param(
        [Parameter(Mandatory)] [string] $FileName,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [scriptblock] $Command
    )
    $path = Join-Path $OutDir $FileName
    $line = ("=" * 80)

    @(
        $line
        $Title
        ("Host: {0}" -f $env:COMPUTERNAME)
        ("User: {0}" -f $env:USERNAME)
        ("Time: {0}" -f (Get-Date).ToString("s"))
        $line
        ""
    ) | Out-File -FilePath $path -Encoding utf8

    try {
        & $Command 2>&1 | Out-File -FilePath $path -Encoding utf8 -Append
    }
    catch {
        $_ | Out-File -FilePath $path -Encoding utf8 -Append
    }
}

function Run-CmdToFile {
    param(
        [Parameter(Mandatory)] [string] $FileName,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $CmdLine
    )
    Write-Section -FileName $FileName -Title $Title -Command {
        cmd.exe /c $CmdLine
    }.GetNewClosure()
}

Write-Host "[+] Logging to: $OutDir"

# ---------- SYSTEM INFORMATION ----------
Write-Section -FileName "system_info.txt" -Title "SYSTEM INFORMATION" -Command {
    if (Get-Command Get-ComputerInfo -ErrorAction SilentlyContinue) {
        Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, CsHostname
    }
    else {
        # fallback for older systems
        Run-CmdToFile -FileName "system_info_wmic.txt" -Title "SYSTEM INFORMATION (WMIC fallback)" -CmdLine 'wmic os get Caption,Version,BuildNumber /value'
        Run-CmdToFile -FileName "system_info_hostname.txt" -Title "HOSTNAME" -CmdLine 'hostname'
        "Get-ComputerInfo not available; see WMIC fallback files."
    }
}

# ---------- USER INFORMATION ----------
Write-Section -FileName "user_whoami.txt" -Title "USER INFORMATION (whoami)" -Command {
    whoami
    "`n--- groups ---"
    whoami /groups
    "`n--- priv ---"
    whoami /priv
}

# ---------- LOCAL USERS ----------
Write-Section -FileName "local_users.txt" -Title "LOCAL USERS" -Command {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon
    }
    else {
        # fallback
        "Get-LocalUser not available; using net user"
        cmd.exe /c "net user"
    }
}

# ---------- LOCAL ADMINS ----------
Write-Section -FileName "local_admins.txt" -Title "LOCAL ADMINS (Administrators group)" -Command {
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        Get-LocalGroupMember -Group "Administrators"
    }
    else {
        cmd.exe /c "net localgroup administrators"
    }
}

# ---------- NETWORK CONFIGURATION ----------
Write-Section -FileName "network_ipconfig_all.txt" -Title "NETWORK CONFIGURATION (ipconfig /all)" -Command {
    ipconfig /all
}

Write-Section -FileName "network_connections.txt" -Title "NETWORK CONNECTIONS" -Command {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, State
    }
    else {
        # fallback
        cmd.exe /c "netstat -ano"
    }
}

# ---------- ROUTES ----------
Write-Section -FileName "routes.txt" -Title "ROUTES (route print)" -Command {
    route print
}

# ---------- RUNNING PROCESSES ----------
Write-Section -FileName "processes_top_cpu.txt" -Title "RUNNING PROCESSES (Top 15 CPU)" -Command {
    Get-Process | Where-Object { $_.CPU -ne $null } | Sort-Object CPU -Descending | Select-Object -First 15 Name, Id, CPU, WS
}

# ---------- SERVICES ----------
Write-Section -FileName "services_running.txt" -Title "SERVICES (Running)" -Command {
    Get-Service | Where-Object { $_.Status -eq "Running" } | Sort-Object Name
}

# ---------- INSTALLED SOFTWARE ----------
Write-Section -FileName "installed_software_32on64.txt" -Title "INSTALLED SOFTWARE (Wow6432Node Uninstall)" -Command {
    $path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    if (Test-Path $path) {
        Get-ItemProperty $path |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName
    }
    else {
        "Registry path not found: $path"
    }
}

Write-Section -FileName "installed_software_64.txt" -Title "INSTALLED SOFTWARE (HKLM Uninstall)" -Command {
    $path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    if (Test-Path $path) {
        Get-ItemProperty $path |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName
    }
    else {
        "Registry path not found: $path"
    }
}

# ---------- POWERSHELL CONTEXT ----------
Write-Section -FileName "powershell_context.txt" -Title "POWERSHELL CONTEXT" -Command {
    $PSVersionTable
    "`n--- ExecutionPolicy (All scopes) ---"
    Get-ExecutionPolicy -List
}

# ---------- DEFENDER STATUS ----------
Write-Section -FileName "defender_status.txt" -Title "DEFENDER STATUS" -Command {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Get-MpComputerStatus
    }
    else {
        "Get-MpComputerStatus not available (Defender module missing or not Windows Defender)."
    }
}

# ---------- FIREWALL STATUS ----------
Write-Section -FileName "firewall_status.txt" -Title "FIREWALL STATUS" -Command {
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    }
    else {
        cmd.exe /c "netsh advfirewall show allprofiles"
    }
}

# ---------- SCHEDULED TASKS ----------
Write-Section -FileName "scheduled_tasks.txt" -Title "SCHEDULED TASKS" -Command {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        Get-ScheduledTask | Select-Object TaskName, State, Author | Sort-Object TaskName
    }
    else {
        cmd.exe /c "schtasks /query /fo LIST /v"
    }
}

# ---------- ENVIRONMENT VARIABLES ----------
Write-Section -FileName "environment_variables.txt" -Title "ENVIRONMENT VARIABLES" -Command {
    Get-ChildItem Env: | Sort-Object Name
}

# ---------- SUMMARY ----------
Write-Section -FileName "RUN_SUMMARY.txt" -Title "RUN SUMMARY" -Command {
    "Output folder: $script:OutDir"
    "`nFiles:"
    Get-ChildItem -File $script:OutDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
}

Stop-Transcript | Out-Null
Write-Host "[+] Done. Output: $OutDir"
