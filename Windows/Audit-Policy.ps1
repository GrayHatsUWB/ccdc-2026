<#
    Audit-Policy.ps1
    1. Enables Advanced Audit Policies using auditpol.exe
    2. Enables "Include Command Line in Process Audit Events" (Event 4688)
#>

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[!] This script must run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Configuring Advanced Audit Policies..." -ForegroundColor Cyan

# Clear existing policies (optional, but good for baseline)
# auditpol /clear /y 

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Object Access
auditpol /set /subcategory:"File System" /success:disable /failure:disable # Can be too noisy, enable if specific requirements
auditpol /set /subcategory:"Registry" /success:disable /failure:enable     # Detect failed modification attempts

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Detailed Tracking
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

Write-Host "[+] Audit Policies Configured." -ForegroundColor Green

Write-Host "[*] Enabling Command Line Auditing (Event 4688)..." -ForegroundColor Cyan
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

try {
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Write-Host "[+] Command Line Auditing Enabled." -ForegroundColor Green
}
catch {
    Write-Host "[!] Failed to enable Command Line Auditing." -ForegroundColor Red
}

Write-Host "[*] Audit Hardening Complete." -ForegroundColor Green
