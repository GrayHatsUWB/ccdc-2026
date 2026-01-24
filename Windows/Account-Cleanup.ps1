<#
.SYNOPSIS
    Configures specific Windows Security settings: Disables Guest, Maxes UAC, Disables Reversible Encryption.

.DESCRIPTION
    1. Disables the built-in Guest account.
    2. Sets User Account Control (UAC) to "Always Notify".
    3. Disables "Store passwords using reversible encryption" via Local Security Policy (secedit).

.NOTES
    Requires Administrative privileges.
#>

# 0. Check for Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges. Please run PowerShell as Administrator."
    Break
}

Write-Host "--- Starting Security Configuration ---" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# 1. Disable Guest Account
# -------------------------------------------------------------------------
Write-Host "1. Disabling Guest Account..." -NoNewline
try {
    # Attempt using native PowerShell command (Available in newer Windows versions)
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
    Write-Host " [Success]" -ForegroundColor Green
}
catch {
    # Fallback to net user if Disable-LocalUser fails or isn't available
    try {
        $null = net user Guest /active:no
        if ($LASTEXITCODE -eq 0) {
            Write-Host " [Success]" -ForegroundColor Green
        }
        else {
            throw
        }
    }
    catch {
        Write-Host " [Failed]" -ForegroundColor Red
        Write-Error "Could not disable Guest account: $_"
    }
}

# -------------------------------------------------------------------------
# 2. Enable "Always Notify" for UAC
# -------------------------------------------------------------------------
# "Always Notify" corresponds to:
# ConsentPromptBehaviorAdmin = 2 (Prompt for consent on the secure desktop)
# PromptOnSecureDesktop = 1 (Dim the display)

Write-Host "2. Configuring UAC to 'Always Notify'..." -NoNewline

$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    # Set Consent Prompt Behavior for Admin
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Force
    
    # Set Prompt on Secure Desktop (Dimming)
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Force

    Write-Host " [Success]" -ForegroundColor Green
}
catch {
    Write-Host " [Failed]" -ForegroundColor Red
    Write-Error "Could not update Registry keys for UAC: $_"
}

# -------------------------------------------------------------------------
# 3. Disable "Store passwords using reversible encryption"
# -------------------------------------------------------------------------
# Security Policies (Account Policies) are best handled via secedit.exe 
# rather than raw registry edits to ensure the SAM database is updated correctly.

Write-Host "3. Disabling 'Store passwords using reversible encryption'..." -NoNewline

$exportPath = "$env:TEMP\secpol_export.inf"
$dbPath = "$env:TEMP\security_policy.sdb"

try {
    # Export current security settings
    Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg `"$exportPath`"" -Wait -NoNewWindow

    # Read the file content
    $content = Get-Content -Path $exportPath

    # Define the setting we want to change (ClearTextPassword = 0 is Disabled)
    # This setting is usually found under [System Access]
    
    $found = $false
    $newContent = @()
    foreach ($line in $content) {
        if ($line -match "^\s*ClearTextPassword\s*=") {
            $found = $true
            $newContent += "ClearTextPassword = 0" # Replace with Disabled (0)
        }
        else {
            $newContent += $line
        }
    }

    # If the key wasn't in the export, we need to add it under [System Access]
    if (-not $found) {
        $finalContent = @()
        $inSystemAccess = $false
        foreach ($line in $content) {
            $finalContent += $line
            if ($line -match "^\[System Access\]") {
                $finalContent += "ClearTextPassword = 0"
                $inSystemAccess = $true
            }
        }
        # If [System Access] section didn't exist (rare), append it
        if (-not $inSystemAccess) {
            $finalContent += "[System Access]"
            $finalContent += "ClearTextPassword = 0"
        }
        $newContent = $finalContent
    }

    # Save the modified INF file
    $newContent | Set-Content -Path $exportPath

    # Apply the new settings
    Start-Process -FilePath "secedit.exe" -ArgumentList "/configure /db `"$dbPath`" /cfg `"$exportPath`" /areas SECURITYPOLICY" -Wait -NoNewWindow

    Write-Host " [Success]" -ForegroundColor Green
}
catch {
    Write-Host " [Failed]" -ForegroundColor Red
    Write-Error "Could not modify Local Security Policy: $_"
}
finally {
    # Cleanup temp files
    if (Test-Path $exportPath) { Remove-Item $exportPath -Force }
    if (Test-Path $dbPath) { Remove-Item $dbPath -Force }
}

Write-Host "--- Configuration Complete ---" -ForegroundColor Cyan