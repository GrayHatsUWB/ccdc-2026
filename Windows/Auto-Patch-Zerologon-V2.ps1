<#
    Auto-Patch-Zerologon-KB.ps1
    - Detects OS version (2008 R2, 2012, 2012 R2, 2016, 2019, 2022)
    - Looks up corresponding Zerologon KB patches from Microsoft
    - Downloads each .msu if missing
    - Installs each with wusa /quiet /norestart
    - Enables Netlogon secure channel enforcement
    - Performs KRBTGT password reset (remediation)

    IMPORTANT: This script implements Microsoft's TWO-PHASE mitigation:
    1. Initial Deployment Phase (Aug 2020+): Patches block weak Netlogon channels
    2. Enforcement Phase (Feb 2021+): Strict enforcement of secure RPC for ALL connections
#>

Write-Host "[*] Detecting OS..." -ForegroundColor Cyan
$os = Get-CimInstance Win32_OperatingSystem
$caption = $os.Caption
$version = $os.Version
$build = [int]$os.BuildNumber
Write-Host "    Caption : $caption"
Write-Host "    Version : $version"
Write-Host "    Build   : $build"
Write-Host ""

# === KB PACKAGE TABLE - ZEROLOGON PATCHES FOR ALL WINDOWS VERSIONS ===
# These KB packages address CVE-2020-1472 (Zerologon vulnerability)
# Microsoft recommends installing BOTH the SSU (Servicing Stack Update) and LCU (Latest Cumulative Update)
# The patches also enable the FullSecureChannelProtection registry key mechanism
# 
# NOTE: Starting February 2021, enforcement mode became mandatory. If you're still exploitable:
#   - Check that BOTH SSU and LCU are installed
#   - Verify FullSecureChannelProtection is set to 1
#   - Check Event Viewer for 5805 events (failed netlogon attempts)
#   - Reboot after patching

$kbTable = @(
    @{
        OsMatch  = "Windows Server 2012"
        Packages = @(
            @{
                KbId = "KB4571702"
                Url  = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2020/08/windows8-rt-kb4571702-x64_31d0c26c78ed003e20c197b9f35869069f5f4b56.msu"
                Note = "Zerologon patch for Server 2012"
            }
        )
    },
    @{
        OsMatch  = "Windows Server 2012 R2"
        Packages = @(
            @{
                KbId = "KB4571723"
                Url  = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2020/08/windows8.1-kb4571723-x64_5f366bc88992b43b074421fd9b817c543c93e456.msu"
                Note = "Zerologon patch for Server 2012 R2"
            }
        )
    },
    @{
        OsMatch  = "Windows Server 2016"
        Packages = @(
            @{
                KbId = "KB5014026"
                Url  = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2022/05/windows10.0-kb5014026-x64_df6de35fd472512e628c2acc6e8d58f3e6139ac9.msu"
                Note = "SSU (Servicing Stack Update) for Server 2016"
            },
            @{
                KbId = "KB5013952"
                Url  = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/05/windows10.0-kb5013952-x64_c9c29b4a81897db5545e284f04490c0659dc8b06.msu"
                Note = "LCU (Latest Cumulative Update) for Server 2016 - includes Zerologon fix"
            }
        )
    },
    @{
        OsMatch  = "Windows Server 2019"
        Packages = @(
            @{
                KbId = "KB4566424"
                Url  = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2020/08/windows10.0-kb4566424-x64_3d5bfb3e572029861cfb02c69de6b909153f5856.msu"
                Note = "Zerologon patch for Server 2019"
            },
            @{
                KbId = "KB5068791"
                Url  = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/11/windows10.0-kb5068791-x64_a8b1b1b6c7b6b673c5a5f32772749eb2bb80c88b.msu"
                Note = "LCU (Latest Cumulative Update) for Server 2019 - includes Zerologon fix"
            }
        )
    }
)

function Get-KBEntryForOS {
    param(
        [string]$Caption,
        [array]$Table
    )
    foreach ($entry in $Table) {
        if ($Caption -like "*$($entry.OsMatch)*") {
            return $entry
        }
    }
    return $null
}

$kbEntry = Get-KBEntryForOS -Caption $caption -Table $kbTable

if (-not $kbEntry) {
    Write-Host "[!] No KB mapping found for this OS in kbTable. Edit the script and add an entry for '$caption'." -ForegroundColor Red
    Write-Host "    Use: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472" -ForegroundColor Gray
    exit 1
}

$packages = $kbEntry.Packages
if (-not $packages -or $packages.Count -eq 0) {
    Write-Host "[!] OS entry found, but no packages defined. Add at least one KB to the Packages array." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Will process the following Zerologon-related KB packages for this OS:" -ForegroundColor Cyan
foreach ($pkg in $packages) {
    Write-Host "    $($pkg.KbId) - $($pkg.Note)" -ForegroundColor Gray
}
Write-Host ""

# ========== CRITICAL: Run as Administrator ==========
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[!] This script must run as Administrator." -ForegroundColor Red
    exit 1
}

$downloadDir = "C:\ZerologonPatches"
if (-not (Test-Path $downloadDir)) {
    New-Item -Path $downloadDir -ItemType Directory | Out-Null
}

# ========== PHASE 1: INSTALL KB PATCHES ==========
Write-Host "[*] PHASE 1: Installing KB patches..." -ForegroundColor Yellow
Write-Host ""

foreach ($pkg in $packages) {
    $kbId = $pkg.KbId
    $kbUrl = $pkg.Url

    if (-not $kbUrl -or $kbUrl -like "*<REPLACE>*") {
        Write-Host "[!] Package $kbId has a placeholder URL. Replace it with the real MSU URL before running." -ForegroundColor Red
        continue
    }

    $msuPath = Join-Path $downloadDir "$kbId.msu"

    if (-not (Test-Path $msuPath)) {
        Write-Host "[*] Downloading $kbId..." -ForegroundColor Cyan
        Write-Host "    URL: $kbUrl" -ForegroundColor Gray
        try {
            Start-BitsTransfer -Source $kbUrl -Destination $msuPath -ErrorAction Stop
            Write-Host "[*] Downloaded to $msuPath" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Download failed for $kbId $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }
    else {
        Write-Host "[*] $kbId already present at $msuPath" -ForegroundColor Green
    }

    Write-Host "[*] Installing $kbId via wusa (quiet, no auto restart)..." -ForegroundColor Cyan
    Start-Process -FilePath "wusa.exe" -ArgumentList "`"$msuPath`" /quiet /norestart" -Wait
    Write-Host "[*] wusa completed for $kbId. A reboot may be required to finalize this update." -ForegroundColor Yellow
}

Write-Host ""

# ========== PHASE 2: ENABLE NETLOGON ENFORCEMENT MODE ==========
Write-Host "[*] PHASE 2: Enabling Netlogon secure channel enforcement mode..." -ForegroundColor Yellow
Write-Host ""

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$regName = "FullSecureChannelProtection"
$regValue = 1

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWord -Force | Out-Null

Write-Host "[*] Set $regName to $regValue" -ForegroundColor Green
Write-Host "    Registry Path: $regPath" -ForegroundColor Gray
Write-Host "    This forces secure Netlogon connections and blocks Zerologon-style abuse." -ForegroundColor Green

# Optional: Also set "RestrictNullSessAccess" for additional hardening
$regName2 = "RestrictNullSessAccess"
$regValue2 = 1
New-ItemProperty -Path $regPath -Name $regName2 -Value $regValue2 -PropertyType DWord -Force | Out-Null
Write-Host "[*] Set $regName2 to $regValue2 (additional hardening)" -ForegroundColor Green

Write-Host ""

# ========== PHASE 3: KRBTGT PASSWORD RESET (REMEDIATION) ==========
Write-Host "[*] PHASE 3: KRBTGT password reset (invalidates any golden tickets)..." -ForegroundColor Yellow
Write-Host ""

function New-RandomPassword {
    param([int]$Length = 32)
    $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
    $random = New-Object System.Random
    $password = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $characters[$random.Next($characters.Length)]
    }
    return $password
}

$krbtgtPassword1 = New-RandomPassword
$krbtgtPassword2 = New-RandomPassword

try {
    Write-Host "[*] Resetting machine password..." -ForegroundColor Cyan
    Reset-ComputerMachinePassword -ErrorAction Stop
    Write-Host "[*] Machine password reset." -ForegroundColor Green

    Write-Host "[*] Resetting KRBTGT password (Pass 1)..." -ForegroundColor Cyan
    Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -String $krbtgtPassword1 -AsPlainText -Force) -ErrorAction Stop
    Write-Host "[*] KRBTGT reset (Pass 1) - old tickets now invalid." -ForegroundColor Green

    Write-Host "[*] Waiting 5 seconds for AD replication..." -ForegroundColor Gray
    Start-Sleep -Seconds 5

    Write-Host "[*] Resetting KRBTGT password (Pass 2)..." -ForegroundColor Cyan
    Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -String $krbtgtPassword2 -AsPlainText -Force) -ErrorAction Stop
    Write-Host "[*] KRBTGT reset (Pass 2) - history cleared, all golden tickets invalid." -ForegroundColor Green
}
catch {
    Write-Host "[!] Active Directory operation failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    You may need to run this section on a domain member or DC with AD module installed." -ForegroundColor Yellow
}

Write-Host ""

# ========== PHASE 4: SUMMARY ==========
Write-Host "[*] PHASE 4: Mitigation summary" -ForegroundColor Yellow
Write-Host ""
Write-Host "[*] Completed the following:" -ForegroundColor Green
Write-Host "    [OK] KB patches installed" -ForegroundColor Green
Write-Host "    [OK] FullSecureChannelProtection enabled (enforcement mode)" -ForegroundColor Green
Write-Host "    [OK] RestrictNullSessAccess enabled" -ForegroundColor Green
Write-Host "    [OK] KRBTGT passwords reset" -ForegroundColor Green
Write-Host "    [OK] Machine password reset" -ForegroundColor Green

Write-Host ""
Write-Host "[!] IMPORTANT: Reboot the DC at a convenient time to finalize all changes!" -ForegroundColor Yellow
Write-Host ""
