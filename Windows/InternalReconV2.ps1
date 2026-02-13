<#
.SYNOPSIS
    Full Process Integrity & C2 Hunter (UWP Aware)
    Enumerates ALL running processes, checks digital signatures (including Store Apps), 
    and maps ANY network activity.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$OutputFile,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string]$CustomName
)

Write-Host "[-] Starting full process integrity scan (This may take a moment)..." -ForegroundColor Cyan

# --- 1. GATHER DATA ---
$allProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
$allConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
$allServices = Get-CimInstance -ClassName Win32_Service -Property Name, ProcessId, PathName, DisplayName

# Pre-fetch Appx Packages for speed (Optimization)
$allAppx = Get-AppxPackage -ErrorAction SilentlyContinue

$results = @()

foreach ($proc in $allProcesses) {
    $pidNum = $proc.Id
    $processName = $proc.ProcessName
    $path = "N/A"
    $description = "N/A"
    $company = "N/A"
    $version = "N/A"
    $user = $proc.UserName
    $category = "Unverified / Unknown"
    $netActivity = "None"
    
    if ($pidNum -eq 0) { continue }

    # --- A. GET PATH & METADATA ---
    try {
        if ($proc.MainModule) { 
            $path = $proc.MainModule.FileName 
            $description = $proc.MainModule.FileVersionInfo.FileDescription
            $company = $proc.MainModule.FileVersionInfo.CompanyName
            $version = $proc.MainModule.FileVersionInfo.FileVersion
        }
    } catch {
        $path = "Access Denied (Protected)"
    }

    # Path Fallback Logic
    if ($path -eq "Access Denied (Protected)" -or $path -eq "N/A") {
        $relatedSvc = $allServices | Where-Object { $_.ProcessId -eq $pidNum }
        if ($relatedSvc) {
            $rawPath = $relatedSvc[0].PathName
            if ($rawPath -match '^"([^"]+)"') { $path = $Matches[1] }
            elseif ($rawPath -match '^([^\s]+)') { $path = $Matches[1] }
        } elseif ($pidNum -eq 4) {
            $path = "System Kernel"
        } else {
            $sysPath = "$env:windir\System32\$processName.exe"
            if (Test-Path $sysPath) { $path = $sysPath }
        }
    }

    # --- B. DETECT NETWORK ACTIVITY ---
    $procConns = $allConns | Where-Object { $_.OwningProcess -eq $pidNum }
    if ($procConns) {
        $listeners = $procConns | Where-Object { $_.State -eq 'Listen' } | Select-Object -ExpandProperty LocalPort -Unique
        $outbound = $procConns | Where-Object { $_.State -eq 'Established' } | Select-Object -ExpandProperty RemoteAddress -Unique
        
        $activity = @()
        if ($listeners) { $activity += "Listen: $($listeners -join ', ')" }
        if ($outbound) { $activity += "Connected to: $($outbound -join ', ')" }
        
        if ($activity) { $netActivity = $activity -join " | " }
    }

    # --- C. VERIFICATION LOGIC ---
    
    # 1. System Kernel
    if ($pidNum -eq 4) {
        $category = "Core Windows"
    } 
    # 2. UWP / Windows Store Apps (The Fix)
    elseif ($path -match "WindowsApps") {
        # Check if the path contains a valid Package Family Name
        $packageMatch = $allAppx | Where-Object { $path -match $_.PackageFamilyName } | Select-Object -First 1
        
        if ($packageMatch) {
            if ($packageMatch.Publisher -match "Microsoft Corporation|Microsoft Windows") {
                $category = "Core Windows (UWP)"
                $description = "Store App: $($packageMatch.Name)"
            } elseif ($packageMatch.SignatureKind -eq "Store") {
                $category = "Third-Party Verified (Store)"
                $description = "Store App: $($packageMatch.Name)"
            } else {
                $category = "Unverified (Sideloaded UWP)"
            }
        } else {
            # Fallback if package lookup fails but path is WindowsApps
            $category = "Core Windows (UWP - Unresolved)"
        }
    }
    # 3. Standard Win32 Apps
    elseif ($path -ne "N/A" -and $path -ne "Access Denied (Protected)" -and (Test-Path $path)) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            if ($sig.Status -eq "Valid") {
                $subject = $sig.SignerCertificate.Subject
                if ($subject -match "Microsoft Windows") { $category = "Core Windows" }
                elseif ($subject -match "Microsoft Corporation") { $category = "Additional Microsoft Software" }
                else { $category = "Third-Party Verified" }
            } else {
                $category = "Unverified / Unsigned"
            }
        } catch { $category = "Unverified / Access Denied" }
    } 
    # 4. Protected System Processes
    elseif ($path -eq "Access Denied (Protected)") {
        if (@('csrss','lsass','wininit','smss','services','svchost') -contains $processName) {
            $category = "Core Windows (Protected)"
        } else {
            $category = "Unverified (Hidden/Root)"
        }
    }

    # --- D. SUSPICIOUS PATH CHECK ---
    if ($path -match "AppData|Temp|Public|ProgramData") {
        if ($category -notmatch "Verified|Microsoft|Windows") {
            $category = "!! SUSPICIOUS PATH !!"
        }
    }

    $results += [PSCustomObject]@{
        Category    = $category
        Process     = $processName
        PID         = $pidNum
        User        = $user
        Network     = $netActivity
        Path        = $path
        Description = $description
    }
}

# --- 3. DISPLAY & OUTPUT ---
$categories = @("!! SUSPICIOUS PATH !!", "Unverified (Hidden/Root)", "Unverified / Unsigned", "Unverified (Sideloaded UWP)", "Third-Party Verified", "Third-Party Verified (Store)", "Additional Microsoft Software", "Core Windows", "Core Windows (UWP)", "Core Windows (Protected)")
$colors = @("Magenta", "Red", "Red", "Red", "Yellow", "Yellow", "Blue", "Cyan", "Cyan", "Cyan")

# Sort by Process Name
$results = $results | Sort-Object Process

foreach ($i in 0..($categories.Count - 1)) {
    $catName = $categories[$i]
    $subset = $results | Where-Object { $_.Category -eq $catName }
    
    $count = if ($subset) { $subset.Count } else { 0 }
    Write-Host "`n[+] $catName ($count)" -ForegroundColor $colors[$i]
    
    if ($subset) {
        $subset | Format-Table -AutoSize -Property Process, PID, User, Network, Path
    } else {
        Write-Host "    --> None detected." -ForegroundColor Gray
    }
}

# --- 4. EXPORT LOGIC ---
$FinalPath = $null
if ($OutputFile) {
    if (-not [string]::IsNullOrWhiteSpace($CustomName)) { $FinalPath = $CustomName }
    else { $FinalPath = "FullScan_$(Get-Date -Format 'yyyy-MM-dd_HHmm').csv" }
}

if ($FinalPath) {
    if ($FinalPath -notlike "*.*") { $FinalPath += ".csv" }
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FinalPath)
    
    try {
        $results | Sort-Object Category, Process | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[V] Full scan saved to: $fullPath" -ForegroundColor Green
    } catch {
        Write-Host "`n[X] Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}