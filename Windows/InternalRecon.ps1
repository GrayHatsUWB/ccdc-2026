<#
.SYNOPSIS
    Internal Inventory Scan (Flat Script Version)
    Usage:
    1. .\InternalRecon.ps1                        (Scan to screen only)
    2. .\InternalRecon.ps1 -OutputFile            (Save to "Inventory_Date.csv")
    3. .\InternalRecon.ps1 -OutputFile "Name.csv" (Save to "Name.csv")
#>

[CmdletBinding()]
param(
    # The Switch: triggers the save logic
    [Parameter(Mandatory=$false)]
    [switch]$OutputFile,

    # The Catch-All: grabs the filename if you typed one
    [Parameter(ValueFromRemainingArguments=$true)]
    [string]$CustomName
)

Write-Host "[-] Starting inventory scan..." -ForegroundColor Cyan

# --- 1. DETERMINE FILE PATH ---
$FinalPath = $null

# Logic: Did the user type the flag?
if ($OutputFile) {
    if (-not [string]::IsNullOrWhiteSpace($CustomName)) {
        # User typed: -OutputFile "my_scan.csv"
        $FinalPath = $CustomName
    } else {
        # User typed: -OutputFile (No name)
        $FinalPath = "Inventory_$(Get-Date -Format 'yyyy-MM-dd_HHmm').csv"
    }
}

# --- 2. GATHER DATA ---
$netConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
$allServices = Get-CimInstance -ClassName Win32_Service -Property Name, ProcessId, PathName, DisplayName
$results = @()

foreach ($conn in $netConnections) {
    $port = $conn.LocalPort
    $pidNum = $conn.OwningProcess
    
    $processName = "Unknown"
    $serviceName = "N/A"
    $version = "N/A"
    $path = "N/A"
    $description = "N/A"
    $category = "Unverified / Unknown"

    # Identify Process
    if ($pidNum -eq 4) {
        $processName = "System"
        $category = "Core Windows"
    }
    elseif ($pidNum -gt 0) {
        try {
            $proc = Get-Process -Id $pidNum -ErrorAction Stop
            $processName = $proc.ProcessName
            if ($proc.MainModule) { $path = $proc.MainModule.FileName }
        } catch {
            $processName = (Get-Process -Id $pidNum -ErrorAction SilentlyContinue).Name -or "Protected Process"
        }
    }

    # Map Service
    $relatedServices = $allServices | Where-Object { $_.ProcessId -eq $pidNum }
    if ($relatedServices) {
        $serviceName = ($relatedServices.Name -join ", ")
        if ($path -eq "N/A") {
            $rawPath = $relatedServices[0].PathName
            if ($rawPath -match '^"([^"]+)"') { $path = $Matches[1] }
            elseif ($rawPath -match '^([^\s]+)') { $path = $Matches[1] }
        }
    }

    # Verification Logic
    if ($category -ne "Core Windows") {
        $protectedSystemApps = @('lsass', 'csrss', 'services', 'smss', 'wininit', 'svchost')
        if ($protectedSystemApps -contains $processName -and $path -eq "N/A") {
            $path = "$env:windir\System32\$processName.exe"
        }

        if ($null -ne $path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
            try {
                $fileInfo = Get-ItemProperty -Path $path -ErrorAction Stop
                $version = $fileInfo.VersionInfo.FileVersion
                $description = $fileInfo.VersionInfo.FileDescription
                
                $sig = Get-AuthenticodeSignature -FilePath $path
                if ($sig.Status -eq "Valid") {
                    $subject = $sig.SignerCertificate.Subject
                    if ($subject -match "Microsoft Windows") { $category = "Core Windows" }
                    elseif ($subject -match "Microsoft Corporation") { $category = "Additional Microsoft Software" }
                    else { $category = "Third-Party Verified" }
                } else { $category = "Unverified / Unsigned" }
            } catch { $category = "Unverified / Access Denied" }
        }
    }

    $results += [PSCustomObject]@{
        Category    = $category
        Process     = $processName
        LocalPort   = $port
        PID         = $pidNum
        Service     = $serviceName
        Version     = $version
        Description = $description
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

# --- 3. DISPLAY OUTPUT ---
$cleanResults = $results | Group-Object -Property LocalPort, PID | ForEach-Object { $_.Group[0] }
$categories = @("Core Windows", "Additional Microsoft Software", "Third-Party Verified", "Unverified / Unknown")
$colors = @("Cyan", "Blue", "Yellow", "Red")

for ($i=0; $i -lt $categories.Count; $i++) {
    $currentCat = $categories[$i]
    $subset = $cleanResults | Where-Object { $_.Category -eq $currentCat } | Sort-Object Process
    $count = if ($subset) { $subset.Count } else { 0 }
    
    Write-Host "`n[+] $($currentCat.ToUpper()) ($count)" -ForegroundColor $colors[$i]
    if ($subset) {
        $subset | Format-Table -AutoSize -Property Process, Description, LocalPort, Service
    } else {
        Write-Host "    --> No processes detected in this category." -ForegroundColor Gray
    }
}

# --- 4. EXPORT LOGIC ---
if ($FinalPath) {
    if ($FinalPath -notlike "*.*") { $FinalPath += ".csv" }
    
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FinalPath)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)

    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        if (-not (Test-Path -Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            Write-Host "[+] Created directory: $directory" -ForegroundColor Green
        }
    }

    try {
        $cleanResults | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[V] Results successfully exported to: $fullPath" -ForegroundColor Green
    } catch {
        Write-Host "`n[X] Failed to export file: $($_.Exception.Message)" -ForegroundColor Red
    }
}