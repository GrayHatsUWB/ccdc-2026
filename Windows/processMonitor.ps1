<#
.SYNOPSIS
Continuous monitoring of Windows services for suspicious activity.

.DESCRIPTION
Monitors services continuously and detects suspicious activity based on:
- Suspicious path
- Unsigned binaries
- High entropy names
- Suspicious file extensions
- Missing descriptions

Logs only new or updated suspicious services to a timestamped log file.
Only *truly high-entropy names* or **major entropy increases** are reported.
#>

# === FUNCTIONS =================================================================

function GetExecutablePath($path) {
    if ([string]::IsNullOrEmpty($path)) { return $null }
    $path = $path.Trim('"')
    $exe = ($path -split '\s+')[0]
    if (Test-Path $exe -PathType Leaf) { return $exe } else { return $null }
}

function IsSuspiciousPath($path) { 
    if ([string]::IsNullOrEmpty($path)) { return $false }
    return ($path -like "C:\Users\*")
}

function IsUnsigned($path) {
    try {
        $exePath = GetExecutablePath $path
        if ($null -eq $exePath) { return $true }
        return (Get-AuthenticodeSignature -FilePath $exePath).Status -ne "Valid"
    } catch { return $true }
}

function CalculateEntropy($input) {
    $inputString = [string]$input
    if ($inputString.Length -eq 0) { return 0 }

    $freq = @{}
    foreach ($c in $inputString.ToCharArray()) { 
        if (-not $freq.ContainsKey($c)) { $freq[$c] = 0 }
        $freq[$c]++
    }

    $entropy = 0.0
    foreach ($f in $freq.Values) {
        $p = $f / $inputString.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 2)
}

function IsHighEntropyName($name, $threshold = 3.5) {
    if ([string]::IsNullOrEmpty($name)) { return $false }
    return (CalculateEntropy($name) -gt $threshold)
}

function HasSuspiciousExtension($path) {
    $exePath = GetExecutablePath $path
    if ($null -eq $exePath) { return $false }
    $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
    $extension = [IO.Path]::GetExtension($exePath)
    return ($suspiciousExtensions -contains $extension)
}

# === MAIN SCRIPT ===============================================================

$MinScore = 4                          # Minimum suspicious score
$HighEntropyThreshold = 4.0            # Only truly random names
$EntropyChangeThreshold = 0.75         # Only big entropy jumps
$TrackedServices = @{}                 # Memory baseline

# Log file (in same folder as script)
$logFile = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath "SuspiciousServices.log"

Write-Host "Monitoring services... Logging only HIGH-ENTROPY or ENTROPY-CHANGED services." -ForegroundColor Cyan
Write-Host "Output log: $logFile" -ForegroundColor DarkCyan

while ($true) {
    try {
        $AllServices = Get-WmiObject Win32_Service -ErrorAction Stop
        $UpdatedServices = @()

        foreach ($S in $AllServices) {
            try {
                $path = GetExecutablePath $S.PathName
                $score = 0
                $entropyScore = 0

                # === Score system =====================================================================
                if (IsSuspiciousPath $S.PathName) { $score += 3 }
                if (IsUnsigned $S.PathName) { $score += 3 }

                if (IsHighEntropyName $S.Name) {
                    $score += 2
                    $entropyScore = CalculateEntropy $S.Name
                }

                if (IsHighEntropyName $S.DisplayName) {
                    $score += 1
                    $calcEntropy = CalculateEntropy $S.DisplayName
                    $entropyScore = [Math]::Max($entropyScore, $calcEntropy)
                }

                if ([string]::IsNullOrEmpty($S.Description)) { $score += 1 }
                if (HasSuspiciousExtension $S.PathName) { $score += 2 }

                # === High‑entropy reporting logic ======================================================
                if ($score -ge $MinScore) {

                    $key = $S.Name
                    $previousEntropy = if ($TrackedServices.ContainsKey($key)) { 
                        $TrackedServices[$key].Entropy 
                    } else { 0 }

                    $isHighEntropy = ($entropyScore -ge $HighEntropyThreshold)
                    $entropyIncreasedSignificantly = (($entropyScore - $previousEntropy) -ge $EntropyChangeThreshold)

                    if ($isHighEntropy -or $entropyIncreasedSignificantly) {

                        $serviceInfo = [PSCustomObject]@{
                            Name        = $S.Name
                            DisplayName = $S.DisplayName
                            Status      = $S.State
                            StartName   = $S.StartName
                            BinaryPath  = $path
                            Score       = $score
                            Entropy     = $entropyScore
                            DetectedAt  = Get-Date
                        }

                        $TrackedServices[$key] = $serviceInfo
                        $UpdatedServices += $serviceInfo
                    }
                }

            } catch {
                Write-Host "Warning: Could not process service $($S.Name)" -ForegroundColor DarkYellow
            }
        }

        # === Output updates ============================================================
        if ($UpdatedServices.Count -gt 0) {
            Write-Host "`n=== New or changed HIGH-ENTROPY services detected ===" -ForegroundColor Yellow
            $UpdatedServices | Sort-Object Score -Descending | Format-Table Name, DisplayName, Status, Score, Entropy, DetectedAt

            foreach ($svc in $UpdatedServices) {
                $logEntry = "[{0}] Name: {1}; DisplayName: {2}; Status: {3}; Score: {4}; Entropy: {5}; BinaryPath: {6}" -f `
                    $svc.DetectedAt, $svc.Name, $svc.DisplayName, $svc.Status, $svc.Score, $svc.Entropy, $svc.BinaryPath
                try { Add-Content -Path $logFile -Value $logEntry } catch { Write-Host "Could not write to log: $_" -ForegroundColor Red }
            }
        } else {
            Write-Host "No suspicious services detected in this iteration." -ForegroundColor Green
            $logEntry = "[{0}] No suspicious services detected." -f (Get-Date)
            try { Add-Content -Path $logFile -Value $logEntry } catch { Write-Host "Could not write to log: $_" -ForegroundColor Red }
        }

    } catch {
        Write-Host "Warning: Could not retrieve services. Retrying..." -ForegroundColor DarkRed
        $logEntry = "[{0}] Warning: Could not retrieve services." -f (Get-Date)
        try { Add-Content -Path $logFile -Value $logEntry } catch { }
    }

    Start-Sleep -Seconds 1
    Write-Host "`n"
}
