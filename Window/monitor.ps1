<#
.SYNOPSIS
Unified monitoring of suspicious Windows events and services.

.DESCRIPTION
- Monitors Security event log every 15 seconds
- Monitors services continuously for suspicious behavior
- Logs all findings in human-readable log files in the script folder
- Tracks new users in KnownUsers.txt
#>

# ---------------------------
# CONFIGURATION
# ---------------------------

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Log files
$eventLogFile = Join-Path $scriptDir "SuspiciousEvents.log"
$serviceLogFile = Join-Path $scriptDir "SuspiciousServices.log"

# Known users file
$knownUsersFile = Join-Path $scriptDir "KnownUsers.txt"
if (-not (Test-Path $knownUsersFile)) { New-Item -Path $knownUsersFile -ItemType File -Force }

# Load known users
$knownUsers = @()
if (Test-Path $knownUsersFile) {
    $knownUsers = Get-Content $knownUsersFile
}

$alertThreshold = 5
$serviceMinScore = 4
$HighEntropyThreshold = 4.0
$EntropyChangeThreshold = 0.75
$TrackedServices = @{}

# ---------------------------
# FUNCTIONS
# ---------------------------

# Safe append to log file
function Append-Log {
    param (
        [string]$Path,
        [string]$Text
    )
    try {
        $writer = [System.IO.StreamWriter]::new($Path, $true)
        $writer.WriteLine($Text)
        $writer.Close()
    } catch {
        Write-Host "Could not write to ${Path}: $_" -ForegroundColor Red
    }
}

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

# ---------------------------
# SUSPICIOUS EVENT DEFINITIONS
# ---------------------------

$suspiciousEvents = @(
    @{Id=4688; Name="Process Creation"; Color="Yellow"; Fields=@("SubjectUserName","NewProcessName","NewProcessId","ProcessCommandLine")},
    @{Id=4697; Name="Service Installation"; Color="Red"; Fields=@("ServiceName","ServiceFileName")},
    @{Id=4672; Name="Special Privilege Assignment"; Color="Magenta"; Fields=@("SubjectUserName","PrivilegeList")},
    @{Id=4720; Name="User Account Creation"; Color="Cyan"; Fields=@("TargetUserName","SubjectUserName")},
    @{Id=4625; Name="Failed Logon Attempt"; Color="Red"; Fields=@("TargetUserName","IpAddress","FailureReason")},
    @{Id=4740; Name="Account Lockout"; Color="DarkMagenta"; Fields=@("TargetUserName","IpAddress")},
    @{Id=4726; Name="User Account Deletion"; Color="DarkCyan"; Fields=@("TargetUserName","SubjectUserName")},
    @{Id=4732; Name="Local Group Member Added"; Color="Blue"; Fields=@("TargetUserName","MemberName")},
    @{Id=4719; Name="Audit Policy Change"; Color="Gray"; Fields=@("SubcategoryGUID","SubcategoryName")}
)

Write-Host "Starting unified monitoring..." -ForegroundColor Cyan

# ---------------------------
# MAIN LOOP
# ---------------------------

while ($true) {

    # ----- AUDIT WINDOWS EVENTS -----
    $startTime = (Get-Date).AddSeconds(-15)
    $header = "====================================`nAudit Interval: $(Get-Date)`n===================================="
    Write-Host $header
    Append-Log -Path $eventLogFile -Text $header

    $newlyCreatedUsers = @()
    $suspiciousActivity = @()

    foreach ($eventDef in $suspiciousEvents) {
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eventDef.Id; StartTime=$startTime} -ErrorAction SilentlyContinue
        } catch { $events = @() }

        if ($events.Count -gt 0) {
            $msg = "`nFound $($events.Count) $($eventDef.Name) event(s):"
            Write-Host -ForegroundColor $eventDef.Color $msg
            Append-Log -Path $eventLogFile -Text $msg

            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $dataItems = $xml.Event.EventData.Data
                $details = ""
                $targetUser = $null

                foreach ($field in $eventDef.Fields) {
                    $value = ($dataItems | Where-Object { $_.Name -eq $field } | Select-Object -ExpandProperty "#text" -ErrorAction SilentlyContinue)
                    if ($value) { 
                        $details += "$($field): $($value); "
                        if ($field -like "*UserName") { $targetUser = $value }
                    }
                }

                $timeStamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $logEntry = "[$timeStamp] $($eventDef.Name) - $details"
                Write-Host -ForegroundColor $eventDef.Color "  $logEntry"
                Append-Log -Path $eventLogFile -Text $logEntry

                if ($eventDef.Id -eq 4720 -and $targetUser -and ($targetUser -notin $knownUsers)) { $newlyCreatedUsers += $targetUser }
                if ($eventDef.Id -in 4625,4740,4672 -and $targetUser) { $suspiciousActivity += $targetUser }
            }
        } else {
            $msg = "`nNo $($eventDef.Name) events in the last 15 seconds."
            Write-Host -ForegroundColor Green $msg
            Append-Log -Path $eventLogFile -Text $msg
        }
    }

    # Handle new users
    if ($newlyCreatedUsers.Count -gt 0) {
        $uniqueNewUsers = $newlyCreatedUsers | Sort-Object -Unique
        foreach ($user in $uniqueNewUsers) {
            Write-Host "New user detected: $user" -ForegroundColor Yellow
            Append-Log -Path $eventLogFile -Text "ALERT: New user detected - $user"
            if ($user -notin $knownUsers) {
                $user | Add-Content -Path $knownUsersFile
                $knownUsers += $user
            }
        }
    }

    # Handle suspicious users
    if ($suspiciousActivity.Count -gt 0) {
        $suspiciousCounts = $suspiciousActivity | Group-Object
        foreach ($group in $suspiciousCounts) {
            if ($group.Count -ge $alertThreshold) {
                Write-Host "Suspicious activity detected for user: $($group.Name) - $($group.Count) events" -ForegroundColor Red
                Append-Log -Path $eventLogFile -Text "ALERT: Suspicious activity detected for user $($group.Name) - $($group.Count) events"
            }
        }
    }

    # ----- MONITOR WINDOWS SERVICES -----
    try {
        $AllServices = Get-WmiObject Win32_Service -ErrorAction Stop
        $UpdatedServices = @()

        foreach ($S in $AllServices) {
            try {
                $path = GetExecutablePath $S.PathName
                $score = 0
                $entropyScore = 0

                if (IsSuspiciousPath $S.PathName) { $score += 3 }
                if (IsUnsigned $S.PathName) { $score += 3 }
                if (IsHighEntropyName $S.Name) { $score += 2; $entropyScore = CalculateEntropy $S.Name }
                if (IsHighEntropyName $S.DisplayName) { 
                    $score += 1
                    $entropyScore = [Math]::Max($entropyScore, (CalculateEntropy $S.DisplayName))
                }
                if ([string]::IsNullOrEmpty($S.Description)) { $score += 1 }
                if (HasSuspiciousExtension $S.PathName) { $score += 2 }

                if ($score -ge $serviceMinScore) {
                    $key = $S.Name
                    $previousEntropy = if ($TrackedServices.ContainsKey($key)) { $TrackedServices[$key].Entropy } else { 0 }
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

        # Output service updates
        if ($UpdatedServices.Count -gt 0) {
            Write-Host "`n=== New or changed HIGH-ENTROPY services detected ===" -ForegroundColor Yellow
            $UpdatedServices | Sort-Object Score -Descending | Format-Table Name, DisplayName, Status, Score, Entropy, DetectedAt

            foreach ($svc in $UpdatedServices) {
                $logEntry = "[{0}] Name: {1}; DisplayName: {2}; Status: {3}; Score: {4}; Entropy: {5}; Path: {6}" -f `
                            $svc.DetectedAt.ToString("yyyy-MM-dd HH:mm:ss"), $svc.Name, $svc.DisplayName, $svc.Status, $svc.Score, $svc.Entropy, $svc.BinaryPath
                Append-Log -Path $serviceLogFile -Text $logEntry
            }
        }

    } catch {
        Write-Host "Warning: Could not retrieve services. Retrying..." -ForegroundColor DarkRed
    }

    Start-Sleep -Seconds 15
    Write-Host "`n"
}
