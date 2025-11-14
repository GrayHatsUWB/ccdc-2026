<#
.SYNOPSIS
    Real-time suspicious security event monitoring with logging, new user detection, and suspicious user alerts.

.DESCRIPTION
    Monitors Security event log every 15 seconds, logs events to a file in the script folder,
    identifies new users, and flags suspicious activity.
#>

# ---------------------------
# Configuration
# ---------------------------

# Folder where the script is running
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Log file and known users file in the script folder
$logFile = Join-Path $scriptDir "SuspiciousUsers.log"
$knownUsersFile = Join-Path $scriptDir "KnownUsers.txt"

$alertThreshold = 5   # Number of failed/suspicious events to flag a user

# Ensure known users file exists
if (-not (Test-Path $knownUsersFile)) { New-Item -Path $knownUsersFile -ItemType File -Force }

# Load known users
$knownUsers = @()
if (Test-Path $knownUsersFile) {
    $knownUsers = Get-Content $knownUsersFile
}

# Suspicious event definitions
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

Write-Host "Starting suspicious security event audit monitoring (every 15 seconds)...`n"

# ---------------------------
# Main Loop
# ---------------------------
while ($true) {
    $startTime = (Get-Date).AddSeconds(-15)

    $header = "====================================`nAudit Interval: $(Get-Date)`n===================================="
    Write-Host $header
    Add-Content -Path $logFile -Value $header

    $newlyCreatedUsers = @()
    $suspiciousActivity = @()

    foreach ($eventDef in $suspiciousEvents) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = $eventDef.Id
                StartTime = $startTime
            } -ErrorAction SilentlyContinue
        } catch { $events = @() }

        if ($events.Count -gt 0) {
            $msg = "`nFound $($events.Count) $($eventDef.Name) event(s):"
            Write-Host -ForegroundColor $eventDef.Color $msg
            Add-Content -Path $logFile -Value $msg

            foreach ($event in $events) {
                $xml       = [xml]$event.ToXml()
                $dataItems = $xml.Event.EventData.Data
                $details   = ""
                $targetUser = $null

                foreach ($field in $eventDef.Fields) {
                    $value = ($dataItems | Where-Object { $_.Name -eq $field } |
                              Select-Object -ExpandProperty "#text" -ErrorAction SilentlyContinue)
                    if ($value) { 
                        $details += "$($field): $($value); " 
                        if ($field -like "*UserName") { $targetUser = $value }
                    }
                }

                $timeStamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $logEntry  = "[$($timeStamp)] $($eventDef.Name) - $details"
                Write-Host -ForegroundColor $eventDef.Color "  $logEntry"
                Add-Content -Path $logFile -Value $logEntry

                # Track new users (for event 4720)
                if ($eventDef.Id -eq 4720 -and $targetUser -and ($targetUser -notin $knownUsers)) {
                    $newlyCreatedUsers += $targetUser
                }

                # Track suspicious users
                if ($eventDef.Id -in 4625,4740,4672 -and $targetUser) {
                    $suspiciousActivity += $targetUser
                }
            }
        }
        else {
            $msg = "`nNo $($eventDef.Name) events in the last 15 seconds."
            Write-Host -ForegroundColor Green $msg
            Add-Content -Path $logFile -Value $msg
        }
    }

    # ---------------------------
    # Handle New Users
    # ---------------------------
    if ($newlyCreatedUsers.Count -gt 0) {
        $uniqueNewUsers = $newlyCreatedUsers | Sort-Object -Unique
        foreach ($user in $uniqueNewUsers) {
            Write-Host "New user detected: $user" -ForegroundColor Yellow
            Add-Content -Path $logFile -Value "ALERT: New user detected - $user"
            # Add to known users
            if ($user -notin $knownUsers) {
                $user | Add-Content -Path $knownUsersFile
                $knownUsers += $user
            }
        }
    }

    # ---------------------------
    # Handle Suspicious Users
    # ---------------------------
    if ($suspiciousActivity.Count -gt 0) {
        $suspiciousCounts = $suspiciousActivity | Group-Object
        foreach ($group in $suspiciousCounts) {
            if ($group.Count -ge $alertThreshold) {
                Write-Host "Suspicious activity detected for user: $($group.Name) - $($group.Count) events" -ForegroundColor Red
                Add-Content -Path $logFile -Value "ALERT: Suspicious activity detected for user $($group.Name) - $($group.Count) events"
            }
        }
    }

    Start-Sleep -Seconds 15
    Write-Host "`n"
}
