<#
Competition script: Reset EVERY domain account password using NET USER
and export Username,Password to DomainUsersPasswords.csv for scoring engine.

RUN AS: Domain Admin
WARNING: This will break services running under domain accounts.
#>

# Output CSV path
$outCsv = Join-Path (Get-Location) "DomainUsersPasswords.csv"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path (Get-Location) "PasswordReset_$timestamp.log"

# Cryptographically secure password generator
function New-RandomPassword {
    param([int]$Length = 24)
    
    $chars = @()
    $chars += 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $chars += '0123456789'.ToCharArray()
    $chars += '!@#$%^&*()-_=+[]{}<>?'.ToCharArray()
    
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $byteBuffer = New-Object 'Byte[]' ($Length)
    $rng.GetBytes($byteBuffer)
    
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        $idx = $byteBuffer[$i] % $chars.Count
        [void]$sb.Append($chars[$idx])
    }
    
    # Ensure compliance with typical domain password complexity
    $pwd = $sb.ToString()
    if ($pwd -notmatch '[A-Z]') { $pwd = $pwd.Substring(0, $Length-1) + 'Z' }
    if ($pwd -notmatch '[a-z]') { $pwd = $pwd.Substring(0, $Length-1) + 'z' }
    if ($pwd -notmatch '\d')    { $pwd = $pwd.Substring(0, $Length-1) + '9' }
    if ($pwd -notmatch '[!@#\$%\^&\*\(\)\-_=+\[\]\{\}<>?]') { $pwd = $pwd.Substring(0, $Length-1) + '!' }
    
    return $pwd
}

$Results = @()
$Stats = @{
    Total = 0
    Success = 0
    Failed = 0
    FailedAccounts = @()
}

Write-Host "=== Starting Competition Password Reset ===" -ForegroundColor Cyan
Write-Host "Target: ALL domain accounts (excluding krbtgt and svc_*)" -ForegroundColor Yellow
Write-Host "Output: $outCsv" -ForegroundColor Cyan
Write-Host "Logging: $logFile`n" -ForegroundColor Cyan

# --- NEW USER ENUMERATION LOGIC ---
Write-Host "Querying domain users via 'net user /domain'..." -ForegroundColor Cyan
$rawOutput = net user /domain 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: 'net user /domain' failed. Are you connected to the DC?" -ForegroundColor Red
    exit 1
}

# Parse the columnar output of net user
# The output has a header, a dashed line, columns of users, and a footer.
$allUsers = @()
$parsing = $false

foreach ($line in $rawOutput) {
    if ($line -match '^-+') {
        # Found the separator line, start capturing after this
        $parsing = $true
        continue
    }
    if ($line -match 'The command completed successfully') {
        # Found the footer, stop capturing
        $parsing = $false
        break
    }
    
    if ($parsing -and -not [string]::IsNullOrWhiteSpace($line)) {
        # Split line by whitespace to get columns and add to list
        $parts = $line -split '\s+'
        foreach ($part in $parts) {
            if (-not [string]::IsNullOrWhiteSpace($part)) {
                $allUsers += $part
            }
        }
    }
}

# Remove critical system accounts and Service Accounts (svc_)
# NOTE: Removing krbtgt prevents breaking the entire domain trust/kerberos
# UPDATED: Added logic to skip svc_*
$userList = $allUsers | Where-Object { 
    $_ -ne 'krbtgt' -and 
    $_ -notlike 'svc_*' 
}

$Stats.Total = $userList.Count
Write-Host "Found $($Stats.Total) accounts (excluding krbtgt/svc_). Beginning password resets...`n" -ForegroundColor Cyan

# --- PROCESS USERS ---
foreach ($sam in $userList) {
    
    Write-Host "Processing: $sam" -NoNewline
    
    # Generate password
    $plain = New-RandomPassword -Length 24
    
    # Reset password using NET USER
    try {
        # Usage: net user <username> <password> /domain
        # We redirect StdErr to StdOut (2>&1) to capture error messages
        $netUserResult = & net user "$sam" "$plain" /domain 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $Stats.Success++
            Write-Host " [SUCCESS]" -ForegroundColor Green
            
            $Results += [PSCustomObject]@{
                Username = $sam
                Password = $plain
                Status = "SUCCESS"
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | SUCCESS | $sam" | Out-File -FilePath $logFile -Append
        }
        else {
            $Stats.Failed++
            $Stats.FailedAccounts += $sam
            # Clean up error message (convert array to string if needed)
            $errorMsg = ($netUserResult | Out-String).Trim()
            
            Write-Host " [FAILED]" -ForegroundColor Red
            
            $Results += [PSCustomObject]@{
                Username = $sam
                Password = "RESET_FAILED"
                Status = "FAILED: $errorMsg"
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | FAILED | $sam | $errorMsg" | Out-File -FilePath $logFile -Append
        }
    }
    catch {
        $Stats.Failed++
        $Stats.FailedAccounts += $sam
        $errorMsg = $_.Exception.Message
        
        Write-Host " [EXCEPTION]" -ForegroundColor Red
        
        $Results += [PSCustomObject]@{
            Username = $sam
            Password = "RESET_FAILED"
            Status = "EXCEPTION: $errorMsg"
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | EXCEPTION | $sam | $errorMsg" | Out-File -FilePath $logFile -Append
    }
}

# Export results (only Username,Password for scoring engine)
$Results | Select-Object Username, Password | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# Display summary
Write-Host "`n=== RESET COMPLETE ===" -ForegroundColor Cyan
Write-Host "Total Accounts: $($Stats.Total)" -ForegroundColor White
Write-Host "Successful: $($Stats.Success)" -ForegroundColor Green
Write-Host "Failed: $($Stats.Failed)" -ForegroundColor Red

if ($Stats.Failed -gt 0) {
    Write-Host "`nFailed Accounts (Check log for details):" -ForegroundColor Red
    $Stats.FailedAccounts | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

Write-Host "`nCSV exported to: $outCsv" -ForegroundColor Cyan
Write-Host "Log file (detailed): $logFile" -ForegroundColor Cyan
if ($Stats.Total -gt 0) {
    Write-Host "Success rate: $(([math]::Round($Stats.Success / $Stats.Total * 100, 2)))%" -ForegroundColor Cyan
}
