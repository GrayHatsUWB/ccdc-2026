<#
Competition script: Reset EVERY domain account password using dsquery/dsmod
and export Username,Password to DomainUsersPasswords.csv for scoring engine.

RUN AS: Domain Admin
WARNING: This will break services running under domain accounts. Use only in competition environments.
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
Write-Host "Target: ALL domain accounts (dsquery/dsmod)" -ForegroundColor Yellow
Write-Host "Output: $outCsv" -ForegroundColor Cyan
Write-Host "Logging: $logFile`n" -ForegroundColor Cyan

# Query all domain user DNs using dsquery
Write-Host "Querying all domain users..." -ForegroundColor Cyan
$dsqueryOutput = & dsquery user -limit 0 2>$null

if ($null -eq $dsqueryOutput) {
    Write-Host "ERROR: dsquery failed - verify you have AD tools installed and domain connectivity" -ForegroundColor Red
    exit 1
}

# Convert output to array (handle single result or multiple)
$userDNs = @($dsqueryOutput)
$Stats.Total = $userDNs.Count

Write-Host "Found $($Stats.Total) accounts. Beginning password resets...`n" -ForegroundColor Cyan

# Process each user
foreach ($dn in $userDNs) {
    $dn = $dn.Trim()  # Remove whitespace
    
    if ([string]::IsNullOrEmpty($dn)) {
        continue
    }
    
    # Extract username from DN (CN=username,...)
    $cnMatch = $dn -match 'CN=([^,]+)'
    $sam = $matches[1]
    
    Write-Host "Processing: $sam" -NoNewline
    
    # Generate password
    $plain = New-RandomPassword -Length 24
    
    # Reset password using dsmod (quotes required for special chars in password)
    try {
        # dsmod user DN -pwd password [-s server]
        $dsmodResult = & dsmod user "$dn" -pwd "$plain" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $Stats.Success++
            Write-Host " [SUCCESS]" -ForegroundColor Green
            
            $Results += [PSCustomObject]@{
                Username = $sam
                Password = $plain
                Status = "SUCCESS"
                DN = $dn
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | SUCCESS | $sam | $dn" | Out-File -FilePath $logFile -Append
        }
        else {
            $Stats.Failed++
            $Stats.FailedAccounts += $sam
            $errorMsg = $dsmodResult -join "; "
            
            Write-Host " [FAILED: $errorMsg]" -ForegroundColor Red
            
            $Results += [PSCustomObject]@{
                Username = $sam
                Password = "RESET_FAILED"
                Status = "FAILED: $errorMsg"
                DN = $dn
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | FAILED | $sam | $errorMsg" | Out-File -FilePath $logFile -Append
        }
    }
    catch {
        $Stats.Failed++
        $Stats.FailedAccounts += $sam
        $errorMsg = $_.Exception.Message
        
        Write-Host " [EXCEPTION: $errorMsg]" -ForegroundColor Red
        
        $Results += [PSCustomObject]@{
            Username = $sam
            Password = "RESET_FAILED"
            Status = "EXCEPTION: $errorMsg"
            DN = $dn
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
    Write-Host "`nFailed Accounts:" -ForegroundColor Red
    $Stats.FailedAccounts | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

Write-Host "`nCSV exported to: $outCsv" -ForegroundColor Cyan
Write-Host "Log file (detailed): $logFile" -ForegroundColor Cyan
Write-Host "Success rate: $(([math]::Round($Stats.Success / $Stats.Total * 100, 2)))%" -ForegroundColor Cyan
