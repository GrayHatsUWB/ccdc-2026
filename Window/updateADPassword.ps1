<#
Minimal script: Reset every domain user's password to a unique random password
and export Username,Password to DomainUsersPasswords.csv.

RUN AS: Account with permission to reset domain user passwords (e.g., Domain Admin).
WARNING: This will change passwords for ALL domain users. Use with extreme caution.
#>

Import-Module ActiveDirectory -ErrorAction Stop

# Output CSV path (current directory)
$outCsv = Join-Path (Get-Location) "DomainUsersPasswords.csv"

# Random password generator function (cryptographically secure)
function New-RandomPassword {
    param(
        [int] $Length = 20
    )

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

    # Ensure password has at least one of each required character class (if needed)
    $pwd = $sb.ToString()
    if ($pwd -notmatch '[A-Z]') { $pwd = $pwd.Substring(1) + 'A' }
    if ($pwd -notmatch '[a-z]') { $pwd = $pwd.Substring(1) + 'a' }
    if ($pwd -notmatch '\d')    { $pwd = $pwd.Substring(1) + '0' }
    if ($pwd -notmatch '[!@#\$%\^&\*\(\)\-_=+\[\]\{\}<>?]') { $pwd = $pwd.Substring(1) + '!' }

    return $pwd
}

$Results = @()

# Enumerate all domain users and reset each password to a unique random password
Get-ADUser -Filter * -Properties SamAccountName | ForEach-Object {
    $sam = $_.SamAccountName

    # Generate a random password per-user (length 20, adjust if desired)
    $plain = New-RandomPassword -Length 20
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force

    # Reset password (requires appropriate privileges)
    Set-ADAccountPassword -Identity $sam -NewPassword $secure -Reset -ErrorAction Stop

    # Optionally force change at next logon? (NOT requested — omitted)

    # Add to results (username + plaintext password)
    $Results += [PSCustomObject]@{
        Username = $sam
        Password = $plain
    }

    Write-Host "Password reset for $sam"
}

# Export CSV (plaintext passwords)
$Results | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
Write-Host "Wrote passwords to $outCsv"