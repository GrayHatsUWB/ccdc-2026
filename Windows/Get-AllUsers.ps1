<#
.SYNOPSIS
    Lists every user account and writes them to a file, one username per row.
.DESCRIPTION
    Uses Active Directory when the AD module is present (domain controller or
    RSAT box); otherwise falls back to local accounts. Always writes a file:
    a .csv gets an unquoted "Username" header column, any other
    extension (.txt) gets bare names with no header. Either way it is one
    username per row.
.PARAMETER Local
    Force local accounts only, even on a domain controller.
.PARAMETER OutFile
    Where to write the list. Defaults to .\users.csv
.EXAMPLE
    .\Get-AllUsers.ps1
    .\Get-AllUsers.ps1 -OutFile users.txt
    .\Get-AllUsers.ps1 -Local -OutFile .\local-users.csv
.NOTES
    Read-only: this script never modifies the host.
#>
[CmdletBinding()]
param(
    [switch]$Local,
    [string]$OutFile = ".\users.csv"
)

if (-not $Local -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $users = Get-ADUser -Filter * -ResultSetSize $null | Select-Object -ExpandProperty SamAccountName
}
elseif (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    $users = Get-LocalUser | Select-Object -ExpandProperty Name
}
else {
    # PowerShell 2.0 / older hosts without the LocalAccounts module
    $users = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" |
        Select-Object -ExpandProperty Name
}

$users = @($users | Sort-Object -Unique)
$users

if ([System.IO.Path]::GetExtension($OutFile) -eq ".csv") {
    # Written by hand rather than with Export-Csv, which always quotes values
    @("Username") + $users | Set-Content -Path $OutFile -Encoding ASCII
}
else {
    $users | Set-Content -Path $OutFile -Encoding ASCII
}

Write-Host "`nWrote $($users.Count) usernames to $OutFile" -ForegroundColor Green
