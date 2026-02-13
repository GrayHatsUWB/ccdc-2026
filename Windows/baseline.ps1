<#
PRCCDC_MenuTriage.ps1
Interactive menu triage script (PowerShell 5.1+).
Select which steps to run; outputs to timestamped folder under .\Logs (next to script).

Run elevated for best results.
#>

[CmdletBinding()]
param(
  [string]$TreeRoot = "C:\",
  [switch]$RunADAdminsDefault
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# -------- OUTPUT ROOT (Logs folder next to script) --------
$ScriptBase = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LogsRoot   = Join-Path $ScriptBase "Logs"
if (-not (Test-Path $LogsRoot)) { New-Item -ItemType Directory -Path $LogsRoot | Out-Null }

function New-RunFolder {
  param([string]$Base)
  $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $dir = Join-Path $Base "triage_$stamp"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  return $dir
}

function Write-Header {
  param([string]$Path, [string]$Title)
  $line = ("=" * 80)
  @(
    $line
    $Title
    ("Host: {0}" -f $env:COMPUTERNAME)
    ("User: {0}" -f $env:USERNAME)
    ("Time: {0}" -f (Get-Date).ToString("s"))
    $line
    ""
  ) | Out-File -FilePath $Path -Encoding utf8 -Append
}

function Run-PS {
  param([scriptblock]$Script, [string]$OutFile, [string]$Title)
  Write-Header -Path $OutFile -Title $Title
  try { & $Script 2>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Append }
  catch { $_ | Out-File -FilePath $OutFile -Encoding utf8 -Append }
}

function Run-CMD {
  param([string]$CommandLine, [string]$OutFile, [string]$Title)
  Write-Header -Path $OutFile -Title $Title
  try { cmd.exe /c $CommandLine 2>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Append }
  catch { $_ | Out-File -FilePath $OutFile -Encoding utf8 -Append }
}

function Pause-Enter { Read-Host "Press ENTER to continue" | Out-Null }

# --- Action implementations ---
function Do-Services   { param($OutDir)
  Run-PS { Get-Service | Sort-Object Status, Name | Format-Table -AutoSize } (Join-Path $OutDir "services1.txt") "Get-Service"
}

function Do-Schtasks    { param($OutDir)
  Run-CMD 'schtasks /query /fo LIST /v' (Join-Path $OutDir "tasks.txt") "schtasks /query /fo LIST /v"
}

function Do-Netstat     { param($OutDir)
  Run-CMD 'netstat -ano' (Join-Path $OutDir "netstat1.txt") "netstat -ano"
}

function Do-StartupDirs { param($OutDir)
  Run-PS {
    $paths = @(
      "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
      "C:\Users\localuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($p in $paths) {
      "`n--- $p ---"
      if (Test-Path $p) { Get-ChildItem -Force -ErrorAction SilentlyContinue $p }
      else { "NOT FOUND" }
    }
  } (Join-Path $OutDir "startup1.txt") "Startup folder listings"
}

function Do-LocalAdmins  { param($OutDir)
  Run-CMD 'net localgroup administrators' (Join-Path $OutDir "localgroupadmins.txt") "net localgroup administrators"
}

function Do-TempListing  { param($OutDir)
  Run-PS { if (Test-Path "C:\temp") { Get-ChildItem -Force "C:\temp" } else { "C:\temp NOT FOUND" } } `
    (Join-Path $OutDir "temp1.txt") "C:\temp listing"
}

function Do-PublicListing { param($OutDir)
  Run-PS { if (Test-Path "C:\Users\Public") { Get-ChildItem -Force "C:\Users\Public" } else { "C:\Users\Public NOT FOUND" } } `
    (Join-Path $OutDir "public1.txt") "C:\Users\Public listing"
}

function Do-ProgramFiles { param($OutDir)
  Run-PS { if (Test-Path "C:\Program Files") { Get-ChildItem -Force "C:\Program Files" } else { "C:\Program Files NOT FOUND" } } `
    (Join-Path $OutDir "programs64.txt") "C:\Program Files listing"
}

function Do-ProgramFilesX86 { param($OutDir)
  Run-PS { if (Test-Path "C:\Program Files (x86)") { Get-ChildItem -Force "C:\Program Files (x86)" } else { "C:\Program Files (x86) NOT FOUND" } } `
    (Join-Path $OutDir "program86.txt") "C:\Program Files (x86) listing"
}

function Do-AppDataLocal { param($OutDir)
  Run-PS {
    $p = "C:\Users\localuser\AppData\Local"
    if (Test-Path $p) { Get-ChildItem -Force $p } else { "$p NOT FOUND" }
  } (Join-Path $OutDir "appdata1.txt") "localuser AppData\Local listing"
}

function Do-Tree         { param($OutDir, $TreeRoot)
  Run-CMD ('tree "{0}" /F /A' -f $TreeRoot) (Join-Path $OutDir "tree1.txt") ("tree /F /A of {0} (WARNING: huge)" -f $TreeRoot)
}

function Do-AutorunsReg   { param($OutDir)
  $regOut = Join-Path $OutDir "autoruns_reg.txt"
  Write-Header -Path $regOut -Title "Registry autoruns/persistence queries"

  $regQueries = @(
    'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s',
    'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s',
    'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s',
    'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s',
    'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /s',
    'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /s',
    'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell',
    'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit',
    'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger',
    'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath',
    'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v Start'
  )

  foreach ($q in $regQueries) {
    "`n--- $q ---" | Out-File -FilePath $regOut -Encoding utf8 -Append
    cmd.exe /c $q 2>&1 | Out-File -FilePath $regOut -Encoding utf8 -Append
  }

  Run-PS -Title "Quick scan for script-type autoruns in Run/RunOnce keys" -OutFile (Join-Path $OutDir "autoruns_scriptscan.txt") -Script {
    $keys = @(
      "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
      "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
      "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($k in $keys) {
      "`n--- $k ---"
      if (Test-Path $k) {
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        $props.PSObject.Properties |
          Where-Object { $_.Name -notmatch '^PS' } |
          ForEach-Object {
            $val = [string]$_.Value
            if ($val -match '\.(bat|cmd|vbs|js|jse|ps1)\b' -or $val -match 'wscript|cscript|powershell|cmd\.exe') {
              "{0} = {1}" -f $_.Name, $val
            }
          }
      } else { "NOT FOUND" }
    }
  }
}

function Do-Arp { param($OutDir)
  Run-CMD 'arp -a' (Join-Path $OutDir "arp1.txt") "arp -a"
}

function Do-ADAdmins { param($OutDir)
  # Enumeration only (requires AD module/domain context)
  Run-PS -Title "AD Admins enumeration (PyroTek3 Get-ADAdmins.ps1)" -OutFile (Join-Path $OutDir "ad_admins.txt") -Script {
    $raw = "https://raw.githubusercontent.com/PyroTek3/Misc/main/Get-ADAdmins.ps1"
    $local = Join-Path $using:OutDir "Get-ADAdmins.ps1"

    "Downloading: $raw"
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $raw -OutFile $local -ErrorAction Stop
      "Saved: $local"
    } catch {
      "Download failed: $_"
      if (-not (Test-Path $local)) { return }
    }

    try {
      . $local
      if (Get-Command Get-ADAdmins -ErrorAction SilentlyContinue) {
        Get-ADAdmins | Out-String
      } else {
        "Loaded script, but Get-ADAdmins function not found."
      }
    } catch {
      "Execution failed: $_"
    }
  }
}

# --- Create run folder under .\Logs ---
$OutDir = New-RunFolder -Base $LogsRoot

# Optional: capture console output too
try { Start-Transcript -Path (Join-Path $OutDir "master_transcript.txt") -Append | Out-Null } catch {}

$menu = @(
  @{ Key = 1;  Name = "Get-Service";                                   Action = { Do-Services $OutDir } },
  @{ Key = 2;  Name = "Scheduled Tasks (schtasks /query /v)";          Action = { Do-Schtasks $OutDir } },
  @{ Key = 3;  Name = "Netstat (netstat -ano)";                        Action = { Do-Netstat $OutDir } },
  @{ Key = 4;  Name = "Startup folders listing";                       Action = { Do-StartupDirs $OutDir } },
  @{ Key = 5;  Name = "Local Administrators group";                    Action = { Do-LocalAdmins $OutDir } },
  @{ Key = 6;  Name = "C:\temp listing";                               Action = { Do-TempListing $OutDir } },
  @{ Key = 7;  Name = "C:\Users\Public listing";                       Action = { Do-PublicListing $OutDir } },
  @{ Key = 8;  Name = "C:\Program Files listing";                      Action = { Do-ProgramFiles $OutDir } },
  @{ Key = 9;  Name = "C:\Program Files (x86) listing";                Action = { Do-ProgramFilesX86 $OutDir } },
  @{ Key = 10; Name = "localuser AppData\Local listing";               Action = { Do-AppDataLocal $OutDir } },
  @{ Key = 12; Name = "Tree (tree /F /A) (WARNING: large)";            Action = { Do-Tree $OutDir $TreeRoot } },
  @{ Key = 13; Name = "Autoruns Registry queries (Run/Winlogon/etc.)"; Action = { Do-AutorunsReg $OutDir } },
  @{ Key = 14; Name = "ARP table (arp -a)";                            Action = { Do-Arp $OutDir } },
  @{ Key = 15; Name = "AD Admins enumeration (optional)";              Action = { Do-ADAdmins $OutDir } }
)

function Show-Menu {
  Clear-Host
  Write-Host "PRCCDC Menu Triage" -ForegroundColor Cyan
  Write-Host "Output folder: $OutDir"
  Write-Host ""
  foreach ($item in $menu) {
    "{0,2}) {1}" -f $item.Key, $item.Name | Write-Host
  }
  Write-Host ""
  Write-Host "A) Run ALL"
  Write-Host "S) Show output folder"
  Write-Host "Q) Quit"
  Write-Host ""
  Write-Host "Enter choices like: 1,3,5 or 13  (comma-separated)."
}

function Run-Selection {
  param([string]$inputStr)

  if ([string]::IsNullOrWhiteSpace($inputStr)) { return }
  $trim = $inputStr.Trim()

  if ($trim -match '^(?i)q$') {
    try { Stop-Transcript | Out-Null } catch {}
    exit
  }

  if ($trim -match '^(?i)s$') {
    Write-Host "`nOpening: $OutDir"
    Start-Process explorer.exe $OutDir
    Pause-Enter
    return
  }

  if ($trim -match '^(?i)a$') {
    foreach ($item in $menu) {
      try {
        Write-Host "[*] Running: $($item.Key)) $($item.Name)"
        & $item.Action
      } catch {
        Write-Host "[!] Error running $($item.Name): $_" -ForegroundColor Yellow
      }
    }
    return
  }

  $parts = $trim -split '\s*,\s*' | Where-Object { $_ -ne "" }
  foreach ($p in $parts) {
    if ($p -notmatch '^\d+$') {
      Write-Host "[!] Skipping invalid selection: $p" -ForegroundColor Yellow
      continue
    }
    $k = [int]$p
    $hit = $menu | Where-Object { $_.Key -eq $k } | Select-Object -First 1
    if (-not $hit) {
      Write-Host "[!] Unknown selection: $k" -ForegroundColor Yellow
      continue
    }
    try {
      Write-Host "[*] Running: $($hit.Key)) $($hit.Name)"
      & $hit.Action
    } catch {
      Write-Host "[!] Error running $($hit.Name): $_" -ForegroundColor Yellow
    }
  }
}

# Auto-run AD admins if requested via parameter
if ($RunADAdminsDefault) {
  try { Do-ADAdmins $OutDir } catch {}
}

while ($true) {
  Show-Menu
  $choice = Read-Host "Selection"
  Run-Selection $choice

  $summary = Join-Path $OutDir "RUN_SUMMARY.txt"
  Run-PS -Title "Summary (updated)" -OutFile $summary -Script {
    "Output folder: $using:OutDir"
    "Generated files:"
    Get-ChildItem -File $using:OutDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
  }

  Write-Host "`n[+] Completed selection. Output: $OutDir`n"
  Pause-Enter
}
