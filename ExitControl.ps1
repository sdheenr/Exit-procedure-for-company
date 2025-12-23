<# 
ExitControl.ps1 (PowerShell 5.1 compatible)
Menu-driven exit/offboarding controls.

Features:
1) Password prompt before menu (hash-based; default password: Rafic@786786@Dubai@123$)
2) Toggle HOSTS block list (common upload sites)
3) Toggle USB Mass Storage disable
4) Toggle Chrome/Edge Incognito/InPrivate disable (policy)
5) Toggle Firewall block for browsers outbound (strong)
6) Optional: Disable Snipping tools (rename .exe; reversible)
7) Optional (Aggressive): Disable OpenWith.exe (rename; reversible)
8) Change local Windows user password
9) Checklist + Rollback guide
10) Restore ALL

Backups/State stored in: C:\ProgramData\ExitControl\
Run as Administrator.
#>

$ErrorActionPreference = "Stop"

# ---------------- CONFIG ----------------
$StateDir   = "C:\ProgramData\ExitControl"
$StateFile  = Join-Path $StateDir "state.json"
$HostsPath  = "$env:WINDIR\System32\drivers\etc\hosts"

$ScriptPasswordPlain = "Rafic@786786@Dubai@123$"

$BlockDomains = @(
  "drive.google.com",
  "mail.google.com",
  "gmail.com",
  "dropbox.com",
  "www.dropbox.com",
  "wetransfer.com",
  "www.wetransfer.com",
  "mega.nz",
  "sendgb.com",
  "file.io"
)

$SnipPaths = @(
  "$env:WINDIR\System32\SnippingTool.exe",
  "$env:WINDIR\System32\ScreenSketch.exe"
)

$OpenWithPath = "$env:WINDIR\System32\OpenWith.exe"

$FwGroup = "ExitControl-BrowserBlock"
$BrowserExePaths = @(
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
  "$env:ProgramFiles(x86)\Mozilla Firefox\firefox.exe"
)

# ---------------- HELPERS ----------------
function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
  if (-not $isAdmin) {
    Write-Host "`nERROR: Run PowerShell as Administrator.`n" -ForegroundColor Red
    exit 1
  }
}

function Ensure-StateDir {
  if (-not (Test-Path $StateDir)) {
    New-Item -Path $StateDir -ItemType Directory | Out-Null
  }
}

function Get-Sha256Hex([string]$text) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
  ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Load-State {
  Ensure-StateDir
  if (Test-Path $StateFile) {
    return (Get-Content $StateFile -Raw | ConvertFrom-Json)
  }

  # initial
  $state = [pscustomobject]@{
    CreatedAt = (Get-Date).ToString("s")
    Auth = @{
      PasswordHash = $DefaultScriptPasswordHash
    }
    Hosts = @{
      BackedUp = $false
      BackupPath = (Join-Path $StateDir "hosts.backup")
      ManagedMarker = "# ExitControlManaged"
      Enabled = $false
    }
    USBSTOR = @{
      BackedUp = $false
      OriginalStart = $null
      Enabled = $false
    }
    BrowserPolicies = @{
      BackedUp = $false
      Original = @{
        ChromeIncognitoModeAvailability = $null
        EdgeInPrivateModeAvailability   = $null
      }
      Enabled = $false
    }
    Firewall = @{
      BrowserBlockEnabled = $false
    }
    Renames = @() # {Path, BackupPath, Enabled}
  }
  return $state
}

function Save-State($state) {
  Ensure-StateDir
  $state | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFile -Encoding UTF8
}

function Prompt-ScriptPassword {
  for ($i=1; $i -le 3; $i++) {

    # Read as SecureString
    $sec = Read-Host "Enter ExitControl password" -AsSecureString

    # Convert SecureString -> plain (reliable in PowerShell 5.1)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try {
      $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    if ($plain -ceq $ScriptPasswordPlain) {
      Write-Host "Access granted." -ForegroundColor Green
      return
    } else {
      Write-Host "Wrong password. Attempt $i/3" -ForegroundColor Red
    }
  }

  Write-Host "Too many wrong attempts. Exiting." -ForegroundColor Red
  exit 1
}

# -------- HOSTS block --------
function Backup-HostsIfNeeded($state) {
  if (-not $state.Hosts.BackedUp) {
    Copy-Item -Path $HostsPath -Destination $state.Hosts.BackupPath -Force
    $state.Hosts.BackedUp = $true
    Save-State $state
  }
}

function Set-HostsBlock($state, [bool]$Enable) {
  Backup-HostsIfNeeded $state

  $marker = $state.Hosts.ManagedMarker
  $content = Get-Content $HostsPath

  $startIdx = [Array]::IndexOf($content, "$marker BEGIN")
  $endIdx   = [Array]::IndexOf($content, "$marker END")

  if ($startIdx -ge 0 -and $endIdx -ge 0 -and $endIdx -ge $startIdx) {
    $before = @()
    if ($startIdx -gt 0) { $before = $content[0..($startIdx-1)] }
    $after = @()
    if ($endIdx -lt ($content.Count-1)) { $after = $content[($endIdx+1)..($content.Count-1)] }
    $content = @($before + $after)
  }

  if ($Enable) {
    $blockLines = @()
    $blockLines += "$marker BEGIN"
    foreach ($d in $BlockDomains) {
      $blockLines += "127.0.0.1 $d"
      $blockLines += "::1 $d"
    }
    $blockLines += "$marker END"
    $content = @($content + "" + $blockLines)
  }

  Set-Content -Path $HostsPath -Value $content -Encoding ASCII
  ipconfig /flushdns | Out-Null

  $state.Hosts.Enabled = $Enable
  Save-State $state
}

# -------- USB disable --------
function Backup-USBSTORIfNeeded($state) {
  if (-not $state.USBSTOR.BackedUp) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
    $val = (Get-ItemProperty -Path $key -Name Start -ErrorAction SilentlyContinue).Start
    $state.USBSTOR.OriginalStart = $val
    $state.USBSTOR.BackedUp = $true
    Save-State $state
  }
}

function Set-USBStorage($state, [bool]$Disable) {
  Backup-USBSTORIfNeeded $state
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
  if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }

  if ($Disable) {
    Set-ItemProperty -Path $key -Name Start -Type DWord -Value 4
    $state.USBSTOR.Enabled = $true
  } else {
    $restoreVal = 3
    if ($null -ne $state.USBSTOR.OriginalStart) { $restoreVal = $state.USBSTOR.OriginalStart }
    Set-ItemProperty -Path $key -Name Start -Type DWord -Value $restoreVal
    $state.USBSTOR.Enabled = $false
  }

  Save-State $state
}

# -------- Browser policies --------
function Backup-BrowserPoliciesIfNeeded($state) {
  if (-not $state.BrowserPolicies.BackedUp) {
    $chromeKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    $edgeKey   = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

    $c = (Get-ItemProperty -Path $chromeKey -Name IncognitoModeAvailability -ErrorAction SilentlyContinue).IncognitoModeAvailability
    $e = (Get-ItemProperty -Path $edgeKey -Name InPrivateModeAvailability -ErrorAction SilentlyContinue).InPrivateModeAvailability

    $state.BrowserPolicies.Original.ChromeIncognitoModeAvailability = $c
    $state.BrowserPolicies.Original.EdgeInPrivateModeAvailability   = $e
    $state.BrowserPolicies.BackedUp = $true
    Save-State $state
  }
}

function Set-BrowserPrivacyPolicies($state, [bool]$DisablePrivateModes) {
  Backup-BrowserPoliciesIfNeeded $state

  $chromeKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
  $edgeKey   = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
  if (-not (Test-Path $chromeKey)) { New-Item -Path $chromeKey -Force | Out-Null }
  if (-not (Test-Path $edgeKey))   { New-Item -Path $edgeKey   -Force | Out-Null }

  if ($DisablePrivateModes) {
    Set-ItemProperty -Path $chromeKey -Name IncognitoModeAvailability -Type DWord -Value 1
    Set-ItemProperty -Path $edgeKey   -Name InPrivateModeAvailability -Type DWord -Value 1
    $state.BrowserPolicies.Enabled = $true
  } else {
    $c0 = $state.BrowserPolicies.Original.ChromeIncognitoModeAvailability
    $e0 = $state.BrowserPolicies.Original.EdgeInPrivateModeAvailability

    if ($null -eq $c0) { Remove-ItemProperty -Path $chromeKey -Name IncognitoModeAvailability -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -Path $chromeKey -Name IncognitoModeAvailability -Type DWord -Value $c0 }

    if ($null -eq $e0) { Remove-ItemProperty -Path $edgeKey -Name InPrivateModeAvailability -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -Path $edgeKey -Name InPrivateModeAvailability -Type DWord -Value $e0 }

    $state.BrowserPolicies.Enabled = $false
  }

  Save-State $state
}

# -------- Controlled renames --------
function Rename-FileControlled($state, [string]$Path, [bool]$Enable) {
  if (-not (Test-Path $Path)) { return }

  $existing = $null
  foreach ($r in $state.Renames) {
    if ($r.Path -eq $Path) { $existing = $r; break }
  }

  if (-not $existing) {
    $backup = Join-Path $StateDir ((Split-Path $Path -Leaf) + ".backup")
    $obj = [pscustomobject]@{ Path=$Path; BackupPath=$backup; Enabled=$false }
    $state.Renames += $obj
    Save-State $state
    $existing = $obj
  }

  if ($Enable) {
    if ($existing.Enabled) { return }
    Copy-Item -Path $Path -Destination $existing.BackupPath -Force
    Move-Item -Path $Path -Destination ($Path + ".disabled") -Force
    $existing.Enabled = $true
  } else {
    if (-not $existing.Enabled) { return }
    $disabled = $Path + ".disabled"
    if (Test-Path $disabled) {
      Move-Item -Path $disabled -Destination $Path -Force
    } elseif (Test-Path $existing.BackupPath) {
      Copy-Item -Path $existing.BackupPath -Destination $Path -Force
    }
    $existing.Enabled = $false
  }

  Save-State $state
}

# -------- Firewall browser block --------
function Set-FirewallBrowserBlock($state, [bool]$Enable) {
  Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

  if ($Enable) {
    foreach ($p in $BrowserExePaths) {
      if (Test-Path $p) {
        New-NetFirewallRule `
          -DisplayName ("ExitControl Block " + (Split-Path $p -Leaf)) `
          -Group $FwGroup `
          -Direction Outbound `
          -Action Block `
          -Program $p `
          -Profile Any | Out-Null
      }
    }
    $state.Firewall.BrowserBlockEnabled = $true
  } else {
    $state.Firewall.BrowserBlockEnabled = $false
  }

  Save-State $state
}

# -------- Change local Windows password --------
function Change-WindowsPassword {
  $user = Read-Host "Enter local username to change password (blank = current user)"
  if ([string]::IsNullOrWhiteSpace($user)) { $user = $env:USERNAME }

  try {
    $newPwd = Read-Host "Enter NEW Windows password for '$user'" -AsSecureString
    Set-LocalUser -Name $user -Password $newPwd
    Write-Host "Windows password updated for: $user" -ForegroundColor Green
  } catch {
    Write-Host "Failed to change password. This works for LOCAL users only." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
  }
}

# -------- UI / Info --------
function Show-Status($state) {
  Write-Host "`n--- Current ExitControl Status ---" -ForegroundColor Cyan

  $hostsTxt = "OFF"; if ($state.Hosts.Enabled) { $hostsTxt = "ON" }
  $usbTxt   = "OFF"; if ($state.USBSTOR.Enabled) { $usbTxt = "ON" }
  $privTxt  = "OFF"; if ($state.BrowserPolicies.Enabled) { $privTxt = "ON" }
  $fwTxt    = "OFF"; if ($state.Firewall.BrowserBlockEnabled) { $fwTxt = "ON" }

  $snipOn = $false
  foreach ($r in $state.Renames) {
    if (($SnipPaths -contains $r.Path) -and $r.Enabled) { $snipOn = $true }
  }
  $snipTxt = "OFF"; if ($snipOn) { $snipTxt = "ON" }

  $openWithOn = $false
  foreach ($r in $state.Renames) {
    if (($r.Path -eq $OpenWithPath) -and $r.Enabled) { $openWithOn = $true }
  }
  $owTxt = "OFF"; if ($openWithOn) { $owTxt = "ON (Aggressive)" }

  Write-Host ("HOSTS Blocking:             " + $hostsTxt)
  Write-Host ("USB Mass Storage Disabled:  " + $usbTxt)
  Write-Host ("Incognito/InPrivate Block:  " + $privTxt)
  Write-Host ("Firewall Browser Block:     " + $fwTxt)
  Write-Host ("Snipping Tools Disabled:    " + $snipTxt)
  Write-Host ("OpenWith.exe Disabled:      " + $owTxt)
  Write-Host ("State file:                 " + $StateFile)
  Write-Host "--------------------------------`n" -ForegroundColor Cyan
}

function Print-Checklist {
@"
CHECKLIST: Verify Leak Paths

A) Browser uploads
  [ ] WeTransfer/Dropbox/Mega upload -> FAIL or site blocked
  [ ] Gmail attachment in browser -> FAIL or gmail blocked
  [ ] Drag & drop file into any web upload -> FAIL

B) USB / External storage
  [ ] Plug USB -> not accessible

C) OneDrive (Company)
  [ ] Edit a doc inside OneDrive folder -> sync OK

D) Private browsing
  [ ] Chrome Incognito disabled
  [ ] Edge InPrivate disabled

E) Firewall (if enabled)
  [ ] Browsers cannot browse
  [ ] OneDrive sync still works
"@ | Write-Host
}

function Print-RollbackGuide {
@"
ROLLBACK GUIDE

1) Run ExitControl.ps1 as Administrator
2) Choose: Restore ALL
3) Reboot
4) Verify normal operation

Backups/state stored in: C:\ProgramData\ExitControl\
Hosts backup: hosts.backup
"@ | Write-Host
}

function Restore-All($state) {
  # Hosts restore
  if ($state.Hosts.BackedUp -and (Test-Path $state.Hosts.BackupPath)) {
    Copy-Item $state.Hosts.BackupPath $HostsPath -Force
    ipconfig /flushdns | Out-Null
    $state.Hosts.Enabled = $false
  } else {
    Set-HostsBlock $state $false
  }

  # USB restore
  Set-USBStorage $state $false

  # Browser policies restore
  Set-BrowserPrivacyPolicies $state $false

  # Firewall restore
  Set-FirewallBrowserBlock $state $false

  # Renames restore
  foreach ($r in $state.Renames) {
    if ($r.Enabled) {
      Rename-FileControlled $state $r.Path $false
    }
  }

  Save-State $state
}

function Show-Menu {
  Write-Host "==============================" -ForegroundColor Green
  Write-Host " ExitControl - Offboarding Menu" -ForegroundColor Green
  Write-Host "=============================="
  Write-Host "1) Toggle HOSTS blocking (upload sites)"
  Write-Host "2) Toggle USB Mass Storage disable"
  Write-Host "3) Toggle Incognito/InPrivate disable (Chrome/Edge)"
  Write-Host "4) Toggle Firewall BLOCK browsers outbound (Chrome/Edge/Firefox)"
  Write-Host "5) Toggle Disable Snipping Tools (optional)"
  Write-Host "6) Toggle Disable OpenWith.exe (AGGRESSIVE, optional)"
  Write-Host "7) Change Windows account password (LOCAL user)"
  Write-Host "8) Show verification checklist"
  Write-Host "9) Show rollback guide"
  Write-Host "10) Show current status"
  Write-Host "11) Restore ALL (rollback everything)"
  Write-Host "0) Exit"
}

# ---------------- MAIN ----------------
Ensure-Admin
$state = Load-State
Save-State $state
Prompt-ScriptPassword

while ($true) {
  Show-Menu
  $choice = Read-Host "Select option"
  switch ($choice) {
    "1" { Set-HostsBlock $state (-not $state.Hosts.Enabled) }
    "2" { Set-USBStorage $state (-not $state.USBSTOR.Enabled) }
    "3" { Set-BrowserPrivacyPolicies $state (-not $state.BrowserPolicies.Enabled) }
    "4" { Set-FirewallBrowserBlock $state (-not $state.Firewall.BrowserBlockEnabled) }
    "5" {
      $snipOn = $false
      foreach ($r in $state.Renames) {
        if (($SnipPaths -contains $r.Path) -and $r.Enabled) { $snipOn = $true }
      }
      foreach ($p in $SnipPaths) { Rename-FileControlled $state $p (-not $snipOn) }
    }
    "6" {
      Write-Host "`nWARNING: Aggressive - may disrupt normal Windows 'Open with...' behavior." -ForegroundColor Yellow
      $owOn = $false
      foreach ($r in $state.Renames) {
        if (($r.Path -eq $OpenWithPath) -and $r.Enabled) { $owOn = $true }
      }
      Rename-FileControlled $state $OpenWithPath (-not $owOn)
    }
    "7" { Change-WindowsPassword }
    "8" { Print-Checklist }
    "9" { Print-RollbackGuide }
    "10" { Show-Status $state }
    "11" { Restore-All $state; Write-Host "Restored. Reboot recommended." -ForegroundColor Green }
    "0" { break }
    default { Write-Host "Invalid option." -ForegroundColor Red }
  }
  $state = Load-State
  Write-Host ""
}
