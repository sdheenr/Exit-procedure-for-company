<# 
ExitControl.ps1 (PowerShell 5.1 compatible)
Menu-driven exit/offboarding controls.

Features:
1) Password prompt before menu (hash-based)
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
$StateDir    = "C:\ProgramData\ExitControl"
$StateFile   = Join-Path $StateDir "state.json"
$HostsPath   = "$env:WINDIR\System32\drivers\etc\hosts"
$LogDir      = Join-Path $StateDir "logs"
$ConfigPath  = Join-Path $StateDir "config.json"
$IntegrityHashFile = Join-Path $StateDir "expected.sha256"

function Get-DefaultConfig {
  return @{
    PasswordPolicy = @{
      MinLength      = 12
      RequireUpper   = $true
      RequireLower   = $true
      RequireDigit   = $true
      RequireSpecial = $true
    }
    AdditionalBlockDomains = @()
    Notifications = @{
      WebhookUrl       = $null
      WebhookAuthHeader = $null
    }
    BackupLimit = 5
    Integrity = @{
      ExpectedHashFile = $IntegrityHashFile
    }
  }
}

function Load-Config {
  if (-not (Test-Path $ConfigPath)) {
    return (Get-DefaultConfig)
  }

  try {
    $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    if (-not $cfg) { return (Get-DefaultConfig) }
    return $cfg
  } catch {
    Write-Host "Warning: Failed to parse config.json, using defaults." -ForegroundColor Yellow
    return (Get-DefaultConfig)
  }
}

$Config = Load-Config

$DefaultScriptPasswordHash = $env:EXITCONTROL_PASSWORD_HASH
if ([string]::IsNullOrWhiteSpace($DefaultScriptPasswordHash)) {
  # SHA-256 of the legacy default password; only the hash is stored
  $DefaultScriptPasswordHash = "a6119a077983251821c8650eb7ff22dd5e2c0547ef4be76f5e28d3cbdac10c76"
}

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

if ($Config.AdditionalBlockDomains) {
  $BlockDomains += $Config.AdditionalBlockDomains
  $BlockDomains = $BlockDomains | Select-Object -Unique
}

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

function Ensure-LogDir {
  if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory | Out-Null
  }
}

function Get-Sha256Hex([string]$text) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
  ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Get-DefaultConfig {
  return @{
    PasswordPolicy = @{
      MinLength      = 12
      RequireUpper   = $true
      RequireLower   = $true
      RequireDigit   = $true
      RequireSpecial = $true
    }
    AdditionalBlockDomains = @()
    Notifications = @{
      WebhookUrl       = $null
      WebhookAuthHeader = $null
    }
    BackupLimit = 5
    Integrity = @{
      ExpectedHashFile = $IntegrityHashFile
    }
  }
}

function Load-Config {
  if (-not (Test-Path $ConfigPath)) {
    return (Get-DefaultConfig)
  }

  try {
    $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    if (-not $cfg) { return (Get-DefaultConfig) }
    return $cfg
  } catch {
    Write-Host "Warning: Failed to parse config.json, using defaults." -ForegroundColor Yellow
    return (Get-DefaultConfig)
  }
}

$Config = Load-Config

function Load-State {
  Ensure-StateDir
  if (Test-Path $StateFile) {
    $loaded = (Get-Content $StateFile -Raw | ConvertFrom-Json)
    return (Ensure-StateShape $loaded)
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
    Audit = @{
      LastHash = $null
    }
    Integrity = @{
      ExpectedHash = $null
      LastStatus = "Unknown"
    }
    Backups = @{
      Hosts = @()
      USBSTOR = @()
      BrowserPolicies = @()
      Limit = $Config.BackupLimit
    }
  }
  return (Ensure-StateShape $state)
}

function Save-State($state) {
  Ensure-StateDir
  $state | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFile -Encoding UTF8
}

function Ensure-StateShape($state) {
  if (-not $state.PSObject.Properties["Auth"]) {
    $state | Add-Member -Name Auth -MemberType NoteProperty -Value @{
      PasswordHash = $DefaultScriptPasswordHash
    }
  }

  $currentHash = [string]$state.Auth.PasswordHash
  if ([string]::IsNullOrWhiteSpace($currentHash)) {
    $state.Auth.PasswordHash = $DefaultScriptPasswordHash
    return $state
  }

  $trimmed = $currentHash.Trim()
  $isHex64 = $trimmed -match "^[0-9a-fA-F]{64}$"
  if (-not $isHex64) {
    # Migrate legacy/plaintext value to hash
    $state.Auth.PasswordHash = Get-Sha256Hex $trimmed
  } else {
    $state.Auth.PasswordHash = $trimmed.ToLowerInvariant()
  }

  if (-not $state.PSObject.Properties["Audit"]) {
    $state | Add-Member -Name Audit -MemberType NoteProperty -Value @{ LastHash = $null }
  }

  if (-not $state.PSObject.Properties["Integrity"]) {
    $state | Add-Member -Name Integrity -MemberType NoteProperty -Value @{
      ExpectedHash = $null
      LastStatus = "Unknown"
    }
  } else {
    if (-not $state.Integrity.PSObject.Properties["LastStatus"]) {
      $state.Integrity | Add-Member -Name LastStatus -MemberType NoteProperty -Value "Unknown"
    }
  }

  if (-not $state.PSObject.Properties["Backups"]) {
    $state | Add-Member -Name Backups -MemberType NoteProperty -Value @{
      Hosts = @()
      USBSTOR = @()
      BrowserPolicies = @()
      Limit = $Config.BackupLimit
    }
  } else {
    if (-not $state.Backups.PSObject.Properties["Limit"]) {
      $state.Backups | Add-Member -Name Limit -MemberType NoteProperty -Value $Config.BackupLimit
    }
    if (-not $state.Backups.PSObject.Properties["Hosts"]) { $state.Backups | Add-Member -Name Hosts -MemberType NoteProperty -Value @() }
    if (-not $state.Backups.PSObject.Properties["USBSTOR"]) { $state.Backups | Add-Member -Name USBSTOR -MemberType NoteProperty -Value @() }
    if (-not $state.Backups.PSObject.Properties["BrowserPolicies"]) { $state.Backups | Add-Member -Name BrowserPolicies -MemberType NoteProperty -Value @() }
  }

  return $state
}

function Prompt-ScriptPassword($state) {
  $expectedHash = $state.Auth.PasswordHash

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

    $enteredHash = Get-Sha256Hex $plain
    if ($enteredHash -ceq $expectedHash) {
      Write-Host "Access granted." -ForegroundColor Green
      Write-AuditEntry $state "AuthSuccess" @{User=$env:USERNAME; Machine=$env:COMPUTERNAME}
      return
    } else {
      Write-Host "Wrong password. Attempt $i/3" -ForegroundColor Red
    }
  }

  Write-Host "Too many wrong attempts. Exiting." -ForegroundColor Red
  exit 1
}

# -------- Logging / notifications / integrity --------
function Add-BackupPath($state, [string]$Category, [string]$Path) {
  if (-not $state.Backups) { return }
  $limit = 5
  if ($state.Backups.Limit -gt 0) { $limit = $state.Backups.Limit }

  $list = $state.Backups.$Category
  if (-not $list) { $list = @() }
  $list += $Path
  if ($list.Count -gt $limit) {
    $list = $list[($list.Count-$limit)..($list.Count-1)]
  }
  $state.Backups.$Category = $list
  Save-State $state
}

function Write-AuditEntry($state, [string]$Action, $Details) {
  Ensure-LogDir
  $prevHash = $state.Audit.LastHash
  if (-not $prevHash) { $prevHash = "" }

  $entry = [pscustomobject]@{
    TimeUtc = (Get-Date).ToUniversalTime().ToString("o")
    User    = $env:USERNAME
    Machine = $env:COMPUTERNAME
    Action  = $Action
    Details = $Details
    PrevHash = $prevHash
  }
  $json = $entry | ConvertTo-Json -Compress
  $newHash = Get-Sha256Hex ("$prevHash`n$json")
  $state.Audit.LastHash = $newHash
  $logFile = Join-Path $LogDir ("audit-" + (Get-Date).ToString("yyyyMMdd") + ".log")
  Add-Content -Path $logFile -Value $json
  Save-State $state
}

function Send-Notification($state, [string]$Title, [string]$Body, [string]$Severity="info") {
  $cfg = $Config
  if (-not $cfg.Notifications -or [string]::IsNullOrWhiteSpace($cfg.Notifications.WebhookUrl)) { return }
  try {
    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($cfg.Notifications.WebhookAuthHeader)) {
      $parts = $cfg.Notifications.WebhookAuthHeader.Split(":",2)
      if ($parts.Count -eq 2) { $headers[$parts[0]] = $parts[1] }
    }
    $payload = @{
      title    = $Title
      body     = $Body
      severity = $Severity
      timeUtc  = (Get-Date).ToUniversalTime().ToString("o")
      machine  = $env:COMPUTERNAME
    }
    Invoke-RestMethod -Method Post -Uri $cfg.Notifications.WebhookUrl -Headers $headers -Body ($payload | ConvertTo-Json -Compress) -ContentType "application/json" | Out-Null
  } catch {
    Write-Host "Notification failed: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Check-Integrity($state) {
  $path = $PSCommandPath
  if (-not $path) { $path = $MyInvocation.MyCommand.Path }
  if (-not (Test-Path $path)) { return $true }

  $expected = $state.Integrity.ExpectedHash
  if (-not $expected -and (Test-Path $IntegrityHashFile)) {
    $expected = (Get-Content $IntegrityHashFile -Raw).Trim()
  }

  $current = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()

  if (-not $expected) {
    $state.Integrity.ExpectedHash = $current
    $state.Integrity.LastStatus = "BaselineCreated"
    $current | Set-Content -Path $IntegrityHashFile -Encoding ASCII
    Save-State $state
    return $true
  }

  if ($current -ne $expected.ToLowerInvariant()) {
    $state.Integrity.LastStatus = "Mismatch"
    Save-State $state
    Write-Host "WARNING: Script hash mismatch detected. Limited mode only." -ForegroundColor Yellow
    return $false
  }

  $state.Integrity.LastStatus = "OK"
  Save-State $state
  return $true
}

function Refresh-IntegrityBaseline($state) {
  $path = $PSCommandPath
  if (-not $path) { $path = $MyInvocation.MyCommand.Path }
  $current = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
  $state.Integrity.ExpectedHash = $current
  $state.Integrity.LastStatus = "BaselineUpdated"
  $current | Set-Content -Path $IntegrityHashFile -Encoding ASCII
  Save-State $state
  Write-AuditEntry $state "IntegrityBaselineUpdated" @{Hash=$current}
  Send-Notification $state "ExitControl integrity baseline updated" "New hash: $current" "info"
}

# -------- HOSTS block --------
function Backup-HostsIfNeeded($state) {
  if (-not $state.Hosts.BackedUp) {
    $stamp = (Get-Date).ToString("yyyyMMddTHHmmss")
    $backupPath = Join-Path $StateDir ("hosts.backup-" + $stamp)
    Copy-Item -Path $HostsPath -Destination $backupPath -Force
    $state.Hosts.BackupPath = $backupPath
    $state.Hosts.BackedUp = $true
    Add-BackupPath $state "Hosts" $backupPath
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
  Write-AuditEntry $state "HostsBlock" @{Enabled=$Enable; Domains=$BlockDomains.Count}
  Send-Notification $state "ExitControl hosts block toggled" ("Enabled: " + $Enable) "info"
}

# -------- USB disable --------
function Backup-USBSTORIfNeeded($state) {
  if (-not $state.USBSTOR.BackedUp) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
    $val = (Get-ItemProperty -Path $key -Name Start -ErrorAction SilentlyContinue).Start
    $state.USBSTOR.OriginalStart = $val
    $state.USBSTOR.BackedUp = $true
    $snapshot = @{
      TimeUtc = (Get-Date).ToUniversalTime().ToString("o")
      Start = $val
    } | ConvertTo-Json -Compress
    $backupPath = Join-Path $StateDir ("usbstor.backup-" + (Get-Date).ToString("yyyyMMddTHHmmss") + ".json")
    $snapshot | Set-Content -Path $backupPath -Encoding UTF8
    Add-BackupPath $state "USBSTOR" $backupPath
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
  Write-AuditEntry $state "USBStorage" @{Disabled=$Disable}
  Send-Notification $state "ExitControl USB storage toggle" ("Disabled: " + $Disable) "info"
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
    $snapshot = @{
      TimeUtc = (Get-Date).ToUniversalTime().ToString("o")
      ChromeIncognitoModeAvailability = $c
      EdgeInPrivateModeAvailability   = $e
    } | ConvertTo-Json -Compress
    $backupPath = Join-Path $StateDir ("browserpolicies.backup-" + (Get-Date).ToString("yyyyMMddTHHmmss") + ".json")
    $snapshot | Set-Content -Path $backupPath -Encoding UTF8
    Add-BackupPath $state "BrowserPolicies" $backupPath
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
  Write-AuditEntry $state "BrowserPrivacyPolicies" @{DisabledPrivateModes=$DisablePrivateModes}
  Send-Notification $state "ExitControl browser privacy toggle" ("Disabled private modes: " + $DisablePrivateModes) "info"
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
  Write-AuditEntry $state "RenameToggle" @{Path=$Path; Enabled=$Enable}
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
  Write-AuditEntry $state "FirewallBrowserBlock" @{Enabled=$Enable}
  Send-Notification $state "ExitControl firewall toggle" ("Browser block enabled: " + $Enable) "info"
}

# -------- Change local Windows password --------
function Change-WindowsPassword($state) {
  $user = Read-Host "Enter local username to change password (blank = current user)"
  if ([string]::IsNullOrWhiteSpace($user)) { $user = $env:USERNAME }

  try {
    $newPwd = Read-Host "Enter NEW Windows password for '$user'" -AsSecureString
    Set-LocalUser -Name $user -Password $newPwd
    Write-Host "Windows password updated for: $user" -ForegroundColor Green
    Write-AuditEntry $state "WindowsPasswordChange" @{User=$user}
    Send-Notification $state "ExitControl password change" ("Local user: " + $user) "warning"
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
  $integrityTxt = $state.Integrity.LastStatus

  Write-Host ("HOSTS Blocking:             " + $hostsTxt)
  Write-Host ("USB Mass Storage Disabled:  " + $usbTxt)
  Write-Host ("Incognito/InPrivate Block:  " + $privTxt)
  Write-Host ("Firewall Browser Block:     " + $fwTxt)
  Write-Host ("Snipping Tools Disabled:    " + $snipTxt)
  Write-Host ("OpenWith.exe Disabled:      " + $owTxt)
  Write-Host ("Integrity Status:           " + $integrityTxt)
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

function Test-ExitControlState($state) {
  $results = [ordered]@{}
  # Hosts check
  $marker = $state.Hosts.ManagedMarker
  $content = @()
  if (Test-Path $HostsPath) { $content = Get-Content $HostsPath }
  $results["HostsMarker"] = ($content -contains "$marker BEGIN") -and ($content -contains "$marker END")

  # USB Start value
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
  $start = (Get-ItemProperty -Path $key -Name Start -ErrorAction SilentlyContinue).Start
  $results["USBDisabled"] = ($start -eq 4)

  # Browser policies
  $chromeKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
  $edgeKey   = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
  $c = (Get-ItemProperty -Path $chromeKey -Name IncognitoModeAvailability -ErrorAction SilentlyContinue).IncognitoModeAvailability
  $e = (Get-ItemProperty -Path $edgeKey -Name InPrivateModeAvailability -ErrorAction SilentlyContinue).InPrivateModeAvailability
  $results["ChromeIncognitoDisabled"] = ($c -eq 1)
  $results["EdgeInPrivateDisabled"]   = ($e -eq 1)

  # Firewall
  $fwRules = Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue
  $results["FirewallBrowserRules"] = ($fwRules | Measure-Object).Count -gt 0

  # Renames (Snip/OpenWith)
  $snipDisabled = $false
  foreach ($r in $state.Renames) {
    if (($SnipPaths -contains $r.Path) -and $r.Enabled) { $snipDisabled = $true }
  }
  $results["SnippingToolsDisabled"] = $snipDisabled
  $owDisabled = $false
  foreach ($r in $state.Renames) {
    if ($r.Path -eq $OpenWithPath -and $r.Enabled) { $owDisabled = $true }
  }
  $results["OpenWithDisabled"] = $owDisabled

  return $results
}

function Show-Diagnostics($state) {
  $results = Test-ExitControlState $state
  Write-Host "`n--- Diagnostics ---" -ForegroundColor Cyan
  foreach ($k in $results.Keys) {
    $val = $results[$k]
    if ($val) { Write-Host ("[PASS] " + $k) -ForegroundColor Green }
    else { Write-Host ("[FAIL] " + $k) -ForegroundColor Red }
  }
  Write-Host "--------------------`n" -ForegroundColor Cyan
  Write-AuditEntry $state "DiagnosticsRun" $results
}

function Show-RecentAuditEntries {
  Ensure-LogDir
  $files = Get-ChildItem -Path $LogDir -Filter "audit-*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
  if (-not $files -or $files.Count -eq 0) {
    Write-Host "No audit entries found." -ForegroundColor Yellow
    return
  }
  $latest = $files[0].FullName
  Write-Host "`n--- Recent audit entries ($latest) ---" -ForegroundColor Cyan
  $lines = Get-Content -Path $latest -Tail 20
  foreach ($l in $lines) { Write-Host $l }
  Write-Host "--------------------------------------`n" -ForegroundColor Cyan
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
  Write-AuditEntry $state "RestoreAll" @{}
  Send-Notification $state "ExitControl restore" "All settings restored; reboot recommended." "warning"
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
  Write-Host "12) Run diagnostics"
  Write-Host "13) Refresh integrity baseline"
  Write-Host "14) View recent audit entries"
  Write-Host "0) Exit"
}

# ---------------- MAIN ----------------
Ensure-Admin
$state = Load-State
Save-State $state
$IntegrityOk = Check-Integrity $state
Prompt-ScriptPassword $state

while ($true) {
  Show-Menu
  $choice = Read-Host "Select option"
  if (-not $IntegrityOk -and ($choice -notin @("0","10","13","12"))) {
    Write-Host "Integrity mismatch detected. Only Status, Diagnostics, Refresh Baseline, or Exit are allowed." -ForegroundColor Yellow
    continue
  }
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
    "7" { Change-WindowsPassword $state }
    "8" { Print-Checklist }
    "9" { Print-RollbackGuide }
    "10" { Show-Status $state }
    "11" { Restore-All $state; Write-Host "Restored. Reboot recommended." -ForegroundColor Green }
    "12" { Show-Diagnostics $state }
    "13" { Refresh-IntegrityBaseline $state; $IntegrityOk = $true }
    "14" { Show-RecentAuditEntries }
    "0" { break }
    default { Write-Host "Invalid option." -ForegroundColor Red }
  }
  $state = Load-State
  Write-Host ""
}
