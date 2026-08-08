#Requires -Version 5.1
<#
ExitControl.ps1 (Windows PowerShell 5.1 compatible)

Menu-driven offboarding / data-egress controls for a single Windows workstation.
Every control is reversible and records its pre-change value in the state file so
"Restore ALL" can put the machine back the way it was found.

Menu:
   1) Toggle HOSTS blocking of upload / personal-cloud / webmail sites
   2) Toggle USB Mass Storage disable
   3) Toggle Chrome/Edge private browsing + DNS-over-HTTPS disable (policy)
   4) Toggle firewall block of browser outbound traffic
   5) Toggle Snipping Tool / Snip & Sketch disable (rename .exe)
   6) Toggle OpenWith.exe disable (AGGRESSIVE, rename .exe)
   7) Change a LOCAL Windows account password
   8) Show verification checklist
   9) Show rollback guide
  10) Show current status
  11) Restore ALL
  12) Change the ExitControl password
  13) Run diagnostics (compares the machine against the recorded state)
  14) Refresh script integrity baseline
  15) View recent audit entries
   0) Exit

Everything lives in C:\ProgramData\ExitControl\, ACL-restricted to Administrators
and SYSTEM on every run:

  state.json         password hash + every original setting. Do NOT delete it --
                     rotate the password with option 12 instead.
  config.json        optional site settings; see Get-DefaultConfig below.
  expected.sha256    script integrity baseline.
  logs\audit-*.log   hash-chained audit trail.
  *.backup-*         timestamped backups, pruned to the configured BackupLimit.

Must be run as Administrator.
#>

$ErrorActionPreference = "Stop"

# ---------------- CONFIG ----------------
$StateDir          = "C:\ProgramData\ExitControl"
$StateFile         = Join-Path $StateDir "state.json"
$LogDir            = Join-Path $StateDir "logs"
$ConfigPath        = Join-Path $StateDir "config.json"
$IntegrityHashFile = Join-Path $StateDir "expected.sha256"
$HostsPath         = Join-Path $env:WINDIR "System32\drivers\etc\hosts"
$HostsMarker       = "# ExitControlManaged"
$SchemaVersion     = 2

$Pbkdf2Iterations = 200000

# ---------------- SITE CONFIGURATION ----------------
# Optional C:\ProgramData\ExitControl\config.json, e.g.
#   {
#     "PasswordPolicy": { "MinLength": 12, "RequireUpper": true, "RequireLower": true,
#                         "RequireDigit": true, "RequireSpecial": true },
#     "AdditionalBlockDomains": ["intranet-share.example.com"],
#     "Notifications": { "WebhookUrl": "https://...", "WebhookAuthHeader": "Authorization: Bearer ..." },
#     "BackupLimit": 5
#   }

function Get-DefaultConfig {
  return [pscustomobject]@{
    PasswordPolicy = [pscustomobject]@{
      MinLength      = 12
      RequireUpper   = $true
      RequireLower   = $true
      RequireDigit   = $true
      RequireSpecial = $true
    }
    AdditionalBlockDomains = @()
    Notifications = [pscustomobject]@{
      WebhookUrl        = $null
      WebhookAuthHeader = $null
    }
    BackupLimit = 5
  }
}

function Get-Config {
  <#
    Loaded config is merged OVER the defaults rather than replacing them, so a
    config.json that omits a key -- or omits a key inside PasswordPolicy -- still
    yields a fully populated object instead of $null field accesses later.
  #>
  $config = Get-DefaultConfig
  if (-not (Test-Path -LiteralPath $ConfigPath)) { return $config }

  try {
    $loaded = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
  } catch {
    Write-Host ("WARNING: {0} is not valid JSON; using defaults." -f $ConfigPath) -ForegroundColor Yellow
    return $config
  }
  if ($null -eq $loaded) { return $config }

  foreach ($section in @("PasswordPolicy", "Notifications")) {
    if ($loaded.PSObject.Properties[$section] -and $null -ne $loaded.$section) {
      foreach ($property in $loaded.$section.PSObject.Properties) {
        if ($config.$section.PSObject.Properties[$property.Name]) {
          $config.$section.$($property.Name) = $property.Value
        }
      }
    }
  }

  if ($loaded.PSObject.Properties["AdditionalBlockDomains"] -and $null -ne $loaded.AdditionalBlockDomains) {
    $config.AdditionalBlockDomains = @($loaded.AdditionalBlockDomains)
  }
  if ($loaded.PSObject.Properties["BackupLimit"] -and $loaded.BackupLimit -gt 0) {
    $config.BackupLimit = [int]$loaded.BackupLimit
  }

  return $config
}

# Must run before $BlockDomains is assembled below.
$Config = Get-Config

# Domains blocked via the HOSTS file. Note that a HOSTS block only covers plain
# DNS -- see option 3, which also turns off browser DNS-over-HTTPS so lookups
# cannot route around this list.
$BlockDomains = @(
  # Consumer file transfer
  "wetransfer.com", "www.wetransfer.com"
  "sendgb.com", "file.io", "gofile.io", "filemail.com"
  "transfernow.net", "smash.io", "catbox.moe", "0x0.st"
  # Personal cloud storage
  "drive.google.com"
  "dropbox.com", "www.dropbox.com"
  "mega.nz"
  "box.com", "www.box.com", "app.box.com"
  "pcloud.com", "www.pcloud.com"
  "sync.com", "www.sync.com"
  "icloud.com", "www.icloud.com"
  "onedrive.live.com"
  # Personal webmail
  "mail.google.com", "gmail.com"
  "outlook.live.com"
  "mail.proton.me", "proton.me"
  "mail.yahoo.com"
  "mail.zoho.com"
  # Paste / snippet sites
  "pastebin.com", "hastebin.com", "termbin.com"
  # Chat clients with file upload
  "web.telegram.org"
  "discord.com"
)

if ($Config.AdditionalBlockDomains.Count -gt 0) {
  $BlockDomains = @($BlockDomains + $Config.AdditionalBlockDomains) | Select-Object -Unique
}

$SnipPaths = @(
  (Join-Path $env:WINDIR "System32\SnippingTool.exe"),
  (Join-Path $env:WINDIR "System32\ScreenSketch.exe")
)

$OpenWithPath = Join-Path $env:WINDIR "System32\OpenWith.exe"

$FwGroup = "ExitControl-BrowserBlock"

# Browser executables, relative to an install root. Resolved at runtime against
# Program Files, Program Files (x86) and EVERY user profile's LocalAppData --
# per-user installs are the common case for Chrome, and an elevated shell's own
# %LOCALAPPDATA% points at the admin's profile, not the departing user's.
$BrowserRelativePaths = @(
  "Google\Chrome\Application\chrome.exe"
  "Microsoft\Edge\Application\msedge.exe"
  "Mozilla Firefox\firefox.exe"
  "BraveSoftware\Brave-Browser\Application\brave.exe"
  "Vivaldi\Application\vivaldi.exe"
  "Opera\opera.exe"
  "Programs\Opera\opera.exe"
  "Chromium\Application\chrome.exe"
)

# ---------------- LOW-LEVEL HELPERS ----------------

function Wait-ForKey {
  param([string]$Message = "Press Enter to continue...")
  Read-Host $Message | Out-Null
}

function Assert-Administrator {
  # Checked here rather than with "#Requires -RunAsAdministrator" so the user
  # gets a readable message and a pause -- the #Requires failure would scroll
  # past and the window would close before it could be read.
  $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "ERROR: ExitControl must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click RunExitControl.bat and choose 'Run as administrator'." -ForegroundColor Yellow
    Write-Host ""
    Wait-ForKey
    exit 1
  }
}

function Confirm-Action {
  param([string]$Message)
  $answer = Read-Host "$Message [y/N]"
  return ($answer -match '^(y|yes)$')
}

function Invoke-ControlAction {
  <#
    Runs one menu action with the failure isolated to that action. Without this
    the script's ErrorActionPreference of Stop would terminate the whole
    session on any error, and -- because the script normally runs in its own
    elevated window -- the message would disappear with the window.
  #>
  param([string]$Name, [scriptblock]$Action)

  try {
    # Discarded so a stray pipeline value from an action cannot be mistaken for
    # this function's boolean result. Write-Host output is unaffected.
    $null = & $Action
    return $true
  } catch {
    $message = $_.Exception.Message
    Write-Host ""
    Write-Host ("FAILED: {0}" -f $Name) -ForegroundColor Red
    Write-Host ("  {0}" -f $message) -ForegroundColor Yellow

    if ($message -match 'denied|UnauthorizedAccess') {
      Write-Host "  Hint: files under System32 are owned by TrustedInstaller." -ForegroundColor DarkYellow
      Write-Host "        Administrator rights alone are not enough to rename them." -ForegroundColor DarkYellow
    }
    Write-Host ""
    return $false
  }
}

# ---------------- CRYPTO HELPERS ----------------

function ConvertTo-PasswordByte {
  <# SecureString -> UTF-8 bytes. Caller must Clear-ByteArray the result. #>
  param([Security.SecureString]$Secure)

  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    # Comma-wrapped: without it PowerShell unrolls the byte[] into an Object[],
    # and Clear-ByteArray would then coerce (i.e. copy) it and zero the copy,
    # leaving the real password bytes sitting in memory.
    return ,[Text.Encoding]::UTF8.GetBytes($plain)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
}

function Clear-ByteArray {
  param([byte[]]$Bytes)
  if ($null -ne $Bytes) { [Array]::Clear($Bytes, 0, $Bytes.Length) }
}

function Test-ByteArrayEqual {
  # Hand-rolled rather than [Linq.Enumerable]::SequenceEqual, whose generic type
  # arguments Windows PowerShell 5.1 cannot always infer.
  param([byte[]]$Left, [byte[]]$Right)

  if ($null -eq $Left -or $null -eq $Right) { return $false }
  if ($Left.Length -ne $Right.Length) { return $false }

  $diff = 0
  for ($i = 0; $i -lt $Left.Length; $i++) {
    $diff = $diff -bor ($Left[$i] -bxor $Right[$i])
  }
  return ($diff -eq 0)
}

function Get-Sha256Hex {
  <# Used for legacy v1 password hashes and for the audit hash chain. #>
  param([byte[]]$Bytes)

  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
  } finally {
    $sha.Dispose()
  }
}

function Get-StringSha256Hex {
  param([string]$Text)
  return (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($Text)))
}

function Get-Pbkdf2Prf {
  <# .NET 4.7.2+ can use an HMAC-SHA256 PRF; older runtimes only HMAC-SHA1. #>
  try {
    $probeSalt = New-Object byte[] 8
    $probe = New-Object Security.Cryptography.Rfc2898DeriveBytes(
      (New-Object byte[] 4), $probeSalt, 1, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $probe.Dispose()
    return "SHA256"
  } catch {
    return "SHA1"
  }
}

function Get-Pbkdf2Hash {
  param([byte[]]$PasswordBytes, [byte[]]$Salt, [int]$Iterations, [string]$Prf)

  if ($Prf -eq "SHA256") {
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes(
      $PasswordBytes, $Salt, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
  } else {
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($PasswordBytes, $Salt, $Iterations)
  }

  try {
    return [Convert]::ToBase64String($kdf.GetBytes(32))
  } finally {
    $kdf.Dispose()
  }
}

function Test-StringEqualConstantTime {
  param([string]$Left, [string]$Right)

  if ([string]::IsNullOrEmpty($Left) -or [string]::IsNullOrEmpty($Right)) { return $false }
  if ($Left.Length -ne $Right.Length) { return $false }

  $diff = 0
  for ($i = 0; $i -lt $Left.Length; $i++) {
    $diff = $diff -bor ([int][char]$Left[$i] -bxor [int][char]$Right[$i])
  }
  return ($diff -eq 0)
}

# ---------------- STATE ----------------

function Initialize-StateDirectory {
  if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
  }

  # The state file holds a password hash and the machine's original settings, so
  # it must not be readable by the standard user being offboarded. ProgramData
  # grants Users read by default; drop inheritance and keep SYSTEM + Admins.
  try {
    $acl = Get-Acl -Path $StateDir
    if (-not $acl.AreAccessRulesProtected) {
      $acl.SetAccessRuleProtection($true, $false)
      $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

      $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
      $admins = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
      foreach ($sid in @($system, $admins)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
          $sid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
      }
      Set-Acl -Path $StateDir -AclObject $acl
    }
  } catch {
    Write-Host ("WARNING: could not restrict permissions on {0}: {1}" -f $StateDir, $_.Exception.Message) -ForegroundColor Yellow
  }
}

function New-State {
  return [pscustomobject]@{
    SchemaVersion = $SchemaVersion
    CreatedAt     = (Get-Date).ToString("s")
    Auth          = [pscustomobject]@{
      Prf          = $null
      Iterations   = 0
      Salt         = $null
      Hash         = $null
      LegacySha256 = $null
    }
    Hosts         = [pscustomobject]@{
      BackedUp   = $false
      BackupPath = (Join-Path $StateDir "hosts.backup")
      Applied    = $false
    }
    UsbStorage    = [pscustomobject]@{
      BackedUp      = $false
      OriginalStart = $null
      Applied       = $false
    }
    BrowserPolicies = [pscustomobject]@{
      BackedUp = $false
      Original = [pscustomobject]@{
        ChromeIncognitoModeAvailability = $null
        EdgeInPrivateModeAvailability   = $null
        ChromeDnsOverHttpsMode          = $null
        EdgeDnsOverHttpsMode            = $null
      }
      Applied  = $false
    }
    Firewall      = [pscustomobject]@{
      Applied = $false
    }
    Renames       = @()   # { Path, BackupPath, Applied }
    Audit         = [pscustomobject]@{
      LastHash = $null
    }
    Integrity     = [pscustomobject]@{
      ExpectedHash = $null
      LastStatus   = "Unknown"
    }
    Backups       = [pscustomobject]@{
      Hosts           = @()
      UsbStorage      = @()
      BrowserPolicies = @()
    }
  }
}

function Add-MissingProperty {
  param($Object, [string]$Name, $Value)
  if (-not $Object.PSObject.Properties[$Name]) {
    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
  }
}

function Update-StateSchema {
  <#
    Migrates a v1 state file in place. v1 named every "control is applied" flag
    "Enabled" -- which read as the opposite of its meaning ("USBSTOR.Enabled =
    true" meant USB was DISABLED) -- and used the key "USBSTOR". Migration
    matters: without it a machine with controls already applied would report
    OFF and Restore ALL would skip it.
  #>
  param($State)

  Add-MissingProperty $State "SchemaVersion" 1
  if ($State.SchemaVersion -ge $SchemaVersion) { return $State }

  Add-MissingProperty $State "CreatedAt" (Get-Date).ToString("s")

  # Hosts / Firewall / BrowserPolicies: Enabled -> Applied
  foreach ($section in @("Hosts", "BrowserPolicies")) {
    if ($State.PSObject.Properties[$section]) {
      $node = $State.$section
      $applied = $false
      if ($node.PSObject.Properties["Enabled"]) { $applied = [bool]$node.Enabled }
      Add-MissingProperty $node "Applied" $applied
      $node.Applied = $applied
    }
  }

  if ($State.PSObject.Properties["Firewall"]) {
    $applied = $false
    if ($State.Firewall.PSObject.Properties["BrowserBlockEnabled"]) {
      $applied = [bool]$State.Firewall.BrowserBlockEnabled
    }
    Add-MissingProperty $State.Firewall "Applied" $applied
    $State.Firewall.Applied = $applied
  }

  # USBSTOR -> UsbStorage
  if ($State.PSObject.Properties["USBSTOR"] -and -not $State.PSObject.Properties["UsbStorage"]) {
    $old = $State.USBSTOR
    $applied = $false
    if ($old.PSObject.Properties["Enabled"]) { $applied = [bool]$old.Enabled }
    $State | Add-Member -NotePropertyName "UsbStorage" -NotePropertyValue ([pscustomobject]@{
      BackedUp      = [bool]$old.BackedUp
      OriginalStart = $old.OriginalStart
      Applied       = $applied
    })
    $State.PSObject.Properties.Remove("USBSTOR")
  }

  # Renames[].Enabled -> Renames[].Applied
  if ($State.PSObject.Properties["Renames"]) {
    foreach ($rename in @($State.Renames)) {
      if ($null -eq $rename) { continue }
      $applied = $false
      if ($rename.PSObject.Properties["Enabled"]) { $applied = [bool]$rename.Enabled }
      Add-MissingProperty $rename "Applied" $applied
      $rename.Applied = $applied
    }
  }

  # v1 stored a bare, unsalted SHA-256 under Auth.PasswordHash.
  if ($State.PSObject.Properties["Auth"] -and $State.Auth.PSObject.Properties["PasswordHash"]) {
    $legacy = [string]$State.Auth.PasswordHash
    Add-MissingProperty $State.Auth "LegacySha256" $null
    if (-not [string]::IsNullOrWhiteSpace($legacy)) {
      $State.Auth.LegacySha256 = $legacy.Trim().ToLowerInvariant()
    }
    $State.Auth.PSObject.Properties.Remove("PasswordHash")
  }

  $State.SchemaVersion = $SchemaVersion
  return $State
}

function Initialize-StateShape {
  <# Fills in anything a hand-edited or partially-written state file is missing. #>
  param($State)

  $template = New-State
  foreach ($property in $template.PSObject.Properties) {
    if ($property.Name -eq "SchemaVersion" -or $property.Name -eq "CreatedAt") { continue }
    Add-MissingProperty $State $property.Name $property.Value
  }

  foreach ($name in @("Prf", "Iterations", "Salt", "Hash", "LegacySha256")) {
    Add-MissingProperty $State.Auth $name $null
  }

  # Single normalisation point for the legacy hash. Verification compares against
  # lowercase hex, so an uppercase value anywhere (hand-edited state file, an
  # uppercase env var seed) would otherwise reject every password permanently.
  if (-not [string]::IsNullOrWhiteSpace([string]$State.Auth.LegacySha256)) {
    $State.Auth.LegacySha256 = ([string]$State.Auth.LegacySha256).Trim().ToLowerInvariant()
  }
  Add-MissingProperty $State.Hosts "BackupPath" (Join-Path $StateDir "hosts.backup")
  Add-MissingProperty $State.BrowserPolicies "Original" $template.BrowserPolicies.Original
  foreach ($name in @("ChromeIncognitoModeAvailability", "EdgeInPrivateModeAvailability",
                      "ChromeDnsOverHttpsMode", "EdgeDnsOverHttpsMode")) {
    Add-MissingProperty $State.BrowserPolicies.Original $name $null
  }

  Add-MissingProperty $State.Audit "LastHash" $null
  foreach ($name in @("ExpectedHash", "LastStatus")) {
    Add-MissingProperty $State.Integrity $name $null
  }
  if ([string]::IsNullOrWhiteSpace([string]$State.Integrity.LastStatus)) {
    $State.Integrity.LastStatus = "Unknown"
  }
  foreach ($name in @("Hosts", "UsbStorage", "BrowserPolicies")) {
    Add-MissingProperty $State.Backups $name @()
    if ($null -eq $State.Backups.$name) { $State.Backups.$name = @() }
  }

  if ($null -eq $State.Renames) { $State.Renames = @() }
  return $State
}

function Get-State {
  Initialize-StateDirectory

  if (-not (Test-Path -LiteralPath $StateFile)) {
    return (New-State)
  }

  $raw = Get-Content -LiteralPath $StateFile -Raw
  try {
    $state = $raw | ConvertFrom-Json
  } catch {
    Write-Host ""
    Write-Host ("ERROR: {0} is not valid JSON and cannot be read." -f $StateFile) -ForegroundColor Red
    Write-Host "It records every original setting this tool changed. Repair it by hand" -ForegroundColor Yellow
    Write-Host "rather than deleting it -- deleting it makes rollback impossible." -ForegroundColor Yellow
    Write-Host ""
    Wait-ForKey
    exit 1
  }

  $state = Update-StateSchema $state
  return (Initialize-StateShape $state)
}

function Save-State {
  param($State)
  Initialize-StateDirectory
  $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $StateFile -Encoding UTF8
}

# ---------------- AUDIT LOG ----------------

function Initialize-LogDirectory {
  Initialize-StateDirectory   # applies the restrictive ACL to the parent
  if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
  }
}

function Get-AuditLogPath {
  return (Join-Path $LogDir ("audit-" + (Get-Date).ToString("yyyyMMdd") + ".log"))
}

function Write-AuditEntry {
  <#
    Appends one JSON line and chains it to the previous entry's hash, so a
    deleted or edited line breaks the chain and Test-AuditChain can spot it.

    This is tamper EVIDENCE, not tamper PREVENTION: an Administrator can rewrite
    the whole log and recompute every hash. It catches casual edits and
    accidental loss, and nothing stronger.
  #>
  param($State, [string]$Action, $Details)

  try {
    Initialize-LogDirectory

    $previousHash = [string]$State.Audit.LastHash
    if ([string]::IsNullOrWhiteSpace($previousHash)) { $previousHash = "" }

    $entry = [pscustomobject]@{
      TimeUtc  = (Get-Date).ToUniversalTime().ToString("o")
      User     = $env:USERNAME
      Machine  = $env:COMPUTERNAME
      Action   = $Action
      Details  = $Details
      PrevHash = $previousHash
    }

    $json = $entry | ConvertTo-Json -Depth 6 -Compress
    $State.Audit.LastHash = Get-StringSha256Hex ($previousHash + "`n" + $json)

    Add-Content -LiteralPath (Get-AuditLogPath) -Value $json -Encoding UTF8
    Save-State $State
  } catch {
    # An audit failure must never abort the control the operator asked for.
    Write-Host ("WARNING: could not write audit entry '{0}': {1}" -f $Action, $_.Exception.Message) -ForegroundColor Yellow
  }
}

function Test-AuditChain {
  <#
    Recomputes the chain across every audit file in date order and returns the
    first index where it breaks. Without this the PrevHash field is decoration.
  #>
  if (-not (Test-Path -LiteralPath $LogDir)) {
    return [pscustomobject]@{ Checked = 0; Intact = $true; BrokenAt = $null }
  }

  $files = @(Get-ChildItem -LiteralPath $LogDir -Filter "audit-*.log" -ErrorAction SilentlyContinue |
             Sort-Object Name)

  $expectedPrevious = ""
  $checked = 0
  foreach ($file in $files) {
    foreach ($line in @(Get-Content -LiteralPath $file.FullName)) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      $checked++

      try { $entry = $line | ConvertFrom-Json } catch {
        return [pscustomobject]@{ Checked = $checked; Intact = $false; BrokenAt = "$($file.Name):$checked (unparseable)" }
      }

      if ([string]$entry.PrevHash -ne $expectedPrevious) {
        return [pscustomobject]@{ Checked = $checked; Intact = $false; BrokenAt = "$($file.Name):$checked" }
      }
      $expectedPrevious = Get-StringSha256Hex ($expectedPrevious + "`n" + $line)
    }
  }

  return [pscustomobject]@{ Checked = $checked; Intact = $true; BrokenAt = $null }
}

function Show-AuditEntry {
  param([int]$Count = 20)

  if (-not (Test-Path -LiteralPath $LogDir)) {
    Write-Host "No audit log directory yet." -ForegroundColor Yellow
    return
  }

  $files = @(Get-ChildItem -LiteralPath $LogDir -Filter "audit-*.log" -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending)
  if ($files.Count -eq 0) {
    Write-Host "No audit entries found." -ForegroundColor Yellow
    return
  }

  $latest = $files[0]
  Write-Host ""
  Write-Host ("--- Last {0} audit entries: {1} ---" -f $Count, $latest.Name) -ForegroundColor Cyan
  foreach ($line in @(Get-Content -LiteralPath $latest.FullName -Tail $Count)) {
    try {
      $entry = $line | ConvertFrom-Json
      Write-Host ("{0}  {1,-24} {2}" -f $entry.TimeUtc, $entry.Action, $entry.User)
    } catch {
      Write-Host ("  (unparseable) {0}" -f $line) -ForegroundColor Yellow
    }
  }

  $chain = Test-AuditChain
  Write-Host ""
  if ($chain.Intact) {
    Write-Host ("Hash chain intact across {0} entries." -f $chain.Checked) -ForegroundColor Green
  } else {
    Write-Host ("Hash chain BROKEN at {0} -- entries were edited or removed." -f $chain.BrokenAt) -ForegroundColor Red
  }
  Write-Host ("Log directory: {0}" -f $LogDir) -ForegroundColor DarkGray
  Write-Host ""
}

# ---------------- NOTIFICATIONS ----------------

function Send-Notification {
  <#
    Optional webhook POST. Silent no-op unless config.json sets a WebhookUrl.
    Only the machine name, action and severity are sent -- never a password, a
    hash, or the contents of any backup.
  #>
  param([string]$Title, [string]$Body, [string]$Severity = "info")

  $url = [string]$Config.Notifications.WebhookUrl
  if ([string]::IsNullOrWhiteSpace($url)) { return }

  try {
    $headers = @{}
    $authHeader = [string]$Config.Notifications.WebhookAuthHeader
    if (-not [string]::IsNullOrWhiteSpace($authHeader)) {
      $parts = $authHeader.Split(":", 2)
      if ($parts.Count -eq 2) { $headers[$parts[0].Trim()] = $parts[1].Trim() }
    }

    $payload = @{
      title    = $Title
      body     = $Body
      severity = $Severity
      timeUtc  = (Get-Date).ToUniversalTime().ToString("o")
      machine  = $env:COMPUTERNAME
      user     = $env:USERNAME
    } | ConvertTo-Json -Compress

    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $payload `
      -ContentType "application/json" -TimeoutSec 15 | Out-Null
  } catch {
    # Never let an unreachable webhook block an offboarding step.
    Write-Host ("WARNING: notification failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
  }
}

function Write-ControlEvent {
  <# One call to record a control change in both the audit log and the webhook. #>
  param($State, [string]$Action, $Details, [string]$Title, [string]$Body, [string]$Severity = "info")

  Write-AuditEntry $State $Action $Details
  Send-Notification $Title $Body $Severity
}

# ---------------- SCRIPT INTEGRITY ----------------

function Get-ScriptPath {
  if ($PSCommandPath) { return $PSCommandPath }
  return $MyInvocation.MyCommand.Path
}

function Test-ScriptIntegrity {
  <#
    Compares this file's SHA-256 against a recorded baseline and returns $false
    on mismatch, which restricts the menu to read-only options.

    Scope, stated plainly: the baseline lives in the same Administrator-writable
    folder as the script, and option 14 resets it. This detects accidental or
    unauthorised edits by someone without Administrator rights. It does not stop
    an Administrator, who can edit the script and re-baseline it.
  #>
  param($State)

  $path = Get-ScriptPath
  if (-not $path -or -not (Test-Path -LiteralPath $path)) {
    # A ps2exe build has no .ps1 on disk; there is nothing to hash.
    $State.Integrity.LastStatus = "NotApplicable"
    Save-State $State
    return $true
  }

  $current = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()

  $expected = [string]$State.Integrity.ExpectedHash
  if ([string]::IsNullOrWhiteSpace($expected) -and (Test-Path -LiteralPath $IntegrityHashFile)) {
    $expected = (Get-Content -LiteralPath $IntegrityHashFile -Raw).Trim()
  }

  if ([string]::IsNullOrWhiteSpace($expected)) {
    $State.Integrity.ExpectedHash = $current
    $State.Integrity.LastStatus   = "BaselineCreated"
    Set-Content -LiteralPath $IntegrityHashFile -Value $current -Encoding ASCII
    Save-State $State
    Write-AuditEntry $State "IntegrityBaselineCreated" @{ Hash = $current }
    return $true
  }

  if ($current -ne $expected.ToLowerInvariant()) {
    $State.Integrity.LastStatus = "Mismatch"
    Save-State $State
    Write-Host ""
    Write-Host "WARNING: this script does not match its recorded baseline." -ForegroundColor Red
    Write-Host ("  expected: {0}" -f $expected.ToLowerInvariant()) -ForegroundColor Yellow
    Write-Host ("  actual:   {0}" -f $current) -ForegroundColor Yellow
    Write-Host "Running in limited mode. Only status, diagnostics, audit log," -ForegroundColor Yellow
    Write-Host "baseline refresh and exit are available." -ForegroundColor Yellow
    Write-Host ""
    Write-ControlEvent $State "IntegrityMismatch" @{ Expected = $expected.ToLowerInvariant(); Actual = $current } `
      "ExitControl integrity mismatch" ("Script hash changed on " + $env:COMPUTERNAME) "warning"
    return $false
  }

  $State.Integrity.LastStatus = "OK"
  Save-State $State
  return $true
}

function Reset-ScriptIntegrityBaseline {
  param($State)

  $path = Get-ScriptPath
  if (-not $path -or -not (Test-Path -LiteralPath $path)) {
    Write-Host "No script file on disk to baseline (packaged build?)." -ForegroundColor Yellow
    return
  }

  $current = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  $State.Integrity.ExpectedHash = $current
  $State.Integrity.LastStatus   = "BaselineUpdated"
  Set-Content -LiteralPath $IntegrityHashFile -Value $current -Encoding ASCII
  Save-State $State

  Write-Host ("Integrity baseline updated to {0}" -f $current) -ForegroundColor Green
  Write-ControlEvent $State "IntegrityBaselineUpdated" @{ Hash = $current } `
    "ExitControl integrity baseline updated" ("New hash: " + $current) "info"
}

# ---------------- ROLLING BACKUPS ----------------

function Add-BackupRecord {
  <#
    Records a timestamped backup and prunes the oldest beyond BackupLimit --
    deleting the pruned FILES too. Trimming only the list would leave orphaned
    backups accumulating in a directory nobody ever cleans.
  #>
  param($State, [string]$Category, [string]$Path)

  $limit = 5
  if ($Config.BackupLimit -gt 0) { $limit = [int]$Config.BackupLimit }

  # Both @() wrappers are required. Where-Object unrolls a single survivor to a
  # bare string, and "string + string" concatenates instead of building an
  # array -- which silently pinned the list at one entry.
  $existing = @(@($State.Backups.$Category) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  $list = @($existing) + @($Path)

  if ($list.Count -gt $limit) {
    $prune = $list[0..($list.Count - $limit - 1)]
    foreach ($old in $prune) {
      try {
        if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force }
      } catch {
        Write-Host ("WARNING: could not delete old backup {0}: {1}" -f $old, $_.Exception.Message) -ForegroundColor Yellow
      }
    }
    $list = @($list[($list.Count - $limit)..($list.Count - 1)])
  }

  $State.Backups.$Category = $list
  Save-State $State
}

function New-BackupStamp {
  return (Get-Date).ToString("yyyyMMdd-HHmmss")
}

# ---------------- AUTHENTICATION ----------------

function Test-PasswordPolicy {
  <#
    Enforces the PasswordPolicy block from config.json and returns the list of
    violations ($null-safe, empty when compliant).
  #>
  param([byte[]]$PasswordBytes)

  $policy = $Config.PasswordPolicy
  $text = [Text.Encoding]::UTF8.GetString($PasswordBytes)
  $problems = New-Object Collections.Generic.List[string]

  # Length in characters, not bytes: a non-ASCII character is several bytes.
  $minLength = 12
  if ($policy.MinLength -gt 0) { $minLength = [int]$policy.MinLength }
  if ($text.Length -lt $minLength) {
    $problems.Add("must be at least $minLength characters")
  }

  if ($policy.RequireUpper   -and $text -cnotmatch '[A-Z]')      { $problems.Add("needs an uppercase letter") }
  if ($policy.RequireLower   -and $text -cnotmatch '[a-z]')      { $problems.Add("needs a lowercase letter") }
  if ($policy.RequireDigit   -and $text -notmatch  '[0-9]')      { $problems.Add("needs a digit") }
  if ($policy.RequireSpecial -and $text -notmatch  '[^A-Za-z0-9]') { $problems.Add("needs a symbol") }

  return ,$problems.ToArray()
}

function Set-ScriptPassword {
  param($State)

  while ($true) {
    $first  = Read-Host "Enter a new ExitControl password" -AsSecureString
    $second = Read-Host "Re-enter the new ExitControl password" -AsSecureString

    $firstBytes  = ConvertTo-PasswordByte $first
    $secondBytes = ConvertTo-PasswordByte $second
    try {
      $problems = Test-PasswordPolicy $firstBytes
      if ($problems.Count -gt 0) {
        Write-Host "Password rejected by policy:" -ForegroundColor Red
        foreach ($problem in $problems) { Write-Host ("  - it {0}" -f $problem) -ForegroundColor Red }
        continue
      }
      if (-not (Test-ByteArrayEqual $firstBytes $secondBytes)) {
        Write-Host "The two entries did not match. Try again." -ForegroundColor Red
        continue
      }

      $salt = New-Object byte[] 16
      $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
      try { $rng.GetBytes($salt) } finally { $rng.Dispose() }

      $prf = Get-Pbkdf2Prf
      $State.Auth.Prf          = $prf
      $State.Auth.Iterations   = $Pbkdf2Iterations
      $State.Auth.Salt         = [Convert]::ToBase64String($salt)
      $State.Auth.Hash         = Get-Pbkdf2Hash $firstBytes $salt $Pbkdf2Iterations $prf
      $State.Auth.LegacySha256 = $null
      Save-State $State

      Write-Host "ExitControl password set." -ForegroundColor Green
      Write-ControlEvent $State "ScriptPasswordSet" @{ Prf = $prf; Iterations = $Pbkdf2Iterations } `
        "ExitControl password changed" ("Changed on " + $env:COMPUTERNAME) "warning"
      return $true
    } finally {
      Clear-ByteArray $firstBytes
      Clear-ByteArray $secondBytes
    }
  }
}

function Initialize-AuthState {
  <#
    Bootstraps the password from EXITCONTROL_PASSWORD_HASH when nothing is
    configured yet. There is deliberately no built-in default: shipping one in
    a public repo means shipping a hash anybody can reverse offline.
  #>
  param($State)

  $hasPbkdf2 = -not [string]::IsNullOrWhiteSpace([string]$State.Auth.Hash)
  $hasLegacy = -not [string]::IsNullOrWhiteSpace([string]$State.Auth.LegacySha256)
  if ($hasPbkdf2 -or $hasLegacy) { return $State }

  $seed = $env:EXITCONTROL_PASSWORD_HASH
  if ([string]::IsNullOrWhiteSpace($seed)) { return $State }

  $seed = $seed.Trim()
  if ($seed -notmatch '^[0-9a-fA-F]{64}$') {
    Write-Host "WARNING: EXITCONTROL_PASSWORD_HASH is not a 64-character SHA-256 hex string; ignoring it." -ForegroundColor Yellow
    return $State
  }

  $State.Auth.LegacySha256 = $seed.ToLowerInvariant()
  return $State
}

function Test-ScriptPassword {
  param($State, [byte[]]$PasswordBytes)

  if (-not [string]::IsNullOrWhiteSpace([string]$State.Auth.Hash)) {
    $salt = [Convert]::FromBase64String($State.Auth.Salt)
    $candidate = Get-Pbkdf2Hash $PasswordBytes $salt ([int]$State.Auth.Iterations) ([string]$State.Auth.Prf)
    return (Test-StringEqualConstantTime $candidate ([string]$State.Auth.Hash))
  }

  if (-not [string]::IsNullOrWhiteSpace([string]$State.Auth.LegacySha256)) {
    $candidate = Get-Sha256Hex $PasswordBytes
    return (Test-StringEqualConstantTime $candidate ([string]$State.Auth.LegacySha256))
  }

  return $false
}

function Request-ScriptPassword {
  param($State)

  $configured = (-not [string]::IsNullOrWhiteSpace([string]$State.Auth.Hash)) -or
                (-not [string]::IsNullOrWhiteSpace([string]$State.Auth.LegacySha256))

  if (-not $configured) {
    Write-Host ""
    Write-Host "No ExitControl password is configured on this machine." -ForegroundColor Yellow
    Write-Host "Set one now -- it will be required on every future run." -ForegroundColor Yellow
    Write-Host ""
    [void](Set-ScriptPassword $State)
    return
  }

  for ($attempt = 1; $attempt -le 3; $attempt++) {
    $secure = Read-Host "Enter ExitControl password" -AsSecureString
    $bytes = ConvertTo-PasswordByte $secure
    try {
      if (Test-ScriptPassword $State $bytes) {
        Write-Host "Access granted." -ForegroundColor Green

        # Upgrade a legacy unsalted SHA-256 to a salted PBKDF2 hash now that the
        # plaintext is available and verified.
        if ([string]::IsNullOrWhiteSpace([string]$State.Auth.Hash)) {
          $salt = New-Object byte[] 16
          $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
          try { $rng.GetBytes($salt) } finally { $rng.Dispose() }

          $prf = Get-Pbkdf2Prf
          $State.Auth.Prf          = $prf
          $State.Auth.Iterations   = $Pbkdf2Iterations
          $State.Auth.Salt         = [Convert]::ToBase64String($salt)
          $State.Auth.Hash         = Get-Pbkdf2Hash $bytes $salt $Pbkdf2Iterations $prf
          $State.Auth.LegacySha256 = $null
          Save-State $State
          Write-Host "Stored password upgraded to a salted PBKDF2 hash." -ForegroundColor DarkGray
          if (-not [string]::IsNullOrWhiteSpace($env:EXITCONTROL_PASSWORD_HASH)) {
            Write-Host "You can now remove the EXITCONTROL_PASSWORD_HASH environment variable." -ForegroundColor DarkGray
          }
          Write-AuditEntry $State "ScriptPasswordUpgraded" @{ Prf = $prf }
        }
        Write-AuditEntry $State "AuthSuccess" @{ Attempt = $attempt }
        return
      }

      Write-Host ("Wrong password. Attempt {0}/3" -f $attempt) -ForegroundColor Red
      # Failed attempts are recorded too -- a run of them is exactly what an
      # audit trail exists to show.
      Write-AuditEntry $State "AuthFailure" @{ Attempt = $attempt }
    } finally {
      Clear-ByteArray $bytes
    }
  }

  Write-Host "Too many wrong attempts. Exiting." -ForegroundColor Red
  Write-ControlEvent $State "AuthLockout" @{ Attempts = 3 } `
    "ExitControl authentication lockout" ("3 failed attempts on " + $env:COMPUTERNAME) "warning"
  Wait-ForKey
  exit 1
}

# ---------------- HOSTS BLOCK ----------------

function Remove-HostsManagedBlock {
  <# Strips the ExitControl-managed region from a set of hosts lines. #>
  param([string[]]$Lines)

  $result = New-Object Collections.Generic.List[string]
  $inBlock = $false
  foreach ($line in $Lines) {
    if ($line -eq "$HostsMarker BEGIN") { $inBlock = $true; continue }
    if ($line -eq "$HostsMarker END")   { $inBlock = $false; continue }
    if (-not $inBlock) { $result.Add($line) }
  }
  # Comma-wrapped so an empty or single-line result is not unrolled to $null / a
  # bare string by the PowerShell output pipeline.
  return ,$result.ToArray()
}

function Get-HostsEncoding {
  <#
    Reads and writes must use the SAME encoding or non-ASCII content is
    corrupted on every toggle. Get-Content's default in Windows PowerShell is
    the system ANSI codepage, not UTF-8, so the encoding is detected from the
    file's own bytes. Pure ASCII is valid UTF-8, so an ordinary hosts file
    round-trips byte for byte.
  #>
  $bytes = [IO.File]::ReadAllBytes($HostsPath)

  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    return (New-Object Text.UTF8Encoding($true))
  }

  $strict = New-Object Text.UTF8Encoding($false, $true)
  try {
    [void]$strict.GetString($bytes)
    return (New-Object Text.UTF8Encoding($false))
  } catch {
    return [Text.Encoding]::Default
  }
}

function Get-HostsFileContent {
  param([Text.Encoding]$Encoding)
  return ,[IO.File]::ReadAllLines($HostsPath, $Encoding)
}

function Set-HostsFileContent {
  param([string[]]$Lines, [Text.Encoding]$Encoding)
  [IO.File]::WriteAllLines($HostsPath, $Lines, $Encoding)
}

function Backup-HostsFile {
  param($State)
  if ($State.Hosts.BackedUp) { return }

  # Strip any managed block before saving. If the state file was reset while
  # blocking was active, a raw copy would capture the blocked file and
  # "restore" would then reinstate the block permanently.
  $encoding = Get-HostsEncoding
  $lines = Get-HostsFileContent $encoding
  # No @() here: Remove-HostsManagedBlock comma-wraps its result, and @() around
  # that would produce a one-element array holding the inner array.
  $clean = Remove-HostsManagedBlock $lines

  # Timestamped so successive deployments do not overwrite each other's backup.
  $backupPath = Join-Path $StateDir ("hosts.backup-" + (New-BackupStamp))
  [IO.File]::WriteAllLines($backupPath, $clean, $encoding)

  $State.Hosts.BackupPath = $backupPath
  $State.Hosts.BackedUp   = $true
  Save-State $State
  Add-BackupRecord $State "Hosts" $backupPath
}

function Set-HostsBlock {
  param($State, [bool]$Apply)

  Backup-HostsFile $State

  $encoding = Get-HostsEncoding
  $lines = Get-HostsFileContent $encoding
  $lines = Remove-HostsManagedBlock $lines

  # Trim trailing blank lines so repeated toggles do not accumulate them.
  $end = $lines.Count - 1
  while ($end -ge 0 -and [string]::IsNullOrWhiteSpace($lines[$end])) { $end-- }
  if ($end -lt 0) { $lines = @() } else { $lines = @($lines[0..$end]) }

  if ($Apply) {
    $block = New-Object Collections.Generic.List[string]
    $block.Add("")
    $block.Add("$HostsMarker BEGIN")
    foreach ($domain in $BlockDomains) {
      $block.Add("127.0.0.1 $domain")
      $block.Add("::1 $domain")
    }
    $block.Add("$HostsMarker END")
    $lines = @($lines + $block.ToArray())
  }

  Set-HostsFileContent $lines $encoding
  & ipconfig /flushdns | Out-Null

  $State.Hosts.Applied = $Apply
  Save-State $State
  Write-Host ("HOSTS blocking {0} ({1} domains)." -f $(if ($Apply) { "ENABLED" } else { "DISABLED" }), $BlockDomains.Count) -ForegroundColor Green

  Write-ControlEvent $State "HostsBlock" @{ Applied = $Apply; Domains = $BlockDomains.Count } `
    "ExitControl HOSTS block toggled" ("Applied: " + $Apply) "info"
}

# ---------------- USB MASS STORAGE ----------------

$UsbStorKey = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"

function Backup-UsbStoragePolicy {
  param($State)
  if ($State.UsbStorage.BackedUp) { return }

  $value = $null
  if (Test-Path -LiteralPath $UsbStorKey) {
    $value = (Get-ItemProperty -LiteralPath $UsbStorKey -Name Start -ErrorAction SilentlyContinue).Start
  }
  $State.UsbStorage.OriginalStart = $value
  $State.UsbStorage.BackedUp = $true
  Save-State $State

  # A readable snapshot on disk, so the original value survives even if
  # state.json is later damaged.
  $backupPath = Join-Path $StateDir ("usbstor.backup-" + (New-BackupStamp) + ".json")
  ([pscustomobject]@{
    TimeUtc = (Get-Date).ToUniversalTime().ToString("o")
    Key     = $UsbStorKey
    Start   = $value
  } | ConvertTo-Json) | Set-Content -LiteralPath $backupPath -Encoding UTF8
  Add-BackupRecord $State "UsbStorage" $backupPath
}

function Set-UsbStorageBlock {
  param($State, [bool]$Apply)

  Backup-UsbStoragePolicy $State
  if (-not (Test-Path -LiteralPath $UsbStorKey)) {
    New-Item -Path $UsbStorKey -Force | Out-Null
  }

  if ($Apply) {
    Set-ItemProperty -LiteralPath $UsbStorKey -Name Start -Type DWord -Value 4
  } else {
    $restore = 3
    if ($null -ne $State.UsbStorage.OriginalStart) { $restore = [int]$State.UsbStorage.OriginalStart }
    Set-ItemProperty -LiteralPath $UsbStorKey -Name Start -Type DWord -Value $restore
  }

  $State.UsbStorage.Applied = $Apply
  Save-State $State
  Write-Host ("USB mass storage {0}." -f $(if ($Apply) { "DISABLED" } else { "RESTORED" })) -ForegroundColor Green

  Write-ControlEvent $State "UsbStorage" @{ Applied = $Apply } `
    "ExitControl USB storage toggled" ("Disabled: " + $Apply) "info"
}

# ---------------- BROWSER POLICIES ----------------

$ChromePolicyKey = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$EdgePolicyKey   = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

function Get-PolicyValue {
  param([string]$Key, [string]$Name)
  if (-not (Test-Path -LiteralPath $Key)) { return $null }
  return (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction SilentlyContinue).$Name
}

function Backup-BrowserPolicy {
  param($State)
  if ($State.BrowserPolicies.BackedUp) { return }

  $original = $State.BrowserPolicies.Original
  $original.ChromeIncognitoModeAvailability = Get-PolicyValue $ChromePolicyKey "IncognitoModeAvailability"
  $original.EdgeInPrivateModeAvailability   = Get-PolicyValue $EdgePolicyKey   "InPrivateModeAvailability"
  $original.ChromeDnsOverHttpsMode          = Get-PolicyValue $ChromePolicyKey "DnsOverHttpsMode"
  $original.EdgeDnsOverHttpsMode            = Get-PolicyValue $EdgePolicyKey   "DnsOverHttpsMode"

  $State.BrowserPolicies.BackedUp = $true
  Save-State $State

  $backupPath = Join-Path $StateDir ("browserpolicies.backup-" + (New-BackupStamp) + ".json")
  ([pscustomobject]@{
    TimeUtc  = (Get-Date).ToUniversalTime().ToString("o")
    Original = $original
  } | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $backupPath -Encoding UTF8
  Add-BackupRecord $State "BrowserPolicies" $backupPath
}

function Restore-PolicyValue {
  param([string]$Key, [string]$Name, $OriginalValue, [string]$Type)

  if ($null -eq $OriginalValue) {
    Remove-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction SilentlyContinue
  } elseif ($Type -eq "String") {
    Set-ItemProperty -LiteralPath $Key -Name $Name -Type String -Value ([string]$OriginalValue)
  } else {
    Set-ItemProperty -LiteralPath $Key -Name $Name -Type DWord -Value ([int]$OriginalValue)
  }
}

function Set-BrowserPrivacyPolicy {
  param($State, [bool]$Apply)

  Backup-BrowserPolicy $State

  foreach ($key in @($ChromePolicyKey, $EdgePolicyKey)) {
    if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
  }

  if ($Apply) {
    Set-ItemProperty -LiteralPath $ChromePolicyKey -Name IncognitoModeAvailability -Type DWord -Value 1
    Set-ItemProperty -LiteralPath $EdgePolicyKey   -Name InPrivateModeAvailability -Type DWord -Value 1
    # DNS-over-HTTPS would let the browser resolve blocked domains without
    # consulting the HOSTS file, so option 1 is only meaningful with this off.
    Set-ItemProperty -LiteralPath $ChromePolicyKey -Name DnsOverHttpsMode -Type String -Value "off"
    Set-ItemProperty -LiteralPath $EdgePolicyKey   -Name DnsOverHttpsMode -Type String -Value "off"
  } else {
    $original = $State.BrowserPolicies.Original
    Restore-PolicyValue $ChromePolicyKey "IncognitoModeAvailability" $original.ChromeIncognitoModeAvailability "DWord"
    Restore-PolicyValue $EdgePolicyKey   "InPrivateModeAvailability" $original.EdgeInPrivateModeAvailability   "DWord"
    Restore-PolicyValue $ChromePolicyKey "DnsOverHttpsMode"          $original.ChromeDnsOverHttpsMode          "String"
    Restore-PolicyValue $EdgePolicyKey   "DnsOverHttpsMode"          $original.EdgeDnsOverHttpsMode            "String"
  }

  $State.BrowserPolicies.Applied = $Apply
  Save-State $State
  Write-Host ("Private browsing + DoH policy {0}." -f $(if ($Apply) { "APPLIED" } else { "RESTORED" })) -ForegroundColor Green
  Write-Host "Browsers must be restarted for the policy to take effect." -ForegroundColor DarkGray

  Write-ControlEvent $State "BrowserPrivacyPolicy" @{ Applied = $Apply } `
    "ExitControl browser privacy policy toggled" ("Applied: " + $Apply) "info"
}

# ---------------- CONTROLLED RENAMES ----------------

function Get-RenameEntry {
  param($State, [string]$Path)
  foreach ($entry in @($State.Renames)) {
    if ($null -ne $entry -and $entry.Path -eq $Path) { return $entry }
  }
  return $null
}

function Test-RenameActive {
  param($State, [string[]]$Path)
  foreach ($entry in @($State.Renames)) {
    if ($null -ne $entry -and ($Path -contains $entry.Path) -and $entry.Applied) { return $true }
  }
  return $false
}

function Set-ManagedFileRename {
  param($State, [string]$Path, [bool]$Apply)

  $disabledPath = $Path + ".disabled"

  $entry = Get-RenameEntry $State $Path
  if ($null -eq $entry) {
    $entry = [pscustomobject]@{
      Path       = $Path
      BackupPath = (Join-Path $StateDir ((Split-Path $Path -Leaf) + ".backup"))
      Applied    = $false
    }
    $State.Renames = @(@($State.Renames) + $entry)
    Save-State $State
  }

  if ($Apply) {
    if ($entry.Applied -and (Test-Path -LiteralPath $disabledPath)) {
      Write-Host ("Already disabled: {0}" -f $Path) -ForegroundColor DarkGray
      return
    }
    if (-not (Test-Path -LiteralPath $Path)) {
      Write-Host ("Not present on this machine, skipping: {0}" -f $Path) -ForegroundColor DarkGray
      return
    }

    Copy-Item -LiteralPath $Path -Destination $entry.BackupPath -Force
    Move-Item -LiteralPath $Path -Destination $disabledPath -Force
    $entry.Applied = $true
    Write-Host ("Disabled: {0}" -f $Path) -ForegroundColor Green
  } else {
    # Deliberately NOT guarded on Test-Path $Path: once the file has been
    # renamed, $Path does not exist, and guarding on it made restore a no-op.
    if (Test-Path -LiteralPath $disabledPath) {
      Move-Item -LiteralPath $disabledPath -Destination $Path -Force
      $entry.Applied = $false
      Write-Host ("Restored: {0}" -f $Path) -ForegroundColor Green
    } elseif (Test-Path -LiteralPath $entry.BackupPath) {
      Copy-Item -LiteralPath $entry.BackupPath -Destination $Path -Force
      $entry.Applied = $false
      Write-Host ("Restored from backup copy: {0}" -f $Path) -ForegroundColor Green
    } elseif (Test-Path -LiteralPath $Path) {
      $entry.Applied = $false
      Write-Host ("Already in place: {0}" -f $Path) -ForegroundColor DarkGray
    } else {
      Write-Host ("Cannot restore {0}: neither the renamed file nor a backup was found." -f $Path) -ForegroundColor Red
      Write-Host ("Recover it with: sfc /scannow") -ForegroundColor Yellow
      return
    }
  }

  Save-State $State
  Write-AuditEntry $State "ManagedFileRename" @{ Path = $Path; Applied = $entry.Applied }
}

# ---------------- FIREWALL BROWSER BLOCK ----------------

function Get-BrowserExecutablePath {
  <#
    Resolves installed browser executables across Program Files, Program Files
    (x86) and every user profile. Note the ${env:ProgramFiles(x86)} brace
    syntax -- "$env:ProgramFiles(x86)" parses as $env:ProgramFiles followed by
    a literal "(x86)" and silently yields a path that never exists.
  #>
  $roots = New-Object Collections.Generic.List[string]
  if ($env:ProgramFiles)        { $roots.Add($env:ProgramFiles) }
  if (${env:ProgramFiles(x86)}) { $roots.Add(${env:ProgramFiles(x86)}) }

  $usersDir = Join-Path $env:SystemDrive "Users"
  if (Test-Path -LiteralPath $usersDir) {
    # Not named $profile -- that would shadow the automatic $PROFILE variable.
    foreach ($userProfile in (Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue)) {
      # -ErrorAction SilentlyContinue is required, not tidiness: some profiles
      # (service accounts such as WsiAccount, DefaultAppPool) deny access even
      # to an elevated admin, and under ErrorActionPreference=Stop that access
      # denial would abort the whole firewall operation.
      $local = Join-Path $userProfile.FullName "AppData\Local"
      if (Test-Path -LiteralPath $local -ErrorAction SilentlyContinue) { $roots.Add($local) }
    }
  }

  $found = New-Object Collections.Generic.List[string]
  foreach ($root in $roots) {
    foreach ($relative in $BrowserRelativePaths) {
      $candidate = Join-Path $root $relative
      if ((Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) -and
          -not $found.Contains($candidate)) {
        $found.Add($candidate)
      }
    }
  }
  return ,$found.ToArray()
}

function Assert-FirewallCmdlet {
  if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
    throw "The NetSecurity module is not available on this system; the firewall block cannot be managed from PowerShell."
  }
}

function Remove-FirewallBrowserRule {
  Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function Set-FirewallBrowserBlock {
  param($State, [bool]$Apply)

  Assert-FirewallCmdlet

  if (-not $Apply) {
    Remove-FirewallBrowserRule
    $State.Firewall.Applied = $false
    Save-State $State
    Write-Host "Firewall browser block REMOVED." -ForegroundColor Green
    Write-ControlEvent $State "FirewallBrowserBlock" @{ Applied = $false } `
      "ExitControl firewall block removed" ("Removed on " + $env:COMPUTERNAME) "info"
    return
  }

  # No @(): Get-BrowserExecutablePath comma-wraps its result.
  $paths = Get-BrowserExecutablePath
  if ($paths.Count -eq 0) {
    throw "No browser executables were found; no firewall rules were created."
  }

  # Old rules are removed first, so a failure part way through would otherwise
  # leave the machine unprotected while state still claimed the block was on.
  Remove-FirewallBrowserRule
  try {
    $index = 0
    foreach ($path in $paths) {
      $index++
      New-NetFirewallRule `
        -DisplayName ("ExitControl Block {0:d2} {1}" -f $index, (Split-Path $path -Leaf)) `
        -Group $FwGroup `
        -Direction Outbound `
        -Action Block `
        -Program $path `
        -Profile Any | Out-Null
      Write-Host ("  blocked: {0}" -f $path) -ForegroundColor DarkGray
    }
  } catch {
    Remove-FirewallBrowserRule
    $State.Firewall.Applied = $false
    Save-State $State
    throw
  }

  $State.Firewall.Applied = $true
  Save-State $State
  Write-Host ("Firewall browser block ENABLED ({0} executables)." -f $paths.Count) -ForegroundColor Green

  Write-ControlEvent $State "FirewallBrowserBlock" @{ Applied = $true; Programs = @($paths) } `
    "ExitControl firewall block enabled" ("{0} browser executables blocked" -f $paths.Count) "info"
}

# ---------------- WINDOWS ACCOUNT PASSWORD ----------------

function Update-WindowsPassword {
  param($State)

  if (-not (Get-Command Set-LocalUser -ErrorAction SilentlyContinue)) {
    throw "The LocalAccounts module is not available; local passwords cannot be changed from PowerShell on this system."
  }

  $user = Read-Host "Local username to change (blank = current user '$env:USERNAME')"
  if ([string]::IsNullOrWhiteSpace($user)) { $user = $env:USERNAME }

  $account = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
  if ($null -eq $account) {
    Write-Host ("No LOCAL account named '{0}' exists. Domain and Microsoft accounts cannot be changed here." -f $user) -ForegroundColor Red
    return
  }

  if (-not (Confirm-Action ("Change the Windows password for LOCAL account '{0}'?" -f $account.Name))) {
    Write-Host "Cancelled." -ForegroundColor Yellow
    return
  }

  # Asked twice: a silent typo here locks the account out, and this tool is run
  # precisely when nobody is around to notice until it is too late.
  $first  = Read-Host ("New Windows password for '{0}'" -f $account.Name) -AsSecureString
  $second = Read-Host "Re-enter the new Windows password" -AsSecureString

  $firstBytes  = ConvertTo-PasswordByte $first
  $secondBytes = ConvertTo-PasswordByte $second
  try {
    if ($firstBytes.Length -eq 0) {
      Write-Host "Empty password rejected." -ForegroundColor Red
      return
    }
    if (-not (Test-ByteArrayEqual $firstBytes $secondBytes)) {
      Write-Host "The two entries did not match. No change was made." -ForegroundColor Red
      return
    }
  } finally {
    Clear-ByteArray $firstBytes
    Clear-ByteArray $secondBytes
  }

  Set-LocalUser -Name $account.Name -Password $first
  Write-Host ("Windows password updated for: {0}" -f $account.Name) -ForegroundColor Green

  # The account name is recorded; the password itself never is.
  Write-ControlEvent $State "WindowsPasswordChanged" @{ Account = $account.Name } `
    "ExitControl changed a Windows password" ("Local account: " + $account.Name) "warning"
}

# ---------------- UI ----------------

function Format-Toggle {
  param([bool]$Value, [string]$OnText = "ON", [string]$OffText = "OFF")
  if ($Value) { return $OnText }
  return $OffText
}

function Show-Status {
  param($State)

  $snipOn     = Test-RenameActive $State $SnipPaths
  $openWithOn = Test-RenameActive $State @($OpenWithPath)

  Write-Host ""
  Write-Host "--- Current ExitControl Status ---" -ForegroundColor Cyan
  Write-Host ("HOSTS blocking:             " + (Format-Toggle $State.Hosts.Applied))
  Write-Host ("USB mass storage disabled:  " + (Format-Toggle $State.UsbStorage.Applied))
  Write-Host ("Private browsing + DoH off: " + (Format-Toggle $State.BrowserPolicies.Applied))
  Write-Host ("Firewall browser block:     " + (Format-Toggle $State.Firewall.Applied))
  Write-Host ("Snipping tools disabled:    " + (Format-Toggle $snipOn))
  Write-Host ("OpenWith.exe disabled:      " + (Format-Toggle $openWithOn "ON (Aggressive)"))
  Write-Host ("Script integrity:           " + $State.Integrity.LastStatus)
  Write-Host ("State file:                 " + $StateFile)
  Write-Host ("Audit log:                  " + $LogDir)
  Write-Host ("Config file:                " + $(if (Test-Path -LiteralPath $ConfigPath) { $ConfigPath } else { "(defaults)" }))
  Write-Host ("State created:              " + $State.CreatedAt)
  Write-Host "----------------------------------" -ForegroundColor Cyan
  Write-Host ""
}

function Show-Checklist {
@"
CHECKLIST: Verify Leak Paths

A) Browser uploads
  [ ] WeTransfer/Dropbox/Mega upload -> FAIL or site blocked
  [ ] Personal Gmail attachment in browser -> FAIL or gmail blocked
  [ ] Drag & drop file into any web upload -> FAIL

B) USB / External storage
  [ ] Plug USB -> not accessible

C) OneDrive (Company)
  [ ] Edit a doc inside OneDrive folder -> sync OK

D) Private browsing
  [ ] Chrome Incognito disabled (restart Chrome first)
  [ ] Edge InPrivate disabled (restart Edge first)
  [ ] chrome://settings/security shows "Use secure DNS" forced off

E) Firewall (if enabled)
  [ ] Browsers cannot browse
  [ ] OneDrive sync still works
"@ | Write-Host
}

function Show-RollbackGuide {
@"
ROLLBACK GUIDE

1) Run ExitControl as Administrator (RunExitControl.bat)
2) Choose: 11) Restore ALL
3) Reboot
4) Re-run and choose 10) Show current status to confirm everything reads OFF

Backups and state: $StateDir
  state.json           original settings + password hash (do NOT delete)
  hosts.backup-*       pre-change HOSTS file, timestamped
  usbstor.backup-*     pre-change USBSTOR Start value
  browserpolicies.backup-*  pre-change Chrome/Edge policy values
  *.exe.backup         copies of any renamed executable
  logs\audit-*.log     what was changed, when, by whom

Option 13 (diagnostics) compares the live machine against the recorded state and
reports any control that drifted.

If state.json is lost, rollback has to be done by hand:
  - HOSTS:    remove the "$HostsMarker BEGIN/END" block
  - USB:      set HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start to 3
  - Policies: delete IncognitoModeAvailability / InPrivateModeAvailability /
              DnsOverHttpsMode under HKLM\SOFTWARE\Policies\{Google\Chrome,Microsoft\Edge}
  - Firewall: remove rules in group "$FwGroup"
  - Renames:  rename any *.exe.disabled under System32 back to *.exe
"@ | Write-Host
}

function Test-ControlState {
  <#
    Inspects the MACHINE rather than trusting state.json, and reports each
    control as Actual vs Expected. Divergence means something changed the
    setting outside this tool -- which is the failure mode a status screen
    driven purely by state.json can never show.
  #>
  param($State)

  $results = New-Object Collections.Generic.List[pscustomobject]

  function Add-Result($name, $actual, $expected) {
    $results.Add([pscustomobject]@{
      Control  = $name
      Actual   = [bool]$actual
      Expected = [bool]$expected
      Drift    = ([bool]$actual -ne [bool]$expected)
    })
  }

  # HOSTS: is the managed block physically present?
  $hostsPresent = $false
  if (Test-Path -LiteralPath $HostsPath) {
    $lines = @(Get-Content -LiteralPath $HostsPath -ErrorAction SilentlyContinue)
    $hostsPresent = ($lines -contains "$HostsMarker BEGIN") -and ($lines -contains "$HostsMarker END")
  }
  Add-Result "HostsBlock" $hostsPresent $State.Hosts.Applied

  # USB mass storage
  $start = $null
  if (Test-Path -LiteralPath $UsbStorKey) {
    $start = (Get-ItemProperty -LiteralPath $UsbStorKey -Name Start -ErrorAction SilentlyContinue).Start
  }
  Add-Result "UsbStorageDisabled" ($start -eq 4) $State.UsbStorage.Applied

  # Browser policies
  Add-Result "ChromeIncognitoDisabled" ((Get-PolicyValue $ChromePolicyKey "IncognitoModeAvailability") -eq 1) $State.BrowserPolicies.Applied
  Add-Result "EdgeInPrivateDisabled"   ((Get-PolicyValue $EdgePolicyKey   "InPrivateModeAvailability") -eq 1) $State.BrowserPolicies.Applied
  Add-Result "ChromeDohOff" ((Get-PolicyValue $ChromePolicyKey "DnsOverHttpsMode") -eq "off") $State.BrowserPolicies.Applied
  Add-Result "EdgeDohOff"   ((Get-PolicyValue $EdgePolicyKey   "DnsOverHttpsMode") -eq "off") $State.BrowserPolicies.Applied

  # Firewall
  $ruleCount = 0
  if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
    $ruleCount = @(Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue).Count
  }
  Add-Result "FirewallBrowserRules" ($ruleCount -gt 0) $State.Firewall.Applied

  # Renames: is the .disabled file actually on disk?
  $snipDisabled = $false
  foreach ($snipPath in $SnipPaths) {
    if (Test-Path -LiteralPath ($snipPath + ".disabled") -ErrorAction SilentlyContinue) { $snipDisabled = $true }
  }
  Add-Result "SnippingToolsDisabled" $snipDisabled (Test-RenameActive $State $SnipPaths)

  $openWithDisabled = Test-Path -LiteralPath ($OpenWithPath + ".disabled") -ErrorAction SilentlyContinue
  Add-Result "OpenWithDisabled" $openWithDisabled (Test-RenameActive $State @($OpenWithPath))

  # Deliberately NOT comma-wrapped. This always returns a fixed set of rows, so
  # there is no empty/single-element case to protect, and leaving the comma off
  # means callers can safely write @(Test-ControlState $s) -- with it, the @()
  # would yield a one-element array wrapping the real one.
  return $results.ToArray()
}

function Show-Diagnostic {
  param($State)

  $results = Test-ControlState $State

  Write-Host ""
  Write-Host "--- Diagnostics: machine vs recorded state ---" -ForegroundColor Cyan
  Write-Host ("{0,-26} {1,-8} {2,-8} {3}" -f "CONTROL", "ACTUAL", "EXPECTED", "")
  foreach ($result in $results) {
    $flag  = if ($result.Drift) { "DRIFT" } else { "ok" }
    $color = if ($result.Drift) { "Red" } else { "Green" }
    Write-Host ("{0,-26} {1,-8} {2,-8} {3}" -f `
      $result.Control, (Format-Toggle $result.Actual), (Format-Toggle $result.Expected), $flag) -ForegroundColor $color
  }

  $drifted = @($results | Where-Object { $_.Drift })
  Write-Host ""
  if ($drifted.Count -eq 0) {
    Write-Host "No drift: every control matches what ExitControl recorded." -ForegroundColor Green
  } else {
    Write-Host ("{0} control(s) drifted from the recorded state." -f $drifted.Count) -ForegroundColor Red
    Write-Host "Something changed these outside ExitControl, or a control failed to apply." -ForegroundColor Yellow
  }

  $chain = Test-AuditChain
  if ($chain.Checked -gt 0) {
    if ($chain.Intact) {
      Write-Host ("Audit chain intact across {0} entries." -f $chain.Checked) -ForegroundColor Green
    } else {
      Write-Host ("Audit chain BROKEN at {0}." -f $chain.BrokenAt) -ForegroundColor Red
    }
  }
  Write-Host ("Integrity status: {0}" -f $State.Integrity.LastStatus) -ForegroundColor DarkGray
  Write-Host "----------------------------------------------" -ForegroundColor Cyan
  Write-Host ""

  Write-AuditEntry $State "DiagnosticsRun" @{
    Drifted    = $drifted.Count
    ChainOk    = $chain.Intact
    Checked    = $chain.Checked
  }

  if ($drifted.Count -gt 0) {
    Send-Notification "ExitControl diagnostics found drift" `
      ("{0} control(s) drifted on {1}" -f $drifted.Count, $env:COMPUTERNAME) "warning"
  }
}

function Restore-AllControl {
  param($State)

  $failures = 0

  if (-not (Invoke-ControlAction "restore HOSTS" {
    if ($State.Hosts.BackedUp -and (Test-Path -LiteralPath $State.Hosts.BackupPath)) {
      Copy-Item -LiteralPath $State.Hosts.BackupPath -Destination $HostsPath -Force
      & ipconfig /flushdns | Out-Null
      $State.Hosts.Applied = $false
      Save-State $State
      Write-Host "HOSTS file restored from backup." -ForegroundColor Green
    } else {
      Set-HostsBlock $State $false
    }
  })) { $failures++ }

  if (-not (Invoke-ControlAction "restore USB mass storage" { Set-UsbStorageBlock $State $false })) { $failures++ }
  if (-not (Invoke-ControlAction "restore browser policies" { Set-BrowserPrivacyPolicy $State $false })) { $failures++ }
  if (-not (Invoke-ControlAction "remove firewall rules"    { Set-FirewallBrowserBlock $State $false })) { $failures++ }

  foreach ($entry in @($State.Renames)) {
    if ($null -eq $entry -or -not $entry.Applied) { continue }
    $path = $entry.Path
    if (-not (Invoke-ControlAction ("restore " + $path) { Set-ManagedFileRename $State $path $false })) { $failures++ }
  }

  Save-State $State

  Write-Host ""
  if ($failures -eq 0) {
    Write-Host "Restore ALL completed. Reboot recommended." -ForegroundColor Green
  } else {
    Write-Host ("Restore ALL finished with {0} failure(s) -- see the messages above." -f $failures) -ForegroundColor Red
    Write-Host "The machine is NOT fully rolled back. Option 9 lists the manual steps." -ForegroundColor Yellow
  }

  Write-ControlEvent $State "RestoreAll" @{ Failures = $failures } `
    "ExitControl restore ALL" ("Completed with {0} failure(s) on {1}" -f $failures, $env:COMPUTERNAME) `
    $(if ($failures -eq 0) { "info" } else { "warning" })

  # Verify rather than just claiming success.
  Show-Status $State
  Show-Diagnostic $State
}

# Options still permitted when the script fails its integrity check.
$LimitedModeOptions = @("0", "8", "9", "10", "13", "14", "15")

function Show-Menu {
  param([bool]$Limited = $false)

  Write-Host "==============================" -ForegroundColor Green
  Write-Host " ExitControl - Offboarding Menu" -ForegroundColor Green
  Write-Host "=============================="
  if ($Limited) {
    Write-Host " LIMITED MODE - integrity check failed; changes are blocked" -ForegroundColor Red
  }
  Write-Host " 1) Toggle HOSTS blocking (upload / personal cloud / webmail)"
  Write-Host " 2) Toggle USB mass storage disable"
  Write-Host " 3) Toggle Incognito/InPrivate + DNS-over-HTTPS disable (Chrome/Edge)"
  Write-Host " 4) Toggle firewall BLOCK of browser outbound traffic"
  Write-Host " 5) Toggle disable of Snipping Tool / Snip & Sketch"
  Write-Host " 6) Toggle disable of OpenWith.exe (AGGRESSIVE)"
  Write-Host " 7) Change a LOCAL Windows account password"
  Write-Host " 8) Show verification checklist"
  Write-Host " 9) Show rollback guide"
  Write-Host "10) Show current status"
  Write-Host "11) Restore ALL (rollback everything)"
  Write-Host "12) Change the ExitControl password"
  Write-Host "13) Run diagnostics (machine vs recorded state)"
  Write-Host "14) Refresh script integrity baseline"
  Write-Host "15) View recent audit entries"
  Write-Host " 0) Exit"
}

# ---------------- MAIN ----------------

Assert-Administrator

# Startup runs outside the menu loop, so it has no Invoke-ControlAction around
# it. Guard it explicitly: a corrupt salt or an unreadable state file would
# otherwise terminate the script and take the elevated window -- and the error
# message with it -- straight off the screen.
try {
  $state = Get-State
  $state = Initialize-AuthState $state
  Save-State $state
  $integrityOk = Test-ScriptIntegrity $state
  Request-ScriptPassword $state
} catch {
  Write-Host ""
  Write-Host "ERROR: ExitControl could not start." -ForegroundColor Red
  Write-Host ("  {0}" -f $_.Exception.Message) -ForegroundColor Yellow
  Write-Host ("  State file: {0}" -f $StateFile) -ForegroundColor Yellow
  Write-Host ""
  Wait-ForKey
  exit 1
}

$running = $true
while ($running) {
  Show-Menu (-not $integrityOk)
  $choice = Read-Host "Select option"

  if (-not $integrityOk -and ($LimitedModeOptions -notcontains $choice)) {
    Write-Host ""
    Write-Host "Blocked: the script failed its integrity check." -ForegroundColor Red
    Write-Host "Available: 8, 9, 10, 13, 14, 15, 0. Use 14 to re-baseline if the change was intended." -ForegroundColor Yellow
    Write-Host ""
    continue
  }

  switch ($choice) {
    "1" { [void](Invoke-ControlAction "toggle HOSTS blocking" { Set-HostsBlock $state (-not $state.Hosts.Applied) }) }
    "2" { [void](Invoke-ControlAction "toggle USB mass storage" { Set-UsbStorageBlock $state (-not $state.UsbStorage.Applied) }) }
    "3" { [void](Invoke-ControlAction "toggle browser privacy policy" { Set-BrowserPrivacyPolicy $state (-not $state.BrowserPolicies.Applied) }) }
    "4" { [void](Invoke-ControlAction "toggle firewall browser block" { Set-FirewallBrowserBlock $state (-not $state.Firewall.Applied) }) }

    "5" {
      $target = -not (Test-RenameActive $state $SnipPaths)
      foreach ($snipPath in $SnipPaths) {
        [void](Invoke-ControlAction ("toggle " + $snipPath) { Set-ManagedFileRename $state $snipPath $target })
      }
    }

    "6" {
      $target = -not (Test-RenameActive $state @($OpenWithPath))
      $proceed = $true

      if ($target) {
        Write-Host ""
        Write-Host "WARNING: aggressive. Disabling OpenWith.exe breaks the normal Windows" -ForegroundColor Yellow
        Write-Host "'Open with...' dialog for every user on this machine." -ForegroundColor Yellow
        $proceed = Confirm-Action "Disable OpenWith.exe?"
      }

      if ($proceed) {
        [void](Invoke-ControlAction ("toggle " + $OpenWithPath) { Set-ManagedFileRename $state $OpenWithPath $target })
      } else {
        Write-Host "Cancelled." -ForegroundColor Yellow
      }
    }

    "7"  { [void](Invoke-ControlAction "change Windows password" { Update-WindowsPassword $state }) }
    "8"  { Show-Checklist }
    "9"  { Show-RollbackGuide }
    "10" { Show-Status $state }

    "11" {
      if (Confirm-Action "Roll back every control this tool applied?") {
        Restore-AllControl $state
      } else {
        Write-Host "Cancelled." -ForegroundColor Yellow
      }
    }

    "12" { [void](Invoke-ControlAction "change ExitControl password" { [void](Set-ScriptPassword $state) }) }
    "13" { [void](Invoke-ControlAction "run diagnostics" { Show-Diagnostic $state }) }

    "14" {
      if (Confirm-Action "Record the current script file as the trusted baseline?") {
        [void](Invoke-ControlAction "refresh integrity baseline" {
          Reset-ScriptIntegrityBaseline $state
        })
        $integrityOk = $true
      } else {
        Write-Host "Cancelled." -ForegroundColor Yellow
      }
    }

    "15" { [void](Invoke-ControlAction "read audit log" { Show-AuditEntry 20 }) }

    "0" { $running = $false }

    default { Write-Host "Invalid option." -ForegroundColor Red }
  }

  if ($running) { Write-Host "" }
}

Write-Host "Exiting ExitControl." -ForegroundColor Green
