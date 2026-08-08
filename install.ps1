#Requires -Version 5.1
<#
install.ps1 -- deploys ExitControl to a workstation.

Copies the tool into a locked-down directory, optionally seeds the ExitControl
password hash, and restricts the directory ACL to SYSTEM, Administrators and an
optional extra admin group.

Examples:
  .\install.ps1
  .\install.ps1 -AdminGroup "CONTOSO\Desktop-Admins"
  .\install.ps1 -PasswordHash (Get-Content .\hash.txt) -AdminGroup "CONTOSO\IT"

Must be run as Administrator.
#>
[CmdletBinding()]
# PasswordHash holds a SHA-256 digest, not a password. A SecureString would be
# the wrong type: the value is written to a machine-scope environment variable,
# so wrapping it buys nothing and only complicates the caller.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
  'PSAvoidUsingPlainTextForPassword', 'PasswordHash',
  Justification = 'Parameter is a hex digest, not a plaintext secret.')]
param(
  # SHA-256 hex digest of the chosen ExitControl password. Optional: without it,
  # ExitControl prompts for a password on its first run, which is the stronger
  # option -- see DEPLOYMENT.md.
  [string]$PasswordHash,

  # Folder containing ExitControl.ps1 / .exe / RunExitControl.bat.
  [string]$SourcePath = $PSScriptRoot,

  [string]$TargetDir = "C:\ProgramData\ExitControl\bin",

  # Extra group to grant read/execute, e.g. "CONTOSO\Desktop-Admins".
  # Omit to grant only SYSTEM and the local Administrators group.
  [string]$AdminGroup
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
  $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "install.ps1 must be run as Administrator."
  }
}

function Initialize-Directory {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function Copy-Payload {
  param([string]$Source, [string]$Destination)

  Initialize-Directory $Destination

  $names = @("ExitControl.exe", "ExitControl.ps1", "RunExitControl.bat")
  $copied = 0
  foreach ($name in $names) {
    $from = Join-Path $Source $name
    if (Test-Path -LiteralPath $from) {
      Copy-Item -LiteralPath $from -Destination $Destination -Force
      Write-Host ("  copied {0}" -f $name) -ForegroundColor Green
      $copied++
    }
  }

  if ($copied -eq 0) {
    throw "Nothing to install: none of $($names -join ', ') were found in '$Source'."
  }
  return $copied
}

function Set-RestrictiveAcl {
  <#
    Grants SYSTEM and Administrators full control, plus read/execute to an
    optional extra group, and removes inherited permissions.

    Well-known SIDs are used rather than names like "BUILTIN\Administrators" so
    this works on non-English installs. (OI)(CI) equivalents are applied via
    inheritance flags -- the branch version granted no inheritance, so files
    created later in the folder did not pick the rules up.
  #>
  param([string]$Path, [string]$ExtraGroup)

  $acl = Get-Acl -Path $Path
  $acl.SetAccessRuleProtection($true, $false)   # drop inheritance, discard inherited rules
  foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }

  $inherit = "ContainerInherit,ObjectInherit"

  foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {   # SYSTEM, BUILTIN\Administrators
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
      $identity, "FullControl", $inherit, "None", "Allow")))
  }

  if (-not [string]::IsNullOrWhiteSpace($ExtraGroup)) {
    try {
      $account = New-Object Security.Principal.NTAccount($ExtraGroup)
      [void]$account.Translate([Security.Principal.SecurityIdentifier])   # fail early if unresolvable
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $account, "ReadAndExecute", $inherit, "None", "Allow")))
      Write-Host ("  granted ReadAndExecute to {0}" -f $ExtraGroup) -ForegroundColor Green
    } catch {
      throw "Could not resolve -AdminGroup '$ExtraGroup': $($_.Exception.Message). Re-run with a valid group, or omit it."
    }
  }

  Set-Acl -Path $Path -AclObject $acl
  Write-Host ("  locked down {0} (SYSTEM + Administrators full control)" -f $Path) -ForegroundColor Green
}

function Set-PasswordHashSeed {
  param([string]$Hash)

  $trimmed = $Hash.Trim()
  if ($trimmed -notmatch '^[0-9a-fA-F]{64}$') {
    throw "-PasswordHash must be a 64-character SHA-256 hex digest (got $($trimmed.Length) characters)."
  }

  [Environment]::SetEnvironmentVariable("EXITCONTROL_PASSWORD_HASH", $trimmed.ToLowerInvariant(), "Machine")
  Write-Host "  seeded EXITCONTROL_PASSWORD_HASH (machine scope)" -ForegroundColor Green
  Write-Host ""
  Write-Host "  NOTE: a machine-scope environment variable is readable by every user," -ForegroundColor Yellow
  Write-Host "        and a bare SHA-256 has no salt. ExitControl replaces it with a" -ForegroundColor Yellow
  Write-Host "        salted PBKDF2 hash on first login -- remove the variable after that:" -ForegroundColor Yellow
  Write-Host '        [Environment]::SetEnvironmentVariable("EXITCONTROL_PASSWORD_HASH", $null, "Machine")' -ForegroundColor Yellow
  Write-Host ""
}

# ---------------- MAIN ----------------

try {
  Assert-Administrator

  Write-Host ""
  Write-Host "Installing ExitControl" -ForegroundColor Cyan
  Write-Host ("  source: {0}" -f $SourcePath)
  Write-Host ("  target: {0}" -f $TargetDir)
  Write-Host ""

  # The state directory is created and locked down by ExitControl itself on every
  # run; this only needs to exist so the bin folder has a parent.
  Initialize-Directory (Split-Path $TargetDir -Parent)

  [void](Copy-Payload -Source $SourcePath -Destination $TargetDir)

  if (-not [string]::IsNullOrWhiteSpace($PasswordHash)) {
    Set-PasswordHashSeed -Hash $PasswordHash
  } else {
    Write-Host "  no -PasswordHash given: ExitControl will prompt on first run" -ForegroundColor DarkGray
  }

  Set-RestrictiveAcl -Path $TargetDir -ExtraGroup $AdminGroup

  Write-Host ""
  Write-Host "Deployment complete." -ForegroundColor Green
  Write-Host ("Launch elevated from {0}:" -f $TargetDir)
  Write-Host "  ExitControl.exe        (packaged build), or"
  Write-Host "  RunExitControl.bat     (script build)"
  Write-Host ""
  Write-Host "Verify the ACL with:" -ForegroundColor DarkGray
  Write-Host ("  icacls `"{0}`"" -f $TargetDir) -ForegroundColor DarkGray
  Write-Host ""
  exit 0
} catch {
  Write-Host ""
  Write-Host "INSTALL FAILED" -ForegroundColor Red
  Write-Host ("  {0}" -f $_.Exception.Message) -ForegroundColor Yellow
  Write-Host ""
  exit 1
}
