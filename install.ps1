# install.ps1 - helper to deploy ExitControl
param(
  [string]$PasswordHash,
  [string]$SourcePath = ".",
  [string]$TargetDir = "C:\ProgramData\ExitControl\bin",
  [string]$AdminGroup = "DOMAIN\AdminTeam"
)

function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
  if (-not $isAdmin) {
    Write-Host "Run this script as Administrator." -ForegroundColor Red
    exit 1
  }
}

function Ensure-Dir($path) {
  if (-not (Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force | Out-Null
  }
}

function Copy-Binaries {
  param($src, $dst)
  Ensure-Dir $dst
  $candidates = @("ExitControl.exe","ExitControl.ps1","RunExitControl.bat")
  foreach ($c in $candidates) {
    $from = Join-Path $src $c
    if (Test-Path $from) {
      Copy-Item -Path $from -Destination $dst -Force
      Write-Host "Copied $c -> $dst"
    }
  }
}

function Apply-Acls {
  param($dst, $group)
  icacls $dst /inheritance:r | Out-Null
  icacls $dst /grant "$group:(RX)" | Out-Null
  icacls $dst /grant "SYSTEM:(F)" | Out-Null
}

Ensure-Admin
Ensure-Dir "C:\ProgramData\ExitControl"
Copy-Binaries -src $SourcePath -dst $TargetDir

if ($PasswordHash) {
  [Environment]::SetEnvironmentVariable("EXITCONTROL_PASSWORD_HASH", $PasswordHash, "Machine")
  Write-Host "Configured EXITCONTROL_PASSWORD_HASH"
}

Apply-Acls -dst $TargetDir -group $AdminGroup
Write-Host "Deployment complete. Launch ExitControl via ExitControl.exe or RunExitControl.bat (elevation required)." -ForegroundColor Green
