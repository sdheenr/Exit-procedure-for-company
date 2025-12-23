# ExitControl deployment checklist

## 1) Build a packaged executable (hide source)
Requires PowerShell 5.1+ and `ps2exe`:

```powershell
Install-Module -Name ps2exe -Scope CurrentUser
Import-Module ps2exe

$script      = "ExitControl.ps1"
$output      = "C:\ProgramData\ExitControl\bin\ExitControl.exe"
$icon        = $null # or path to .ico

# Create output folder ahead of time
New-Item -ItemType Directory -Path (Split-Path $output) -Force | Out-Null

Invoke-ps2exe -inputFile $script -outputFile $output -noConsole -iconFile $icon
```

> Tip: you can also use `ps2exe.ps1 -inputFile ...` if the module is not installed.

### Optional: double-click launcher (PS1)
If you prefer to keep using the PS1 instead of the packaged EXE, place `RunExitControl.bat` next to `ExitControl.ps1`. Double-clicking the BAT will prompt for elevation and start the script with execution policy bypassed.

### Optional: config file
Create `C:\ProgramData\ExitControl\config.json` to override defaults:

```json
{
  "PasswordPolicy": {
    "MinLength": 12,
    "RequireUpper": true,
    "RequireLower": true,
    "RequireDigit": true,
    "RequireSpecial": true
  },
  "AdditionalBlockDomains": [ "example.com" ],
  "Notifications": {
    "WebhookUrl": null,
    "WebhookAuthHeader": null
  },
  "BackupLimit": 5
}
```

## 2) Configure the script password (hash-based)
Set the SHA-256 hash of your chosen password as an environment variable before first run so the hash is persisted to state:

```powershell
$Plain = Read-Host "New ExitControl password" -AsSecureString
$bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Plain)
try {
  $plainText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
$hash = Get-Sha256Hex $plainText
[Environment]::SetEnvironmentVariable("EXITCONTROL_PASSWORD_HASH", $hash, "Machine")
```

## 3) Lock down the binary location (NTFS ACL)
Place the packaged executable in a locked directory with read/execute allowed only for intended admins:

```powershell
$binDir = "C:\ProgramData\ExitControl\bin"
New-Item -ItemType Directory -Path $binDir -Force | Out-Null

# Remove inherited permissions and grant only specific admins
icacls $binDir /inheritance:r
icacls $binDir /grant "DOMAIN\\AdminTeam:(RX)"
icacls $binDir /grant "SYSTEM:(F)"
```

If multiple executables live in the folder, explicitly set permissions on the `.exe` as well:

```powershell
icacls "$binDir\\ExitControl.exe" /inheritance:r
icacls "$binDir\\ExitControl.exe" /grant "DOMAIN\\AdminTeam:(RX)"
icacls "$binDir\\ExitControl.exe" /grant "SYSTEM:(F)"
```

## 4) Optional: sign the binary
If you have a code-signing certificate in the local machine store:

```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath "C:\ProgramData\ExitControl\bin\ExitControl.exe" -Certificate $cert
```

## 5) Usage notes
- Run ExitControl **as Administrator**.
- Double-click `ExitControl.exe` (packaged) or `RunExitControl.bat` (script) to launch with elevation prompts.
- State is stored in `C:\ProgramData\ExitControl\state.json` and only contains the password hash.
- To rotate the password, update `EXITCONTROL_PASSWORD_HASH`, delete the stored state file, and relaunch to recreate it with the new hash.
- Audit logs are written to `C:\ProgramData\ExitControl\logs\audit-YYYYMMDD.log` with hash chaining.
- Integrity baseline is stored at `C:\ProgramData\ExitControl\expected.sha256`; refresh via menu option.
- A lightweight installer helper is provided as `install.ps1` to copy binaries, set the password hash, and apply ACLs.
