# ExitControl deployment checklist

Deploy on a company-owned workstation you are authorised to administer. See
[README.md](README.md) for what each control does and its limitations.

## 1) Set the ExitControl password

**Recommended: let the script prompt you.** On the first run with no password
configured, ExitControl asks for one (twice) and stores it as a salted PBKDF2
hash in `C:\ProgramData\ExitControl\state.json`. No pre-work is needed.

There is deliberately **no built-in default password**.

### Unattended alternative

To seed the password across many machines without an interactive first run, set
`EXITCONTROL_PASSWORD_HASH` to the SHA-256 hex digest of your chosen password.
This snippet is self-contained — run it in any PowerShell window:

```powershell
$secure = Read-Host "New ExitControl password" -AsSecureString
$bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try   { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$sha = [System.Security.Cryptography.SHA256]::Create()
try {
  $hash = (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plain)) |
            ForEach-Object { $_.ToString('x2') }) -join '')
} finally { $sha.Dispose() }

[Environment]::SetEnvironmentVariable("EXITCONTROL_PASSWORD_HASH", $hash, "Machine")
$hash
```

The seed is a **bootstrap only**, and it is weaker than the stored hash: a
machine-scope environment variable is readable by every user on the box, and a
bare SHA-256 has no salt and no work factor, so it can be attacked offline.
ExitControl replaces it with a salted PBKDF2 hash on the first successful login
and then tells you so. **Remove the variable once that has happened:**

```powershell
[Environment]::SetEnvironmentVariable("EXITCONTROL_PASSWORD_HASH", $null, "Machine")
```

### Rotating the password

Use menu option **12) Change the ExitControl password**.

Do **not** delete `state.json` to force a new password. That file holds the
original value of every setting the tool changed; without it the machine cannot
be rolled back automatically.

## 2) Optional: build a packaged executable

Requires PowerShell 5.1+ and `ps2exe`:

```powershell
Install-Module -Name ps2exe -Scope CurrentUser
Import-Module ps2exe

$script = "ExitControl.ps1"
$output = "C:\ProgramData\ExitControl\bin\ExitControl.exe"

New-Item -ItemType Directory -Path (Split-Path $output) -Force | Out-Null

Invoke-ps2exe -inputFile $script -outputFile $output -requireAdmin
```

- Do **not** pass `-noConsole`. ExitControl is an interactive console menu; with
  `-noConsole` there is no console for the menu to draw in or read from.
- `-requireAdmin` embeds a manifest so the EXE triggers a UAC prompt by itself.
- Add `-iconFile "path\to\icon.ico"` only if you actually have an icon file;
  passing `$null` is an error.

### Double-click launcher (PS1)

To keep using the PS1 instead, place `RunExitControl.bat` next to
`ExitControl.ps1`. Double-clicking it prompts for elevation and starts the
script with the execution policy bypassed. If elevation is declined the batch
file reports it and pauses rather than closing silently.

## 3) Lock down the binary location (NTFS ACL)

Note: ExitControl already restricts `C:\ProgramData\ExitControl` to SYSTEM and
Administrators on every run. This step covers the packaged EXE if you built one.

### Recommended: use install.ps1

`install.ps1` does the copy and the ACL in one step, with the inheritance flags
and well-known SIDs set correctly:

```powershell
# Copy + lock down, prompting for a password on first run
.\install.ps1

# Grant an extra admin group read/execute as well
.\install.ps1 -AdminGroup "CONTOSO\Desktop-Admins"

# Seed the password hash at the same time (see section 1)
.\install.ps1 -AdminGroup "CONTOSO\Desktop-Admins" -PasswordHash $hash
```

It refuses to run unelevated, fails loudly if `-AdminGroup` cannot be resolved,
validates that `-PasswordHash` is a 64-character hex digest, and errors rather
than silently installing nothing if no payload files are found. Verify with
`icacls "C:\ProgramData\ExitControl\bin"` afterwards.

### Manual equivalent

```powershell
$binDir = "C:\ProgramData\ExitControl\bin"
New-Item -ItemType Directory -Path $binDir -Force | Out-Null

icacls $binDir /inheritance:r
icacls $binDir /grant "DOMAIN\AdminTeam:(OI)(CI)(RX)"
icacls $binDir /grant "SYSTEM:(OI)(CI)(F)"
icacls $binDir /grant "BUILTIN\Administrators:(OI)(CI)(F)"
```

Use a **single** backslash in the account name — `"DOMAIN\\AdminTeam"` inside
PowerShell double quotes is a literal doubled backslash and will not resolve.
Replace `DOMAIN\AdminTeam` with a real group; verify with `icacls $binDir`.

If multiple executables live in the folder, set permissions on the `.exe` too:

```powershell
icacls "$binDir\ExitControl.exe" /inheritance:r
icacls "$binDir\ExitControl.exe" /grant "DOMAIN\AdminTeam:(RX)"
icacls "$binDir\ExitControl.exe" /grant "SYSTEM:(F)"
icacls "$binDir\ExitControl.exe" /grant "BUILTIN\Administrators:(F)"
```

## 4) Optional: sign the binary

With a code-signing certificate in the local machine store:

```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath "C:\ProgramData\ExitControl\bin\ExitControl.exe" -Certificate $cert
```

## 5) Usage notes

- Run ExitControl **as Administrator** — it refuses to start otherwise.
- Double-click `ExitControl.exe` (packaged) or `RunExitControl.bat` (script).
- Apply the controls, then work through option **8) verification checklist**.
- Run option **13) diagnostics** — it inspects the live machine and flags any
  control that drifted from what was recorded. Do this before leaving the
  machine; option 10 alone only shows what ExitControl *believes*.
- To roll back: option **11) Restore ALL**, then reboot, then re-run option 13.
  Restore ALL reports per-control failures and prints status plus diagnostics
  afterwards rather than assuming success.

### Optional: site configuration

Drop a `config.json` in `C:\ProgramData\ExitControl\` to set the password
policy, extra blocked domains, a notification webhook, or the backup retention
count. Every key is optional. See the Configuration section of
[README.md](README.md#configuration) for the schema.

If you set a `WebhookUrl`, ExitControl posts each control change off the box —
which is the only way the audit trail survives an Administrator with something
to hide.

### Files created

All under `C:\ProgramData\ExitControl\`, restricted to SYSTEM + Administrators:

| Path | Purpose |
| --- | --- |
| `state.json` | Password hash + every original setting. Back this up; never delete it. |
| `config.json` | Optional site settings (may contain a webhook token). |
| `expected.sha256` | Script integrity baseline. |
| `logs\audit-*.log` | Hash-chained audit trail. |
| `hosts.backup-*` | Pre-change HOSTS file, timestamped. |
| `usbstor.backup-*` | Pre-change USBSTOR `Start` value. |
| `browserpolicies.backup-*` | Pre-change Chrome/Edge policy values. |
| `*.exe.backup` | Copies of any renamed executable. |

Timestamped backups are pruned to `BackupLimit` (default 5) per category, and the
pruned files are deleted rather than just dropped from the index.
