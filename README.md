# ExitControl

A menu-driven PowerShell tool that applies reversible data-egress controls to a
single Windows workstation during an employee offboarding, and rolls them all
back afterwards.

Every control records the machine's original value before changing anything, so
**11) Restore ALL** can put the workstation back the way it was found.

> Intended for company-owned devices you are authorised to administer, as part
> of a documented offboarding process. Several controls affect *all* users of
> the machine, not just the departing one.

## Requirements

- Windows 10 / 11
- Windows PowerShell 5.1
- Local Administrator rights

## Quick start

1. Right-click `RunExitControl.bat` → **Run as administrator** (or just
   double-click it and accept the UAC prompt).
2. On first run, set an ExitControl password when prompted.
3. Apply the controls you need from the menu.
4. Run option **8** (checklist) and option **10** (status) to verify.

See [DEPLOYMENT.md](DEPLOYMENT.md) for packaging, unattended password seeding,
and ACL hardening.

## What the controls do

| # | Control | Mechanism | Scope |
| --- | --- | --- | --- |
| 1 | HOSTS blocking | Adds a marked block to `%WINDIR%\System32\drivers\etc\hosts` pointing upload / personal-cloud / webmail domains at localhost | Whole machine |
| 2 | USB mass storage | Sets `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start` to `4` | Whole machine |
| 3 | Private browsing + DoH | Chrome/Edge policy: `IncognitoModeAvailability=1`, `InPrivateModeAvailability=1`, `DnsOverHttpsMode=off` | Whole machine |
| 4 | Firewall browser block | Outbound block rules in group `ExitControl-BrowserBlock` for every browser found | Whole machine |
| 5 | Snipping tools | Renames `SnippingTool.exe` / `ScreenSketch.exe` to `.disabled` | Whole machine |
| 6 | OpenWith.exe | Renames `OpenWith.exe` to `.disabled` — **aggressive** | Whole machine |
| 7 | Windows password | `Set-LocalUser -Password`, asked twice | One local account |

Control 3 turns DNS-over-HTTPS off deliberately: with DoH enabled a browser
resolves names itself and never consults the HOSTS file, which would make
control 1 useless.

## Auditing and verification

| # | Option | What it gives you |
| --- | --- | --- |
| 10 | Show current status | What ExitControl *recorded* |
| 13 | Run diagnostics | What the machine *actually* looks like, and any drift between the two |
| 14 | Refresh integrity baseline | Re-trusts the current script file after an intended edit |
| 15 | View recent audit entries | Last 20 log lines plus a hash-chain check |

**Audit log** — every control change, authentication success *and* failure,
diagnostics run and restore is appended to
`C:\ProgramData\ExitControl\logs\audit-YYYYMMDD.log` as one JSON object per
line. Each entry carries the hash of the previous one, so a deleted or edited
line breaks the chain and options 13 and 15 report it. Passwords are never
logged; the Windows password change records only the account name.

**Drift detection** — option 13 reads the live hosts file, registry, firewall
rules and renamed binaries and compares each against what `state.json` claims.
`DRIFT` means a control was changed outside this tool, or failed to apply. A
status screen driven only by `state.json` cannot show this.

**Script integrity** — the script's SHA-256 is compared against
`expected.sha256` on startup. On mismatch it runs in **limited mode**: only
options 8, 9, 10, 13, 14, 15 and 0 work, so no further changes can be made until
someone re-baselines with option 14. This detects edits by someone *without*
Administrator rights. It does not stop an Administrator, who can edit the script
and re-baseline it — see [Known limitations](#known-limitations).

## Configuration

All optional. Create `C:\ProgramData\ExitControl\config.json`; anything omitted
falls back to the built-in default, including individual keys inside a section.

```json
{
  "PasswordPolicy": {
    "MinLength": 12,
    "RequireUpper": true,
    "RequireLower": true,
    "RequireDigit": true,
    "RequireSpecial": true
  },
  "AdditionalBlockDomains": ["fileshare.example.com"],
  "Notifications": {
    "WebhookUrl": "https://hooks.example.com/exitcontrol",
    "WebhookAuthHeader": "Authorization: Bearer TOKEN"
  },
  "BackupLimit": 5
}
```

- **PasswordPolicy** applies to the ExitControl password (options 12 and first
  run). `MinLength` counts characters, not bytes.
- **AdditionalBlockDomains** is appended to the built-in list and de-duplicated.
- **Notifications** is off unless `WebhookUrl` is set. Only the action, severity,
  machine and user are posted — never a password, hash or backup content. A
  failed or unreachable webhook logs a warning and never blocks a control.
- **BackupLimit** caps the timestamped backups kept per category; older ones are
  deleted, not just forgotten.

Because `config.json` can hold a webhook token, it lives in the same
ACL-restricted directory as `state.json`.

## Known limitations

Be honest with whoever signs off on the offboarding about these.

- **HOSTS blocking is a speed bump, not a boundary.** It is per-domain and does
  not cover IP-literal access, VPNs, a non-listed mirror, or a browser
  configured with its own DoH resolver. It is a deterrent against casual
  copying, not a control against a determined actor.
- **System32 renames (controls 5 and 6) often fail.** `SnippingTool.exe` and
  `OpenWith.exe` are owned by `TrustedInstaller`; Administrator rights alone do
  not permit renaming them. ExitControl reports the failure clearly instead of
  crashing, but it will not take ownership on your behalf.
- **Control 7 handles local accounts only.** Domain and Microsoft accounts have
  to be changed in AD or at account.microsoft.com.
- **Browser policies need a browser restart** before they take effect.
- **Firewall rules are matched by executable path.** A browser installed after
  the rules are created, or a portable browser run from a USB stick or a
  network share, is not covered. Re-apply control 4 after any browser install.
- **Nothing here stops physical exfiltration** — phone camera, printing, or
  reading the screen.
- **The integrity check and audit log are tamper *evidence*, not tamper
  *prevention*.** Both the baseline hash and the log live in a folder that
  Administrators can write, and option 14 re-baselines on demand. An
  Administrator can edit the script, rewrite the log and recompute every chain
  hash. They catch accidental edits, non-admin tampering and silent drift —
  nothing stronger. For a real audit trail, ship the logs off the machine (set
  a `WebhookUrl`) or forward the directory to your SIEM.
- **The ExitControl password gates the menu, not the machine.** Anyone with
  Administrator rights can undo every control directly.

## Rollback

Option **11) Restore ALL** reverses every control, reports any per-control
failure, and then prints the status so the result can be verified rather than
assumed. Reboot afterwards.

### If `state.json` is lost

Automatic rollback depends on `C:\ProgramData\ExitControl\state.json`. Without
it, undo by hand:

- **HOSTS** — delete the `# ExitControlManaged BEGIN` … `END` block, then
  `ipconfig /flushdns`
- **USB** — set `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start` to `3`
- **Policies** — delete `IncognitoModeAvailability`, `InPrivateModeAvailability`
  and `DnsOverHttpsMode` under `HKLM\SOFTWARE\Policies\Google\Chrome` and
  `HKLM\SOFTWARE\Policies\Microsoft\Edge`
- **Firewall** — `Get-NetFirewallRule -Group ExitControl-BrowserBlock | Remove-NetFirewallRule`
- **Renames** — rename any `*.exe.disabled` under System32 back to `*.exe`, or
  run `sfc /scannow`

Option **9) Show rollback guide** prints the same list on the machine itself.

## Security notes

- The ExitControl password is stored as a **salted PBKDF2 hash** (200,000
  iterations, HMAC-SHA256 where the runtime supports it, HMAC-SHA1 otherwise).
- `C:\ProgramData\ExitControl` is restricted to SYSTEM and Administrators on
  every run, so the account being offboarded cannot read the hash or the
  recorded original settings.
- There is **no default password**. A state file written by an older version
  (bare unsalted SHA-256) still works and is upgraded to PBKDF2 automatically on
  the next successful login.
- The password gates the menu only. It is not a defence against someone who
  already has Administrator rights on the machine — they can undo any of these
  controls directly.

## Repository layout

| File | Purpose |
| --- | --- |
| `ExitControl.ps1` | The tool |
| `RunExitControl.bat` | Double-click launcher that elevates |
| `install.ps1` | Copies the tool to a locked-down folder and sets the ACL |
| `DEPLOYMENT.md` | Packaging, password seeding, ACL hardening |
| `README.md` | This file |
| `LICENSE` | Proprietary licence — internal use only |

### Runtime files (not in the repo)

All under `C:\ProgramData\ExitControl\`, restricted to SYSTEM + Administrators:

| Path | Purpose |
| --- | --- |
| `state.json` | Password hash and every original setting. Never delete. |
| `config.json` | Optional settings (above). |
| `expected.sha256` | Script integrity baseline. |
| `logs\audit-*.log` | Hash-chained audit trail. |
| `hosts.backup-*`, `usbstor.backup-*`, `browserpolicies.backup-*` | Timestamped pre-change snapshots. |
| `*.exe.backup` | Copies of any renamed executable. |

## Licence

Proprietary and confidential. See [LICENSE](LICENSE). Not for redistribution.

Authorised for use by the Owner's IT and security personnel, on devices the
Owner owns or controls, in line with the Owner's policies and applicable law.
