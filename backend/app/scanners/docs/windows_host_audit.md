# Windows Host Audit Adapter

**ID:** `windows_host_audit` · **Phase:** 7 · **Capability:** host · **Active:** nein

## Binary
`powershell` oder `pwsh` auf PATH (Windows).

## Scope
- `path` (lokale Host-Freigabe / Consent)
- `ip` nur `127.0.0.1` / `::1`
- `domain` nur `localhost`

## Checks (read-only)
Defender Realtime/AV, Firewall-Profile, UAC EnableLUA, SMBv1, RDP NLA, AutoAdminLogon, BitLocker (info), ExecutionPolicy.

Skript: `scanners/scripts/windows_host_audit.ps1` → JSON. Nur `fail`/`warn` werden Findings.

## Fehlendes Binary
Klarer Fehler, keine Fake-Findings.
