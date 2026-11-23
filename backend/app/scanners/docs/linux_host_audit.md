# Linux Host Audit Adapter

**ID:** `linux_host_audit` · **Phase:** 7 · **Capability:** host · **Active:** nein

## Runtime
- Windows 11: **WSL2** (`wsl -e bash …`)
- Linux: natives `bash` + `python3`

## Scope
Wie Windows-Audit: `path` Consent, lokale `ip`/`localhost`.

## Checks (read-only)
`/etc/passwd|shadow|sudoers`-Rechte, SSH `PermitRootLogin` / `PasswordAuthentication`, UFW/firewalld/nft, Unattended-Upgrades-Config, Listening-Sockets (`ss`), ASLR.

Skript: `scanners/scripts/linux_host_audit.sh` → JSON. Nur `fail`/`warn` → Findings.

## Fehlendes Binary / kein WSL
Klarer Fehler, keine Fake-Findings.
