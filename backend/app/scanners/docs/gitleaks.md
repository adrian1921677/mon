# Gitleaks Adapter

**ID:** `gitleaks` · **Phase:** 4 · **Capability:** code · **Active:** nein

## Binary
`gitleaks` auf PATH.

## Scope
`path` (Git-Repo oder Verzeichnis mit `--no-git`)

## Defaults
`gitleaks detect --report-format json --no-banner`
- Exit 0 = clean, 1 = Leaks gefunden (beides Erfolg)
- Secrets in Evidence werden redaktiert

## Fehlendes Binary
Klarer Fehler, keine simulierten Secrets.
