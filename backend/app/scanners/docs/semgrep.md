# Semgrep Adapter

**ID:** `semgrep` · **Phase:** 4 · **Capability:** code · **Active:** nein

## Binary
`semgrep` auf PATH (`pip install semgrep` / WSL).

## Scope
`path` (lokales Repo/Verzeichnis)

## Defaults
- `--json --quiet --metrics=off`
- Config: `p/security-audit` (quick), `p/ci` (standard), `auto` (deep)
- Exit 0/1 = erfolgreicher Lauf (1 = Findings)

## Fehlendes Binary
Klarer Fehler, keine erfundenen Results.
