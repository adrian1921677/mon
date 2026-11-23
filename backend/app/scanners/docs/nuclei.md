# Nuclei Adapter

**ID:** `nuclei` · **Phase:** 5 · **Capability:** web, network · **Active (Klasse):** nein

## Binary
`nuclei` auf PATH (Native / WSL).

## Scope
`url`, `domain`, `ip`

## Kontrollierte Templates
Allowlist-Tags (kein Blank-Lauf über alle Templates):

| Depth | Tags |
| --- | --- |
| quick | `tech,exposure` |
| standard | `tech,exposure,misconfig,vuln` |
| deep | `…,cve,default-login` (+ `panel,config` nur mit Active-Gate) |

**Immer ausgeschlossen:** `exploit`, `dos`, `ddos`, `intrusive`, `fuzz`, `fuzzing`, `bruteforce`, `brute`, `rce`

Rate-Limit und niedrige Concurrency gegen DoS-ähnliche Last. Ausgabe: JSONL (`-jsonl -o`).

## Fehlendes Binary
`ScannerNotInstalledError` — Scan-Task `failed`, keine Fake-Findings.
