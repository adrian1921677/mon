# Nmap Adapter

**ID:** `nmap` · **Phase:** 4 · **Capability:** network · **Active:** nein

## Binary
`nmap` auf PATH (Windows/Npc oder WSL).

## Scope
`ip`, `cidr`, `domain`

## Defaults (risikoarm)
| Depth | Flags |
| --- | --- |
| quick | `-sn` (Host-Discovery) |
| standard | `-sT -F --open` |
| deep | `-sT --top-ports 1000 --open` |

Keine NSE-Exploit-Scripts. Ausgabe: XML (`-oX`).

## Fehlendes Binary
`ScannerNotInstalledError` — Scan-Task `failed`, keine Fake-Findings.
