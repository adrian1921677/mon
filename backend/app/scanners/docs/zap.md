# OWASP ZAP Adapter

**ID:** `zap` · **Phase:** 5 · **Capability:** web · **Active (Klasse):** nein (Baseline)

## Binary
Bevorzugt `zap-baseline.py` auf PATH; alternativ `zap-full-scan.py`, `zap.sh`, `zaproxy`, `zap`.

## Scope
`url`, `domain` (Domain wird zu `https://…`)

## Modi
| Depth | Modus | Active-Gate |
| --- | --- | --- |
| quick / standard | Baseline / quick (passiv zuerst) | nicht nötig |
| deep | Full / active Scan | **erforderlich** (`security.active_tests_enabled`) |

Ausgabe: JSON (`-J` bzw. `-report_json`).

## Fehlendes Binary
`ScannerNotInstalledError` — Scan-Task `failed`, keine Fake-Findings.
