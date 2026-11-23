# Schemathesis Adapter

**ID:** `schemathesis` · **Phase:** 6 · **Capability:** api · **Active:** ja (Active-Gate Pflicht)

## Binary
`schemathesis` oder `st` auf PATH (`pip install schemathesis`, empfohlen in venv).

## Scope
| Typ | Rolle |
| --- | --- |
| `api_spec` | OpenAPI-Datei (lokal) oder http(s)-URL zur Spec — **LOCATION** |
| `url` | API-Basis-URL (`--url`), Pflicht bei dateibasierter Spec; optional bei Spec-URL |

## Modi (risikoarm)
| Depth | Phases | Mode | max-examples |
| --- | --- | --- | --- |
| quick | `examples` | `positive` | 10 |
| standard | `examples,coverage` | `positive` | 25 |
| deep | `examples,coverage,fuzzing` | `all` | 50 |

Kein `stateful` per Default. Report: JSON (`--report json` / `--report-json-path`).

## Fehlendes Binary
`ScannerNotInstalledError` — Scan-Task `failed`, keine Fake-Findings.
