# Greenbone / OpenVAS Adapter

**ID:** `greenbone` · **Phase:** 7 · **Capability:** network · **Active:** ja (Active-Gate Pflicht)

## Binary / Runtime
- `gvm-cli` oder `gvm-script` auf PATH (`pip install gvm-tools`)
- Typisch: **Greenbone Community Edition** per Docker
- Alternativ: `HCK_GREENBONE_DOCKER_EXEC=<container>` + `docker` auf PATH (GMP im Container)

## Docker-Pfad (Community Edition)
1. Offizielles Compose-Setup von Greenbone Community Edition starten (gvmd + redis + feeds).
2. `gvm-tools` installieren **oder** `HCK_GREENBONE_DOCKER_EXEC` auf den Container mit `gvm-cli` setzen.
3. Env setzen:
   - `HCK_GVM_PASSWORD` (Pflicht)
   - `HCK_GVM_USERNAME` (Default `admin`)
   - `HCK_GVM_SOCKET` (Default `/run/gvmd/gvmd.sock`) **oder** `HCK_GVM_TLS=1` + Host/Port

## Scope
`ip`, `cidr`, `domain`

## Depth → Scan-Config (GMP)
| Depth | Bevorzugte Config-Namen |
| --- | --- |
| quick | Discovery / Host Discovery |
| standard | Full and fast |
| deep | Full and very deep ultimate |

## Ausführung
`python -m app.scanners.runners.gvm_scan` (via ProcessManager, kein `shell=True`) → XML-Report → Parser.

## Fehlendes Binary / fehlende Anmeldung
`ScannerNotInstalledError` bzw. Runner-Exit mit klarer Meldung — Scan-Task `failed`, **keine Fake-Findings**.
