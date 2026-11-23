# Windows Packaging (Phase 9 / 9.1)

Zielplattform: **Windows 11**. Artefakte: **NSIS** (`*-setup.exe`) und **MSI** (WiX).

## Was der Installer enthält

| Inhalt | Quelle |
| --- | --- |
| Desktop-UI + Tauri-Runtime | `apps/desktop` Release-Build |
| Backend-Quellbaum | gebündelt unter `$RESOURCE/backend/` (`app/`, `alembic/`, `pyproject.toml`, …); Quellpfade in `tauri.conf.json` relativ zu `src-tauri` → `../../../backend/…` |
| Setup-Script | `$RESOURCE/setup-backend.ps1` (auch Release-Asset) |
| Python-Interpreter / venv | **nicht** im Installer — First-Run in der App oder `setup-backend.ps1 -Portable` |

Kein eingebetteter CPython-Sidecar (Portabilität vs. Größe). Stattdessen:

1. System-Python 3.11+ (Installer von python.org, „Add to PATH“)
2. **Empfohlen:** In der App **„Backend einrichten“** — legt `%LOCALAPPDATA%\com.hck.platform\python-venv` an und installiert Abhängigkeiten
3. Alternativ: `setup-backend.ps1 -Portable` (Installationsordner oder Release-Asset)
4. Optional: `HCK_PYTHON` auf einen festen Interpreter setzen
5. Optional (advanced): Portable/Embeddable Python nach `$RESOURCE/backend/python/` legen

Tauri sucht Interpreter in dieser Reihenfolge: `HCK_PYTHON` → AppData-venv → `backend/.venv` → `backend/python|runtime` → System-`py`/`python`. Fehlt `uvicorn`, bootstrapped die Shell automatisch das AppData-venv (sofern Python installiert ist).

Nach dem Spawn wartet die Shell bis Port `8765` offen ist bzw. erkennt einen Sofort-Crash und zeigt den Log-Auszug.

Backend-Logs: `%LOCALAPPDATA%\com.hck.platform\backend.log` (bzw. App-Data-Dir). Setup-Log: `backend-setup.log`.

## Nach der Installation (User)

1. Python **3.11+** von https://www.python.org/downloads/ („Add to PATH“).
2. Hck starten.
3. Bei „Failed to fetch“ / Offline: Button **Backend einrichten** (ein Klick).
4. Falls nötig: Log öffnen oder manuell  
   `powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Hck\setup-backend.ps1" -Portable`  
   (Pfad je nach NSIS/MSI-Ziel; Script liegt neben den Resources).

## Build auf Windows 11 (unterstützt)

Voraussetzungen: Node 20+, Rust (MSVC), WebView2, WiX v3 (für MSI), NSIS (wird von Tauri ggf. geholt), Python 3.11+.

```powershell
cd apps\desktop
npm install --legacy-peer-deps
npm run typecheck
# beide Bundles:
npm run tauri:build
# oder einzeln:
npm run tauri:build:nsis
npm run tauri:build:msi
```

Oder: `.\scripts\windows\build-installer.ps1`

Artefakte typischerweise unter:

`apps/desktop/src-tauri/target/release/bundle/{nsis,msi}/`

## GitHub Actions (Windows Runner)

Workflow: `.github/workflows/windows-installer.yml` auf `windows-latest`.

| Trigger | Release? |
| --- | --- |
| `workflow_dispatch` (`create_release=true`) | ja → Tag `v<version>` + Assets |
| Push Tag `v*` | ja |
| Push `main` / PR | nein — nur Build-Artefakte |

Baut NSIS + MSI (WiX v3 via Chocolatey), lädt Artefakte hoch und hängt bei Release zusätzlich `setup-backend.ps1` / `smoke-check.ps1` / diese Doku an.

## Linux-CI-Grenzen

| Bundle | Auf Linux-CI | Hinweis |
| --- | --- | --- |
| **MSI** | **Nein** | WiX läuft nur auf Windows; VBSCRIPT-Feature nötig |
| **NSIS** | Theoretisch (Cross-Compile) | `cargo-xwin` + NSIS + `x86_64-pc-windows-msvc` — offiziell „last resort“, hier **nicht** in CI verdrahtet |
| Frontend `npm run build` / `typecheck` | Ja | ohne Windows-Bundler |
| Backend `pytest` | Ja | Parser-Fixtures, kein Netzwerk-Scan |

Empfehlung: Installer über den Windows-Actions-Workflow oder lokal auf Windows 11 bauen. Linux-Agenten validieren Code/Tests/Typecheck + Smoke gegen lokal gestartetes Backend.

## Manuell auf Windows validieren

1. `setup-backend.ps1` → `dev-start.ps1 -Desktop` (Dev) oder Installer + App-Button / `-Portable`
2. `smoke-check.ps1 -StartBackend`
3. In der UI: Projekt anlegen, Tool Manager öffnen (fehlende Tools → Hinweis, **keine** Fake-Findings)
4. Optional: Nmap/Semgrep/… installieren (WSL/Docker je Adapter-Doku unter `backend/app/scanners/docs/`)
5. Installer-Build: NSIS und MSI erzeugen, installieren, App starten, Health online **ohne** manuelles Script (wenn Python auf PATH)

## Smoke (Linux/CI)

```bash
cd backend && . .venv/bin/activate && python -m app.main &
./scripts/smoke-check.sh
# oder:
./scripts/smoke-check.sh --start
```
