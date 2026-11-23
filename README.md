# Hck — Lokale Pentesting-Plattform (Phase 9.1)

Monorepo für die **lokale** Windows-11-Sicherheitsplattform. Scan-Engine und API laufen nur auf `127.0.0.1`.

> Website-Repo `adrian1921677/OK` ist getrennt und wird hier nicht angefasst.

## Struktur

```
backend/                 FastAPI + SQLite (WAL) + Alembic
  app/scope/             Scope Engine (Backend-only)
  app/process/           Process Manager (kein shell=True)
  app/scanners/          Registry + Adapter (Phase 4–7 CLI)
  app/findings/          Fingerprint + Persistenz
  app/reporting/         JSON/PDF-Export, Scan-Vergleich
  app/jobs/              Scan-Pipeline
apps/desktop/            Tauri 2 + Vite + React + TypeScript
scripts/windows/         Setup, Dev-Start, Installer-Build, Smoke
docs/windows-packaging.md
```

## Voraussetzungen (Windows 11)

| Komponente | Hinweis |
| --- | --- |
| **Windows 11** | Zielplattform (Dev auch unter WSL/Linux möglich) |
| **Python 3.11+** | [python.org](https://www.python.org/downloads/) — Haken „Add python.exe to PATH“; oder WSL2 |
| **Node.js 20+** | Desktop-UI / Tauri CLI |
| **Rust (MSVC)** + Tauri 2 | [Tauri Prerequisites](https://tauri.app/start/prerequisites/) inkl. **WebView2** |
| **WiX Toolset v3** | nur für **MSI**-Build |
| **NSIS** | für `*-setup.exe` (Tauri kann NSIS auf Windows nachladen) |

### Scanner-Tools (optional, echte Binaries — keine Simulation)

| Tool | Typische Runtime | Doku |
| --- | --- | --- |
| Nmap (+ Npcap) | Windows-native | `backend/app/scanners/docs/nmap.md` |
| Semgrep, Trivy, Gitleaks | WSL2 / Docker / Binary | jeweilige `docs/*.md` |
| OWASP ZAP, Nuclei | Java/Docker bzw. Binary/WSL | `zap.md`, `nuclei.md` |
| Schemathesis | Python (Backend-venv) | `schemathesis.md` |
| Greenbone/OpenVAS | Docker | `greenbone.md` |
| Host Audit | PowerShell / Bash (WSL) | `windows_host_audit.md`, `linux_host_audit.md` |

Fehlende Installation → Tool Manager zeigt Status `not_installed`; Scans starten **nicht** mit Fake-Findings.

### WSL2 / Docker

- **WSL2:** empfohlen für Linux-first-Tools (Semgrep, Trivy, Gitleaks, Nuclei, testssl, Linux Host Audit).
- **Docker Desktop:** für Greenbone und optional ZAP-Container; Ressourcen (RAM/CPU) großzügig bemessen.
- Adapter wählen Runtime über Install-Probe (native → WSL → Docker); Details in den Scanner-Docs.

---

## Schnellstart Windows 11 (Entwicklung)

In **PowerShell** (Repo-Root):

```powershell
# 1) Backend-venv + Migrationen
.\scripts\windows\setup-backend.ps1

# 2a) Nur Backend
.\scripts\windows\dev-start.ps1

# 2b) Backend + Tauri-Desktop
.\scripts\windows\dev-start.ps1 -Desktop

# 3) Smoke
.\scripts\windows\smoke-check.ps1 -StartBackend
```

Manuell:

```powershell
cd backend
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
alembic upgrade head
python -m app.main
```

```powershell
cd apps\desktop
npm install --legacy-peer-deps
npm run tauri dev
# nur UI: npm run dev
```

Health: `http://127.0.0.1:8765/health`

---

## Installer bauen (Windows 11)

```powershell
.\scripts\windows\build-installer.ps1
# oder:
cd apps\desktop
npm run tauri:build          # NSIS + MSI
npm run tauri:build:nsis     # nur Setup-EXE
npm run tauri:build:msi      # nur MSI (WiX)
```

Nach Installation:

1. Python 3.11+ (python.org, „Add to PATH“)
2. Hck starten → bei Offline **„Backend einrichten“** in der UI (legt AppData-venv an)
3. Alternativ: `setup-backend.ps1 -Portable` (liegt im Installationsordner / Release-Assets)

```powershell
# nur falls der UI-Button nicht genutzt wird:
.\setup-backend.ps1 -Portable
```

Details und **Linux-CI-Grenzen** (MSI nur auf Windows, NSIS-Cross-Compile nicht in CI): [`docs/windows-packaging.md`](docs/windows-packaging.md).

### Backend-Bundling / Start-Pfad

1. Installer legt Backend-Quellen unter den Tauri-**Resources**-Ordner (`backend/`) + `setup-backend.ps1`.
2. Desktop-Shell startet Uvicorn gegen `app.main:app` mit `HCK_DATA_DIR` = App-Data; wartet auf Port 8765 / erkennt Sofort-Crash.
3. Python: `HCK_PYTHON` → AppData-`python-venv` → `backend\.venv` → portable `backend\python` → System-Python. Fehlt `uvicorn` → Auto-Bootstrap des AppData-venvs.
4. Log: `backend.log` / `backend-setup.log` im App-Data-Verzeichnis.

---

## Dev unter Linux / WSL (ohne Windows-Installer)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
alembic upgrade head
python -m app.main
```

```bash
cd apps/desktop && npm install --legacy-peer-deps
npm run dev          # UI
npm run typecheck
# npm run tauri dev  # braucht WebKit/GTK-Deps; Windows-Bundles hier nicht
```

Tests: `cd backend && pytest`  
Smoke: `./scripts/smoke-check.sh --start`

---

## Phase-9-Scope

- Tauri **NSIS + MSI**-Konfiguration, Windows-Scripts, Packaging-Doku
- Backend-Resource-Bundling + robuster Desktop-Startpfad (venv/portable/`HCK_PYTHON`)
- Root-README: Install/Start, Tool-Voraussetzungen, WSL/Docker
- Stabilisierung (Tests/Typecheck), Smoke-Scripts
- **Kein** neuer Scanner-/Feature-Scope; **keine** Fake-Findings

Vorherige Phasen: Dashboard, Findings, Reports, Scanner Phase 4–7 — siehe Git-History / frühere READMEs.
