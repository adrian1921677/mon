# Hck — Lokale Pentesting-Plattform (Phase 1)

Monorepo für die **lokale** Windows-11-Sicherheitsplattform. Scan-Engine und API laufen nur auf `127.0.0.1`.

> Website-Repo `adrian1921677/OK` ist getrennt und wird hier nicht angefasst.

## Struktur

```
backend/           FastAPI + SQLite (WAL) + Alembic
apps/desktop/      Tauri 2 + Vite + React + TypeScript
```

## Voraussetzungen

| Komponente | Hinweis |
| --- | --- |
| Python 3.11+ | Windows: Installer oder **WSL2** |
| Node.js 20+ | für Desktop-UI |
| Rust + Tauri 2 | [Tauri Voraussetzungen](https://tauri.app/start/prerequisites/) — unter Windows WebView2 |
| Windows 11 | Zielplattform; Dev auch unter WSL/Linux möglich (UI-Build ohne native WebKit ggf. eingeschränkt) |

### Windows vs. WSL

- **Backend** läuft gut nativ unter Windows *oder* in WSL2.
- **Tauri Desktop** am besten **nativ unter Windows** (WebView2). In WSL fehlen oft WebKit/GUI-Deps.
- Empfohlen für Phase 1 Dev: Backend in WSL oder Windows-venv; Desktop mit `npm run tauri dev` unter Windows. Alternativ UI nur mit Vite gegen ein laufendes Backend: `npm run dev` in `apps/desktop`.

## Backend starten

```bash
cd backend
python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# WSL / Linux
source .venv/bin/activate

pip install -e ".[dev]"
alembic upgrade head
python -m app.main
```

- Health: http://127.0.0.1:8765/health  
- OpenAPI: http://127.0.0.1:8765/docs  

Tests:

```bash
cd backend && pytest
```

## Desktop starten

```bash
cd apps/desktop
npm install
npm run generate:api   # optional, openapi.json ist committed
npm run tauri dev      # spawnt Backend automatisch (wenn Pfad/venv gefunden)
```

Nur UI (Backend separat):

```bash
cd apps/desktop
npm run dev
```

OpenAPI → TypeScript:

```bash
# openapi.json aktualisieren (Backend muss importierbar sein)
cd backend && python -c "from app.main import app; import json; print(json.dumps(app.openapi(), indent=2))" > ../apps/desktop/openapi.json
cd ../apps/desktop && npm run generate:api
```

## Phase-1-Scope

Enthalten: Health, Projects-CRUD, Settings-Stub, Audit-Events, SQLite-Schema inkl. späterer Tabellen, Desktop-Shell + Health-UI.

**Nicht** enthalten: Scanner, Process Manager, Scope Engine, Findings-UI, Packaging.
