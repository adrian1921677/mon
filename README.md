# Hck — Lokale Pentesting-Plattform (Phase 2)

Monorepo für die **lokale** Windows-11-Sicherheitsplattform. Scan-Engine und API laufen nur auf `127.0.0.1`.

> Website-Repo `adrian1921677/OK` ist getrennt und wird hier nicht angefasst.

## Struktur

```
backend/           FastAPI + SQLite (WAL) + Alembic
  app/scope/       Scope Engine (Backend-only)
  app/process/     Process Manager (kein shell=True)
apps/desktop/      Tauri 2 + Vite + React + TypeScript
```

## Voraussetzungen

| Komponente | Hinweis |
| --- | --- |
| Python 3.11+ | Windows: Installer oder **WSL2** |
| Node.js 20+ | für Desktop-UI |
| Rust + Tauri 2 | [Tauri Voraussetzungen](https://tauri.app/start/prerequisites/) — unter Windows WebView2 |
| Windows 11 | Zielplattform; Dev auch unter WSL/Linux möglich |

### Windows vs. WSL

- **Backend** läuft gut nativ unter Windows *oder* in WSL2.
- **Tauri Desktop** am besten **nativ unter Windows** (WebView2).
- Empfohlen: Backend in WSL oder Windows-venv; Desktop mit `npm run tauri dev` unter Windows. Alternativ UI nur mit Vite: `npm run dev` in `apps/desktop`.

## Backend starten

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
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
npm run tauri dev
```

Nur UI (Backend separat):

```bash
cd apps/desktop && npm run dev
```

## Phase-2-Scope

Enthalten:

- Scope Engine inkl. DNS/SSRF/Rebinding/Redirect/Metadata-Block
- Scope-CRUD + Validate-API an `scope_entries`
- Active-Test-Freigabe (`security.active_tests_enabled`)
- Process Manager (Timeout, Cancel, Concurrency, sanitized logs)
- Crash-Recovery → `interrupted`
- Desktop: Scope verwalten/validieren pro Projekt

**Nicht** enthalten: Scanner-Registry/Adapter (Phase 3), echte Tool-Scans (Phase 4+).
