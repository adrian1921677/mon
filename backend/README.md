# Hck Backend (Phase 9)

Lokales FastAPI-Backend, bindet ausschließlich `127.0.0.1`.

## Voraussetzungen

- Python 3.11+
- Windows 11: native oder **WSL2** empfohlen
- Optional Phase-4–7-Binaries je Scanner (`app/scanners/docs/`)
- Optional: [uv](https://github.com/astral-sh/uv)

## Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Windows-Helfer: `..\scripts\windows\setup-backend.ps1`  
Nach Desktop-Installer: `..\scripts\windows\setup-backend.ps1 -Portable`

## Datenbank

```bash
alembic upgrade head
```

SQLite unter `~/.hck/hck.db` (WAL + Foreign Keys). Override: `HCK_DATA_DIR` / `HCK_DATABASE_URL`.  
Desktop setzt `HCK_DATA_DIR` auf das Tauri-App-Data-Verzeichnis.

## Start

```bash
python -m app.main
```

- Health: `GET http://127.0.0.1:8765/health`
- OpenAPI: `http://127.0.0.1:8765/docs`

## Packaging-Hinweise

Der Windows-Installer bundelt diesen Baum (ohne `.venv`) als Tauri-Resource.  
Interpreter bleibt systemseitig / AppData-venv — siehe `docs/windows-packaging.md`.

## Tests & Smoke

```bash
pytest
../scripts/smoke-check.sh --start
```

## Invarianten

Findings nur aus Adapter-Normalisierung → DB. Leere Projekte liefern leere Listen/Reports — **keine** Simulation.
