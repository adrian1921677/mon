# Hck Backend (Phase 1)

Lokales FastAPI-Backend, bindet ausschließlich `127.0.0.1`.

## Voraussetzungen

- Python 3.11+
- Windows 11: empfohlen oder **WSL2** empfohlen
- Optional: [uv](https://github.com/astral-sh/uv)

## Setup

```bash
cd backend
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# WSL / Linux / macOS
source .venv/bin/activate

pip install -e ".[dev]"
# oder: uv sync --extra dev
```

## Datenbank

```bash
# Migrationen
alembic upgrade head
```

SQLite-Datei standardmäßig unter `~/.hck/hck.db` (WAL + Foreign Keys).

Override:

```bash
export HCK_DATA_DIR=/path/to/data
# oder
export HCK_DATABASE_URL=sqlite:///./dev.db
```

## Start

```bash
python -m app.main
# oder
uvicorn app.main:app --host 127.0.0.1 --port 8765
```

- Health: `GET http://127.0.0.1:8765/health`
- OpenAPI: `http://127.0.0.1:8765/docs`

## Tests

```bash
pytest
```

## API (Phase 1)

| Methode | Pfad | Beschreibung |
| --- | --- | --- |
| GET | `/health` | Health + DB-Check |
| GET/POST | `/api/v1/projects` | Projekte listen / anlegen |
| GET/PATCH/DELETE | `/api/v1/projects/{id}` | Projekt lesen / ändern / löschen |
| GET/PUT | `/api/v1/settings`, `/api/v1/settings/{key}` | Settings-Stub |
| GET | `/api/v1/audit-events` | Audit-Events |
