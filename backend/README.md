# Hck Backend (Phase 2)

Lokales FastAPI-Backend, bindet ausschließlich `127.0.0.1`.

## Voraussetzungen

- Python 3.11+
- Windows 11: native oder **WSL2** empfohlen
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

Beim Start: laufende/pending Scans/Tasks → Status `interrupted` (Crash-Recovery).

- Health: `GET http://127.0.0.1:8765/health`
- OpenAPI: `http://127.0.0.1:8765/docs`

## Tests

```bash
pytest
```

## API

| Methode | Pfad | Beschreibung |
| --- | --- | --- |
| GET | `/health` | Health + DB-Check |
| GET/POST | `/api/v1/projects` | Projekte listen / anlegen |
| GET/PATCH/DELETE | `/api/v1/projects/{id}` | Projekt lesen / ändern / löschen |
| GET/POST | `/api/v1/projects/{id}/scope` | Scope-Einträge listen / anlegen |
| GET/PATCH/DELETE | `/api/v1/projects/{id}/scope/{entry_id}` | Scope lesen / ändern / löschen |
| POST | `/api/v1/projects/{id}/scope/validate` | Dry-Run (entry/target/redirect/ssrf/active_gate) |
| GET/PUT | `/api/v1/settings`, `/api/v1/settings/{key}` | Settings (z. B. `security.active_tests_enabled`) |
| GET | `/api/v1/audit-events` | Audit-Events |

## Phase-2-Module

- `app/scope/` — Scope Engine (IP/CIDR/Domain/URL/API-Spec/Path, DNS, Rebinding, Redirect, SSRF, Metadata-Block, Rate-/Zeit-Hooks, Active-Test-Gate)
- `app/process/` — Process Manager (`create_subprocess_exec`, kein `shell=True`, Timeout/Cancel/Concurrency, Log-Sanitizing, Interrupted-Recovery)

**Nicht** in Phase 2: Scanner-Adapter (Phase 3+).
