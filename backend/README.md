# Hck Backend (Phase 3)

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

Beim Start: Scanner-Registry laden; laufende/pending Scans/Tasks → Status `interrupted`.

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
| GET | `/api/v1/tools` | Live-Probe aller produktiven Scanner |
| POST | `/api/v1/tools/refresh` | Probe + Persistenz in `tool_installations` |
| GET | `/api/v1/tools/installations` | Persistierte Installationen |
| GET | `/api/v1/tools/{scanner_id}` | Einzelnes Tool |
| GET/POST | `/api/v1/projects/{id}/scans` | Scans listen / Pipeline-Stub starten |
| GET | `/api/v1/projects/{id}/scans/{scan_id}` | Scan inkl. Tasks |
| GET/PUT | `/api/v1/settings`, `/api/v1/settings/{key}` | Settings (z. B. `security.active_tests_enabled`) |
| GET | `/api/v1/audit-events` | Audit-Events |

## Phase-3-Module

- `app/scanners/` — Registry, Adapter-Interface, Skelette (Nmap, Greenbone, TShark, ZAP, Nuclei, testssl, Semgrep, Trivy, Gitleaks, Schemathesis, Host Audits), Echo nur für Pipeline-Tests
- `app/jobs/pipeline.py` — Scan-Stub mit ScopeEngine + ProcessManager + Active-Gate
- `app/services/tool_manager.py` — `tool_installations` listen/prüfen

**Nicht** in Phase 3: volle CLI-Integration (Phase 4: Nmap/Semgrep/Trivy/Gitleaks). Keine Fake-Findings.
