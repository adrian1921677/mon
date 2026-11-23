# Hck Backend (Phase 6)

Lokales FastAPI-Backend, bindet ausschließlich `127.0.0.1`.

## Voraussetzungen

- Python 3.11+
- Windows 11: native oder **WSL2** empfohlen
- Optional Phase-4-Binaries: `nmap`, `semgrep`, `trivy`, `gitleaks`
- Optional Phase-5-Binaries: `zap-baseline.py` / `zap.sh`, `nuclei`
- Optional Phase-6-Binaries: `schemathesis` / `st`
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
```

## Datenbank

```bash
alembic upgrade head
```

SQLite unter `~/.hck/hck.db` (WAL + Foreign Keys). Override: `HCK_DATA_DIR` / `HCK_DATABASE_URL`.

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

Parser-/Normalize-Tests nutzen Fixtures unter `tests/fixtures/` (kein Netzwerk-Scan in CI).

## API (Auszug)

| Methode | Pfad | Beschreibung |
| --- | --- | --- |
| GET | `/api/v1/tools` | Live-Probe produktiver Scanner |
| POST | `/api/v1/tools/refresh` | Probe + `tool_installations` |
| GET/POST | `/api/v1/projects/{id}/scans` | Scans listen / starten |
| GET/PUT | `/api/v1/settings` | u. a. `security.active_tests_enabled` |

## Phase 6

- Volle CLI: **Schemathesis** (`app/scanners/schemathesis.py`)
- Scope: `api_spec` (+ `url` als API-Basis bei Datei-Spec)
- Active-Gate Pflicht; Depth steuert Phases/Mode (kein stateful default)
- Kurz-Doku: `app/scanners/docs/schemathesis.md`
- Findings → DB (Fingerprint-Dedup); fehlendes Binary → klarer Fehler, **keine** Fake-Findings

**Phase 7:** Greenbone, Host Security
