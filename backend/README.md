# Hck Backend (Phase 8)

Lokales FastAPI-Backend, bindet ausschließlich `127.0.0.1`.

## Voraussetzungen

- Python 3.11+
- Windows 11: native oder **WSL2** empfohlen
- Optional Phase-4–7-Binaries je Scanner
- Optional: [uv](https://github.com/astral-sh/uv)

## Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Datenbank

```bash
alembic upgrade head
```

SQLite unter `~/.hck/hck.db` (WAL + Foreign Keys). Override: `HCK_DATA_DIR` / `HCK_DATABASE_URL`.

Phase-8-Migration ergänzt Finding-Felder: `status`, `confidence`, `remediation`, `description`.

## Start

```bash
python -m app.main
```

- Health: `GET http://127.0.0.1:8765/health`
- OpenAPI: `http://127.0.0.1:8765/docs`

## Tests

```bash
pytest
```

## API (Phase 8 Auszug)

| Methode | Pfad | Beschreibung |
| --- | --- | --- |
| GET | `/api/v1/projects/{id}/dashboard` | Aggregates (Assets, Scans, Findings, Trend, Tools) |
| GET | `/api/v1/projects/{id}/findings` | Finding-Liste (Filter Status/Severity) |
| GET/PATCH | `/api/v1/projects/{id}/findings/{fid}` | Detail / Status & Remediation |
| GET | `/api/v1/projects/{id}/assets` | Asset Inventory |
| GET | `/api/v1/projects/{id}/reports/project?format=json\|pdf` | Projektbericht |
| GET | `/api/v1/projects/{id}/reports/findings/{fid}?format=…` | Finding-Bericht |
| POST | `/api/v1/projects/{id}/reports/compare` | Scan-Vergleich + Verlauf |

## Invarianten

Findings nur aus Adapter-Normalisierung → DB. Leere Projekte liefern leere Listen/Reports — **keine** Simulation.

**Phase 9:** Windows Packaging + Stabilisierung
