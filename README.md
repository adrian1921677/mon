# Hck — Lokale Pentesting-Plattform (Phase 4)

Monorepo für die **lokale** Windows-11-Sicherheitsplattform. Scan-Engine und API laufen nur auf `127.0.0.1`.

> Website-Repo `adrian1921677/OK` ist getrennt und wird hier nicht angefasst.

## Struktur

```
backend/           FastAPI + SQLite (WAL) + Alembic
  app/scope/       Scope Engine (Backend-only)
  app/process/     Process Manager (kein shell=True)
  app/scanners/    Registry + Adapter (Phase-4-CLI: Nmap/Semgrep/Trivy/Gitleaks)
  app/findings/    Fingerprint + Persistenz
  app/jobs/        Scan-Pipeline
apps/desktop/      Tauri 2 + Vite + React + TypeScript
```

## Voraussetzungen

| Komponente | Hinweis |
| --- | --- |
| Python 3.11+ | Windows: Installer oder **WSL2** |
| Node.js 20+ | für Desktop-UI |
| Rust + Tauri 2 | [Tauri Voraussetzungen](https://tauri.app/start/prerequisites/) — unter Windows WebView2 |
| Optional | `nmap`, `semgrep`, `trivy`, `gitleaks` auf PATH |
| Windows 11 | Zielplattform; Dev auch unter WSL/Linux möglich |

## Backend starten

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
alembic upgrade head
python -m app.main
```

Tests: `cd backend && pytest` (Parser mit Fixtures, kein Netzwerk-Scan in CI).

## Desktop starten

```bash
cd apps/desktop
npm install
npm run tauri dev
# oder nur UI: npm run dev
```

## Phase-4-Scope

- Volle CLI-Integration: **Nmap**, **Semgrep**, **Trivy**, **Gitleaks**
- Findings → DB (`findings` / `finding_occurrences` / `evidence`) mit Fingerprint-Dedup
- Fehlendes Binary → klarer Fehler, **keine** Fake-Findings
- Desktop: Scan starten, wenn Tool installiert

**Phase 5:** OWASP ZAP, Nuclei
