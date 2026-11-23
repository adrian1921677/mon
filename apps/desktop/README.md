# Hck Desktop (Tauri 2)

Desktop-UI: Dashboard, Projects/Scope, Inventory, Security-Tabs → Scan Manager, Findings, Reports, Tool Manager, Settings.

## Scripts

| Script | Beschreibung |
| --- | --- |
| `npm run dev` | Vite-Devserver (Port 1420), Backend separat nötig |
| `npm run tauri:dev` / `tauri dev` | Tauri-Fenster; spawnt lokales Backend |
| `npm run tauri:build` | Release + **NSIS + MSI** (nur sinnvoll auf Windows) |
| `npm run tauri:build:nsis` | nur NSIS-Setup |
| `npm run tauri:build:msi` | nur MSI (WiX, Windows-only) |
| `npm run generate:api` | OpenAPI → `src/api/schema.d.ts` |
| `npm run build` | Production-Frontend-Build |
| `npm run typecheck` | `tsc --noEmit` |

Install: `npm install --legacy-peer-deps`

## Backend-Start (Tauri)

`src-tauri` sucht `backend/app/main.py` (Dev: Monorepo; Release: gebündelte Resources) und startet Uvicorn mit dem ersten gefundenen Python (`HCK_PYTHON` / AppData-venv / `.venv` / System). Details: `docs/windows-packaging.md`.

## API-Client

- Spec: `openapi.json` (aus FastAPI exportiert)
- Typen: `src/api/schema.d.ts`
- Wrapper: `src/api/client.ts`
