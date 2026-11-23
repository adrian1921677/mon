# Hck Desktop (Tauri 2)

Desktop-UI Phase 8: Dashboard, Projects/Scope, Inventory, Security-Tabs → Scan Manager (Live-Fortschritt), Findings, Reports, Tool Manager, Settings.

## Scripts

| Script | Beschreibung |
| --- | --- |
| `npm run dev` | Vite-Devserver (Port 1420), Backend separat nötig |
| `npm run tauri dev` | Tauri-Fenster; spawnt lokales Backend |
| `npm run generate:api` | OpenAPI → `src/api/schema.d.ts` |
| `npm run build` | Production-Frontend-Build |

## API-Client

- Spec: `openapi.json` (aus FastAPI exportiert)
- Typen: `src/api/schema.d.ts`
- Wrapper: `src/api/client.ts` (Findings, Dashboard, Reports inkl. Blob-Download)
