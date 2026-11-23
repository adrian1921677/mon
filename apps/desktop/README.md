# Hck Desktop (Tauri 2)

Desktop-UI: Backend-Status, Projects/Scope, Tool Manager, Scan-Start (Phase 4–7 CLI).

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
- Wrapper: `src/api/client.ts`
