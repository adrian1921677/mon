# Hck Desktop (Tauri 2)

Professionelle Minimal-UI für Phase 1: Backend-Status, Health-Check, Projects-CRUD.

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
