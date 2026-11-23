"""FastAPI application entrypoint — binds only to 127.0.0.1."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import audit, health, projects, scope
from app.api import settings as settings_api
from app.core.config import get_settings
from app.db.session import SessionLocal, init_db
from app.process.recovery import mark_interrupted_tasks


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    cfg = get_settings()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    init_db(cfg)
    # Crash recovery: orphaned running/pending scans → interrupted.
    if SessionLocal is not None:
        db = SessionLocal()
        try:
            mark_interrupted_tasks(db)
        finally:
            db.close()
    yield


def create_app() -> FastAPI:
    cfg = get_settings()
    application = FastAPI(
        title=cfg.app_name,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    # Desktop (Vite/Tauri) talks to localhost only.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:1420",
            "http://127.0.0.1:1420",
            "tauri://localhost",
            "http://tauri.localhost",
            "https://tauri.localhost",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(health.router)
    application.include_router(projects.router, prefix="/api/v1")
    application.include_router(scope.router, prefix="/api/v1")
    application.include_router(settings_api.router, prefix="/api/v1")
    application.include_router(audit.router, prefix="/api/v1")
    return application


app = create_app()


def run() -> None:
    """CLI entry for local development."""
    import uvicorn

    cfg = get_settings()
    if cfg.host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Refusing to bind outside localhost — set HCK_HOST=127.0.0.1")
    uvicorn.run(
        "app.main:app",
        host=cfg.host,
        port=cfg.port,
        reload=False,
        log_level=cfg.log_level.lower(),
    )


if __name__ == "__main__":
    run()
