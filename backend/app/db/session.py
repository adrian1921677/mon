"""SQLAlchemy engine and session helpers (SQLite WAL + foreign keys)."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.db.base import Base

# Import models so metadata is populated for create_all / Alembic.
from app.db import models as _models  # noqa: F401

_engine: Engine | None = None
SessionLocal: sessionmaker[Session] | None = None


def _configure_sqlite(dbapi_conn: object, _connection_record: object) -> None:
    cursor = dbapi_conn.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def create_db_engine(settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    if settings.resolved_database_url.startswith("sqlite:///"):
        raw = settings.resolved_database_url.removeprefix("sqlite:///")
        Path(raw).parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        settings.resolved_database_url,
        connect_args={"check_same_thread": False},
        future=True,
    )
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def init_engine(settings: Settings | None = None) -> Engine:
    global _engine, SessionLocal
    _engine = create_db_engine(settings)
    SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        return init_engine()
    return _engine


def init_db(settings: Settings | None = None) -> None:
    """Ensure data dir exists and schema is available (Alembic preferred in prod)."""
    engine = init_engine(settings)
    # Soft bootstrap for fresh installs; Alembic migrations are authoritative.
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        if engine.dialect.name == "sqlite":
            conn.execute(text("PRAGMA foreign_keys=ON"))
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.commit()


def get_db() -> Generator[Session, None, None]:
    if SessionLocal is None:
        init_engine()
    assert SessionLocal is not None
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
