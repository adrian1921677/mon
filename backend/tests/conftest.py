"""Pytest fixtures — isolated temp SQLite DB per test."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings, get_settings
from app.db.session import create_db_engine, get_db, init_engine
from app.main import create_app
from app.db.base import Base


@pytest.fixture()
def settings(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("HCK_DATA_DIR", str(data_dir))
    monkeypatch.setenv("HCK_HOST", "127.0.0.1")
    get_settings.cache_clear()
    s = Settings(data_dir=data_dir, host="127.0.0.1")
    get_settings.cache_clear()

    def _override() -> Settings:
        return s

    monkeypatch.setattr("app.core.config.get_settings", _override)
    monkeypatch.setattr("app.main.get_settings", _override)
    return s


@pytest.fixture()
def client(settings: Settings) -> TestClient:
    engine = create_db_engine(settings)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    init_engine(settings)

    app = create_app()

    def _override_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    get_settings.cache_clear()
