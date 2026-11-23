"""Application configuration — local-only bindings."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the local FastAPI backend."""

    model_config = SettingsConfigDict(
        env_prefix="HCK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Hck Local Platform"
    host: str = Field(default="127.0.0.1", description="Bind address (localhost only)")
    port: int = Field(default=8765, ge=1, le=65535)
    data_dir: Path = Field(
        default_factory=lambda: Path.home() / ".hck",
        description="Directory for SQLite DB and local data",
    )
    database_url: str | None = Field(
        default=None,
        description="Override SQLite URL; defaults to sqlite:///<data_dir>/hck.db",
    )
    api_token: str | None = Field(
        default=None,
        description="Optional shared secret for local API auth (Phase 1 optional)",
    )
    log_level: str = "INFO"

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = self.data_dir / "hck.db"
        return f"sqlite:///{db_path}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
