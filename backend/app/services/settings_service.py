"""Settings stub service (key/value JSON)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Setting
from app.services.audit import record_audit


def list_settings(db: Session) -> list[Setting]:
    return list(db.scalars(select(Setting).order_by(Setting.key)).all())


def get_setting(db: Session, key: str) -> Setting | None:
    return db.get(Setting, key)


def upsert_setting(db: Session, key: str, value_json: Any) -> Setting:
    setting = db.get(Setting, key)
    created = setting is None
    if setting is None:
        setting = Setting(key=key, value_json=value_json)
        db.add(setting)
    else:
        setting.value_json = value_json
    record_audit(
        db,
        action="settings.created" if created else "settings.updated",
        detail={"key": key},
    )
    db.commit()
    db.refresh(setting)
    return setting
