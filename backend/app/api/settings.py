"""Settings stub API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas import SettingRead, SettingUpsert
from app.db.session import get_db
from app.services import settings_service

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=list[SettingRead])
def list_settings(db: Session = Depends(get_db)) -> list[SettingRead]:
    return [
        SettingRead(key=s.key, value_json=s.value_json, updated_at=s.updated_at)
        for s in settings_service.list_settings(db)
    ]


@router.get("/{key}", response_model=SettingRead)
def get_setting(key: str, db: Session = Depends(get_db)) -> SettingRead:
    setting = settings_service.get_setting(db, key)
    if setting is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Setting not found")
    return SettingRead(key=setting.key, value_json=setting.value_json, updated_at=setting.updated_at)


@router.put("/{key}", response_model=SettingRead)
def upsert_setting(key: str, payload: SettingUpsert, db: Session = Depends(get_db)) -> SettingRead:
    setting = settings_service.upsert_setting(db, key, payload.value_json)
    return SettingRead(key=setting.key, value_json=setting.value_json, updated_at=setting.updated_at)
