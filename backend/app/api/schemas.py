"""Pydantic request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import ScopeEntryStatus, ScopeEntryType


class HealthResponse(BaseModel):
    status: str = "ok"
    app: str
    version: str
    database: str = "ok"


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime


class SettingRead(BaseModel):
    key: str
    value_json: Any
    updated_at: datetime


class SettingUpsert(BaseModel):
    value_json: Any


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str | None
    action: str
    actor: str
    detail_json: Any
    created_at: datetime


class ScopeEntryCreate(BaseModel):
    type: ScopeEntryType
    value: str = Field(min_length=1, max_length=10_000)
    meta_json: dict[str, Any] = Field(default_factory=dict)


class ScopeEntryUpdate(BaseModel):
    type: ScopeEntryType | None = None
    value: str | None = Field(default=None, min_length=1, max_length=10_000)
    meta_json: dict[str, Any] | None = None
    status: ScopeEntryStatus | None = None


class ScopeEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    type: ScopeEntryType
    value: str
    meta_json: Any
    verified_at: datetime | None
    status: ScopeEntryStatus
    created_at: datetime


class ScopeValidateRequest(BaseModel):
    mode: Literal["entry", "target", "redirect", "ssrf", "active_gate"] = "entry"
    type: ScopeEntryType = ScopeEntryType.url
    value: str = Field(min_length=1, max_length=10_000)
    meta_json: dict[str, Any] = Field(default_factory=dict)
    redirect_location: str | None = None
    resolve_dns: bool = True


class ScopeValidateResponse(BaseModel):
    allowed: bool
    reason: str
    message: str
    resolved_ips: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
