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


class ToolInstallationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scanner_id: str
    version: str | None
    path_or_runtime: str
    status: str
    meta_json: Any
    checked_at: datetime | None


class ToolLiveRead(BaseModel):
    scanner_id: str
    display_name: str
    description: str = ""
    capabilities: list[str] = Field(default_factory=list)
    preferred_runtime: str
    is_active: bool = False
    is_test_only: bool = False
    integration_phase: int = 4
    status: str
    version: str | None = None
    path_or_runtime: str
    message: str = ""
    binary_path: str | None = None
    checked_at: str | None = None
    persisted: bool = False
    meta: dict[str, Any] = Field(default_factory=dict)


class ScanCreate(BaseModel):
    scanner_ids: list[str] = Field(min_length=1)
    depth: Literal["quick", "standard", "deep"] = "standard"
    #: Internal/tests only — never expose echo as a UI default.
    allow_test_adapters: bool = False


class ScanTaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    scanner_id: str
    status: str
    pid: int | None
    handle_ref: str | None
    exit_code: int | None
    log_path: str | None
    created_at: datetime


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    profile_id: str | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    scope_snapshot_json: Any
    created_at: datetime
    tasks: list[ScanTaskRead] = Field(default_factory=list)
