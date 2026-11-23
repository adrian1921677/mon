"""Scope entry CRUD + validation against Scope Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import ScopeEntryCreate, ScopeEntryUpdate, ScopeValidateRequest
from app.db.models import ScopeEntry, ScopeEntryStatus, ScopeEntryType
from app.scope.engine import ScopeEngine
from app.scope.rate_limits import DEFAULT_RATE_LIMITS, SETTING_RATE_LIMITS
from app.scope.types import ScopeTarget, ValidationReason, ValidationResult
from app.services.audit import record_audit
from app.services.projects import get_project
from app.services import settings_service


class ScopeEntryNotFoundError(LookupError):
    pass


class ScopeRejectedError(ValueError):
    def __init__(self, result: ValidationResult) -> None:
        super().__init__(result.message)
        self.result = result


def _engine() -> ScopeEngine:
    return ScopeEngine()


def _rate_limits_from_db(db: Session) -> dict[str, int]:
    row = settings_service.get_setting(db, SETTING_RATE_LIMITS)
    if row is None or not isinstance(row.value_json, dict):
        return dict(DEFAULT_RATE_LIMITS)
    merged = dict(DEFAULT_RATE_LIMITS)
    for k, v in row.value_json.items():
        if isinstance(v, int):
            merged[k] = v
    return merged


def list_scope_entries(db: Session, project_id: str) -> list[ScopeEntry]:
    get_project(db, project_id)
    return list(
        db.scalars(
            select(ScopeEntry)
            .where(ScopeEntry.project_id == project_id)
            .order_by(ScopeEntry.created_at.desc())
        ).all()
    )


def get_scope_entry(db: Session, project_id: str, entry_id: str) -> ScopeEntry:
    get_project(db, project_id)
    entry = db.get(ScopeEntry, entry_id)
    if entry is None or entry.project_id != project_id:
        raise ScopeEntryNotFoundError(entry_id)
    return entry


def create_scope_entry(
    db: Session,
    project_id: str,
    payload: ScopeEntryCreate,
    *,
    resolve_dns: bool = True,
) -> ScopeEntry:
    get_project(db, project_id)
    engine = _engine()
    result = engine.validate_entry(
        payload.type,
        payload.value,
        resolve_dns=resolve_dns,
        project_id=project_id,
        rate_limits_cfg=_rate_limits_from_db(db),
    )
    if not result.allowed:
        raise ScopeRejectedError(result)

    status = ScopeEntryStatus.verified if result.allowed else ScopeEntryStatus.rejected
    meta = dict(payload.meta_json or {})
    meta["validation"] = {
        "reason": result.reason.value,
        "message": result.message,
        "resolved_ips": list(result.resolved_ips),
        **result.meta,
    }
    entry = ScopeEntry(
        project_id=project_id,
        type=payload.type,
        value=payload.value.strip(),
        meta_json=meta,
        status=status,
        verified_at=datetime.now(timezone.utc) if status is ScopeEntryStatus.verified else None,
    )
    db.add(entry)
    db.flush()
    record_audit(
        db,
        action="scope.created",
        project_id=project_id,
        detail={"id": entry.id, "type": entry.type.value, "value": entry.value, "status": entry.status.value},
    )
    db.commit()
    db.refresh(entry)
    return entry


def update_scope_entry(
    db: Session,
    project_id: str,
    entry_id: str,
    payload: ScopeEntryUpdate,
    *,
    resolve_dns: bool = True,
) -> ScopeEntry:
    entry = get_scope_entry(db, project_id, entry_id)
    data = payload.model_dump(exclude_unset=True)
    new_type = data.get("type", entry.type)
    new_value = data.get("value", entry.value)
    if "type" in data or "value" in data:
        engine = _engine()
        result = engine.validate_entry(
            new_type if isinstance(new_type, ScopeEntryType) else ScopeEntryType(new_type),
            str(new_value),
            resolve_dns=resolve_dns,
            project_id=project_id,
            rate_limits_cfg=_rate_limits_from_db(db),
        )
        if not result.allowed:
            raise ScopeRejectedError(result)
        entry.type = new_type if isinstance(new_type, ScopeEntryType) else ScopeEntryType(new_type)
        entry.value = str(new_value).strip()
        meta = dict(entry.meta_json or {})
        meta["validation"] = {
            "reason": result.reason.value,
            "message": result.message,
            "resolved_ips": list(result.resolved_ips),
            **result.meta,
        }
        entry.meta_json = meta
        entry.status = ScopeEntryStatus.verified
        entry.verified_at = datetime.now(timezone.utc)
    if "meta_json" in data and data["meta_json"] is not None:
        merged = dict(entry.meta_json or {})
        merged.update(data["meta_json"])
        entry.meta_json = merged
    if "status" in data and data["status"] is not None:
        entry.status = data["status"]
        if entry.status is ScopeEntryStatus.verified and entry.verified_at is None:
            entry.verified_at = datetime.now(timezone.utc)

    record_audit(
        db,
        action="scope.updated",
        project_id=project_id,
        detail={"id": entry.id, **{k: str(v) for k, v in data.items()}},
    )
    db.commit()
    db.refresh(entry)
    return entry


def delete_scope_entry(db: Session, project_id: str, entry_id: str) -> None:
    entry = get_scope_entry(db, project_id, entry_id)
    record_audit(
        db,
        action="scope.deleted",
        project_id=project_id,
        detail={"id": entry.id, "type": entry.type.value, "value": entry.value},
    )
    db.delete(entry)
    db.commit()


def validate_dry_run(db: Session, project_id: str, payload: ScopeValidateRequest) -> dict[str, Any]:
    """Dry-run validation — does not persist."""
    get_project(db, project_id)
    engine = _engine()
    entries = list_scope_entries(db, project_id)

    if payload.mode == "entry":
        result = engine.validate_entry(
            payload.type,
            payload.value,
            resolve_dns=payload.resolve_dns,
            project_id=project_id,
            rate_limits_cfg=_rate_limits_from_db(db),
        )
    elif payload.mode == "target":
        result = engine.check_target_in_scope(
            ScopeTarget(type=payload.type, value=payload.value, meta=payload.meta_json or {}),
            entries,
            resolve_dns=payload.resolve_dns,
        )
    elif payload.mode == "redirect":
        if not payload.redirect_location:
            result = ValidationResult.deny(
                ValidationReason.invalid_format,
                "redirect_location required for mode=redirect",
            )
        else:
            result = engine.check_redirect(
                payload.value,
                payload.redirect_location,
                entries,
            )
    elif payload.mode == "ssrf":
        result = engine.check_ssrf_fetch(payload.value, entries)
    elif payload.mode == "active_gate":
        result = engine.require_active_tests(db)
    else:
        result = ValidationResult.deny(ValidationReason.invalid_format, f"unknown mode {payload.mode}")

    return {
        "allowed": result.allowed,
        "reason": result.reason.value,
        "message": result.message,
        "resolved_ips": list(result.resolved_ips),
        "meta": result.meta,
    }
