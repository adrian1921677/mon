"""Audit events read API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import AuditEventRead
from app.db.models import AuditEvent
from app.db.session import get_db

router = APIRouter(prefix="/audit-events", tags=["audit"])


@router.get("", response_model=list[AuditEventRead])
def list_audit_events(
    db: Session = Depends(get_db),
    project_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[AuditEventRead]:
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    if project_id is not None:
        stmt = stmt.where(AuditEvent.project_id == project_id)
    events = db.scalars(stmt).all()
    return [AuditEventRead.model_validate(e) for e in events]
