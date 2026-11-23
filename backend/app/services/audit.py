"""Audit event helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AuditEvent


def record_audit(
    db: Session,
    *,
    action: str,
    actor: str = "local",
    project_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        action=action,
        actor=actor,
        project_id=project_id,
        detail_json=detail or {},
    )
    db.add(event)
    return event
