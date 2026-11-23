"""Finding list/detail/update — real DB data only."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import (
    Finding,
    FindingConfidence,
    FindingOccurrence,
    FindingSeverity,
    FindingStatus,
)
from app.services.audit import record_audit
from app.services.projects import get_project


class FindingNotFoundError(LookupError):
    pass


def list_findings(
    db: Session,
    project_id: str,
    *,
    status: FindingStatus | None = None,
    severity: FindingSeverity | None = None,
    scanner_id: str | None = None,
    q: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[Finding], int]:
    get_project(db, project_id)
    query = db.query(Finding).filter(Finding.project_id == project_id)
    if status is not None:
        query = query.filter(Finding.status == status)
    if severity is not None:
        query = query.filter(Finding.severity == severity)
    if scanner_id:
        query = query.filter(Finding.scanner_id == scanner_id)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(Finding.title.ilike(like) | Finding.category.ilike(like))
    total = query.count()
    rows = (
        query.options(
            selectinload(Finding.occurrences),
            selectinload(Finding.evidence),
        )
        .order_by(Finding.last_seen_at.desc())
        .offset(max(0, offset))
        .limit(min(max(1, limit), 500))
        .all()
    )
    return rows, total


def get_finding(db: Session, project_id: str, finding_id: str) -> Finding:
    get_project(db, project_id)
    row = (
        db.query(Finding)
        .options(
            selectinload(Finding.occurrences),
            selectinload(Finding.evidence),
        )
        .filter(Finding.id == finding_id, Finding.project_id == project_id)
        .one_or_none()
    )
    if row is None:
        raise FindingNotFoundError(finding_id)
    return row


def update_finding(
    db: Session,
    project_id: str,
    finding_id: str,
    *,
    status: FindingStatus | None = None,
    confidence: FindingConfidence | None = None,
    remediation: str | None = None,
    description: str | None = None,
) -> Finding:
    row = get_finding(db, project_id, finding_id)
    changed: dict[str, str] = {}
    if status is not None and row.status != status:
        row.status = status
        changed["status"] = status.value
    if confidence is not None and row.confidence != confidence:
        row.confidence = confidence
        changed["confidence"] = confidence.value
    if remediation is not None:
        row.remediation = remediation.strip() or None
        changed["remediation"] = "updated"
    if description is not None:
        row.description = description.strip() or None
        changed["description"] = "updated"
    if changed:
        record_audit(
            db,
            action="finding.updated",
            project_id=project_id,
            detail={"finding_id": finding_id, **changed},
        )
        db.commit()
        db.refresh(row)
    return row


def occurrence_counts(db: Session, finding_ids: list[str]) -> dict[str, int]:
    if not finding_ids:
        return {}
    rows = (
        db.query(FindingOccurrence.finding_id, func.count(FindingOccurrence.id))
        .filter(FindingOccurrence.finding_id.in_(finding_ids))
        .group_by(FindingOccurrence.finding_id)
        .all()
    )
    return {fid: int(cnt) for fid, cnt in rows}


def findings_for_scan(db: Session, project_id: str, scan_id: str) -> list[Finding]:
    get_project(db, project_id)
    occ_ids = select(FindingOccurrence.finding_id).where(FindingOccurrence.scan_id == scan_id)
    return (
        db.query(Finding)
        .options(
            selectinload(Finding.occurrences),
            selectinload(Finding.evidence),
        )
        .filter(Finding.project_id == project_id, Finding.id.in_(occ_ids))
        .order_by(Finding.severity.desc(), Finding.title.asc())
        .all()
    )
