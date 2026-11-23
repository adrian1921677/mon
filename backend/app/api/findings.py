"""Findings API — list, detail, status updates (real DB only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.schemas import (
    FindingListResponse,
    FindingRead,
    FindingUpdate,
)
from app.db.models import Finding, FindingSeverity, FindingStatus
from app.db.session import get_db
from app.services.findings_service import FindingNotFoundError, get_finding, list_findings, update_finding
from app.services.projects import ProjectNotFoundError, get_project

router = APIRouter(tags=["findings"])


def _finding_read(row: Finding, *, detail: bool = False) -> FindingRead:
    occs = list(row.occurrences or [])
    evs = list(row.evidence or [])
    return FindingRead(
        id=row.id,
        project_id=row.project_id,
        fingerprint=row.fingerprint,
        title=row.title,
        severity=row.severity,
        category=row.category,
        scanner_id=row.scanner_id,
        status=row.status,
        confidence=row.confidence,
        remediation=row.remediation,
        description=row.description,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        occurrence_count=len(occs),
        occurrences=occs if detail else [],
        evidence=evs if detail else [],
    )


@router.get("/projects/{project_id}/findings", response_model=FindingListResponse)
def list_project_findings(
    project_id: str,
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    severity: FindingSeverity | None = Query(default=None),
    scanner_id: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> FindingListResponse:
    try:
        get_project(db, project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    rows, total = list_findings(
        db,
        project_id,
        status=status_filter,
        severity=severity,
        scanner_id=scanner_id,
        q=q,
        limit=limit,
        offset=offset,
    )
    return FindingListResponse(
        items=[_finding_read(r, detail=False) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/projects/{project_id}/findings/{finding_id}", response_model=FindingRead)
def get_project_finding(
    project_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
) -> FindingRead:
    try:
        row = get_finding(db, project_id, finding_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found") from exc
    return _finding_read(row, detail=True)


@router.patch("/projects/{project_id}/findings/{finding_id}", response_model=FindingRead)
def patch_project_finding(
    project_id: str,
    finding_id: str,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
) -> FindingRead:
    try:
        row = update_finding(
            db,
            project_id,
            finding_id,
            status=payload.status,
            confidence=payload.confidence,
            remediation=payload.remediation,
            description=payload.description,
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found") from exc
    # Reload with relationships
    row = get_finding(db, project_id, finding_id)
    return _finding_read(row, detail=True)
