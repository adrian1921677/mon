"""Reports API — JSON/PDF export, finding report, scan compare."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.schemas import ScanCompareRequest
from app.db.session import get_db
from app.reporting.compare import ScanCompareError, compare_scans
from app.reporting.export import (
    build_finding_report,
    finding_report_pdf,
    project_report_json,
    project_report_pdf,
)
from app.services.findings_service import FindingNotFoundError
from app.services.projects import ProjectNotFoundError

router = APIRouter(tags=["reports"])


@router.get("/projects/{project_id}/reports/project")
def export_project_report(
    project_id: str,
    format: str = Query(default="json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
) -> Response:
    try:
        if format == "pdf":
            body = project_report_pdf(db, project_id)
            return Response(
                content=body,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="hck-project-{project_id}.pdf"'
                },
            )
        data = project_report_json(db, project_id)
        payload = json.dumps(data, indent=2, default=str).encode("utf-8")
        return Response(
            content=payload,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="hck-project-{project_id}.json"'
            },
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc


@router.get("/projects/{project_id}/reports/findings/{finding_id}")
def export_finding_report(
    project_id: str,
    finding_id: str,
    format: str = Query(default="json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
) -> Response:
    try:
        if format == "pdf":
            body = finding_report_pdf(db, project_id, finding_id)
            return Response(
                content=body,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="hck-finding-{finding_id}.pdf"'
                },
            )
        data = build_finding_report(db, project_id, finding_id)
        payload = json.dumps(data, indent=2, default=str).encode("utf-8")
        return Response(
            content=payload,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="hck-finding-{finding_id}.json"'
            },
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found") from exc


@router.post("/projects/{project_id}/reports/compare")
def compare_project_scans(
    project_id: str,
    payload: ScanCompareRequest,
    db: Session = Depends(get_db),
) -> dict:
    try:
        return compare_scans(
            db,
            project_id,
            baseline_scan_id=payload.baseline_scan_id,
            candidate_scan_id=payload.candidate_scan_id,
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    except ScanCompareError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.detail) from exc
