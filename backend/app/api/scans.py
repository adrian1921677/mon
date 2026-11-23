"""Scan pipeline API — ScopeEngine + ProcessManager; Phase-4 findings persisted."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, selectinload

from app.api.schemas import ScanCreate, ScanRead, ScanTaskRead
from app.db.models import Scan, ScanTask
from app.db.session import get_db
from app.jobs.pipeline import ScanPipelineError, create_scan_stub
from app.services.projects import ProjectNotFoundError, get_project

router = APIRouter(tags=["scans"])


def _scan_read(scan: Scan) -> ScanRead:
    tasks = [
        ScanTaskRead(
            id=t.id,
            scan_id=t.scan_id,
            scanner_id=t.scanner_id,
            status=t.status.value if hasattr(t.status, "value") else str(t.status),
            pid=t.pid,
            handle_ref=t.handle_ref,
            exit_code=t.exit_code,
            log_path=t.log_path,
            created_at=t.created_at,
        )
        for t in (scan.tasks or [])
    ]
    return ScanRead(
        id=scan.id,
        project_id=scan.project_id,
        profile_id=scan.profile_id,
        status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        scope_snapshot_json=scan.scope_snapshot_json,
        created_at=scan.created_at,
        tasks=tasks,
    )


@router.get("/projects/{project_id}/scans", response_model=list[ScanRead])
def list_scans(project_id: str, db: Session = Depends(get_db)) -> list[ScanRead]:
    try:
        get_project(db, project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    rows = (
        db.query(Scan)
        .options(selectinload(Scan.tasks))
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return [_scan_read(s) for s in rows]


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_scan(
    project_id: str,
    payload: ScanCreate,
    db: Session = Depends(get_db),
) -> ScanRead:
    try:
        get_project(db, project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc

    # Production API never enables test adapters via default UI payload.
    # allow_test_adapters stays available for automated pipeline tests only.
    try:
        scan = await create_scan_stub(
            db,
            project_id=project_id,
            scanner_ids=payload.scanner_ids,
            depth=payload.depth,
            allow_test_adapters=payload.allow_test_adapters,
            execute_ready=True,
        )
    except ScanPipelineError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.detail) from exc

    # Reload with tasks
    scan = (
        db.query(Scan)
        .options(selectinload(Scan.tasks))
        .filter(Scan.id == scan.id)
        .one()
    )
    return _scan_read(scan)


@router.get("/projects/{project_id}/scans/{scan_id}", response_model=ScanRead)
def get_scan(project_id: str, scan_id: str, db: Session = Depends(get_db)) -> ScanRead:
    try:
        get_project(db, project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found") from exc
    scan = (
        db.query(Scan)
        .options(selectinload(Scan.tasks))
        .filter(Scan.id == scan_id, Scan.project_id == project_id)
        .one_or_none()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_read(scan)


@router.get("/scans/{scan_id}/tasks", response_model=list[ScanTaskRead])
def list_scan_tasks(scan_id: str, db: Session = Depends(get_db)) -> list[ScanTaskRead]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    tasks = db.query(ScanTask).filter(ScanTask.scan_id == scan_id).order_by(ScanTask.created_at.asc()).all()
    return [
        ScanTaskRead(
            id=t.id,
            scan_id=t.scan_id,
            scanner_id=t.scanner_id,
            status=t.status.value if hasattr(t.status, "value") else str(t.status),
            pid=t.pid,
            handle_ref=t.handle_ref,
            exit_code=t.exit_code,
            log_path=t.log_path,
            created_at=t.created_at,
        )
        for t in tasks
    ]
