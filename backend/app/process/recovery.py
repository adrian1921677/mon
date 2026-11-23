"""Crash recovery — mark running/pending scan tasks as interrupted."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db.models import Scan, ScanStatus, ScanTask
from app.services.audit import record_audit


def mark_interrupted_tasks(db: Session, *, actor: str = "system") -> dict[str, int]:
    """
    On backend startup after a crash: any scan/task still pending/running
    cannot have a live process — mark them interrupted.
    """
    now = datetime.now(timezone.utc)
    active = (ScanStatus.pending, ScanStatus.running)

    tasks = list(
        db.scalars(select(ScanTask).where(ScanTask.status.in_(active))).all()
    )
    scans = list(db.scalars(select(Scan).where(Scan.status.in_(active))).all())

    task_count = 0
    for task in tasks:
        task.status = ScanStatus.interrupted
        task.exit_code = task.exit_code  # unchanged
        task_count += 1

    scan_count = 0
    for scan in scans:
        scan.status = ScanStatus.interrupted
        if scan.finished_at is None:
            scan.finished_at = now
        scan_count += 1

    if task_count or scan_count:
        record_audit(
            db,
            action="process.recovery_interrupted",
            actor=actor,
            detail={"tasks": task_count, "scans": scan_count},
        )
        db.commit()

    return {"tasks": task_count, "scans": scan_count}


def mark_task_status(
    db: Session,
    task_id: str,
    status: ScanStatus,
    *,
    pid: int | None = None,
    handle_ref: str | None = None,
    exit_code: int | None = None,
    log_path: str | None = None,
) -> ScanTask | None:
    task = db.get(ScanTask, task_id)
    if task is None:
        return None
    task.status = status
    if pid is not None:
        task.pid = pid
    if handle_ref is not None:
        task.handle_ref = handle_ref
    if exit_code is not None:
        task.exit_code = exit_code
    if log_path is not None:
        task.log_path = log_path
    db.commit()
    db.refresh(task)
    return task
