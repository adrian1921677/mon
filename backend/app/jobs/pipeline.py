"""Scan job pipeline stub — ScopeEngine + ProcessManager + Active-Gate."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import (
    Scan,
    ScanStatus,
    ScanTask,
    ScopeEntry,
    ScopeEntryStatus,
    ScopeEntryType,
)
from app.process.manager import ProcessManager
from app.scope.active_gate import require_active_tests
from app.scope.engine import ScopeEngine
from app.scope.types import ScopeTarget
from app.scanners.base import (
    InstallationStatus,
    ParseArtifacts,
    ScanContext,
    ScannerNotImplementedError,
    ScannerNotInstalledError,
)
from app.scanners.registry import ScannerRegistry, get_registry
from app.services.audit import record_audit


class ScanPipelineError(Exception):
    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.detail = {"message": message, **(detail or {})}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _scope_snapshot(entries: list[ScopeEntry]) -> dict[str, Any]:
    return {
        "entries": [
            {
                "id": e.id,
                "type": e.type.value if hasattr(e.type, "value") else str(e.type),
                "value": e.value,
                "status": e.status.value if hasattr(e.status, "value") else str(e.status),
            }
            for e in entries
            if e.status is not ScopeEntryStatus.rejected
        ]
    }


def _targets_from_scope(entries: list[ScopeEntry]) -> list[ScopeTarget]:
    return [
        ScopeTarget(type=e.type, value=e.value, meta=dict(e.meta_json or {}))
        for e in entries
        if e.status is not ScopeEntryStatus.rejected
    ]


async def create_scan_stub(
    db: Session,
    *,
    project_id: str,
    scanner_ids: list[str],
    depth: str = "standard",
    allow_test_adapters: bool = False,
    execute_ready: bool = True,
    process_manager: ProcessManager | None = None,
    registry: ScannerRegistry | None = None,
    scope_engine: ScopeEngine | None = None,
) -> Scan:
    """
    Create a scan + tasks, validate scope, enforce active-gate.

    Productive scanners that are not installed → task ``failed`` (clear reason).
    Skeletons that are installed but not CLI-ready → task ``failed`` with NotImplemented.
    Echo only when ``allow_test_adapters`` (tests) — never persists production findings.
    """
    if not scanner_ids:
        raise ScanPipelineError("at least one scanner_id required")

    reg = registry or get_registry()
    engine = scope_engine or ScopeEngine()
    pm = process_manager or ProcessManager(max_concurrent=2, default_timeout_seconds=60.0)

    # Resolve adapters
    adapters = []
    for sid in scanner_ids:
        if not reg.has(sid):
            raise ScanPipelineError(f"unknown scanner: {sid}", detail={"scanner_id": sid})
        adapter = reg.get(sid)
        if adapter.is_test_only and not allow_test_adapters:
            raise ScanPipelineError(
                f"scanner '{sid}' is test-only and cannot run as a production scan",
                detail={"scanner_id": sid, "test_only": True},
            )
        adapters.append(adapter)

    # Active-gate for any active adapter in this scan
    active_needed = [a for a in adapters if a.is_active]
    if active_needed:
        gate = require_active_tests(db)
        if not gate.allowed:
            raise ScanPipelineError(
                gate.message,
                detail={
                    "reason": gate.reason.value,
                    "active_scanners": [a.scanner_id for a in active_needed],
                },
            )

    entries = (
        db.query(ScopeEntry)
        .filter(ScopeEntry.project_id == project_id)
        .order_by(ScopeEntry.created_at.asc())
        .all()
    )
    if not entries:
        raise ScanPipelineError("project has no scope entries")

    targets = _targets_from_scope(entries)
    if not targets:
        raise ScanPipelineError("no usable (non-rejected) scope entries")

    # ScopeEngine: re-validate entries + membership for runtime connect targets
    for entry in entries:
        if entry.status is ScopeEntryStatus.rejected:
            continue
        result = engine.validate_entry(
            entry.type,
            entry.value,
            resolve_dns=False,
            project_id=project_id,
        )
        if not result.allowed:
            raise ScanPipelineError(
                result.message,
                detail={"reason": result.reason.value, "target": entry.value},
            )

    for target in targets:
        # CIDR is a scope definition, not a connect target — skip membership check.
        if target.type is ScopeEntryType.cidr:
            continue
        result = engine.check_target_in_scope(target, entries, resolve_dns=False)
        if not result.allowed:
            raise ScanPipelineError(
                result.message,
                detail={"reason": result.reason.value, "target": target.value},
            )

    # Adapter-level target shape: each scanner must accept at least one target
    for adapter in adapters:
        ok_any = False
        for target in targets:
            if adapter.validate_target(target).allowed:
                ok_any = True
                break
        if not ok_any:
            raise ScanPipelineError(
                f"no in-scope target compatible with scanner '{adapter.scanner_id}'",
                detail={"scanner_id": adapter.scanner_id},
            )

    scan = Scan(
        project_id=project_id,
        status=ScanStatus.running,
        started_at=_utcnow(),
        scope_snapshot_json=_scope_snapshot(entries),
    )
    db.add(scan)
    db.flush()

    tasks: list[ScanTask] = []
    for adapter in adapters:
        task = ScanTask(
            scan_id=scan.id,
            scanner_id=adapter.scanner_id,
            status=ScanStatus.pending,
        )
        db.add(task)
        db.flush()
        tasks.append(task)

    record_audit(
        db,
        action="scan.create",
        project_id=project_id,
        detail={
            "scan_id": scan.id,
            "scanners": [a.scanner_id for a in adapters],
            "depth": depth,
            "allow_test_adapters": allow_test_adapters,
        },
    )
    db.commit()
    db.refresh(scan)

    if execute_ready:
        for task in tasks:
            db.refresh(task)
            adapter = reg.get(task.scanner_id)
            await run_task_stub(
                db,
                scan=scan,
                task=task,
                adapter=adapter,
                targets=targets,
                depth=depth,
                process_manager=pm,
                allow_test_findings=allow_test_adapters and adapter.is_test_only,
            )

    # Aggregate scan status
    db.refresh(scan)
    task_rows = db.query(ScanTask).filter(ScanTask.scan_id == scan.id).all()
    statuses = {t.status for t in task_rows}
    if statuses == {ScanStatus.completed}:
        scan.status = ScanStatus.completed
    elif ScanStatus.running in statuses or ScanStatus.pending in statuses:
        scan.status = ScanStatus.running
    elif ScanStatus.cancelled in statuses and len(statuses) == 1:
        scan.status = ScanStatus.cancelled
    else:
        # Any failure / mix without success-only → failed if none completed, else completed
        # with partial failures still "completed" if at least one ok? Prefer failed when all failed.
        if statuses <= {ScanStatus.failed, ScanStatus.interrupted, ScanStatus.cancelled}:
            scan.status = ScanStatus.failed
        elif ScanStatus.completed in statuses:
            scan.status = ScanStatus.completed
        else:
            scan.status = ScanStatus.failed
    scan.finished_at = _utcnow()
    db.commit()
    db.refresh(scan)
    return scan


async def run_task_stub(
    db: Session,
    *,
    scan: Scan,
    task: ScanTask,
    adapter: Any,
    targets: list[ScopeTarget],
    depth: str,
    process_manager: ProcessManager,
    allow_test_findings: bool = False,
) -> ScanTask:
    """Execute one task stub: install check → ProcessManager (echo) or clean failure."""
    task.status = ScanStatus.running
    db.commit()

    compatible = [t for t in targets if adapter.validate_target(t).allowed]
    ctx = ScanContext(
        project_id=scan.project_id,
        scan_id=scan.id,
        task_id=task.id,
        targets=compatible or targets,
        depth=depth,
        allow_test_findings=allow_test_findings,
    )

    try:
        info = await adapter.check_installation()
        if info.status is not InstallationStatus.installed:
            raise ScannerNotInstalledError(adapter.scanner_id, info.message)

        result = await adapter.execute(ctx, process_manager)
        task.pid = result.pid
        task.handle_ref = result.handle_id
        task.exit_code = result.exit_code

        # Parse / normalize — production adapters raise NotImplemented;
        # echo returns findings only when allow_test_findings.
        artifacts = ParseArtifacts(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
        )
        parsed = adapter.parse_results(artifacts)
        findings = adapter.normalize_findings(parsed, ctx)
        # Invariant: never write findings to DB in Phase 3 stub
        # (even test findings stay in-memory for test assertions only).
        _ = findings

        if result.ok:
            task.status = ScanStatus.completed
        else:
            task.status = ScanStatus.failed
            task.log_path = result.error or result.stderr[:500] or "process failed"

    except ScannerNotInstalledError as exc:
        task.status = ScanStatus.failed
        task.log_path = f"not installed: {exc}"
        task.exit_code = None
    except ScannerNotImplementedError as exc:
        task.status = ScanStatus.failed
        task.log_path = f"not implemented (Phase {exc.phase}): {exc}"
        task.exit_code = None
    except Exception as exc:  # noqa: BLE001 — persist failure
        task.status = ScanStatus.failed
        task.log_path = str(exc)[:2000]
        task.exit_code = None

    db.commit()
    db.refresh(task)
    return task
