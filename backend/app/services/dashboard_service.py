"""Dashboard aggregates from real DB rows — never invents findings."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import (
    Asset,
    AuditEvent,
    Finding,
    FindingSeverity,
    FindingStatus,
    Scan,
    ScanStatus,
)
from app.scanners.registry import get_registry
from app.services.projects import get_project
from app.services.tool_manager import list_installations


def _enum_val(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)


def build_dashboard(db: Session, project_id: str) -> dict[str, Any]:
    get_project(db, project_id)

    asset_count = db.query(Asset).filter(Asset.project_id == project_id).count()

    running_scans = (
        db.query(Scan)
        .filter(
            Scan.project_id == project_id,
            Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
        )
        .order_by(Scan.created_at.desc())
        .limit(20)
        .all()
    )

    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    by_severity: dict[str, int] = {s.value: 0 for s in FindingSeverity}
    by_status: dict[str, int] = {s.value: 0 for s in FindingStatus}
    for f in findings:
        by_severity[_enum_val(f.severity)] = by_severity.get(_enum_val(f.severity), 0) + 1
        by_status[_enum_val(f.status)] = by_status.get(_enum_val(f.status), 0) + 1

    critical_open = [
        f
        for f in findings
        if f.severity is FindingSeverity.critical and f.status is FindingStatus.open
    ]
    critical_open.sort(key=lambda x: x.last_seen_at or x.first_seen_at, reverse=True)

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=13)
    day_buckets: dict[str, int] = defaultdict(int)
    for i in range(14):
        day = (start + timedelta(days=i)).date().isoformat()
        day_buckets[day] = 0
    for f in findings:
        ts = f.first_seen_at
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < start:
            continue
        day_buckets[ts.date().isoformat()] += 1
    trend = [{"date": d, "new_findings": day_buckets[d]} for d in sorted(day_buckets.keys())]

    installations = {r.scanner_id: r for r in list_installations(db)}
    scanners: list[dict[str, Any]] = []
    for adapter in get_registry().list(include_test_only=False):
        row = installations.get(adapter.scanner_id)
        scanners.append(
            {
                "scanner_id": adapter.scanner_id,
                "display_name": adapter.display_name,
                "status": row.status if row else "unknown",
                "version": row.version if row else None,
                "preferred_runtime": adapter.preferred_runtime.value,
                "integration_phase": adapter.integration_phase,
            }
        )
    installed = sum(1 for s in scanners if s["status"] == "installed")

    recent_scans = (
        db.query(Scan)
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .limit(8)
        .all()
    )
    activities: list[dict[str, Any]] = []
    for s in recent_scans:
        activities.append(
            {
                "kind": "scan",
                "id": s.id,
                "status": _enum_val(s.status),
                "at": s.finished_at or s.started_at or s.created_at,
                "summary": f"Scan {_enum_val(s.status)}",
            }
        )
    audit_rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.project_id == project_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(12)
        .all()
    )
    for a in audit_rows:
        activities.append(
            {
                "kind": "audit",
                "id": a.id,
                "status": a.action,
                "at": a.created_at,
                "summary": a.action,
            }
        )
    activities.sort(key=lambda x: x["at"] or now, reverse=True)
    activities = activities[:15]

    return {
        "project_id": project_id,
        "asset_count": asset_count,
        "finding_counts": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_status": by_status,
        },
        "critical_findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": _enum_val(f.severity),
                "status": _enum_val(f.status),
                "scanner_id": f.scanner_id,
                "fingerprint": f.fingerprint,
                "last_seen_at": f.last_seen_at,
            }
            for f in critical_open[:10]
        ],
        "running_scans": [
            {
                "id": s.id,
                "status": _enum_val(s.status),
                "started_at": s.started_at,
                "created_at": s.created_at,
            }
            for s in running_scans
        ],
        "trend": trend,
        "scanners": {
            "installed": installed,
            "total": len(scanners),
            "items": scanners,
        },
        "recent_activities": activities,
        "generated_at": now,
    }
