"""Scan comparison / history from real finding occurrences."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Finding, FindingOccurrence, Scan
from app.services.projects import get_project


class ScanCompareError(ValueError):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _enum_val(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)


def _findings_by_scan(db: Session, project_id: str, scan_id: str) -> dict[str, Finding]:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != project_id:
        raise ScanCompareError(f"scan not found: {scan_id}")
    occs = (
        db.query(FindingOccurrence)
        .filter(FindingOccurrence.scan_id == scan_id)
        .all()
    )
    finding_ids = {o.finding_id for o in occs}
    if not finding_ids:
        return {}
    rows = (
        db.query(Finding)
        .filter(Finding.project_id == project_id, Finding.id.in_(finding_ids))
        .all()
    )
    return {f.fingerprint: f for f in rows}


def compare_scans(
    db: Session,
    project_id: str,
    *,
    baseline_scan_id: str,
    candidate_scan_id: str,
) -> dict[str, Any]:
    get_project(db, project_id)
    if baseline_scan_id == candidate_scan_id:
        raise ScanCompareError("baseline and candidate must differ")

    base = _findings_by_scan(db, project_id, baseline_scan_id)
    cand = _findings_by_scan(db, project_id, candidate_scan_id)

    base_fps = set(base)
    cand_fps = set(cand)

    new_fps = sorted(cand_fps - base_fps)
    resolved_fps = sorted(base_fps - cand_fps)
    persistent_fps = sorted(base_fps & cand_fps)

    def brief(f: Finding) -> dict[str, Any]:
        return {
            "id": f.id,
            "fingerprint": f.fingerprint,
            "title": f.title,
            "severity": _enum_val(f.severity),
            "status": _enum_val(f.status),
            "scanner_id": f.scanner_id,
        }

    history = (
        db.query(Scan)
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.asc())
        .all()
    )

    return {
        "project_id": project_id,
        "baseline_scan_id": baseline_scan_id,
        "candidate_scan_id": candidate_scan_id,
        "summary": {
            "baseline_count": len(base),
            "candidate_count": len(cand),
            "new": len(new_fps),
            "resolved": len(resolved_fps),
            "persistent": len(persistent_fps),
        },
        "new_findings": [brief(cand[fp]) for fp in new_fps],
        "resolved_findings": [brief(base[fp]) for fp in resolved_fps],
        "persistent_findings": [brief(cand[fp]) for fp in persistent_fps],
        "history": [
            {
                "id": s.id,
                "status": _enum_val(s.status),
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in history
        ],
    }
