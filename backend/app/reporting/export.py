"""Build project/finding report payloads and PDF bytes from DB data."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session, selectinload

from app.db.models import Asset, Finding, Scan
from app.reporting.pdf_util import text_pdf
from app.services.findings_service import get_finding, list_findings
from app.services.projects import get_project


def _enum_val(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)


def _iso(v: datetime | None) -> str | None:
    if v is None:
        return None
    if v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc).isoformat()
    return v.isoformat()


def _finding_dict(f: Finding, *, include_details: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": f.id,
        "project_id": f.project_id,
        "fingerprint": f.fingerprint,
        "title": f.title,
        "severity": _enum_val(f.severity),
        "category": f.category,
        "scanner_id": f.scanner_id,
        "status": _enum_val(f.status),
        "confidence": _enum_val(f.confidence),
        "remediation": f.remediation,
        "description": f.description,
        "first_seen_at": _iso(f.first_seen_at),
        "last_seen_at": _iso(f.last_seen_at),
        "occurrence_count": len(f.occurrences or []),
    }
    if include_details:
        data["occurrences"] = [
            {
                "id": o.id,
                "scan_id": o.scan_id,
                "asset_id": o.asset_id,
                "raw_ref": o.raw_ref,
                "seen_at": _iso(o.seen_at),
            }
            for o in (f.occurrences or [])
        ]
        data["evidence"] = [
            {
                "id": e.id,
                "kind": e.kind,
                "path_or_blob_ref": e.path_or_blob_ref,
                "created_at": _iso(e.created_at),
            }
            for e in (f.evidence or [])
        ]
    return data


def build_project_report(db: Session, project_id: str) -> dict[str, Any]:
    project = get_project(db, project_id)
    findings, total = list_findings(db, project_id, limit=500)
    assets = (
        db.query(Asset)
        .filter(Asset.project_id == project_id)
        .order_by(Asset.created_at.desc())
        .all()
    )
    scans = (
        db.query(Scan)
        .options(selectinload(Scan.tasks))
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )
    by_sev: dict[str, int] = {}
    for f in findings:
        key = _enum_val(f.severity)
        by_sev[key] = by_sev.get(key, 0) + 1

    return {
        "report_type": "project",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "created_at": _iso(project.created_at),
            "updated_at": _iso(project.updated_at),
        },
        "summary": {
            "finding_total": total,
            "by_severity": by_sev,
            "asset_count": len(assets),
            "scan_count": len(scans),
        },
        "assets": [
            {
                "id": a.id,
                "type": a.type,
                "identifier": a.identifier,
                "last_seen_at": _iso(a.last_seen_at),
            }
            for a in assets
        ],
        "scans": [
            {
                "id": s.id,
                "status": _enum_val(s.status),
                "started_at": _iso(s.started_at),
                "finished_at": _iso(s.finished_at),
                "created_at": _iso(s.created_at),
                "tasks": [
                    {
                        "scanner_id": t.scanner_id,
                        "status": _enum_val(t.status),
                        "exit_code": t.exit_code,
                    }
                    for t in (s.tasks or [])
                ],
            }
            for s in scans
        ],
        "findings": [_finding_dict(f) for f in findings],
    }


def build_finding_report(db: Session, project_id: str, finding_id: str) -> dict[str, Any]:
    project = get_project(db, project_id)
    finding = get_finding(db, project_id, finding_id)
    return {
        "report_type": "finding",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": {"id": project.id, "name": project.name},
        "finding": _finding_dict(finding, include_details=True),
    }


def project_report_json(db: Session, project_id: str) -> dict[str, Any]:
    return build_project_report(db, project_id)


def project_report_pdf(db: Session, project_id: str) -> bytes:
    report = build_project_report(db, project_id)
    project = report["project"]
    summary = report["summary"]
    lines = [
        f"Project: {project['name']} ({project['id']})",
        f"Generated: {report['generated_at']}",
        "",
        f"Findings: {summary['finding_total']}",
        f"Assets: {summary['asset_count']}",
        f"Scans: {summary['scan_count']}",
        f"By severity: {summary['by_severity']}",
        "",
        "Findings:",
    ]
    for f in report["findings"][:200]:
        lines.append(
            f"- [{f['severity']}/{f['status']}] {f['title']} "
            f"(fp={f['fingerprint'][:12]}… occ={f['occurrence_count']})"
        )
        if f.get("remediation"):
            lines.append(f"  Remediation: {f['remediation'][:200]}")
    return text_pdf(f"Hck Project Report — {project['name']}", lines)


def finding_report_pdf(db: Session, project_id: str, finding_id: str) -> bytes:
    report = build_finding_report(db, project_id, finding_id)
    f = report["finding"]
    lines = [
        f"Project: {report['project']['name']}",
        f"Generated: {report['generated_at']}",
        "",
        f"Title: {f['title']}",
        f"Severity: {f['severity']}",
        f"Confidence: {f['confidence']}",
        f"Status: {f['status']}",
        f"Category: {f['category']}",
        f"Scanner: {f['scanner_id']}",
        f"Fingerprint: {f['fingerprint']}",
        f"Occurrences: {f['occurrence_count']}",
        f"First seen: {f['first_seen_at']}",
        f"Last seen: {f['last_seen_at']}",
        "",
        f"Description: {f.get('description') or '—'}",
        f"Remediation: {f.get('remediation') or '—'}",
        "",
        "Evidence:",
    ]
    for e in f.get("evidence") or []:
        lines.append(f"- [{e['kind']}] {e['path_or_blob_ref'][:300]}")
    lines.append("")
    lines.append("Occurrences:")
    for o in f.get("occurrences") or []:
        lines.append(f"- scan={o['scan_id']} at={o['seen_at']} ref={o.get('raw_ref') or '—'}")
    return text_pdf(f"Hck Finding Report — {f['title'][:60]}", lines)
