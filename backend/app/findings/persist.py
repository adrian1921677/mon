"""Persist normalized findings with fingerprint dedup."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Evidence, Finding, FindingOccurrence, FindingSeverity
from app.findings.fingerprint import fingerprint_for
from app.scanners.base import NormalizedFinding


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _map_severity(raw: str) -> FindingSeverity:
    key = (raw or "info").strip().lower()
    aliases = {
        "informational": "info",
        "warning": "medium",
        "error": "high",
        "err": "high",
        "crit": "critical",
        "moderate": "medium",
        "unknown": "info",
    }
    key = aliases.get(key, key)
    try:
        return FindingSeverity(key)
    except ValueError:
        return FindingSeverity.info


def persist_normalized_findings(
    db: Session,
    *,
    project_id: str,
    scan_id: str,
    scanner_id: str,
    findings: list[NormalizedFinding],
) -> list[Finding]:
    """
    Upsert findings by (project_id, fingerprint), add occurrence + evidence.

    Never invents findings — only persists what adapters already normalized.
    """
    now = _utcnow()
    stored: list[Finding] = []
    for item in findings:
        fp = fingerprint_for(scanner_id, item.fingerprint_parts)
        row = (
            db.query(Finding)
            .filter(Finding.project_id == project_id, Finding.fingerprint == fp)
            .one_or_none()
        )
        if row is None:
            row = Finding(
                project_id=project_id,
                fingerprint=fp,
                title=item.title[:512],
                severity=_map_severity(item.severity),
                category=item.category[:128],
                scanner_id=scanner_id,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(row)
            db.flush()
        else:
            row.title = item.title[:512]
            row.severity = _map_severity(item.severity)
            row.category = item.category[:128]
            row.last_seen_at = now

        db.add(
            FindingOccurrence(
                finding_id=row.id,
                scan_id=scan_id,
                raw_ref=item.raw_ref,
                seen_at=now,
            )
        )

        for ev in item.evidence or []:
            kind = str(ev.get("kind") or "snippet")[:64]
            ref = str(ev.get("path_or_blob_ref") or ev.get("ref") or "")[:4000]
            if not ref:
                continue
            db.add(
                Evidence(
                    finding_id=row.id,
                    kind=kind,
                    path_or_blob_ref=ref,
                )
            )
        stored.append(row)

    if findings:
        db.flush()
    return stored
