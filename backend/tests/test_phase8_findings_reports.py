"""Phase 8: Findings API, Dashboard, Reports (JSON/PDF/compare) — real DB only."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import (
    Evidence,
    Finding,
    FindingConfidence,
    FindingOccurrence,
    FindingSeverity,
    FindingStatus,
    Scan,
    ScanStatus,
)
from app.db.session import get_db
from app.findings.fingerprint import fingerprint_for
from app.findings.persist import persist_normalized_findings
from app.scanners.base import NormalizedFinding


def _create_project(client: TestClient, name: str = "Phase8 Lab") -> str:
    res = client.post("/api/v1/projects", json={"name": name, "description": "p8"})
    assert res.status_code == 201
    return res.json()["id"]


def _db(client: TestClient) -> Session:
    gen = client.app.dependency_overrides[get_db]()
    return next(gen)


def _seed_finding(
    db: Session,
    *,
    project_id: str,
    scan_id: str | None,
    title: str,
    severity: FindingSeverity = FindingSeverity.high,
    fingerprint_parts: tuple[str, ...] = ("rule", "target"),
    scanner_id: str = "nmap",
) -> Finding:
    stored = persist_normalized_findings(
        db,
        project_id=project_id,
        scan_id=scan_id or "00000000-0000-0000-0000-000000000000",
        scanner_id=scanner_id,
        findings=[
            NormalizedFinding(
                title=title,
                severity=severity.value,
                category="network",
                fingerprint_parts=fingerprint_parts,
                raw_ref="fixture://evidence",
                evidence=[{"kind": "snippet", "path_or_blob_ref": "port 22 open"}],
                meta={
                    "confidence": "high",
                    "remediation": "Restrict SSH exposure",
                    "description": "Service exposed",
                },
            )
        ],
    )
    db.commit()
    return stored[0]


def _create_scan(db: Session, project_id: str, status: ScanStatus = ScanStatus.completed) -> Scan:
    scan = Scan(
        project_id=project_id,
        status=status,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc) if status is ScanStatus.completed else None,
        scope_snapshot_json={"entries": []},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def test_findings_list_detail_status_and_dedup(client: TestClient):
    pid = _create_project(client)
    db = _db(client)
    scan = _create_scan(db, pid)

    first = _seed_finding(
        db,
        project_id=pid,
        scan_id=scan.id,
        title="Open SSH",
        fingerprint_parts=("ssh", "10.0.0.5"),
    )
    # Same fingerprint again → occurrence++, no second finding row
    again = persist_normalized_findings(
        db,
        project_id=pid,
        scan_id=scan.id,
        scanner_id="nmap",
        findings=[
            NormalizedFinding(
                title="Open SSH",
                severity="high",
                category="network",
                fingerprint_parts=("ssh", "10.0.0.5"),
                raw_ref="fixture://again",
                evidence=[],
                meta={"confidence": "medium"},
            )
        ],
    )
    db.commit()
    assert again[0].id == first.id
    assert db.query(Finding).filter(Finding.project_id == pid).count() == 1
    assert db.query(FindingOccurrence).filter(FindingOccurrence.finding_id == first.id).count() == 2

    listed = client.get(f"/api/v1/projects/{pid}/findings")
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 1
    assert body["items"][0]["occurrence_count"] == 2
    assert body["items"][0]["status"] == "open"
    # Last occurrence may refresh confidence; remediation from first persist remains
    assert body["items"][0]["confidence"] in {"high", "medium"}
    assert body["items"][0]["remediation"]

    detail = client.get(f"/api/v1/projects/{pid}/findings/{first.id}")
    assert detail.status_code == 200
    d = detail.json()
    assert len(d["occurrences"]) == 2
    assert len(d["evidence"]) >= 1
    assert d["fingerprint"] == fingerprint_for("nmap", ("ssh", "10.0.0.5"))

    patched = client.patch(
        f"/api/v1/projects/{pid}/findings/{first.id}",
        json={"status": "false_positive"},
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "false_positive"


def test_dashboard_uses_real_counts(client: TestClient):
    pid = _create_project(client)
    # Scope → asset
    scope = client.post(
        f"/api/v1/projects/{pid}/scope",
        json={"type": "ip", "value": "10.0.0.8", "meta_json": {}},
    )
    assert scope.status_code == 201, scope.text

    db = _db(client)
    scan = _create_scan(db, pid, status=ScanStatus.running)
    _seed_finding(
        db,
        project_id=pid,
        scan_id=scan.id,
        title="Critical hole",
        severity=FindingSeverity.critical,
        fingerprint_parts=("crit", "a"),
    )
    _seed_finding(
        db,
        project_id=pid,
        scan_id=scan.id,
        title="Low note",
        severity=FindingSeverity.low,
        fingerprint_parts=("low", "b"),
    )

    assets = client.get(f"/api/v1/projects/{pid}/assets")
    assert assets.status_code == 200
    assert len(assets.json()) >= 1

    dash = client.get(f"/api/v1/projects/{pid}/dashboard")
    assert dash.status_code == 200
    data = dash.json()
    assert data["asset_count"] >= 1
    assert data["finding_counts"]["total"] == 2
    assert data["finding_counts"]["by_severity"]["critical"] == 1
    assert len(data["critical_findings"]) == 1
    assert data["critical_findings"][0]["title"] == "Critical hole"
    assert any(s["id"] == scan.id for s in data["running_scans"])
    assert len(data["trend"]) == 14
    assert data["scanners"]["total"] >= 1
    # Empty project dashboard must not invent findings
    pid2 = _create_project(client, name="Empty")
    empty = client.get(f"/api/v1/projects/{pid2}/dashboard").json()
    assert empty["finding_counts"]["total"] == 0
    assert empty["critical_findings"] == []


def test_reports_json_pdf_and_compare(client: TestClient):
    pid = _create_project(client)
    db = _db(client)
    scan_a = _create_scan(db, pid)
    scan_b = _create_scan(db, pid)

    shared = persist_normalized_findings(
        db,
        project_id=pid,
        scan_id=scan_a.id,
        scanner_id="semgrep",
        findings=[
            NormalizedFinding(
                title="Shared issue",
                severity="medium",
                category="code",
                fingerprint_parts=("rule-x", "file.py"),
                evidence=[{"kind": "snippet", "ref": "line 10"}],
                meta={"remediation": "Sanitize input"},
            )
        ],
    )
    # Only in A
    persist_normalized_findings(
        db,
        project_id=pid,
        scan_id=scan_a.id,
        scanner_id="semgrep",
        findings=[
            NormalizedFinding(
                title="Only A",
                severity="low",
                category="code",
                fingerprint_parts=("only-a", "file.py"),
            )
        ],
    )
    # Shared again in B + new in B
    persist_normalized_findings(
        db,
        project_id=pid,
        scan_id=scan_b.id,
        scanner_id="semgrep",
        findings=[
            NormalizedFinding(
                title="Shared issue",
                severity="medium",
                category="code",
                fingerprint_parts=("rule-x", "file.py"),
            ),
            NormalizedFinding(
                title="Only B",
                severity="high",
                category="code",
                fingerprint_parts=("only-b", "file.py"),
            ),
        ],
    )
    db.commit()
    finding_id = shared[0].id

    json_res = client.get(f"/api/v1/projects/{pid}/reports/project?format=json")
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers["content-type"]
    report = json.loads(json_res.content)
    assert report["report_type"] == "project"
    assert report["summary"]["finding_total"] == 3
    assert len(report["findings"]) == 3

    pdf_res = client.get(f"/api/v1/projects/{pid}/reports/project?format=pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")

    f_json = client.get(f"/api/v1/projects/{pid}/reports/findings/{finding_id}?format=json")
    assert f_json.status_code == 200
    f_body = json.loads(f_json.content)
    assert f_body["finding"]["id"] == finding_id
    assert f_body["finding"]["remediation"]

    f_pdf = client.get(f"/api/v1/projects/{pid}/reports/findings/{finding_id}?format=pdf")
    assert f_pdf.status_code == 200
    assert f_pdf.content.startswith(b"%PDF")

    cmp = client.post(
        f"/api/v1/projects/{pid}/reports/compare",
        json={"baseline_scan_id": scan_a.id, "candidate_scan_id": scan_b.id},
    )
    assert cmp.status_code == 200, cmp.text
    c = cmp.json()
    assert c["summary"]["new"] == 1
    assert c["summary"]["resolved"] == 1
    assert c["summary"]["persistent"] == 1
    assert c["new_findings"][0]["title"] == "Only B"
    assert c["resolved_findings"][0]["title"] == "Only A"
    assert len(c["history"]) >= 2

    bad = client.post(
        f"/api/v1/projects/{pid}/reports/compare",
        json={"baseline_scan_id": scan_a.id, "candidate_scan_id": scan_a.id},
    )
    assert bad.status_code == 400


def test_empty_project_report_has_no_fake_findings(client: TestClient):
    pid = _create_project(client, name="Blank")
    res = client.get(f"/api/v1/projects/{pid}/reports/project?format=json")
    assert res.status_code == 200
    data = json.loads(res.content)
    assert data["summary"]["finding_total"] == 0
    assert data["findings"] == []

    listed = client.get(f"/api/v1/projects/{pid}/findings")
    assert listed.json()["total"] == 0
    assert listed.json()["items"] == []


def test_finding_update_preserves_confidence_enum(client: TestClient):
    pid = _create_project(client)
    db = _db(client)
    scan = _create_scan(db, pid)
    f = _seed_finding(db, project_id=pid, scan_id=scan.id, title="X", fingerprint_parts=("x",))
    assert f.confidence is FindingConfidence.high
    assert f.status is FindingStatus.open

    res = client.patch(
        f"/api/v1/projects/{pid}/findings/{f.id}",
        json={"status": "fixed", "confidence": "low", "remediation": "Patched upstream"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "fixed"
    assert body["confidence"] == "low"
    assert body["remediation"] == "Patched upstream"

    # Evidence rows stay linked
    assert db.query(Evidence).filter(Evidence.finding_id == f.id).count() >= 1
