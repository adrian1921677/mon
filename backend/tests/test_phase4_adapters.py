"""Phase 4 adapters — parse/normalize from fixtures; persist fingerprint dedup."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import Evidence, Finding, FindingOccurrence, ScopeEntryType
from app.db.session import get_db
from app.findings.fingerprint import fingerprint_for
from app.findings.persist import persist_normalized_findings
from app.process.manager import CommandSpec
from app.scanners.base import ParseArtifacts, ScanContext
from app.scanners.gitleaks import GitleaksAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.semgrep import SemgrepAdapter
from app.scanners.trivy import TrivyAdapter
from app.scope.types import ScopeTarget

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(**kwargs) -> ScanContext:
    base = dict(
        project_id="p1",
        scan_id="s1",
        task_id="t1",
        targets=[],
        depth="standard",
    )
    base.update(kwargs)
    return ScanContext(**base)


def test_nmap_parse_normalize_fixture():
    adapter = NmapAdapter()
    xml = (FIXTURES / "nmap" / "sample.xml").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=xml, exit_code=0))
    assert len(parsed["hosts"]) == 1
    assert len(parsed["hosts"][0]["ports"]) == 2  # filtered skipped
    findings = adapter.normalize_findings(parsed, _ctx())
    assert len(findings) == 2
    assert all(f.category == "network.port" for f in findings)
    assert "22" in findings[0].title or "22" in findings[1].title
    # Fingerprints stable
    fp_a = fingerprint_for("nmap", findings[0].fingerprint_parts)
    fp_b = fingerprint_for("nmap", findings[0].fingerprint_parts)
    assert fp_a == fp_b


def test_nmap_build_command_risk_low():
    adapter = NmapAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.5")],
        depth="standard",
        options={"_binary": "nmap"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert isinstance(spec, CommandSpec)
    assert spec.argv[0] == "nmap"
    assert "-sT" in spec.argv
    assert "-F" in spec.argv
    assert "--open" in spec.argv
    assert "10.0.0.5" in spec.argv
    # No aggressive NSE script flags
    assert "-sC" not in spec.argv
    assert "--script" not in spec.argv


def test_semgrep_parse_normalize_fixture():
    adapter = SemgrepAdapter()
    raw = (FIXTURES / "semgrep" / "sample.json").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=1))
    findings = adapter.normalize_findings(parsed, _ctx())
    assert len(findings) == 2
    severities = {f.severity for f in findings}
    assert "high" in severities
    assert "medium" in severities
    assert all(f.category == "sast.semgrep" for f in findings)


def test_semgrep_build_command():
    adapter = SemgrepAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.path, value="/tmp/repo")],
        options={"_binary": "semgrep"},
    )
    spec = adapter.build_command(ctx)
    assert spec.argv[0] == "semgrep"
    assert "--json" in spec.argv
    assert "--metrics=off" in spec.argv
    assert "/tmp/repo" in spec.argv


def test_trivy_parse_normalize_fixture():
    adapter = TrivyAdapter()
    raw = (FIXTURES / "trivy" / "sample.json").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=0))
    findings = adapter.normalize_findings(parsed, _ctx())
    # 2 vulns + 1 misconfig + 1 secret
    assert len(findings) == 4
    cats = {f.category for f in findings}
    assert "vuln.trivy" in cats
    assert "misconfig.trivy" in cats
    assert "secret.trivy" in cats


def test_trivy_build_command():
    adapter = TrivyAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.path, value="/tmp/app")],
        options={"_binary": "trivy"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert spec.argv[0] == "trivy"
    assert "fs" in spec.argv
    assert "--format" in spec.argv
    assert "json" in spec.argv
    assert "--exit-code" in spec.argv


def test_gitleaks_parse_normalize_redacts_secret():
    adapter = GitleaksAdapter()
    raw = (FIXTURES / "gitleaks" / "sample.json").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=1))
    findings = adapter.normalize_findings(parsed, _ctx())
    assert len(findings) == 2
    for f in findings:
        assert f.severity == "high"
        assert f.category == "secret.gitleaks"
        blob = f.evidence[0]["path_or_blob_ref"]
        assert "example-secret-value-not-a-real-credential" not in blob
        assert "EXAMPLEKEYNOTREAL0000" not in blob
        assert "redacted" in blob


def test_gitleaks_build_command_no_git():
    adapter = GitleaksAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.path, value="/tmp/not-a-repo")],
        options={"_binary": "gitleaks"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert spec.argv[0] == "gitleaks"
    assert "detect" in spec.argv
    assert "--no-git" in spec.argv


def test_persist_dedup(client: TestClient):
    res = client.post("/api/v1/projects", json={"name": "Findings Lab"})
    assert res.status_code == 201
    project_id = res.json()["id"]

    gen = client.app.dependency_overrides[get_db]()
    db: Session = next(gen)

    from app.db.models import Scan, ScanStatus

    scan = Scan(project_id=project_id, status=ScanStatus.completed, scope_snapshot_json={})
    db.add(scan)
    db.commit()
    db.refresh(scan)

    adapter = NmapAdapter()
    xml = (FIXTURES / "nmap" / "sample.xml").read_text(encoding="utf-8")
    findings = adapter.normalize_findings(
        adapter.parse_results(ParseArtifacts(stdout=xml, exit_code=0)),
        _ctx(),
    )
    first = persist_normalized_findings(
        db,
        project_id=project_id,
        scan_id=scan.id,
        scanner_id="nmap",
        findings=findings,
    )
    db.commit()
    assert len(first) == 2
    assert db.query(Finding).filter(Finding.project_id == project_id).count() == 2
    assert db.query(FindingOccurrence).count() == 2
    assert db.query(Evidence).count() >= 2

    # Second scan same findings → same Finding rows, new occurrences
    scan2 = Scan(project_id=project_id, status=ScanStatus.completed, scope_snapshot_json={})
    db.add(scan2)
    db.commit()
    db.refresh(scan2)
    second = persist_normalized_findings(
        db,
        project_id=project_id,
        scan_id=scan2.id,
        scanner_id="nmap",
        findings=findings,
    )
    db.commit()
    assert len(second) == 2
    assert db.query(Finding).filter(Finding.project_id == project_id).count() == 2
    assert db.query(FindingOccurrence).count() == 4


@pytest.mark.asyncio
async def test_phase4_not_installed_message():
    adapter = SemgrepAdapter()
    info = await adapter.check_installation()
    # Environment may or may not have semgrep — only assert shape
    assert info.status.value in {"installed", "not_installed", "error", "unknown"}
    if info.status.value == "not_installed":
        assert info.message
