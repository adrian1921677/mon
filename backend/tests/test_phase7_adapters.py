"""Phase 7 adapters — Greenbone + Windows/Linux host audit parse/normalize."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.db.models import ScopeEntryType
from app.findings.fingerprint import fingerprint_for
from app.process.manager import CommandSpec
from app.scanners.base import ParseArtifacts, ScanContext
from app.scanners.cli_base import CliScannerAdapter
from app.scanners.greenbone import GreenboneAdapter
from app.scanners.linux_host_audit import LinuxHostAuditAdapter
from app.scanners.windows_host_audit import WindowsHostAuditAdapter
from app.scope.types import ScopeTarget

FIXTURES = Path(__file__).parent / "fixtures"


def _ctx(**kwargs) -> ScanContext:
    base = dict(
        project_id="p1",
        scan_id="s1",
        task_id="t1",
        targets=[],
        depth="standard",
        options={},
    )
    base.update(kwargs)
    return ScanContext(**base)


def test_greenbone_parse_normalize_fixture():
    adapter = GreenboneAdapter()
    raw = (FIXTURES / "greenbone" / "sample.xml").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=0))
    # Log threat filtered out → 4 results
    assert len(parsed["results"]) == 4
    findings = adapter.normalize_findings(parsed, _ctx())
    assert len(findings) == 4
    assert all(f.category == "network.greenbone" for f in findings)
    sevs = {f.severity for f in findings}
    assert "critical" in sevs  # 9.8 score
    assert "high" in sevs
    assert "medium" in sevs
    assert "low" in sevs
    fp_a = fingerprint_for("greenbone", findings[0].fingerprint_parts)
    fp_b = fingerprint_for("greenbone", findings[0].fingerprint_parts)
    assert fp_a == fp_b


def test_greenbone_build_command_requires_active_gate():
    adapter = GreenboneAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.5")],
        options={"_binary": "gvm-cli"},
        work_dir=Path("/tmp"),
    )
    with pytest.raises(ValueError, match="Active-Gate"):
        adapter.build_command(ctx)


def test_greenbone_build_command_ok():
    adapter = GreenboneAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.5")],
        depth="quick",
        options={"_binary": "gvm-cli", "active_tests_enabled": True},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert isinstance(spec, CommandSpec)
    assert "app.scanners.runners.gvm_scan" in spec.argv
    assert "--targets" in spec.argv
    assert "10.0.0.5" in spec.argv
    assert "--out" in spec.argv
    assert (ctx.options or {}).get("greenbone_xml")


def test_windows_parse_normalize_fixture():
    adapter = WindowsHostAuditAdapter()
    raw = (FIXTURES / "windows_host_audit" / "sample.json").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=0))
    assert len(parsed["checks"]) == 5
    findings = adapter.normalize_findings(parsed, _ctx())
    # pass entries filtered → fail+warn = 3
    assert len(findings) == 3
    assert all(f.category == "host.windows" for f in findings)
    titles = " ".join(f.title for f in findings)
    assert "Defender" in titles
    assert "SMBv1" in titles


def test_windows_validate_local_only():
    adapter = WindowsHostAuditAdapter()
    assert adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.ip, value="127.0.0.1")
    ).allowed
    assert adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.path, value="local")
    ).allowed
    assert not adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.1")
    ).allowed


def test_windows_build_command():
    adapter = WindowsHostAuditAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.path, value="local")],
        options={"_binary": "powershell"},
        work_dir=Path("/tmp"),
    )
    spec = adapter.build_command(ctx)
    assert spec.argv[0] == "powershell"
    assert "-File" in spec.argv
    assert any("windows_host_audit.ps1" in a for a in spec.argv)
    assert (ctx.options or {}).get("windows_host_audit_json")


def test_linux_parse_normalize_fixture():
    adapter = LinuxHostAuditAdapter()
    raw = (FIXTURES / "linux_host_audit" / "sample.json").read_text(encoding="utf-8")
    parsed = adapter.parse_results(ParseArtifacts(stdout=raw, exit_code=0))
    assert len(parsed["checks"]) == 5
    findings = adapter.normalize_findings(parsed, _ctx())
    assert len(findings) == 3
    assert all(f.category == "host.linux" for f in findings)
    titles = " ".join(f.title for f in findings)
    assert "shadow" in titles.lower() or "Permissions" in titles
    assert "PermitRootLogin" in titles


def test_linux_validate_local_only():
    adapter = LinuxHostAuditAdapter()
    assert adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.ip, value="127.0.0.1")
    ).allowed
    assert adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.path, value="/")
    ).allowed
    assert not adapter.validate_target(
        ScopeTarget(type=ScopeEntryType.domain, value="evil.example")
    ).allowed


def test_linux_build_command_native(tmp_path: Path):
    adapter = LinuxHostAuditAdapter()
    ctx = _ctx(
        targets=[ScopeTarget(type=ScopeEntryType.path, value="local")],
        options={"_binary": "bash", "_mode": "native"},
        work_dir=tmp_path,
    )
    spec = adapter.build_command(ctx)
    assert "bash" in spec.argv[0] or spec.argv[0] == "bash"
    assert any("linux_host_audit.sh" in a for a in spec.argv)
    assert "--out" in spec.argv
    assert (ctx.options or {}).get("linux_host_audit_json")


def test_phase7_adapters_are_cli():
    for adapter in (GreenboneAdapter(), WindowsHostAuditAdapter(), LinuxHostAuditAdapter()):
        assert isinstance(adapter, CliScannerAdapter)
        assert adapter.integration_phase == 7


@pytest.mark.asyncio
async def test_phase7_not_installed_shape():
    for adapter in (GreenboneAdapter(), WindowsHostAuditAdapter(), LinuxHostAuditAdapter()):
        info = await adapter.check_installation()
        assert info.status.value in {"installed", "not_installed", "error", "unknown"}
        if info.status.value == "not_installed":
            assert info.message
