"""Scanner registry + adapter interface (Phase 3)."""

from __future__ import annotations

import pytest

from app.process.manager import ProcessManager
from app.scanners.base import (
    Capability,
    InstallationStatus,
    ScanContext,
    ScannerNotImplementedError,
    ScannerNotInstalledError,
)
from app.scanners.bootstrap import PRODUCTIVE_ADAPTER_CLASSES, build_default_registry
from app.scanners.echo import EchoAdapter
from app.scanners.registry import reset_registry
from app.scope.types import ScopeTarget
from app.db.models import ScopeEntryType


EXPECTED_PRODUCTIVE_IDS = {
    "nmap",
    "greenbone",
    "tshark",
    "zap",
    "nuclei",
    "testssl",
    "semgrep",
    "trivy",
    "gitleaks",
    "schemathesis",
    "windows_host_audit",
    "linux_host_audit",
}


@pytest.fixture()
def registry():
    return reset_registry(build_default_registry())


def test_registry_contains_all_productive_and_echo(registry):
    assert set(registry.ids(include_test_only=False)) == EXPECTED_PRODUCTIVE_IDS
    assert "echo" in registry.ids(include_test_only=True)
    assert len(PRODUCTIVE_ADAPTER_CLASSES) == len(EXPECTED_PRODUCTIVE_IDS)
    echo = registry.get("echo")
    assert echo.is_test_only is True
    assert Capability.pipeline_test in echo.capabilities


def test_productive_list_excludes_echo(registry):
    for adapter in registry.list(include_test_only=False):
        assert adapter.is_test_only is False
        assert adapter.scanner_id != "echo"


@pytest.mark.asyncio
async def test_skeleton_not_installed_or_not_implemented(registry):
    nmap = registry.get("nmap")
    info = await nmap.check_installation()
    assert info.status in {
        InstallationStatus.installed,
        InstallationStatus.not_installed,
        InstallationStatus.error,
    }
    ctx = ScanContext(
        project_id="p",
        scan_id="s",
        task_id="t",
        targets=[ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.1")],
    )
    pm = ProcessManager(max_concurrent=1, default_timeout_seconds=5.0)
    if info.status is not InstallationStatus.installed:
        with pytest.raises(ScannerNotInstalledError):
            await nmap.execute(ctx, pm)
    else:
        with pytest.raises(ScannerNotImplementedError) as exc:
            await nmap.execute(ctx, pm)
        assert exc.value.phase == 4


@pytest.mark.asyncio
async def test_skeleton_normalize_never_fakes(registry):
    semgrep = registry.get("semgrep")
    ctx = ScanContext(project_id="p", scan_id="s", task_id="t", targets=[])
    with pytest.raises(ScannerNotImplementedError):
        semgrep.normalize_findings({}, ctx)


@pytest.mark.asyncio
async def test_echo_pipeline_via_process_manager():
    adapter = EchoAdapter()
    info = await adapter.check_installation()
    assert info.status is InstallationStatus.installed
    ctx = ScanContext(
        project_id="p",
        scan_id="s",
        task_id="t",
        targets=[ScopeTarget(type=ScopeEntryType.ip, value="10.1.2.3")],
        allow_test_findings=True,
    )
    pm = ProcessManager(max_concurrent=1, default_timeout_seconds=10.0)
    result = await adapter.execute(ctx, pm)
    assert result.ok
    from app.scanners.base import ParseArtifacts

    parsed = adapter.parse_results(
        ParseArtifacts(stdout=result.stdout, stderr=result.stderr, exit_code=result.exit_code)
    )
    findings = adapter.normalize_findings(parsed, ctx)
    assert len(findings) == 1
    assert findings[0].meta.get("test_only") is True
    assert findings[0].meta.get("not_a_security_finding") is True

    # Without allow_test_findings → empty (no production findings)
    ctx2 = ScanContext(
        project_id="p",
        scan_id="s",
        task_id="t",
        targets=[ScopeTarget(type=ScopeEntryType.ip, value="10.1.2.3")],
        allow_test_findings=False,
    )
    assert adapter.normalize_findings(parsed, ctx2) == []


def test_active_adapters_flagged(registry):
    active = {a.scanner_id for a in registry.list() if a.is_active}
    assert "zap" in active
    assert "nuclei" in active
    assert "greenbone" in active
    assert "schemathesis" in active
    assert "nmap" not in active
