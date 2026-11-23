"""Scanner registry + adapter interface (Phase 3/4)."""

from __future__ import annotations

import pytest

from app.db.models import ScopeEntryType
from app.process.manager import ProcessManager
from app.scanners.base import (
    Capability,
    InstallationStatus,
    ParseArtifacts,
    ScanContext,
    ScannerNotImplementedError,
    ScannerNotInstalledError,
)
from app.scanners.bootstrap import PRODUCTIVE_ADAPTER_CLASSES, build_default_registry
from app.scanners.cli_base import CliScannerAdapter
from app.scanners.echo import EchoAdapter
from app.scanners.registry import reset_registry
from app.scope.types import ScopeTarget

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

PHASE4_IDS = {"nmap", "semgrep", "trivy", "gitleaks"}
PHASE5_IDS = {"zap", "nuclei"}


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


def test_phase4_adapters_are_cli(registry):
    for sid in PHASE4_IDS:
        adapter = registry.get(sid)
        assert isinstance(adapter, CliScannerAdapter)
        assert adapter.integration_phase == 4


def test_phase5_adapters_are_cli(registry):
    for sid in PHASE5_IDS:
        adapter = registry.get(sid)
        assert isinstance(adapter, CliScannerAdapter)
        assert adapter.integration_phase == 5
        assert adapter.is_active is False


@pytest.mark.asyncio
async def test_phase4_missing_binary_fails_clean(registry):
    """If binary missing → ScannerNotInstalledError; never fake findings."""
    for sid in PHASE4_IDS:
        adapter = registry.get(sid)
        info = await adapter.check_installation()
        if info.status is InstallationStatus.installed:
            continue
        if sid == "nmap":
            targets = [ScopeTarget(type=ScopeEntryType.ip, value="10.0.0.1")]
        else:
            targets = [ScopeTarget(type=ScopeEntryType.path, value="/tmp")]
        ctx = ScanContext(project_id="p", scan_id="s", task_id="t", targets=targets)
        pm = ProcessManager(max_concurrent=1, default_timeout_seconds=5.0)
        with pytest.raises(ScannerNotInstalledError):
            await adapter.execute(ctx, pm)


@pytest.mark.asyncio
async def test_phase5_missing_binary_fails_clean(registry):
    for sid in PHASE5_IDS:
        adapter = registry.get(sid)
        info = await adapter.check_installation()
        if info.status is InstallationStatus.installed:
            continue
        targets = [ScopeTarget(type=ScopeEntryType.url, value="https://example.test")]
        ctx = ScanContext(project_id="p", scan_id="s", task_id="t", targets=targets)
        pm = ProcessManager(max_concurrent=1, default_timeout_seconds=5.0)
        with pytest.raises(ScannerNotInstalledError):
            await adapter.execute(ctx, pm)


@pytest.mark.asyncio
async def test_later_phase_skeleton_still_not_implemented(registry):
    schemathesis = registry.get("schemathesis")
    ctx = ScanContext(project_id="p", scan_id="s", task_id="t", targets=[])
    with pytest.raises(ScannerNotImplementedError) as exc:
        schemathesis.normalize_findings({}, ctx)
    assert exc.value.phase == 6


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
    parsed = adapter.parse_results(
        ParseArtifacts(stdout=result.stdout, stderr=result.stderr, exit_code=result.exit_code)
    )
    findings = adapter.normalize_findings(parsed, ctx)
    assert len(findings) == 1
    assert findings[0].meta.get("test_only") is True
    assert findings[0].meta.get("not_a_security_finding") is True

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
    # Phase-5 ZAP/Nuclei: baseline/controlled — Active-Gate only for ZAP deep/active mode.
    assert "zap" not in active
    assert "nuclei" not in active
    assert "greenbone" in active
    assert "schemathesis" in active
    assert "nmap" not in active
