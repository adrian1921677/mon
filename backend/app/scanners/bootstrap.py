"""Register all Phase-3 adapters (skeletons + echo)."""

from __future__ import annotations

from app.scanners.echo import EchoAdapter
from app.scanners.gitleaks import GitleaksAdapter
from app.scanners.greenbone import GreenboneAdapter
from app.scanners.linux_host_audit import LinuxHostAuditAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter
from app.scanners.registry import ScannerRegistry
from app.scanners.schemathesis import SchemathesisAdapter
from app.scanners.semgrep import SemgrepAdapter
from app.scanners.testssl import TestsslAdapter
from app.scanners.trivy import TrivyAdapter
from app.scanners.tshark import TsharkAdapter
from app.scanners.windows_host_audit import WindowsHostAuditAdapter
from app.scanners.zap import ZapAdapter

# Productive scanners (UI / Tool Manager). Echo is registered but filtered by default.
PRODUCTIVE_ADAPTER_CLASSES = (
    NmapAdapter,
    GreenboneAdapter,
    TsharkAdapter,
    ZapAdapter,
    NucleiAdapter,
    TestsslAdapter,
    SemgrepAdapter,
    TrivyAdapter,
    GitleaksAdapter,
    SchemathesisAdapter,
    WindowsHostAuditAdapter,
    LinuxHostAuditAdapter,
)


def build_default_registry() -> ScannerRegistry:
    registry = ScannerRegistry()
    for cls in PRODUCTIVE_ADAPTER_CLASSES:
        registry.register(cls())
    registry.register(EchoAdapter())
    return registry
